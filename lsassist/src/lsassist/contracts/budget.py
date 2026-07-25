"""BudgetState contract model (SPEC §4.3 budget table).

Frozen, I/O-free, stdlib+pydantic only per the §2.2 contracts rules. Limits
default verbatim to §4.3; usage counters are consumed by the kernel loop.
Exhaustion kinds follow the §4.4 ``budget_exhausted:<kind>`` wire form
(``tool_calls`` | ``tokens`` | ``time`` | ``cost``); plan-revision and
session-cap exhaustion share the §4.3 forced-REPORT behavior and are reported
under the ``tool_calls`` kind (§4.4 defines no dedicated kind for them).

Refund rule (§4.3): a failed schema validation (model error) does not consume
``max_tool_calls`` — the kernel consumes on dispatch and calls
:meth:`BudgetState.refund_tool_call` on schema-validation failure.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class BudgetState(BaseModel):
    """Per-task budget limits (§4.3) plus usage counters. Pure value object."""

    model_config = ConfigDict(frozen=True)

    # --- §4.3 limits (defaults verbatim) ---
    max_tool_calls: int = Field(default=25, ge=1)
    max_plan_revisions: int = Field(default=8, ge=1)
    max_tokens: int = Field(default=180_000, ge=1)
    max_wall_clock_s: int = Field(default=1800, ge=1)
    # (max_stdout_bytes, max_stderr_bytes) = 50 KB stdout + 20 KB stderr.
    max_output_per_tool: tuple[int, int] = (50_000, 20_000)
    max_session_tool_calls: int = Field(default=200, ge=1)

    # --- usage counters ---
    tool_calls_used: int = Field(default=0, ge=0)
    plan_revisions_used: int = Field(default=0, ge=0)
    tokens_used: int = Field(default=0, ge=0)
    wall_clock_used_s: int = Field(default=0, ge=0)
    session_tool_calls_used: int = Field(default=0, ge=0)

    def consume(
        self,
        *,
        tool_calls: int = 0,
        plan_revisions: int = 0,
        tokens: int = 0,
        wall_clock_s: int = 0,
    ) -> BudgetState:
        """Return a new state with the given consumption applied.

        Pure: ``self`` is never mutated. Tool calls also count against the
        session cap (§4.3 session budgets = sum caps).
        """
        return self.model_copy(
            update={
                "tool_calls_used": self.tool_calls_used + tool_calls,
                "session_tool_calls_used": self.session_tool_calls_used + tool_calls,
                "plan_revisions_used": self.plan_revisions_used + plan_revisions,
                "tokens_used": self.tokens_used + tokens,
                "wall_clock_used_s": self.wall_clock_used_s + wall_clock_s,
            }
        )

    def refund_tool_call(self) -> BudgetState:
        """Refund one tool call (§4.3: failed schema validation costs nothing).

        A no-op when nothing has been consumed (never goes negative).
        """
        if self.tool_calls_used == 0:
            return self
        return self.model_copy(
            update={
                "tool_calls_used": self.tool_calls_used - 1,
                "session_tool_calls_used": max(0, self.session_tool_calls_used - 1),
            }
        )

    def exhausted_kind(self) -> str | None:
        """First exhausted budget kind (§4.4 parameter), or None if all fit."""
        if (
            self.tool_calls_used >= self.max_tool_calls
            or self.plan_revisions_used >= self.max_plan_revisions
            or self.session_tool_calls_used >= self.max_session_tool_calls
        ):
            return "tool_calls"
        if self.tokens_used >= self.max_tokens:
            return "tokens"
        if self.wall_clock_used_s >= self.max_wall_clock_s:
            return "time"
        return None

    def is_exhausted(self) -> bool:
        """True when any budget is at or over its limit."""
        return self.exhausted_kind() is not None
