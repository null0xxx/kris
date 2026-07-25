"""Per-task budget tracker for the SPEC §4.3 table (T2.08).

This module is the KERNEL-side logic over the T1.05 value object
:class:`~lsassist.contracts.budget.BudgetState`. The split is deliberate:

- ``contracts.BudgetState`` owns the §4.3 NUMBERS (defaults) and the pure
  copy-on-write counter arithmetic. It is the single source of truth for every
  limit; this module NEVER re-declares one. :func:`default_budget` is a
  one-line passthrough precisely so that no §4.3 constant is ever typed twice
  (a drift between the two would silently widen a security-relevant cap).
- ``kernel.budgets`` (here) owns the DECISIONS: which budget tripped, what §4.4
  ``budget_exhausted:<kind>`` parameter that maps to, when a tool call is
  refunded, and how oversized tool output is capped.

PURITY (§2.2, TCB): no filesystem, no environment, no child process, nothing
nondeterministic — and, critically, **no clock**. Wall-clock is measured
from an INJECTED ``now`` (:func:`observe_wall_clock`); the caller owns the
clock, which is what makes the kernel loop replayable from the journal (§14.5)
and testable without freezing time.

FAIL-CLOSED: every entry point validates its inputs and raises
:class:`BudgetError` rather than clamping. Silently clamping a negative token
count to 0, or a zero output cap to "unlimited", turns a caller bug into an
unbounded budget — exactly the failure this module exists to prevent. The one
operation that cannot express its failure as a raise is the wall-clock write,
because a stale ``started_at`` is indistinguishable from a legitimate one; it
is made MONOTONE instead (see :func:`observe_wall_clock`).

WHY BUDGET COUNTERS ARE SAFETY STATE, NOT BOOKKEEPING.
``machine._budget_remains`` gates the EXECUTE and APPROVAL transition rows on
``BudgetState.exhausted_kind()``. An exhausted budget is therefore a CLOSED
I15 EXECUTE gate, and anything that LOWERS a counter re-opens it. Consequently
no function here ever decreases a counter except the one §4.3 explicitly
mandates (:func:`settle_tool_call`'s refund, which is bounded to a single call
and requires a matching prior charge), and :func:`observe_wall_clock` writes a
high-water mark rather than an absolute value.

FIELD OWNERSHIP — ``wall_clock_used_s`` HAS TWO WRITERS.
``contracts.BudgetState.consume(wall_clock_s=…)`` is the contract's published
ADDITIVE writer; :func:`observe_wall_clock` is the kernel's AUTHORITATIVE one
and writes a monotone measurement. Their semantics are opposite, so a caller
must not mix them on the same budget object: the kernel loop uses
:func:`observe_wall_clock` exclusively. (``contracts/`` is frozen, so the
additive writer stays; the monotone floor is what makes mixing them safe
rather than budget-widening.)

REFUND REACHABILITY (documented deliberately — see :class:`ToolCallOutcome`).
Under the current §4.2 transition table the machine charges a tool call
(``budget:consume_tool_call``) only on the two EXECUTE-entry rows, which sit
AFTER schema validation has already passed on the PLAN→POLICY_CHECK edge. A
schema-invalid request therefore never reaches a charge, and the §4.3 refund
branch is UNREACHABLE in the composed design today: the only live settle is the
:attr:`ToolCallOutcome.EXECUTED` no-op. The branch is retained as a guard
against a future charge point (or a runner that charges before validation) and
is named here so it is not mistaken for a live path and left to rot.

§4.4 kinds. The wire form carries only four parameters
(``tool_calls|tokens|time|cost``) while §4.3 lists six budgets. The mapping is
therefore many-to-one and is stated once, in :data:`_BUDGET_KIND`:
``max_plan_revisions`` and ``max_session_tool_calls`` both report under
``tool_calls`` (§4.4 defines no dedicated parameter for them, and both share
the §4.3 forced-REPORT behavior). :class:`Exhaustion` keeps the SPECIFIC budget
name alongside the kind so the REPORT can say which one actually tripped
without inventing a non-§4.4 wire value.

SCOPE NOTE — ``cost``. §4.3's ``max_cost_estimate`` is "user-configured;
default = warn at 80% of observed weekly quota pattern", i.e. a WARNING with a
user decision, not a hard counter; ``BudgetState`` accordingly has no cost
field. This tracker therefore never emits the ``cost`` kind. It remains
reachable via ``ExitReason.BUDGET_EXHAUSTED.render("cost")`` for whichever
component lands the §4.3 cost estimator.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from enum import StrEnum

from lsassist.contracts.budget import BudgetState
from lsassist.contracts.enums import ExitReason


class BudgetError(ValueError):
    """A budget operation received an impossible input (§4.3, fail-closed).

    Raised for a negative or non-finite quantity, a non-positive output cap, a
    settle of a tool call that was never charged, backwards wall-clock, or an
    exhaustion kind outside the §4.4 parameter set. Never clamps — a caller bug
    that quietly widened a budget would defeat the whole §4.3 mechanism.
    """


# ---------------------------------------------------------------------------
# §4.3 budget → §4.4 exit-reason parameter
# ---------------------------------------------------------------------------

# Ordered: this IS the exhaustion precedence, and it is kept identical to
# ``BudgetState.exhausted_kind`` (a drift test pins the two together). Tuple of
# (BudgetState limit field, BudgetState usage field, §4.4 kind).
_BUDGET_KIND: tuple[tuple[str, str, str], ...] = (
    ("max_tool_calls", "tool_calls_used", "tool_calls"),
    ("max_plan_revisions", "plan_revisions_used", "tool_calls"),
    ("max_session_tool_calls", "session_tool_calls_used", "tool_calls"),
    ("max_tokens", "tokens_used", "tokens"),
    ("max_wall_clock_s", "wall_clock_used_s", "time"),
)


@dataclass(frozen=True)
class Exhaustion:
    """A tripped §4.3 budget, carrying everything the §4.4 REPORT needs.

    ``kind`` is the §4.4 wire parameter (``tool_calls`` | ``tokens`` |
    ``time``); ``budget`` is the specific ``BudgetState`` field that tripped
    (e.g. ``max_plan_revisions``), preserved for the human-facing REPORT text
    and the audit event, because several budgets share one wire kind.
    """

    budget: str
    kind: str
    limit: int
    used: int

    @property
    def reason(self) -> ExitReason:
        """The §4.4 ExitReason — always ``budget_exhausted`` for this class."""
        return ExitReason.BUDGET_EXHAUSTED

    def render(self) -> str:
        """Render the §4.4 wire form, e.g. ``budget_exhausted:tool_calls``.

        Delegates the parameter check to the contract enum so the allowed set
        lives in exactly one place; an out-of-set kind fails closed here.
        """
        try:
            return ExitReason.BUDGET_EXHAUSTED.render(self.kind)
        except ValueError as exc:
            raise BudgetError(f"not a §4.4 budget kind: {self.kind!r}") from exc


def default_budget() -> BudgetState:
    """A fresh per-task budget carrying the §4.3 defaults.

    Intentionally a passthrough to the contract default: the §4.3 numbers are
    declared once, in ``contracts.budget``, and re-stating them here is the
    drift bug this function exists to make impossible.
    """
    return BudgetState()


def classify_exhaustion(state: BudgetState) -> Exhaustion | None:
    """Return the first exhausted §4.3 budget, or ``None`` if all still fit.

    A budget is exhausted when ``used >= limit`` (at the limit, not past it):
    the 25th tool call is the last one allowed, so a state showing 25 used has
    nothing left. Precedence follows :data:`_BUDGET_KIND` and is pinned equal
    to :meth:`BudgetState.exhausted_kind` by test.
    """
    for budget, counter, kind in _BUDGET_KIND:
        limit: int = getattr(state, budget)
        used: int = getattr(state, counter)
        if used >= limit:
            return Exhaustion(budget=budget, kind=kind, limit=limit, used=used)
    return None


# ---------------------------------------------------------------------------
# Consumption
# ---------------------------------------------------------------------------


def consume_tool_call(state: BudgetState) -> BudgetState:
    """Charge one tool call, against BOTH the task and session caps (§4.3).

    Called at DISPATCH, before the tool runs — charging first is what makes the
    refund rule (:func:`settle_tool_call`) meaningful and what prevents a crash
    mid-execution from leaving an uncharged call behind.
    """
    return state.consume(tool_calls=1)


def consume_plan_revision(state: BudgetState) -> BudgetState:
    """Charge one plan revision (§4.3 ``max_plan_revisions``, §4.2 PLAN edge)."""
    return state.consume(plan_revisions=1)


def consume_tokens(state: BudgetState, tokens: int) -> BudgetState:
    """Charge ``tokens`` against the §4.3 combined in+out token budget.

    ``tokens`` is the in+out total for one provider round trip. Zero is a legal
    no-op (a cached or refused request); a negative count is a caller bug and
    fails closed rather than silently refunding tokens.
    """
    if tokens < 0:
        raise BudgetError(f"token count must be >= 0, got {tokens}")
    return state.consume(tokens=tokens)


def observe_wall_clock(state: BudgetState, *, started_at: float, now: float) -> BudgetState:
    """Record elapsed task wall-clock from an INJECTED clock reading (§4.3).

    Both arguments are seconds from the SAME monotonic source, supplied by the
    caller — this module never reads a clock (purity, §2.2), which is what lets
    the kernel loop be replayed deterministically from the journal.

    MEASURED, not accrued: the counter tracks ``now - started_at`` (floored to
    whole seconds) rather than summing deltas, so calling this repeatedly
    during a task converges on the true elapsed time instead of
    multiply-counting it.

    HIGH-WATER MARK — the write is MONOTONE and NEVER lowers the counter
    (``max(current, elapsed)``). This is a security property, not tidiness.
    ``machine._budget_remains`` gates the EXECUTE and APPROVAL rows on
    ``BudgetState.exhausted_kind()``, so ANY write that lowers
    ``wall_clock_used_s`` re-opens the I15 EXECUTE gate on a task whose §4.3
    30-minute budget is already spent. That is an invited mistake, not an
    exotic one: a runner must carry ONE ``BudgetState`` across tasks (the
    session tool-call counter lives on the same object), so it will naturally
    pass a fresh per-task ``started_at`` to an object that already carries a
    previous task's elapsed time. Under an absolute write that call silently
    widens a spent budget. Clamping upward is the fail-closed direction here —
    every other caller mistake in this module (backwards clock, non-finite
    reading, negative tokens, zero cap) fails closed by RAISING, and this is
    the one operation whose natural failure mode WIDENS a budget, so it is the
    one that needs the floor.

    WRITER OWNERSHIP: ``BudgetState.consume(wall_clock_s=…)`` is the contract's
    ADDITIVE writer of this same field; this function is the kernel's
    AUTHORITATIVE one. They have opposite semantics — do not mix them on one
    budget object. The kernel loop uses this function exclusively; the
    monotone floor means that even if something did call ``consume`` first, the
    elapsed reading can only ever raise the result, never undo it.

    Time running backwards, or a non-finite reading, still fails closed — under
    a clamp either would read as "no time has passed" and disable the cap.
    """
    if not math.isfinite(started_at) or not math.isfinite(now):
        raise BudgetError(f"clock readings must be finite, got {started_at!r} → {now!r}")
    elapsed = now - started_at
    if elapsed < 0:
        raise BudgetError(f"clock ran backwards: started_at={started_at!r} > now={now!r}")
    return state.model_copy(
        update={"wall_clock_used_s": max(state.wall_clock_used_s, int(elapsed))}
    )


# ---------------------------------------------------------------------------
# The §4.3 refund rule
# ---------------------------------------------------------------------------


class ToolCallOutcome(StrEnum):
    """How a charged tool call ended — the ONLY input to the §4.3 refund rule.

    The two members are the two sides of the rule and are kept separate so a
    caller must NAME the case rather than pass a bare ``refund: bool`` that
    reads the same at both call sites:

    - :attr:`SCHEMA_INVALID` — the MODEL emitted a request that failed schema
      validation against the registry (§4.2 PLAN→POLICY_CHECK guard). Nothing
      executed and no side effect exists. §4.3: this does NOT consume
      ``max_tool_calls``, so the model gets its budget back and can be asked to
      re-emit a well-formed request.

      **NOT REACHABLE IN THE COMPOSED DESIGN TODAY.** ``machine`` emits
      ``budget:consume_tool_call`` only on the two EXECUTE-entry rows, i.e.
      after the PLAN→POLICY_CHECK schema check has already passed, so a
      schema-invalid request is rejected before any charge exists to refund.
      Every live settle site therefore takes the :attr:`EXECUTED` no-op branch.
      This member and ``BudgetState.refund_tool_call`` are kept — §4.3 mandates
      the rule, and it becomes load-bearing the moment a charge point moves
      earlier (e.g. a runner that charges at PLAN to bill malformed model
      output, or a future §4.2 row that charges pre-validation). Stated
      explicitly so nobody reads this as an exercised path.
    - :attr:`EXECUTED` — the tool RAN. Its exit code is irrelevant: a tool that
      ran and failed (non-zero exit, timeout, sandbox kill) consumed real
      resources and may have left side effects, so it keeps its charge. This is
      the case an over-eager "it errored, refund it" reading would get wrong,
      turning ``max_tool_calls`` into an unbounded retry loop.
    """

    SCHEMA_INVALID = "schema_invalid"
    EXECUTED = "executed"


def settle_tool_call(state: BudgetState, outcome: ToolCallOutcome) -> BudgetState:
    """Settle a tool call previously charged by :func:`consume_tool_call`.

    Refunds exactly one call (task AND session counters) iff ``outcome`` is
    :attr:`ToolCallOutcome.SCHEMA_INVALID` — the §4.3 refund rule. Every other
    outcome is a no-op returning ``state`` unchanged.

    Settling when nothing is charged (``tool_calls_used == 0``) fails closed:
    it means the caller settled twice, or settled a call it never dispatched,
    and a silent no-op there would let a double-refund manufacture budget out
    of nothing.
    """
    if state.tool_calls_used == 0:
        raise BudgetError("no charged tool call to settle (tool_calls_used == 0)")
    if outcome is ToolCallOutcome.SCHEMA_INVALID:
        return state.refund_tool_call()
    return state


# ---------------------------------------------------------------------------
# §4.3 max_output_per_tool — truncation marker + digest of the full output
# ---------------------------------------------------------------------------

# The marker the kernel appends to a truncated capture. Deterministic and
# self-describing: it states what was kept, what the real size was, and the
# digest that lets an auditor prove what the discarded bytes were.
_MARKER_TEMPLATE = (
    "[lsassist: output truncated — kept {kept} of {total} bytes; full output {digest}]"
)


@dataclass(frozen=True)
class CappedOutput:
    """One tool stream capped to its §4.3 limit, with the full-output digest.

    ``digest`` is a sha256 over the **entire pre-truncation output**, not over
    the kept prefix and not over the discarded tail. §4.3 asks for a "digest of
    full (discarded) output" and the whole-output reading is the only one that
    is useful: it lets a later auditor take a re-captured output and prove it
    is byte-identical to what the tool actually produced. Digesting only the
    tail would be unverifiable without also knowing the cut point, and
    digesting the kept prefix would be redundant with the prefix itself.

    ``digest`` is always present, truncated or not, and carries the ``sha256:``
    prefix used everywhere else in the contracts (``ToolResult.stdout_digest``,
    ``policy.canonical.action_hash``).
    """

    kept: bytes
    truncated: bool
    original_bytes: int
    digest: str
    marker: str

    @property
    def kept_text(self) -> str:
        """The kept prefix as text, lossy at the cut.

        A byte-exact cap can land mid-codepoint, so decoding uses
        ``errors="replace"``: the cut is a display artefact, and the ``digest``
        remains the authoritative record of the real bytes.
        """
        return self.kept.decode("utf-8", errors="replace")


def cap_output(data: bytes | str, limit: int) -> CappedOutput:
    """Cap one captured stream at ``limit`` bytes (§4.3 ``max_output_per_tool``).

    ``str`` input is encoded UTF-8 first, so ``limit`` is always a count of
    BYTES — the unit §4.3 states, and the only unit that actually bounds memory
    (a character count would let a multi-byte output blow past the cap).

    The cap is inclusive: output of exactly ``limit`` bytes is kept whole and
    reported as not truncated. A non-positive ``limit`` fails closed — a zero
    cap is a misconfiguration that would silently discard every tool's output,
    not an instruction to keep nothing.
    """
    if limit < 1:
        raise BudgetError(f"output cap must be >= 1 byte, got {limit}")
    raw = data.encode("utf-8") if isinstance(data, str) else data
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    total = len(raw)
    if total <= limit:
        return CappedOutput(
            kept=raw, truncated=False, original_bytes=total, digest=digest, marker=""
        )
    return CappedOutput(
        kept=raw[:limit],
        truncated=True,
        original_bytes=total,
        digest=digest,
        marker=_MARKER_TEMPLATE.format(kept=limit, total=total, digest=digest),
    )


def cap_stdout(data: bytes | str, state: BudgetState) -> CappedOutput:
    """Cap a stdout capture at the budget's §4.3 stdout limit (default 50 KB)."""
    return cap_output(data, state.max_output_per_tool[0])


def cap_stderr(data: bytes | str, state: BudgetState) -> CappedOutput:
    """Cap a stderr capture at the budget's §4.3 stderr limit (default 20 KB)."""
    return cap_output(data, state.max_output_per_tool[1])
