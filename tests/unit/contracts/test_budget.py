"""T1.05 RED: BudgetState (SPEC §4.3 budget table).

§4.3 defaults are pinned verbatim; exhaustion kinds follow the §4.4
``budget_exhausted:<kind>`` wire form. Refund rule (§4.3): a failed schema
validation (model error) does not consume ``max_tool_calls`` — the kernel
consumes on dispatch and refunds on schema-validation failure, so net
consumption for such a turn is zero.
"""

from __future__ import annotations

from typing import Any

import pytest

from lsassist.contracts.budget import BudgetState

# --- (1) defaults exactly per §4.3 --------------------------------------------


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("max_tool_calls", 25),
        ("max_plan_revisions", 8),
        ("max_tokens", 180_000),
        ("max_wall_clock_s", 1800),
        ("max_output_per_tool", (50_000, 20_000)),
        ("max_session_tool_calls", 200),
    ],
)
def test_defaults_match_spec_43(field: str, expected: Any) -> None:
    assert getattr(BudgetState(), field) == expected


def test_fresh_budget_not_exhausted() -> None:
    budget = BudgetState()
    assert budget.exhausted_kind() is None
    assert not budget.is_exhausted()


# --- (2) consume at the limit → budget_exhausted with the right kind ----------


def test_consume_tool_call_at_limit_exhausts_tool_calls() -> None:
    budget = BudgetState(tool_calls_used=24).consume(tool_calls=1)
    assert budget.exhausted_kind() == "tool_calls"
    assert budget.is_exhausted()


def test_consume_tool_call_below_limit_not_exhausted() -> None:
    assert BudgetState(tool_calls_used=23).consume(tool_calls=1).exhausted_kind() is None


def test_tokens_at_limit_exhausts_tokens() -> None:
    assert BudgetState(tokens_used=180_000).exhausted_kind() == "tokens"


def test_wall_clock_at_limit_exhausts_time() -> None:
    assert BudgetState(wall_clock_used_s=1800).exhausted_kind() == "time"


def test_session_tool_call_cap_exhausts_tool_calls() -> None:
    assert BudgetState(session_tool_calls_used=200).exhausted_kind() == "tool_calls"


def test_plan_revision_exhaustion_reports_tool_calls_kind() -> None:
    # §4.4 has no dedicated plan-revision kind; §4.3 exhaustion behavior is the
    # same forced REPORT, reported under the "tool_calls" budget kind.
    assert BudgetState(plan_revisions_used=8).exhausted_kind() == "tool_calls"


def test_consume_is_pure_and_counts_session_calls() -> None:
    original = BudgetState()
    updated = original.consume(tool_calls=1, plan_revisions=1, tokens=100, wall_clock_s=5)
    assert original.tool_calls_used == 0  # untouched (frozen/pure)
    assert updated.tool_calls_used == 1
    assert updated.session_tool_calls_used == 1
    assert updated.plan_revisions_used == 1
    assert updated.tokens_used == 100
    assert updated.wall_clock_used_s == 5


# --- (3) refund rule: schema-validation failure costs no tool call (§4.3) -----


def test_schema_validation_failure_net_zero_consumption() -> None:
    original = BudgetState()
    refunded = original.consume(tool_calls=1).refund_tool_call()
    assert refunded.tool_calls_used == original.tool_calls_used == 0
    assert refunded.session_tool_calls_used == 0
    assert not refunded.is_exhausted()


def test_refund_restores_exhausted_tool_call_budget() -> None:
    budget = BudgetState(tool_calls_used=25).refund_tool_call()
    assert budget.tool_calls_used == 24
    assert budget.exhausted_kind() is None


def test_refund_at_zero_stays_zero() -> None:
    refunded = BudgetState().refund_tool_call()
    assert refunded.tool_calls_used == 0
    assert refunded.session_tool_calls_used == 0
