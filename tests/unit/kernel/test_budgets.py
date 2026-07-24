"""T2.08: per-task budget tracker (SPEC §4.3) + §4.4 exhaustion reasons.

RED-first tests for :mod:`lsassist.kernel.budgets`. They pin the four things
the SPEC actually constrains:

1. **No default drift.** The §4.3 table is hardcoded HERE (the test is the
   spec assertion); the tracker must read its defaults from
   ``contracts.BudgetState``, never re-declare them. A change to either side
   without the other fails :func:`test_spec_4_3_defaults_match_contract`.
2. **Typed exhaustion.** Consuming TO a limit exhausts with the right §4.4
   parameter (``tool_calls`` | ``tokens`` | ``time``); one below the limit does
   not. The rendered wire form is ``budget_exhausted:<kind>`` (§4.4).
3. **The refund rule.** A failed schema validation (a MODEL error) refunds
   exactly one tool call; a tool that RAN and failed does not. The two cases
   are separate :class:`ToolCallOutcome` members so a caller cannot conflate
   them by accident.
4. **Output caps.** 50 KB stdout / 20 KB stderr truncation yields a marker
   plus a sha256 digest **of the FULL (pre-truncation) output** — the digest is
   what makes the discarded bytes auditable (§4.3).

Purity: wall-clock is measured from an INJECTED ``now``; nothing here touches a
clock, the filesystem, or the environment.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from lsassist.contracts.budget import BudgetState
from lsassist.contracts.enums import BUDGET_KINDS, ExitReason
from lsassist.kernel.budgets import (
    BudgetError,
    CappedOutput,
    Exhaustion,
    ToolCallOutcome,
    cap_output,
    cap_stderr,
    cap_stdout,
    classify_exhaustion,
    consume_plan_revision,
    consume_tokens,
    consume_tool_call,
    default_budget,
    observe_wall_clock,
    settle_tool_call,
)

# The SPEC §4.3 budget table, transcribed. This is the ONLY place the numbers
# are written down outside the contract — the drift test compares the two.
SPEC_4_3_TABLE: tuple[tuple[str, Any], ...] = (
    ("max_tool_calls", 25),
    ("max_plan_revisions", 8),
    ("max_tokens", 180_000),
    ("max_wall_clock_s", 30 * 60),
    ("max_output_per_tool", (50_000, 20_000)),
    ("max_session_tool_calls", 200),
)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# §4.3 defaults — sourced from the contract, never re-hardcoded
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("field", "expected"), SPEC_4_3_TABLE)
def test_spec_4_3_defaults_match_contract(field: str, expected: Any) -> None:
    assert getattr(BudgetState(), field) == expected


def test_default_budget_is_the_contract_default() -> None:
    assert default_budget() == BudgetState()


@pytest.mark.parametrize(("field", "expected"), SPEC_4_3_TABLE)
def test_default_budget_carries_the_spec_defaults(field: str, expected: Any) -> None:
    assert getattr(default_budget(), field) == expected


def test_fresh_budget_is_not_exhausted() -> None:
    assert classify_exhaustion(default_budget()) is None


# ---------------------------------------------------------------------------
# Exhaustion classification → §4.4 parameter
# ---------------------------------------------------------------------------

# (BudgetState field that trips, usage counter, §4.4 kind)
_LIMIT_CASES: tuple[tuple[str, str, str], ...] = (
    ("max_tool_calls", "tool_calls_used", "tool_calls"),
    ("max_plan_revisions", "plan_revisions_used", "tool_calls"),
    ("max_session_tool_calls", "session_tool_calls_used", "tool_calls"),
    ("max_tokens", "tokens_used", "tokens"),
    ("max_wall_clock_s", "wall_clock_used_s", "time"),
)


@pytest.mark.parametrize(("budget", "counter", "kind"), _LIMIT_CASES)
def test_consuming_to_the_limit_is_exhausted_with_the_right_kind(
    budget: str, counter: str, kind: str
) -> None:
    limit: int = getattr(BudgetState(), budget)
    state = BudgetState(**{counter: limit})

    result = classify_exhaustion(state)

    assert result is not None
    assert result.kind == kind
    assert result.budget == budget
    assert result.limit == limit
    assert result.used == limit
    assert result.reason is ExitReason.BUDGET_EXHAUSTED
    assert result.render() == f"budget_exhausted:{kind}"


@pytest.mark.parametrize(("budget", "counter", "kind"), _LIMIT_CASES)
def test_one_below_the_limit_is_not_exhausted(budget: str, counter: str, kind: str) -> None:
    limit: int = getattr(BudgetState(), budget)
    assert classify_exhaustion(BudgetState(**{counter: limit - 1})) is None


@pytest.mark.parametrize(("budget", "counter", "kind"), _LIMIT_CASES)
def test_over_the_limit_is_still_exhausted(budget: str, counter: str, kind: str) -> None:
    limit: int = getattr(BudgetState(), budget)
    result = classify_exhaustion(BudgetState(**{counter: limit + 7}))
    assert result is not None
    assert result.kind == kind


@pytest.mark.parametrize(("budget", "counter", "kind"), _LIMIT_CASES)
def test_kind_agrees_with_the_contract_classifier(budget: str, counter: str, kind: str) -> None:
    """Drift guard: the tracker's precedence must equal the contract's."""
    limit: int = getattr(BudgetState(), budget)
    state = BudgetState(**{counter: limit})
    result = classify_exhaustion(state)
    assert result is not None
    assert result.kind == state.exhausted_kind()


def test_every_emitted_kind_is_a_spec_4_4_budget_kind() -> None:
    for budget, counter, _kind in _LIMIT_CASES:
        limit: int = getattr(BudgetState(), budget)
        result = classify_exhaustion(BudgetState(**{counter: limit}))
        assert result is not None
        assert result.kind in BUDGET_KINDS


def test_exhaustion_rejects_an_unknown_kind() -> None:
    with pytest.raises(BudgetError):
        Exhaustion(budget="max_tool_calls", kind="wall_clock", limit=1, used=1).render()


# ---------------------------------------------------------------------------
# Consumption
# ---------------------------------------------------------------------------


def test_consume_tool_call_charges_task_and_session() -> None:
    after = consume_tool_call(default_budget())
    assert after.tool_calls_used == 1
    assert after.session_tool_calls_used == 1


def test_consume_tool_call_is_pure() -> None:
    before = default_budget()
    consume_tool_call(before)
    assert before.tool_calls_used == 0


def test_consume_plan_revision_charges_one() -> None:
    after = consume_plan_revision(default_budget())
    assert after.plan_revisions_used == 1
    assert after.tool_calls_used == 0


def test_consume_tokens_accumulates() -> None:
    after = consume_tokens(consume_tokens(default_budget(), 1_000), 500)
    assert after.tokens_used == 1_500


def test_consume_tokens_rejects_a_negative_amount() -> None:
    with pytest.raises(BudgetError):
        consume_tokens(default_budget(), -1)


def test_consume_tokens_accepts_zero() -> None:
    assert consume_tokens(default_budget(), 0).tokens_used == 0


def test_consume_tool_call_to_the_limit_exhausts_on_tool_calls() -> None:
    state = default_budget()
    for _ in range(BudgetState().max_tool_calls):
        state = consume_tool_call(state)
    result = classify_exhaustion(state)
    assert result is not None
    assert result.kind == "tool_calls"
    assert result.budget == "max_tool_calls"


def test_consume_plan_revision_to_the_limit_reports_the_tool_calls_kind() -> None:
    state = default_budget()
    for _ in range(BudgetState().max_plan_revisions):
        state = consume_plan_revision(state)
    result = classify_exhaustion(state)
    assert result is not None
    assert result.budget == "max_plan_revisions"
    assert result.kind == "tool_calls"


# ---------------------------------------------------------------------------
# The §4.3 refund rule
# ---------------------------------------------------------------------------


def test_schema_validation_failure_refunds_exactly_one_tool_call() -> None:
    charged = consume_tool_call(consume_tool_call(default_budget()))

    settled = settle_tool_call(charged, ToolCallOutcome.SCHEMA_INVALID)

    assert settled.tool_calls_used == charged.tool_calls_used - 1
    assert settled.session_tool_calls_used == charged.session_tool_calls_used - 1


def test_executed_tool_that_failed_does_not_refund() -> None:
    charged = consume_tool_call(default_budget())

    settled = settle_tool_call(charged, ToolCallOutcome.EXECUTED)

    assert settled.tool_calls_used == charged.tool_calls_used
    assert settled.session_tool_calls_used == charged.session_tool_calls_used
    assert settled == charged


def test_refund_only_ever_returns_one_call() -> None:
    state = default_budget()
    for _ in range(5):
        state = consume_tool_call(state)
    settled = settle_tool_call(state, ToolCallOutcome.SCHEMA_INVALID)
    assert settled.tool_calls_used == 4


def test_refund_lets_the_task_continue_past_the_limit_boundary() -> None:
    """25 dispatches where the last is a model error leaves one call left."""
    state = default_budget()
    for _ in range(BudgetState().max_tool_calls):
        state = consume_tool_call(state)
    assert classify_exhaustion(state) is not None

    state = settle_tool_call(state, ToolCallOutcome.SCHEMA_INVALID)

    assert classify_exhaustion(state) is None


@pytest.mark.parametrize("outcome", list(ToolCallOutcome))
def test_settling_an_uncharged_tool_call_raises(outcome: ToolCallOutcome) -> None:
    with pytest.raises(BudgetError):
        settle_tool_call(default_budget(), outcome)


def test_settle_is_pure() -> None:
    charged = consume_tool_call(default_budget())
    settle_tool_call(charged, ToolCallOutcome.SCHEMA_INVALID)
    assert charged.tool_calls_used == 1


def test_tool_call_outcome_members_are_distinct() -> None:
    assert ToolCallOutcome.SCHEMA_INVALID is not ToolCallOutcome.EXECUTED


# ---------------------------------------------------------------------------
# Wall clock — injected ``now``, never a real clock
# ---------------------------------------------------------------------------


def test_observe_wall_clock_records_injected_elapsed_seconds() -> None:
    after = observe_wall_clock(default_budget(), started_at=100.0, now=161.5)
    assert after.wall_clock_used_s == 61


def test_observe_wall_clock_is_measured_not_accrued() -> None:
    """Repeated readings converge on true elapsed; they do not sum to 30."""
    state = observe_wall_clock(default_budget(), started_at=0.0, now=10.0)
    state = observe_wall_clock(state, started_at=0.0, now=20.0)
    assert state.wall_clock_used_s == 20


def test_observe_wall_clock_never_lowers_the_counter() -> None:
    """Monotone high-water mark: a smaller later elapsed cannot walk it back."""
    state = observe_wall_clock(default_budget(), started_at=0.0, now=900.0)
    assert state.wall_clock_used_s == 900

    state = observe_wall_clock(state, started_at=1000.0, now=1005.0)

    assert state.wall_clock_used_s == 900


def test_observe_wall_clock_still_raises_the_counter_when_time_advances() -> None:
    """Monotonicity must not freeze the counter — a larger reading still wins."""
    state = observe_wall_clock(default_budget(), started_at=0.0, now=900.0)
    state = observe_wall_clock(state, started_at=0.0, now=1200.0)
    assert state.wall_clock_used_s == 1200


def test_observe_wall_clock_does_not_lower_a_counter_set_by_contract_consume() -> None:
    """The contract's ADDITIVE writer and this MEASURED one must not fight.

    ``BudgetState.consume(wall_clock_s=…)`` writes the same field additively.
    A stale ``started_at`` against such a state must not undo it.
    """
    accrued = default_budget().consume(wall_clock_s=600)

    state = observe_wall_clock(accrued, started_at=1000.0, now=1005.0)

    assert state.wall_clock_used_s == 600


def test_an_exhausted_time_budget_stays_exhausted_across_an_observation() -> None:
    """REGRESSION (seam N1): lowering ``wall_clock_used_s`` re-opened the I15
    EXECUTE gate, because ``machine._budget_remains`` gates EXECUTE/APPROVAL on
    ``BudgetState.exhausted_kind()``. A spent §4.3 30-minute budget must stay
    spent no matter what clock readings arrive afterwards.
    """
    spent = default_budget().consume(wall_clock_s=BudgetState().max_wall_clock_s)
    assert spent.exhausted_kind() == "time"
    assert classify_exhaustion(spent) is not None

    after = observe_wall_clock(spent, started_at=1000.0, now=1005.0)

    assert after.exhausted_kind() == "time"
    result = classify_exhaustion(after)
    assert result is not None
    assert result.kind == "time"
    assert result.render() == "budget_exhausted:time"


def test_a_fresh_per_task_started_at_cannot_widen_a_carried_budget() -> None:
    """The invited mistake: one BudgetState carried across tasks (the session
    tool-call counter lives on it) given a per-task ``started_at``.
    """
    carried = observe_wall_clock(default_budget(), started_at=0.0, now=1799.0)

    for task_start in (5_000.0, 9_000.0, 12_345.0):
        carried = observe_wall_clock(carried, started_at=task_start, now=task_start + 3.0)

    assert carried.wall_clock_used_s == 1799


def test_observe_wall_clock_at_the_limit_exhausts_on_time() -> None:
    limit = BudgetState().max_wall_clock_s
    state = observe_wall_clock(default_budget(), started_at=0.0, now=float(limit))
    result = classify_exhaustion(state)
    assert result is not None
    assert result.kind == "time"
    assert result.render() == "budget_exhausted:time"


def test_observe_wall_clock_rejects_time_running_backwards() -> None:
    with pytest.raises(BudgetError):
        observe_wall_clock(default_budget(), started_at=100.0, now=99.0)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_observe_wall_clock_rejects_non_finite_inputs(bad: float) -> None:
    with pytest.raises(BudgetError):
        observe_wall_clock(default_budget(), started_at=0.0, now=bad)
    with pytest.raises(BudgetError):
        observe_wall_clock(default_budget(), started_at=bad, now=0.0)


# ---------------------------------------------------------------------------
# §4.3 max_output_per_tool — truncation marker + digest of the FULL output
# ---------------------------------------------------------------------------


def test_cap_output_truncates_and_digests_the_full_output() -> None:
    full = b"A" * 120
    capped = cap_output(full, 50)

    assert isinstance(capped, CappedOutput)
    assert capped.truncated is True
    assert capped.kept == full[:50]
    assert len(capped.kept) == 50
    assert capped.original_bytes == 120
    assert capped.digest == _sha256(full)


def test_cap_output_digest_is_of_the_full_output_not_the_kept_prefix() -> None:
    full = b"B" * 200
    capped = cap_output(full, 10)
    assert capped.digest != _sha256(capped.kept)
    assert capped.digest == _sha256(full)


def test_cap_output_digest_has_the_sha256_prefix_form() -> None:
    capped = cap_output(b"x" * 10, 4)
    assert capped.digest.startswith("sha256:")
    assert len(capped.digest) == len("sha256:") + 64


def test_cap_output_marker_names_the_sizes_and_the_digest() -> None:
    full = b"C" * 300
    capped = cap_output(full, 100)
    assert capped.marker
    assert capped.digest in capped.marker
    assert "300" in capped.marker
    assert "100" in capped.marker


def test_cap_output_under_the_limit_is_not_truncated_but_still_digested() -> None:
    full = b"short"
    capped = cap_output(full, 50_000)
    assert capped.truncated is False
    assert capped.kept == full
    assert capped.marker == ""
    assert capped.digest == _sha256(full)
    assert capped.original_bytes == 5


def test_cap_output_exactly_at_the_limit_is_not_truncated() -> None:
    full = b"D" * 64
    capped = cap_output(full, 64)
    assert capped.truncated is False
    assert capped.kept == full


def test_cap_output_one_over_the_limit_is_truncated() -> None:
    full = b"D" * 65
    capped = cap_output(full, 64)
    assert capped.truncated is True
    assert capped.original_bytes == 65


def test_cap_output_accepts_str_and_digests_its_utf8_bytes() -> None:
    text = "ю" * 40  # 2 bytes each = 80 bytes
    capped = cap_output(text, 10)
    assert capped.original_bytes == 80
    assert capped.digest == _sha256(text.encode("utf-8"))
    assert capped.truncated is True


def test_kept_text_never_raises_on_a_split_codepoint() -> None:
    capped = cap_output("ю" * 40, 9)  # odd cut splits a 2-byte codepoint
    assert isinstance(capped.kept_text, str)


def test_cap_output_of_empty_output_is_the_empty_digest() -> None:
    capped = cap_output(b"", 50_000)
    assert capped.truncated is False
    assert capped.original_bytes == 0
    assert capped.digest == _sha256(b"")


@pytest.mark.parametrize("limit", [0, -1, -50_000])
def test_cap_output_rejects_a_non_positive_limit(limit: int) -> None:
    with pytest.raises(BudgetError):
        cap_output(b"data", limit)


def test_cap_stdout_uses_the_50kb_contract_limit() -> None:
    budget = default_budget()
    full = b"E" * (budget.max_output_per_tool[0] + 1)
    capped = cap_stdout(full, budget)
    assert capped.truncated is True
    assert len(capped.kept) == 50_000


def test_cap_stderr_uses_the_20kb_contract_limit() -> None:
    budget = default_budget()
    full = b"F" * (budget.max_output_per_tool[1] + 1)
    capped = cap_stderr(full, budget)
    assert capped.truncated is True
    assert len(capped.kept) == 20_000


def test_cap_stdout_at_exactly_50kb_is_not_truncated() -> None:
    budget = default_budget()
    assert cap_stdout(b"G" * 50_000, budget).truncated is False


def test_cap_stderr_at_exactly_20kb_is_not_truncated() -> None:
    budget = default_budget()
    assert cap_stderr(b"H" * 20_000, budget).truncated is False


def test_cap_stdout_rejects_a_corrupt_output_cap_pair() -> None:
    bad = BudgetState(max_output_per_tool=(0, 20_000))
    with pytest.raises(BudgetError):
        cap_stdout(b"data", bad)
