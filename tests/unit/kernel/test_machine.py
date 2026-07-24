"""T2.07: kernel state machine — §4.2 transition table, row by row (I15, I12, AC-07).

TABLE-FORM tests. Every row has (a) a POSITIVE case where the guard holds and
the transition fires with the right target, and (b) at least one NEGATIVE case
where the guard is falsified and ``step`` returns ``None`` (fail-closed, never a
permissive default).

The two EXECUTE entry edges (POLICY_CHECK with an AUTO class; APPROVAL with a
``TokenVerdict.VALID`` token) are proven to be the ONLY rows whose target is
``State.EXECUTE`` — exhaustively, over every ``(State, Event)`` pair and an
adversarial cross-product of policy classes and token verdicts.

SEAM-REFINE regressions pinned here (each names the defect it re-runs):
S1 the mid-turn §4.6 capability reduction, S2 a loop halt reaching REPORT,
S3 the omission matrix over every ``GuardInput`` field, S5 GROUND/PLAN failure
reaching REPORT, S8 sub-goal-level I12.

The machine is PURE (§2.2): every collaborator is a hand-written in-memory fake
(no filesystem, no network, no child process, no clock).
"""

from __future__ import annotations

import dataclasses
import itertools
from typing import Any

import pytest
from pydantic import ValidationError

from lsassist.contracts.enums import ExitReason, PermissionClass, VerdictStatus
from lsassist.contracts.intent import IntentRecord, make_intent
from lsassist.contracts.tool_request import ToolRequest
from lsassist.kernel import machine
from lsassist.kernel.machine import (
    AUTO_CLASSES,
    CONFIRM_CLASSES,
    DEFAULT_APPROVAL_TIMEOUT_S,
    DEFAULT_GROUND_READ_CAP,
    EXECUTE_ENTRY_RULES,
    REPLAY_ALLOWED,
    TASK_TYPES,
    TRANSITION_TABLE,
    GuardInput,
    MachineState,
    MachineTableError,
    Transition,
    advance,
    missing_measurements,
    reduced_class,
    replay_block,
    step,
)
from lsassist.kernel.states import TERMINAL_STATES, Event, ExecOutcome, State
from lsassist.policy.classes import rank
from lsassist.policy.token import TokenVerdict

# --- in-memory fakes for the injected Protocols (no I/O anywhere) -------------


@dataclasses.dataclass(frozen=True)
class FakeRegistry:
    known: bool = True
    valid: bool = True

    def knows(self, tool: str) -> bool:
        return self.known

    def args_valid(self, request: ToolRequest) -> bool:
        return self.valid


@dataclasses.dataclass(frozen=True)
class FakePolicy:
    result: PermissionClass

    def classify(self, request: ToolRequest) -> PermissionClass:
        return self.result


@dataclasses.dataclass(frozen=True)
class FakeBudget:
    kind: str | None = None

    def exhausted_kind(self) -> str | None:
        return self.kind


@dataclasses.dataclass(frozen=True)
class FakeProvider:
    ok: bool = True

    def available(self) -> bool:
        return self.ok


@dataclasses.dataclass(frozen=True)
class FakeReplay:
    """§4.7 ReplayView. Values mirror ``kernel.idempotency.ReplayVerdict``."""

    seen: str | None = "ALLOWED"

    def replay_verdict(self) -> str | None:
        return self.seen


@dataclasses.dataclass(frozen=True)
class FakeVerdict:
    is_emitted: bool = True
    verdict_status: VerdictStatus | None = VerdictStatus.PARTIAL
    evidence: int = 0
    sub_goals_verified: int = 0

    def emitted(self) -> bool:
        return self.is_emitted

    def status(self) -> VerdictStatus | None:
        return self.verdict_status

    def evidence_count(self) -> int:
        return self.evidence

    def sub_goal_verified_count(self) -> int:
        return self.sub_goals_verified


REQUEST = ToolRequest(call_id="c1", tool="fs.read", args={"path": "/ws/a.txt"})
INTENT: IntentRecord = make_intent("show me the kernel config")

AR = PermissionClass.AUTO_READ
ASW = PermissionClass.AUTO_SCOPED_WRITE
C1 = PermissionClass.CONFIRM_ONCE
CE = PermissionClass.CONFIRM_EXACT
DENY = PermissionClass.DENY_ALWAYS
ALL_CLASSES = (AR, ASW, C1, CE, DENY)


def _policy_check(policy_class: PermissionClass, **overrides: Any) -> GuardInput:
    """A POLICY_CHECK bundle on a TRUSTED turn, classified as ``policy_class``."""
    base: dict[str, Any] = {
        "request": REQUEST,
        "policy": FakePolicy(policy_class),
        "budget": FakeBudget(),
        "provider": FakeProvider(),
        "untrusted_turn": False,
        "replay": FakeReplay(),
    }
    base.update(overrides)
    return GuardInput(**base)


def _approval(**overrides: Any) -> GuardInput:
    """An APPROVAL bundle that satisfies every condition of the token edge: a
    VALID token minted at CONFIRM_EXACT, affirmative live consent, a decidable
    reduced class, and an ALLOWED §4.7 replay verdict."""
    base: dict[str, Any] = {
        "request": REQUEST,
        "policy": FakePolicy(CE),
        "untrusted_turn": False,
        "token_verdict": TokenVerdict.VALID,
        "token_class": CE,
        "approval_granted": True,
        "approval_elapsed_s": 5,
        "replay": FakeReplay(),
    }
    base.update(overrides)
    return GuardInput(**base)


PERMISSIVE_KWARGS: dict[str, Any] = {
    "request": REQUEST,
    "registry": FakeRegistry(),
    "policy": FakePolicy(AR),
    "budget": FakeBudget(None),
    "provider": FakeProvider(True),
    "verdict": FakeVerdict(),
    "replay": FakeReplay(),
    "intent": INTENT,
    "task_type": "coding",
    "untrusted_turn": False,
    "ground_reads": 1,
    "token_verdict": TokenVerdict.VALID,
    "token_class": CE,
    "approval_granted": True,
    "approval_denied": False,
    "approval_elapsed_s": 0,
    "exec_outcome": ExecOutcome.EXITED,
    "output_captured": True,
    "digests_computed": True,
    "postconditions_ok": True,
    "retryable_failure": True,
    "unrecoverable_failure": False,
    "plan_complete": True,
    "loop_clear": True,
}


def permissive(**overrides: Any) -> GuardInput:
    """A GuardInput in which EVERY forward guard's precondition holds.

    The adversarial baseline: if an illegal ``(state, event)`` pair still yields
    ``None`` under this maximally-permissive input, the table has no permissive
    default anywhere.
    """
    return GuardInput(**{**PERMISSIVE_KWARGS, **overrides})


# --- §4.1 state vocabulary ----------------------------------------------------


def test_state_enum_is_exactly_spec_4_1() -> None:
    assert [s.value for s in State] == [
        "RECEIVE",
        "CLASSIFY",
        "GROUND",
        "PLAN",
        "POLICY_CHECK",
        "APPROVAL",
        "EXECUTE",
        "OBSERVE",
        "VERIFY",
        "REPORT",
        "BLOCKED",
        "CANCELLED",
    ]


def test_terminal_pseudo_states() -> None:
    assert set(TERMINAL_STATES) == {State.BLOCKED, State.CANCELLED}


# --- table shape --------------------------------------------------------------

#: The 14 literal SPEC §4.2 lines — the human review checkpoint compares these
#: one-for-one with the document.
SPEC_4_2_ROWS: tuple[tuple[State, State], ...] = (
    (State.RECEIVE, State.CLASSIFY),
    (State.CLASSIFY, State.GROUND),
    (State.GROUND, State.PLAN),
    (State.PLAN, State.POLICY_CHECK),
    (State.POLICY_CHECK, State.EXECUTE),
    (State.POLICY_CHECK, State.APPROVAL),
    (State.POLICY_CHECK, State.BLOCKED),
    (State.APPROVAL, State.EXECUTE),
    (State.APPROVAL, State.CANCELLED),
    (State.EXECUTE, State.OBSERVE),
    (State.OBSERVE, State.VERIFY),
    (State.VERIFY, State.PLAN),
    (State.VERIFY, State.REPORT),
    (State.REPORT, State.RECEIVE),
)

#: Two rows §4.2 does not draw but §4.4 REQUIRES, because it enumerates
#: ``grounding_failed`` and ``malformed_model_output`` as REPORT-able exit
#: reasons while REPORT was otherwise reachable only from VERIFY (defect S5).
REACHABILITY_ROWS: tuple[tuple[State, State], ...] = (
    (State.GROUND, State.REPORT),
    (State.PLAN, State.REPORT),
)


def test_transition_table_contains_every_spec_4_2_row() -> None:
    pairs = {(rule.source, rule.target) for rule in TRANSITION_TABLE}
    assert set(SPEC_4_2_ROWS) <= pairs


def test_transition_table_is_exactly_spec_rows_plus_the_reachability_rows() -> None:
    pairs = tuple((rule.source, rule.target) for rule in TRANSITION_TABLE)
    assert set(pairs) == set(SPEC_4_2_ROWS) | set(REACHABILITY_ROWS)
    # 16 edges, but 19 rows: §4.2's single BLOCKED edge is split into its three
    # causes and its single CANCELLED edge into two, so each terminal row names
    # ONE exact §4.4 exit reason (N2).
    assert len(pairs) == 19
    assert pairs.count((State.POLICY_CHECK, State.BLOCKED)) == 3
    assert pairs.count((State.APPROVAL, State.CANCELLED)) == 2


def test_no_row_leaves_a_terminal_state() -> None:
    assert all(rule.source not in TERMINAL_STATES for rule in TRANSITION_TABLE)


def test_every_target_and_source_is_a_known_state() -> None:
    for rule in TRANSITION_TABLE:
        assert rule.source in set(State)
        assert rule.target in set(State)


def test_no_state_is_a_dead_end() -> None:
    """S5 regression: every non-terminal state has at least one outgoing row."""
    sources = {rule.source for rule in TRANSITION_TABLE}
    for state in State:
        if state in TERMINAL_STATES:
            continue
        assert state in sources, f"{state} has no outgoing row — parked forever"


#: The states whose event is TOTAL: a decision has been MADE by the time the
#: event arrives, so exactly one row must always fire and the task can never be
#: stranded without a route to a verdict (seam defects S2 and S5). The other
#: states legitimately stall on an UNMEASURED fact — the child has not exited
#: yet, the output is still being captured, the user has not answered — which is
#: a WAIT the runner resolves by calling again, not a park.
TOTAL_DECISIONS: tuple[tuple[State, Event], ...] = (
    (State.GROUND, Event.CONTEXT_GATHERED),
    (State.PLAN, Event.PLAN_PROPOSED),
    (State.POLICY_CHECK, Event.POLICY_CLASSIFIED),
    (State.VERIFY, Event.POSTCONDITIONS_CHECKED),
)


@pytest.mark.parametrize(("state", "event"), TOTAL_DECISIONS, ids=str)
def test_wired_decision_states_are_total_and_never_park(state: State, event: Event) -> None:
    """S2/S5: given a WIRED bundle, a decision state always moves.

    N4 narrowed this from "any bundle": an UNWIRED bundle must stall rather than
    manufacture a cause. That stall is asserted separately, and is reported by
    :func:`missing_measurements`.
    """
    for guard_input in (
        permissive(),
        permissive(policy=FakePolicy(DENY)),
        permissive(budget=FakeBudget("time")),
        permissive(provider=FakeProvider(False)),
        permissive(policy=FakePolicy(C1)),
        permissive(postconditions_ok=False, retryable_failure=False, loop_clear=True),
        permissive(ground_reads=999, registry=FakeRegistry(known=False)),
        permissive(replay=FakeReplay("ALREADY_EXECUTED"), policy=FakePolicy(DENY)),
    ):
        assert step(state, event, guard_input) is not None, f"{state}/{event} parked"


def test_verify_is_total_even_unwired() -> None:
    """VERIFY stays unconditionally total: a checked task always gets a verdict,
    and its REPORT row names no cause, so nothing is misattributed."""
    for guard_input in (GuardInput(), permissive(), permissive(budget=None)):
        transition = step(State.VERIFY, Event.POSTCONDITIONS_CHECKED, guard_input)
        assert transition is not None
        if transition.target is State.REPORT:
            assert not [tag for tag in transition.side_effect if tag.startswith("exit_reason:")]


# --- positive: every row fires under its guard --------------------------------

LEGAL_CASES: tuple[tuple[str, State, Event, GuardInput, State], ...] = (
    (
        "RECEIVE->CLASSIFY: non-empty immutable intent",
        State.RECEIVE,
        Event.INTENT_CAPTURED,
        GuardInput(intent=INTENT),
        State.CLASSIFY,
    ),
    (
        "CLASSIFY->GROUND: known task type",
        State.CLASSIFY,
        Event.TASK_TYPE_RESOLVED,
        GuardInput(task_type="tutor"),
        State.GROUND,
    ),
    (
        "GROUND->PLAN: reads within ground_read_cap",
        State.GROUND,
        Event.CONTEXT_GATHERED,
        GuardInput(ground_reads=DEFAULT_GROUND_READ_CAP),
        State.PLAN,
    ),
    (
        "GROUND->REPORT: reads over cap (S5 grounding_failed)",
        State.GROUND,
        Event.CONTEXT_GATHERED,
        GuardInput(ground_reads=DEFAULT_GROUND_READ_CAP + 1),
        State.REPORT,
    ),
    (
        "PLAN->POLICY_CHECK: schema-valid request vs registry",
        State.PLAN,
        Event.PLAN_PROPOSED,
        GuardInput(request=REQUEST, registry=FakeRegistry()),
        State.POLICY_CHECK,
    ),
    (
        "PLAN->REPORT: args fail schema (S5 malformed_model_output)",
        State.PLAN,
        Event.PLAN_PROPOSED,
        GuardInput(request=REQUEST, registry=FakeRegistry(valid=False)),
        State.REPORT,
    ),
    (
        "PLAN->REPORT: registry answered - unknown tool (S5)",
        State.PLAN,
        Event.PLAN_PROPOSED,
        GuardInput(request=REQUEST, registry=FakeRegistry(known=False)),
        State.REPORT,
    ),
    (
        "POLICY_CHECK->EXECUTE: AUTO_READ on a trusted turn",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(AR),
        State.EXECUTE,
    ),
    (
        "POLICY_CHECK->EXECUTE: AUTO_READ even on an UNTRUSTED turn (§4.6 carve-out)",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(AR, untrusted_turn=True),
        State.EXECUTE,
    ),
    (
        "POLICY_CHECK->EXECUTE: AUTO_SCOPED_WRITE on a trusted turn",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(ASW),
        State.EXECUTE,
    ),
    (
        "POLICY_CHECK->APPROVAL: AUTO_SCOPED_WRITE on an UNTRUSTED turn (S1)",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(ASW, untrusted_turn=True),
        State.APPROVAL,
    ),
    (
        "POLICY_CHECK->APPROVAL: CONFIRM_ONCE",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(C1),
        State.APPROVAL,
    ),
    (
        "POLICY_CHECK->APPROVAL: CONFIRM_EXACT",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(CE),
        State.APPROVAL,
    ),
    (
        "POLICY_CHECK->BLOCKED: DENY_ALWAYS",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(DENY),
        State.BLOCKED,
    ),
    (
        "POLICY_CHECK->BLOCKED: DENY_ALWAYS stays DENY on an untrusted turn",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(DENY, untrusted_turn=True),
        State.BLOCKED,
    ),
    (
        "POLICY_CHECK->BLOCKED: budget exhausted",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(AR, budget=FakeBudget("tool_calls")),
        State.BLOCKED,
    ),
    (
        "POLICY_CHECK->BLOCKED: provider unavailable",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(AR, provider=FakeProvider(False)),
        State.BLOCKED,
    ),
    (
        "APPROVAL->EXECUTE: VALID token, granted, prompt live",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(),
        State.EXECUTE,
    ),
    (
        "APPROVAL->CANCELLED: user deny",
        State.APPROVAL,
        Event.APPROVAL_REFUSED,
        GuardInput(approval_denied=True, approval_elapsed_s=1),
        State.CANCELLED,
    ),
    (
        "APPROVAL->CANCELLED: 120 s timeout",
        State.APPROVAL,
        Event.APPROVAL_REFUSED,
        GuardInput(approval_elapsed_s=DEFAULT_APPROVAL_TIMEOUT_S),
        State.CANCELLED,
    ),
    (
        "APPROVAL->CANCELLED: no elapsed reading taken (fail closed)",
        State.APPROVAL,
        Event.APPROVAL_REFUSED,
        GuardInput(approval_elapsed_s=None),
        State.CANCELLED,
    ),
    (
        "APPROVAL->CANCELLED: denied WINS attribution over a simultaneous timeout",
        State.APPROVAL,
        Event.APPROVAL_REFUSED,
        GuardInput(approval_denied=True, approval_elapsed_s=9_999),
        State.CANCELLED,
    ),
    (
        "EXECUTE->OBSERVE: process exited",
        State.EXECUTE,
        Event.PROCESS_TERMINATED,
        GuardInput(exec_outcome=ExecOutcome.EXITED),
        State.OBSERVE,
    ),
    (
        "EXECUTE->OBSERVE: killed",
        State.EXECUTE,
        Event.PROCESS_TERMINATED,
        GuardInput(exec_outcome=ExecOutcome.KILLED),
        State.OBSERVE,
    ),
    (
        "OBSERVE->VERIFY: output captured + digests computed",
        State.OBSERVE,
        Event.OUTPUT_CAPTURED,
        GuardInput(output_captured=True, digests_computed=True),
        State.VERIFY,
    ),
    (
        "VERIFY->PLAN: postconditions ok, budget remains, loop clear",
        State.VERIFY,
        Event.POSTCONDITIONS_CHECKED,
        GuardInput(postconditions_ok=True, budget=FakeBudget(), loop_clear=True),
        State.PLAN,
    ),
    (
        "VERIFY->PLAN: retryable failure, budget remains, loop clear",
        State.VERIFY,
        Event.POSTCONDITIONS_CHECKED,
        GuardInput(retryable_failure=True, budget=FakeBudget(), loop_clear=True),
        State.PLAN,
    ),
    (
        "VERIFY->REPORT: plan complete",
        State.VERIFY,
        Event.POSTCONDITIONS_CHECKED,
        GuardInput(plan_complete=True, budget=FakeBudget(), loop_clear=True),
        State.REPORT,
    ),
    (
        "VERIFY->REPORT: budget exhausted",
        State.VERIFY,
        Event.POSTCONDITIONS_CHECKED,
        GuardInput(postconditions_ok=True, budget=FakeBudget("tokens"), loop_clear=True),
        State.REPORT,
    ),
    (
        "VERIFY->REPORT: unrecoverable failure",
        State.VERIFY,
        Event.POSTCONDITIONS_CHECKED,
        GuardInput(unrecoverable_failure=True, budget=FakeBudget(), loop_clear=True),
        State.REPORT,
    ),
    (
        "VERIFY->REPORT: loop halt (S2 — §4.3 mandated REPORT)",
        State.VERIFY,
        Event.POSTCONDITIONS_CHECKED,
        GuardInput(postconditions_ok=True, budget=FakeBudget(), loop_clear=False),
        State.REPORT,
    ),
    (
        "VERIFY->REPORT: no budget view at all reads as exhausted (fail closed)",
        State.VERIFY,
        Event.POSTCONDITIONS_CHECKED,
        GuardInput(postconditions_ok=True, budget=None, loop_clear=True),
        State.REPORT,
    ),
    (
        "VERIFY->REPORT: postconditions failed and not retryable",
        State.VERIFY,
        Event.POSTCONDITIONS_CHECKED,
        GuardInput(
            postconditions_ok=False,
            retryable_failure=False,
            budget=FakeBudget(),
            loop_clear=True,
        ),
        State.REPORT,
    ),
    (
        "REPORT->RECEIVE: verdict emitted",
        State.REPORT,
        Event.VERDICT_EMITTED,
        GuardInput(verdict=FakeVerdict()),
        State.RECEIVE,
    ),
)


@pytest.mark.parametrize(
    ("label", "state", "event", "guard_input", "expected"),
    LEGAL_CASES,
    ids=[case[0] for case in LEGAL_CASES],
)
def test_legal_transition_fires(
    label: str, state: State, event: Event, guard_input: GuardInput, expected: State
) -> None:
    transition = step(state, event, guard_input)
    assert transition is not None, label
    assert transition.source is state
    assert transition.event is event
    assert transition.target is expected


def test_legal_cases_cover_every_table_row() -> None:
    covered = {(case[1], case[4]) for case in LEGAL_CASES}
    assert covered == set(SPEC_4_2_ROWS) | set(REACHABILITY_ROWS)


# --- negative: falsified guards yield None ------------------------------------

ILLEGAL_CASES: tuple[tuple[str, State, Event, GuardInput], ...] = (
    (
        "RECEIVE: no intent record",
        State.RECEIVE,
        Event.INTENT_CAPTURED,
        GuardInput(intent=None),
    ),
    (
        "RECEIVE: blank intent text",
        State.RECEIVE,
        Event.INTENT_CAPTURED,
        GuardInput(intent=make_intent("   ")),
    ),
    (
        "CLASSIFY: unknown task type",
        State.CLASSIFY,
        Event.TASK_TYPE_RESOLVED,
        GuardInput(task_type="rootkit"),
    ),
    (
        "CLASSIFY: no task type",
        State.CLASSIFY,
        Event.TASK_TYPE_RESOLVED,
        GuardInput(task_type=None),
    ),
    (
        "APPROVAL: HMAC mismatch token",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(token_verdict=TokenVerdict.HMAC_MISMATCH),
    ),
    (
        "APPROVAL: expired token",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(token_verdict=TokenVerdict.EXPIRED),
    ),
    (
        "APPROVAL: exhausted token",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(token_verdict=TokenVerdict.EXHAUSTED),
    ),
    (
        "APPROVAL: unknown token",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(token_verdict=TokenVerdict.UNKNOWN_TOKEN),
    ),
    (
        "APPROVAL: no token at all",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(token_verdict=None),
    ),
    (
        "APPROVAL: S3 — VALID token but consent never granted",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(approval_granted=False),
    ),
    (
        "APPROVAL: S3 — VALID token, granted, but no elapsed reading taken",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(approval_elapsed_s=None),
    ),
    (
        "APPROVAL: VALID token but user already denied",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(approval_denied=True),
    ),
    (
        "APPROVAL: VALID token past the 120 s prompt timeout",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(approval_elapsed_s=121),
    ),
    (
        "APPROVAL: N3 - token minted at CONFIRM_ONCE cannot gate a CONFIRM_EXACT action",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(token_class=C1),
    ),
    (
        "APPROVAL: N3 - the minted class is unknown",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(token_class=None),
    ),
    (
        "APPROVAL: N3 - the required class is undecidable (no policy view)",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(policy=None),
    ),
    (
        "APPROVAL: N6 - replay guard says ALREADY_EXECUTED",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(replay=FakeReplay("ALREADY_EXECUTED")),
    ),
    (
        "APPROVAL: N6 - replay guard says PARTIAL_EXECUTION",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(replay=FakeReplay("PARTIAL_EXECUTION")),
    ),
    (
        "APPROVAL: N6 - the ledger was never consulted",
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        _approval(replay=None),
    ),
    (
        "POLICY_CHECK: N6 - AUTO edge shut by an already-executed seq",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(AR, replay=FakeReplay("ALREADY_EXECUTED")),
    ),
    (
        "POLICY_CHECK: N6 - AUTO edge shut when the ledger was never consulted",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(AR, replay=None),
    ),
    (
        "GROUND: N4 - no read count taken is a WIRING stall, not grounding_failed",
        State.GROUND,
        Event.CONTEXT_GATHERED,
        GuardInput(ground_reads=None),
    ),
    (
        "PLAN: N4 - absent registry is a WIRING stall, not malformed output",
        State.PLAN,
        Event.PLAN_PROPOSED,
        GuardInput(request=REQUEST, registry=None),
    ),
    (
        "PLAN: N4 - absent request is a WIRING stall",
        State.PLAN,
        Event.PLAN_PROPOSED,
        GuardInput(request=None, registry=FakeRegistry()),
    ),
    (
        "POLICY_CHECK: N4 - absent policy view is a WIRING stall, not policy_blocked",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(AR, policy=None),
    ),
    (
        "POLICY_CHECK: N4 - absent budget view is a WIRING stall",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(AR, budget=None),
    ),
    (
        "POLICY_CHECK: N4 - absent provider view is a WIRING stall",
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(AR, provider=None),
    ),
    (
        "APPROVAL: refusal event while the prompt is still live",
        State.APPROVAL,
        Event.APPROVAL_REFUSED,
        GuardInput(approval_denied=False, approval_elapsed_s=0),
    ),
    (
        "EXECUTE: process still running",
        State.EXECUTE,
        Event.PROCESS_TERMINATED,
        GuardInput(exec_outcome=None),
    ),
    (
        "OBSERVE: output not captured",
        State.OBSERVE,
        Event.OUTPUT_CAPTURED,
        GuardInput(output_captured=False, digests_computed=True),
    ),
    (
        "OBSERVE: digests not computed",
        State.OBSERVE,
        Event.OUTPUT_CAPTURED,
        GuardInput(output_captured=True, digests_computed=False),
    ),
    (
        "REPORT: no verdict",
        State.REPORT,
        Event.VERDICT_EMITTED,
        GuardInput(verdict=None),
    ),
    (
        "REPORT: verdict not emitted",
        State.REPORT,
        Event.VERDICT_EMITTED,
        GuardInput(verdict=FakeVerdict(is_emitted=False)),
    ),
    (
        "REPORT: I12 — VERIFIED with zero evidence refs",
        State.REPORT,
        Event.VERDICT_EMITTED,
        GuardInput(verdict=FakeVerdict(verdict_status=VerdictStatus.VERIFIED, evidence=0)),
    ),
    (
        "REPORT: S8 — PARTIAL claiming a VERIFIED sub-goal with zero evidence",
        State.REPORT,
        Event.VERDICT_EMITTED,
        GuardInput(
            verdict=FakeVerdict(
                verdict_status=VerdictStatus.PARTIAL, evidence=0, sub_goals_verified=1
            )
        ),
    ),
)


@pytest.mark.parametrize(
    ("label", "state", "event", "guard_input"),
    ILLEGAL_CASES,
    ids=[case[0] for case in ILLEGAL_CASES],
)
def test_illegal_transition_returns_none(
    label: str, state: State, event: Event, guard_input: GuardInput
) -> None:
    assert step(state, event, guard_input) is None, label


# --- I12 at both levels (S8) --------------------------------------------------


def test_i12_verified_with_evidence_is_allowed_through_report() -> None:
    guard_input = GuardInput(
        verdict=FakeVerdict(verdict_status=VerdictStatus.VERIFIED, evidence=1)
    )
    transition = step(State.REPORT, Event.VERDICT_EMITTED, guard_input)
    assert transition is not None
    assert transition.target is State.RECEIVE


def test_i12_partial_with_verified_sub_goal_and_evidence_is_allowed() -> None:
    guard_input = GuardInput(
        verdict=FakeVerdict(
            verdict_status=VerdictStatus.PARTIAL, evidence=1, sub_goals_verified=2
        )
    )
    assert step(State.REPORT, Event.VERDICT_EMITTED, guard_input) is not None


def test_i12_a_verdict_claiming_nothing_needs_no_evidence() -> None:
    """An honestly UNVERIFIED verdict asserts no green check, so it may close
    the turn with no evidence — that is the §4.5 UNVERIFIED row, not a hole."""
    guard_input = GuardInput(
        verdict=FakeVerdict(
            verdict_status=VerdictStatus.UNVERIFIED, evidence=0, sub_goals_verified=0
        )
    )
    assert step(State.REPORT, Event.VERDICT_EMITTED, guard_input) is not None


# --- S1: the mid-turn §4.6 capability reduction -------------------------------


def test_s1_stale_policy_adapter_cannot_carry_an_auto_write_past_ingestion() -> None:
    """SEAM S1 regression, two-round inner loop.

    Round 1 runs a scoped write on a trusted turn and reaches EXECUTE. At
    OBSERVE the tool's own output is ingested, so the turn is untrusted from
    then on. Round 2 reuses the SAME policy adapter — whose PolicyContext was
    bound at construction and therefore still says "trusted". The machine must
    still refuse the AUTO edge and route to APPROVAL.
    """
    stale_adapter = FakePolicy(ASW)  # never rebuilt; classifies as it did in round 1

    round1 = _policy_check(ASW, policy=stale_adapter, untrusted_turn=False)
    first = step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, round1)
    assert first is not None
    assert first.target is State.EXECUTE

    # ... the tool's own output is ingested at OBSERVE -> turn is now untrusted
    round2 = _policy_check(ASW, policy=stale_adapter, untrusted_turn=True)
    second = step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, round2)
    assert second is not None
    assert second.target is State.APPROVAL
    assert second.target is not State.EXECUTE


@pytest.mark.parametrize("policy_class", ALL_CLASSES)
def test_s1_reduction_is_monotone_and_never_lowers_a_class(
    policy_class: PermissionClass,
) -> None:
    """§4.6 raises; it never lowers. The untrusted target is never MORE
    permissive than the trusted one."""
    order = {State.EXECUTE: 0, State.APPROVAL: 1, State.BLOCKED: 2}
    trusted = step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, _policy_check(policy_class))
    untrusted = step(
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        _policy_check(policy_class, untrusted_turn=True),
    )
    assert trusted is not None and untrusted is not None
    assert order[untrusted.target] >= order[trusted.target]


def test_s1_untrusted_turn_defaults_to_true() -> None:
    """Fail-closed: a bundle that never mentions trust is treated as untrusted."""
    assert GuardInput().untrusted_turn is True


# --- S2: a detected loop reaches the §4.3 mandated REPORT ----------------------


def test_s2_loop_halt_reaches_report_and_carries_the_verdict_obligation() -> None:
    guard_input = GuardInput(postconditions_ok=True, budget=FakeBudget(), loop_clear=False)
    transition = step(State.VERIFY, Event.POSTCONDITIONS_CHECKED, guard_input)
    assert transition is not None
    assert transition.target is State.REPORT
    assert "compute:verdict" in transition.side_effect


def test_s2_loop_halt_is_not_a_dead_end() -> None:
    """Before the fix, EVERY event at VERIFY with a tripped detector returned
    None and the machine parked. Exactly one event now moves it — to REPORT."""
    guard_input = GuardInput(postconditions_ok=True, budget=FakeBudget(), loop_clear=False)
    moves = [event for event in Event if step(State.VERIFY, event, guard_input) is not None]
    assert moves == [Event.POSTCONDITIONS_CHECKED]


def test_s2_loop_clear_is_required_for_another_planning_round() -> None:
    cleared = GuardInput(postconditions_ok=True, budget=FakeBudget(), loop_clear=True)
    transition = step(State.VERIFY, Event.POSTCONDITIONS_CHECKED, cleared)
    assert transition is not None
    assert transition.target is State.PLAN


# --- S3: the omission matrix --------------------------------------------------

#: Per OBSERVATION field, the most restrictive admissible value. Omitting the
#: field must never yield a transition that this value would refuse.
ADVERSARIAL: dict[str, Any] = {
    "request": None,
    "registry": FakeRegistry(known=False, valid=False),
    "policy": FakePolicy(DENY),
    "budget": FakeBudget("tokens"),
    "provider": FakeProvider(False),
    "verdict": FakeVerdict(is_emitted=False),
    "replay": FakeReplay("ALREADY_EXECUTED"),
    "intent": make_intent("  "),
    "task_type": "pwn",
    "untrusted_turn": True,
    "ground_reads": DEFAULT_GROUND_READ_CAP + 1,
    "token_verdict": TokenVerdict.EXPIRED,
    "token_class": None,
    "approval_granted": False,
    "approval_elapsed_s": 10_000,
    "exec_outcome": None,
    "output_captured": False,
    "digests_computed": False,
    "postconditions_ok": False,
    "retryable_failure": False,
    "loop_clear": False,
}

#: VETO fields: presence only ever RESTRICTS, so the omission property does not
#: apply (a veto's absence cannot be safer than its presence). The property
#: asserted for them instead is that setting one can never OPEN the EXECUTE gate.
VETO_FIELDS: frozenset[str] = frozenset(
    {"approval_denied", "unrecoverable_failure", "plan_complete"}
)

#: §4.2/§4.3 LIMITS, not observations. Their defaults are the SPEC values and
#: any change LOOSENS the guard, so a caller can only widen them deliberately.
LIMIT_FIELDS: frozenset[str] = frozenset({"ground_read_cap", "approval_timeout_s"})

MATRIX_BASE: dict[str, Any] = {
    **PERMISSIVE_KWARGS,
    # A CONTINUING task, so VERIFY->PLAN is the base transition and the budget /
    # loop comparisons below are not made vacuous by an already-complete plan.
    "plan_complete": False,
    "unrecoverable_failure": False,
}


def test_omission_matrix_covers_every_guard_input_field() -> None:
    """The matrix must not silently miss a field added later."""
    fields = {f.name for f in dataclasses.fields(GuardInput)}
    assert fields == set(ADVERSARIAL) | VETO_FIELDS | LIMIT_FIELDS


@pytest.mark.parametrize("field_name", sorted(ADVERSARIAL))
def test_s3_omitting_a_field_never_beats_its_adversarial_value(field_name: str) -> None:
    """S3: an unpopulated bundle can never advance further than a hostile one.

    For every ``(state, event)`` pair: the transition obtained with the field at
    its DEFAULT is either ``None`` (a stall) or exactly the transition obtained
    with the field at its most restrictive value.
    """
    omitted = GuardInput(**{k: v for k, v in MATRIX_BASE.items() if k != field_name})
    adversarial = GuardInput(**{**MATRIX_BASE, field_name: ADVERSARIAL[field_name]})
    for state, event in itertools.product(State, Event):
        got = step(state, event, omitted)
        worst = step(state, event, adversarial)
        if got is None:
            continue
        assert worst is not None, (
            f"omitting {field_name} advanced {state}--{event}-->{got.target} "
            "where the adversarial value refuses outright"
        )
        assert got.target is worst.target, (
            f"omitting {field_name} advanced {state}--{event}-->{got.target} "
            f"where the adversarial value gives {worst.target}"
        )


@pytest.mark.parametrize("field_name", sorted(VETO_FIELDS))
def test_s3_a_veto_field_can_never_open_the_execute_gate(field_name: str) -> None:
    base = GuardInput(**MATRIX_BASE)
    vetoed = GuardInput(**{**MATRIX_BASE, field_name: True})
    for state, event in itertools.product(State, Event):
        after = step(state, event, vetoed)
        if after is None or after.target is not State.EXECUTE:
            continue
        before = step(state, event, base)
        assert before is not None and before.target is State.EXECUTE


def test_s3_limit_fields_default_to_the_spec_values() -> None:
    fresh = GuardInput()
    assert fresh.ground_read_cap == DEFAULT_GROUND_READ_CAP == 40
    assert fresh.approval_timeout_s == DEFAULT_APPROVAL_TIMEOUT_S == 120


def test_s3_an_entirely_empty_bundle_opens_nothing() -> None:
    """The headline claim, run: a bundle with NOTHING populated reaches no
    EXECUTE, and the only advances it can make are task-ENDING ones."""
    empty = GuardInput()
    for state, event in itertools.product(State, Event):
        transition = step(state, event, empty)
        if transition is None:
            continue
        assert transition.target is not State.EXECUTE
        assert transition.target in {State.REPORT, State.CANCELLED}


# --- S5: GROUND / PLAN failure reaches REPORT ---------------------------------


def test_s5_over_cap_grounding_reaches_report_not_a_park() -> None:
    guard_input = GuardInput(ground_reads=DEFAULT_GROUND_READ_CAP + 1)
    transition = step(State.GROUND, Event.CONTEXT_GATHERED, guard_input)
    assert transition is not None
    assert transition.target is State.REPORT
    assert "exit_reason:grounding_failed" in transition.side_effect


def test_s5_malformed_request_reaches_report_not_a_park() -> None:
    guard_input = GuardInput(request=REQUEST, registry=FakeRegistry(valid=False))
    transition = step(State.PLAN, Event.PLAN_PROPOSED, guard_input)
    assert transition is not None
    assert transition.target is State.REPORT
    assert "exit_reason:malformed_model_output" in transition.side_effect


def test_s5_ground_rows_partition_every_MEASURED_reading() -> None:
    """Given a reading, exactly one GROUND row fires — success or grounding_failed."""
    for reads in (0, 1, DEFAULT_GROUND_READ_CAP, DEFAULT_GROUND_READ_CAP + 1, 999, -1):
        guard_input = GuardInput(ground_reads=reads)
        assert step(State.GROUND, Event.CONTEXT_GATHERED, guard_input) is not None


def test_s5_plan_rows_partition_every_ANSWERED_registry() -> None:
    """Given a registry that answers, exactly one PLAN row fires."""
    for registry in (FakeRegistry(), FakeRegistry(valid=False), FakeRegistry(known=False)):
        guard_input = GuardInput(request=REQUEST, registry=registry)
        assert step(State.PLAN, Event.PLAN_PROPOSED, guard_input) is not None


# --- N4: a missing collaborator is never reported as a cause -----------------


def test_n4_absent_registry_does_not_blame_the_model() -> None:
    """RAN by the critic: before this fix, a runner wired before T3.01 turned
    EVERY turn into a verdict accusing the model of malformed output."""
    guard_input = GuardInput(request=REQUEST, registry=None)
    assert step(State.PLAN, Event.PLAN_PROPOSED, guard_input) is None
    assert missing_measurements(State.PLAN, guard_input) == ("registry",)


def test_n4_uncounted_grounding_does_not_report_grounding_failed() -> None:
    guard_input = GuardInput(ground_reads=None)
    assert step(State.GROUND, Event.CONTEXT_GATHERED, guard_input) is None
    assert missing_measurements(State.GROUND, guard_input) == ("ground_reads",)


def test_n4_absent_policy_view_does_not_report_policy_blocked() -> None:
    guard_input = _policy_check(AR, policy=None)
    assert step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, guard_input) is None
    assert "policy" in missing_measurements(State.POLICY_CHECK, guard_input)


@pytest.mark.parametrize(
    ("state", "event", "guard_input", "forbidden"),
    [
        (
            State.PLAN,
            Event.PLAN_PROPOSED,
            GuardInput(request=REQUEST, registry=None),
            "exit_reason:malformed_model_output",
        ),
        (
            State.GROUND,
            Event.CONTEXT_GATHERED,
            GuardInput(ground_reads=None),
            "exit_reason:grounding_failed",
        ),
        (
            State.POLICY_CHECK,
            Event.POLICY_CLASSIFIED,
            _policy_check(AR, policy=None),
            "exit_reason:policy_blocked",
        ),
    ],
    ids=["registry", "ground_reads", "policy"],
)
def test_n4_no_cause_is_fabricated_for_an_unwired_bundle(
    state: State, event: Event, guard_input: GuardInput, forbidden: str
) -> None:
    transition = step(state, event, guard_input)
    assert transition is None or forbidden not in transition.side_effect


def test_n4_measured_failures_still_report_their_real_cause() -> None:
    over_cap = step(
        State.GROUND, Event.CONTEXT_GATHERED, GuardInput(ground_reads=DEFAULT_GROUND_READ_CAP + 1)
    )
    assert over_cap is not None
    assert "exit_reason:grounding_failed" in over_cap.side_effect

    rejected = step(
        State.PLAN,
        Event.PLAN_PROPOSED,
        GuardInput(request=REQUEST, registry=FakeRegistry(valid=False)),
    )
    assert rejected is not None
    assert "exit_reason:malformed_model_output" in rejected.side_effect


def test_n4_a_wiring_stall_is_distinguishable_from_a_wait() -> None:
    """The two stalls must not look alike to the runner."""
    wiring = GuardInput(request=REQUEST, registry=None)
    assert missing_measurements(State.PLAN, wiring) == ("registry",)

    waiting = permissive(exec_outcome=None)  # child has not exited yet
    assert step(State.EXECUTE, Event.PROCESS_TERMINATED, waiting) is None
    assert missing_measurements(State.EXECUTE, waiting) == ()


# --- N2: every absorbing terminal row carries the verdict obligation ---------


ABSORBING_OR_REPORT = (State.BLOCKED, State.CANCELLED, State.REPORT)


@pytest.mark.parametrize(
    "rule", [r for r in TRANSITION_TABLE if r.target in ABSORBING_OR_REPORT], ids=str
)
def test_n2_every_terminating_row_obliges_a_verdict(rule: object) -> None:
    assert "compute:verdict" in rule.side_effect  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "rule", [r for r in TRANSITION_TABLE if r.target in TERMINAL_STATES], ids=str
)
def test_n2_absorbing_rows_also_emit_and_checkpoint(rule: object) -> None:
    """BLOCKED/CANCELLED have no outgoing row, so unlike REPORT nothing follows
    to emit the verdict — these rows must do all of it themselves."""
    tags = rule.side_effect  # type: ignore[attr-defined]
    assert "audit:verdict" in tags
    assert "journal:checkpoint" in tags
    assert any(tag.startswith("exit_reason:") for tag in tags)


def test_n2_every_exit_reason_tag_names_a_real_spec_4_4_value() -> None:
    """No invented wire values: each tag must be an ExitReason member."""
    known = {reason.value for reason in ExitReason}
    for rule in TRANSITION_TABLE:
        for tag in rule.side_effect:
            if tag.startswith("exit_reason:"):
                assert tag.split(":", 1)[1] in known, tag


@pytest.mark.parametrize(
    ("guard_input", "expected"),
    [
        (_policy_check(DENY), "exit_reason:policy_blocked"),
        (_policy_check(AR, budget=FakeBudget("tokens")), "exit_reason:budget_exhausted"),
        (_policy_check(AR, provider=FakeProvider(False)), "exit_reason:provider_unavailable"),
    ],
    ids=["deny", "budget", "provider"],
)
def test_n2_each_blocked_cause_names_itself(guard_input: GuardInput, expected: str) -> None:
    transition = step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, guard_input)
    assert transition is not None
    assert transition.target is State.BLOCKED
    assert expected in transition.side_effect


@pytest.mark.parametrize(
    ("guard_input", "expected"),
    [
        (GuardInput(approval_denied=True), "exit_reason:approval_denied"),
        (GuardInput(approval_elapsed_s=999), "exit_reason:approval_timeout"),
    ],
    ids=["denied", "timeout"],
)
def test_n2_each_cancelled_cause_names_itself(guard_input: GuardInput, expected: str) -> None:
    transition = step(State.APPROVAL, Event.APPROVAL_REFUSED, guard_input)
    assert transition is not None
    assert transition.target is State.CANCELLED
    assert expected in transition.side_effect


def test_n2_blocked_attribution_follows_spec_order_when_causes_overlap() -> None:
    """DENY under an exhausted budget with a down provider reports the DENY."""
    guard_input = _policy_check(DENY, budget=FakeBudget("time"), provider=FakeProvider(False))
    transition = step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, guard_input)
    assert transition is not None
    assert "exit_reason:policy_blocked" in transition.side_effect


# --- N3: the reduced class is carried out and enforced at the token gate -----


def test_n3_transition_publishes_the_reduced_class() -> None:
    """The minting layer must be able to read the class the machine gated on,
    instead of re-asking the stale PolicyView."""
    stale = FakePolicy(C1)  # says CONFIRM_ONCE; the turn is untrusted
    guard_input = _policy_check(C1, policy=stale, untrusted_turn=True)
    transition = step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, guard_input)
    assert transition is not None
    assert transition.target is State.APPROVAL
    assert transition.reduced_class is CE
    assert stale.classify(REQUEST) is C1  # the adapter still disagrees
    assert reduced_class(guard_input) is CE


def test_n3_a_confirm_once_token_cannot_gate_a_reduced_confirm_exact_action() -> None:
    """RAN by the critic: an injected turn whose stale view said CONFIRM_ONCE
    would otherwise be gated by a multi-use, long-TTL token."""
    untrusted = _approval(policy=FakePolicy(C1), untrusted_turn=True, token_class=C1)
    assert reduced_class(untrusted) is CE
    assert step(State.APPROVAL, Event.APPROVAL_TOKEN_PRESENTED, untrusted) is None

    strengthened = _approval(policy=FakePolicy(C1), untrusted_turn=True, token_class=CE)
    transition = step(State.APPROVAL, Event.APPROVAL_TOKEN_PRESENTED, strengthened)
    assert transition is not None
    assert transition.target is State.EXECUTE


@pytest.mark.parametrize("token_class", ALL_CLASSES)
def test_n3_token_class_must_be_at_least_as_strict_as_the_reduced_class(
    token_class: PermissionClass,
) -> None:
    guard_input = _approval(policy=FakePolicy(CE), token_class=token_class)
    transition = step(State.APPROVAL, Event.APPROVAL_TOKEN_PRESENTED, guard_input)
    assert (transition is not None) is (rank(token_class) >= rank(CE))


def test_n3_reduced_class_is_none_when_undecidable() -> None:
    assert reduced_class(GuardInput()) is None
    transition = step(State.CLASSIFY, Event.TASK_TYPE_RESOLVED, GuardInput(task_type="meta"))
    assert transition is not None
    assert transition.reduced_class is None


# --- N6: the §4.7 replay guard is structural --------------------------------


def test_n6_replay_allowed_matches_the_sibling_enum_wire_value() -> None:
    """machine.py must not import kernel.idempotency, so the ONE coupling point
    is this string. Pin it here: if the sibling renames the value, this fails
    instead of silently closing (or worse, opening) the gate."""
    from lsassist.kernel.idempotency import ReplayVerdict

    assert ReplayVerdict.ALLOWED.value == REPLAY_ALLOWED
    assert REPLAY_ALLOWED not in {
        ReplayVerdict.ALREADY_EXECUTED.value,
        ReplayVerdict.PARTIAL_EXECUTION.value,
    }


@pytest.mark.parametrize(
    "seen", ["ALREADY_EXECUTED", "PARTIAL_EXECUTION", "", "allowed", None]
)
def test_n6_only_an_allowed_verdict_opens_either_execute_edge(seen: str | None) -> None:
    auto = _policy_check(AR, replay=FakeReplay(seen))
    assert step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, auto) is None
    token = _approval(replay=FakeReplay(seen))
    assert step(State.APPROVAL, Event.APPROVAL_TOKEN_PRESENTED, token) is None


def test_n6_an_allowed_verdict_opens_both_edges() -> None:
    auto = step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, _policy_check(AR))
    assert auto is not None and auto.target is State.EXECUTE
    token = step(State.APPROVAL, Event.APPROVAL_TOKEN_PRESENTED, _approval())
    assert token is not None and token.target is State.EXECUTE


def test_n6_an_unconsulted_ledger_never_authorizes() -> None:
    no_ledger = _policy_check(AR, replay=None)
    assert step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, no_ledger) is None
    assert step(State.APPROVAL, Event.APPROVAL_TOKEN_PRESENTED, _approval(replay=None)) is None


def test_n6_begin_is_obliged_before_the_gate_not_after_it() -> None:
    """The ledger must be consulted while refusing is still possible, so the
    obligation sits on the row BEFORE the EXECUTE edges."""
    edge = (State.PLAN, State.POLICY_CHECK)
    before = [r for r in TRANSITION_TABLE if (r.source, r.target) == edge]
    assert before and all("idempotency:begin" in r.side_effect for r in before)
    for rule in TRANSITION_TABLE:
        if rule.target is State.EXECUTE:
            assert "idempotency:begin" not in rule.side_effect


@pytest.mark.parametrize("seen", ["ALREADY_EXECUTED", "PARTIAL_EXECUTION"])
def test_n6_a_replay_stop_is_nameable_rather_than_a_silent_park(seen: str) -> None:
    """RESIDUAL made visible: neither value has a §4.4 exit reason or a §4.1
    state, so the machine stalls — but the runner can name why and escalate."""
    guard_input = _policy_check(AR, replay=FakeReplay(seen))
    assert step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, guard_input) is None
    assert missing_measurements(State.POLICY_CHECK, guard_input) == ()
    assert replay_block(guard_input) == seen


def test_n6_replay_block_is_silent_when_allowed_or_unconsulted() -> None:
    assert replay_block(_policy_check(AR)) is None
    assert replay_block(GuardInput()) is None


# --- S6/S7: the runner obligations are NAMED in the table ---------------------

EXPECTED_TAGS: dict[tuple[State, State], tuple[str, ...]] = {
    # N6 moved `idempotency:begin` HERE, one row before the gate: it produces
    # the replay verdict both EXECUTE guards now require, so it must be
    # discharged while refusing is still possible.
    (State.PLAN, State.POLICY_CHECK): ("budget:consume_plan_revision", "idempotency:begin"),
    (State.POLICY_CHECK, State.EXECUTE): ("budget:consume_tool_call",),
    (State.APPROVAL, State.EXECUTE): ("budget:consume_tool_call",),
    (State.EXECUTE, State.OBSERVE): ("budget:settle_tool_call", "idempotency:complete"),
    (State.OBSERVE, State.VERIFY): ("budget:cap_output",),
}


@pytest.mark.parametrize(("edge", "tags"), sorted(EXPECTED_TAGS.items(), key=str))
def test_s6_obligations_are_named_on_the_row_that_incurs_them(
    edge: tuple[State, State], tags: tuple[str, ...]
) -> None:
    rows = [rule for rule in TRANSITION_TABLE if (rule.source, rule.target) == edge]
    assert rows, f"no row for {edge}"
    for row in rows:
        for tag in tags:
            assert tag in row.side_effect, f"{edge} does not name {tag}"


def test_s6_every_tag_is_a_namespaced_obligation() -> None:
    for rule in TRANSITION_TABLE:
        for tag in rule.side_effect:
            assert tag.split(":", 1)[0] in {
                "audit",
                "budget",
                "compute",
                "enforce",
                "exit_reason",
                "idempotency",
                "journal",
                "prompt",
            }, tag


# --- the EXECUTE gate (I15 / AC-07) ------------------------------------------


def test_execute_entry_rules_are_exactly_two() -> None:
    assert len(EXECUTE_ENTRY_RULES) == 2
    assert {(rule.source, rule.event) for rule in EXECUTE_ENTRY_RULES} == {
        (State.POLICY_CHECK, Event.POLICY_CLASSIFIED),
        (State.APPROVAL, Event.APPROVAL_TOKEN_PRESENTED),
    }
    assert all(rule.target is State.EXECUTE for rule in EXECUTE_ENTRY_RULES)


def test_execute_entry_rules_are_the_only_execute_targets_in_the_table() -> None:
    from_table = tuple(rule for rule in TRANSITION_TABLE if rule.target is State.EXECUTE)
    assert from_table == EXECUTE_ENTRY_RULES


@pytest.mark.parametrize("policy_class", ALL_CLASSES)
@pytest.mark.parametrize("token_verdict", (*TokenVerdict, None))
@pytest.mark.parametrize("untrusted", (True, False))
def test_execute_unreachable_from_every_other_state_event_pair(
    policy_class: PermissionClass, token_verdict: TokenVerdict | None, untrusted: bool
) -> None:
    """Exhaustive I15: no (state, event) other than the two entry edges reaches
    EXECUTE, under a maximally-permissive input crossed with every policy class,
    every token verdict, and both trust states."""
    guard_input = permissive(
        policy=FakePolicy(policy_class),
        token_verdict=token_verdict,
        untrusted_turn=untrusted,
    )
    for state, event in itertools.product(State, Event):
        transition = step(state, event, guard_input)
        if transition is None or transition.target is not State.EXECUTE:
            continue
        assert (state, event) in {
            (State.POLICY_CHECK, Event.POLICY_CLASSIFIED),
            (State.APPROVAL, Event.APPROVAL_TOKEN_PRESENTED),
        }
        if state is State.POLICY_CHECK:
            assert policy_class in AUTO_CLASSES
            assert policy_class is AR or not untrusted
        else:
            assert token_verdict is TokenVerdict.VALID


def test_widening_the_execute_gate_fails_the_import_time_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NEGATIVE CONTROL: a third EXECUTE-targeting row (or a re-guarded entry
    edge) is rejected by the import-time validator."""
    rogue = machine.TransitionRule(
        source=State.VERIFY,
        event=Event.POSTCONDITIONS_CHECKED,
        target=State.EXECUTE,
        guard=lambda _inp: True,
    )
    monkeypatch.setattr(
        machine, "EXECUTE_ENTRY_RULES", (*machine.EXECUTE_ENTRY_RULES, rogue), raising=True
    )
    with pytest.raises(MachineTableError, match="I15 violation"):
        machine._validate_execute_gate()


def test_replacing_an_entry_guard_fails_the_import_time_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    weakened = tuple(
        dataclasses.replace(rule, guard=lambda _inp: True)
        for rule in machine.EXECUTE_ENTRY_RULES
    )
    monkeypatch.setattr(machine, "EXECUTE_ENTRY_RULES", weakened, raising=True)
    with pytest.raises(MachineTableError, match="I15 violation"):
        machine._validate_execute_gate()


def test_outgoing_rule_from_a_terminal_state_fails_the_import_time_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    escape = machine.TransitionRule(
        source=State.BLOCKED,
        event=Event.INTENT_CAPTURED,
        target=State.RECEIVE,
        guard=lambda _inp: True,
    )
    monkeypatch.setattr(machine, "TRANSITION_TABLE", (*TRANSITION_TABLE, escape), raising=True)
    with pytest.raises(MachineTableError, match="absorbing"):
        machine._validate_execute_gate()


@pytest.mark.parametrize("policy_class", (C1, CE, DENY))
def test_non_auto_class_never_goes_straight_to_execute(policy_class: PermissionClass) -> None:
    transition = step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, _policy_check(policy_class))
    assert transition is not None
    assert transition.target is not State.EXECUTE
    assert transition.target is (State.BLOCKED if policy_class is DENY else State.APPROVAL)


def test_class_partition_is_total_and_disjoint() -> None:
    assert set(AUTO_CLASSES) == {AR, ASW}
    assert set(CONFIRM_CLASSES) == {C1, CE}
    assert AUTO_CLASSES.isdisjoint(CONFIRM_CLASSES)
    assert AUTO_CLASSES | CONFIRM_CLASSES | {DENY} == set(PermissionClass)


def test_task_types_match_spec_4_2() -> None:
    assert set(TASK_TYPES) == {"coding", "tutor", "sysinfo", "memory", "skill", "meta"}


# --- fail-closed: unknown pairs, terminal absorption --------------------------


def test_every_unknown_state_event_pair_returns_none_even_when_permissive() -> None:
    known = {(rule.source, rule.event) for rule in TRANSITION_TABLE}
    guard_input = permissive()
    for state, event in itertools.product(State, Event):
        if (state, event) in known:
            continue
        assert step(state, event, guard_input) is None, f"{state}/{event} leaked a transition"


@pytest.mark.parametrize("state", sorted(TERMINAL_STATES))
def test_terminal_states_are_absorbing(state: State) -> None:
    guard_input = permissive()
    for event in Event:
        assert step(state, event, guard_input) is None
        machine_state = MachineState(state=state)
        assert advance(machine_state, event, guard_input) is machine_state


# --- determinism / purity -----------------------------------------------------


def test_step_is_deterministic() -> None:
    guard_input = permissive(policy=FakePolicy(ASW))
    first = step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, guard_input)
    second = step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, guard_input)
    assert first == second


def test_guard_input_is_frozen() -> None:
    guard_input = GuardInput(task_type="coding")
    with pytest.raises(dataclasses.FrozenInstanceError):
        guard_input.task_type = "meta"  # type: ignore[misc]


def test_transition_is_frozen_value() -> None:
    transition = step(State.CLASSIFY, Event.TASK_TYPE_RESOLVED, GuardInput(task_type="meta"))
    assert isinstance(transition, Transition)
    with pytest.raises(dataclasses.FrozenInstanceError):
        transition.target = State.EXECUTE  # type: ignore[misc]


def test_intent_record_is_immutable() -> None:
    """§4.2 row 1 side condition: the intent record is stored IMMUTABLE."""
    with pytest.raises(ValidationError):
        INTENT.text = "rewritten"  # type: ignore[misc]


def test_step_does_not_mutate_its_inputs() -> None:
    guard_input = permissive()
    before = dataclasses.asdict(guard_input)
    step(State.POLICY_CHECK, Event.POLICY_CLASSIFIED, guard_input)
    assert dataclasses.asdict(guard_input) == before


# --- advance(): MachineState + side-effect tags -------------------------------


def test_advance_moves_state_and_records_side_effect_tag() -> None:
    machine_state = MachineState(state=State.RECEIVE)
    moved = advance(machine_state, Event.INTENT_CAPTURED, GuardInput(intent=INTENT))
    assert moved.state is State.CLASSIFY
    assert moved.emitted == ("audit:intent",)
    assert machine_state.state is State.RECEIVE and machine_state.emitted == ()


def test_advance_is_a_noop_when_no_guard_holds() -> None:
    machine_state = MachineState(state=State.RECEIVE)
    assert advance(machine_state, Event.POLICY_CLASSIFIED, permissive()) is machine_state


def test_advance_accumulates_tags_along_the_happy_path() -> None:
    machine_state = MachineState(state=State.RECEIVE)
    script: tuple[tuple[Event, GuardInput], ...] = (
        (Event.INTENT_CAPTURED, GuardInput(intent=INTENT)),
        (Event.TASK_TYPE_RESOLVED, GuardInput(task_type="coding")),
        (Event.CONTEXT_GATHERED, GuardInput(ground_reads=3)),
        (Event.PLAN_PROPOSED, GuardInput(request=REQUEST, registry=FakeRegistry())),
        (Event.POLICY_CLASSIFIED, _policy_check(AR)),
        (Event.PROCESS_TERMINATED, GuardInput(exec_outcome=ExecOutcome.EXITED)),
        (Event.OUTPUT_CAPTURED, GuardInput(output_captured=True, digests_computed=True)),
        (
            Event.POSTCONDITIONS_CHECKED,
            GuardInput(plan_complete=True, budget=FakeBudget(), loop_clear=True),
        ),
        (Event.VERDICT_EMITTED, GuardInput(verdict=FakeVerdict())),
    )
    for event, guard_input in script:
        machine_state = advance(machine_state, event, guard_input)
    assert machine_state.state is State.RECEIVE
    assert "audit:policy_decision" in machine_state.emitted
    assert "budget:consume_tool_call" in machine_state.emitted
    assert "idempotency:complete" in machine_state.emitted
    # §4.2 REPORT row carries TWO side effects: the verdict audit + the journal
    # checkpoint. Both are emitted as tags, in table order.
    assert machine_state.emitted[-2:] == ("audit:verdict", "journal:checkpoint")


def test_inner_loop_execute_observe_verify_can_repeat_and_return_to_plan() -> None:
    """§4.1 inner loop: EXECUTE→OBSERVE→VERIFY→PLAN repeats within budget."""
    machine_state = MachineState(state=State.EXECUTE)
    for _ in range(3):
        machine_state = advance(
            machine_state, Event.PROCESS_TERMINATED, GuardInput(exec_outcome=ExecOutcome.EXITED)
        )
        assert machine_state.state is State.OBSERVE
        machine_state = advance(
            machine_state,
            Event.OUTPUT_CAPTURED,
            GuardInput(output_captured=True, digests_computed=True),
        )
        assert machine_state.state is State.VERIFY
        machine_state = advance(
            machine_state,
            Event.POSTCONDITIONS_CHECKED,
            GuardInput(postconditions_ok=True, budget=FakeBudget(), loop_clear=True),
        )
        assert machine_state.state is State.PLAN
        machine_state = advance(
            machine_state,
            Event.PLAN_PROPOSED,
            GuardInput(request=REQUEST, registry=FakeRegistry()),
        )
        assert machine_state.state is State.POLICY_CHECK
        machine_state = advance(machine_state, Event.POLICY_CLASSIFIED, _policy_check(AR))
        assert machine_state.state is State.EXECUTE
