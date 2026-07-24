"""§23.1 PT / AC-07 / I15: EXECUTE is never reached without an AUTO class or a
VALID approval token.

Hypothesis drives the §4.1-4.2 machine with ARBITRARY event sequences over
arbitrary guard inputs (every policy class, every ``TokenVerdict``, every
budget-exhaustion kind, provider up/down, both trust states, all boolean
observation flags) and asserts, per step and over whole runs:

1. **The EXECUTE gate (I15/AC-07).** Every fresh entry into ``EXECUTE`` came
   from exactly one of the two entry edges, and the edge's own condition held —
   an AUTO class from ``POLICY_CHECK``, or ``TokenVerdict.VALID`` plus an
   affirmative grant from ``APPROVAL``. 0 violations.
2. **§4.6 step 2 (seam defect S1).** No untrusted turn ever reaches EXECUTE
   with anything but a pure ``AUTO_READ``.
3. **No implicit gate crossing.** ``EXECUTE`` is never entered before
   ``POLICY_CHECK`` has been visited in the run (``APPROVAL`` is itself only
   reachable from ``POLICY_CHECK``).
4. **Closure.** No transition escapes the ``State`` set.
5. **Terminal absorption.** Once ``BLOCKED`` / ``CANCELLED`` is reached, no
   event moves the machine again.
6. **No parking (seam defects S2/S5).** From any live state there is always an
   event that moves the machine — a task can never be stranded without a route
   to a verdict.
7. **Determinism/purity.** The same ``(state, event, input)`` always yields the
   same transition and never mutates it.

Run with ``--hypothesis-profile=ci`` for >=200 examples (300; see
``tests/property/conftest``). Every collaborator is an in-memory fake — the
machine performs no I/O, so the property suite needs no fixtures.
"""

from __future__ import annotations

import dataclasses

from hypothesis import given
from hypothesis import strategies as st

from lsassist.contracts.enums import PermissionClass, VerdictStatus
from lsassist.contracts.intent import IntentRecord, make_intent
from lsassist.contracts.tool_request import ToolRequest
from lsassist.kernel.machine import (
    AUTO_CLASSES,
    REPLAY_ALLOWED,
    GuardInput,
    MachineState,
    advance,
    missing_measurements,
    reduced_class,
    step,
)
from lsassist.kernel.states import TERMINAL_STATES, Event, ExecOutcome, State
from lsassist.policy.classes import rank
from lsassist.policy.token import TokenVerdict

REQUEST = ToolRequest(call_id="c1", tool="fs.read", args={"path": "/ws/a.txt"})
INTENT: IntentRecord = make_intent("do the thing")

EXECUTE_ENTRY_EDGES: frozenset[tuple[State, Event]] = frozenset(
    {
        (State.POLICY_CHECK, Event.POLICY_CLASSIFIED),
        (State.APPROVAL, Event.APPROVAL_TOKEN_PRESENTED),
    }
)


# --- in-memory fakes for the injected Protocols (no I/O) ---------------------


@dataclasses.dataclass(frozen=True)
class FakeRegistry:
    known: bool
    valid: bool

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
    kind: str | None

    def exhausted_kind(self) -> str | None:
        return self.kind


@dataclasses.dataclass(frozen=True)
class FakeProvider:
    ok: bool

    def available(self) -> bool:
        return self.ok


@dataclasses.dataclass(frozen=True)
class FakeReplay:
    seen: str | None

    def replay_verdict(self) -> str | None:
        return self.seen


@dataclasses.dataclass(frozen=True)
class FakeVerdict:
    is_emitted: bool
    verdict_status: VerdictStatus | None
    evidence: int
    sub_goals_verified: int

    def emitted(self) -> bool:
        return self.is_emitted

    def status(self) -> VerdictStatus | None:
        return self.verdict_status

    def evidence_count(self) -> int:
        return self.evidence

    def sub_goal_verified_count(self) -> int:
        return self.sub_goals_verified


# --- strategies ---------------------------------------------------------------

_policy_classes = st.sampled_from(list(PermissionClass))
_token_verdicts = st.one_of(st.none(), st.sampled_from(list(TokenVerdict)))
_budget_kinds = st.sampled_from([None, "tool_calls", "tokens", "time", "cost"])
_task_types = st.sampled_from(["coding", "tutor", "sysinfo", "memory", "skill", "meta", "", "pwn"])


@st.composite
def guard_inputs(draw: st.DrawFn) -> GuardInput:
    """An arbitrary — frequently adversarial — §4.2 guard input bundle."""
    return GuardInput(
        request=draw(st.sampled_from([REQUEST, None])),
        registry=draw(
            st.one_of(st.none(), st.builds(FakeRegistry, known=st.booleans(), valid=st.booleans()))
        ),
        policy=draw(st.one_of(st.none(), st.builds(FakePolicy, result=_policy_classes))),
        provider=draw(st.one_of(st.none(), st.builds(FakeProvider, ok=st.booleans()))),
        replay=draw(
            st.one_of(
                st.none(),
                st.builds(
                    FakeReplay,
                    seen=st.sampled_from(
                        [None, "ALLOWED", "ALREADY_EXECUTED", "PARTIAL_EXECUTION", "nonsense"]
                    ),
                ),
            )
        ),
        budget=draw(st.one_of(st.none(), st.builds(FakeBudget, kind=_budget_kinds))),
        verdict=draw(
            st.one_of(
                st.none(),
                st.builds(
                    FakeVerdict,
                    is_emitted=st.booleans(),
                    verdict_status=st.one_of(st.none(), st.sampled_from(list(VerdictStatus))),
                    evidence=st.integers(min_value=0, max_value=3),
                    sub_goals_verified=st.integers(min_value=0, max_value=3),
                ),
            )
        ),
        intent=draw(st.sampled_from([INTENT, make_intent(""), None])),
        task_type=draw(st.one_of(st.none(), _task_types)),
        untrusted_turn=draw(st.booleans()),
        ground_reads=draw(st.one_of(st.none(), st.integers(min_value=-5, max_value=100))),
        token_verdict=draw(_token_verdicts),
        token_class=draw(st.one_of(st.none(), _policy_classes)),
        approval_granted=draw(st.booleans()),
        approval_denied=draw(st.booleans()),
        approval_elapsed_s=draw(st.one_of(st.none(), st.integers(min_value=0, max_value=400))),
        exec_outcome=draw(st.one_of(st.none(), st.sampled_from(list(ExecOutcome)))),
        output_captured=draw(st.booleans()),
        digests_computed=draw(st.booleans()),
        postconditions_ok=draw(st.booleans()),
        retryable_failure=draw(st.booleans()),
        unrecoverable_failure=draw(st.booleans()),
        plan_complete=draw(st.booleans()),
        loop_clear=draw(st.booleans()),
    )


_event_stream = st.lists(st.tuples(st.sampled_from(list(Event)), guard_inputs()), max_size=40)


def _classified(guard_input: GuardInput) -> PermissionClass | None:
    if guard_input.policy is None or guard_input.request is None:
        return None
    return guard_input.policy.classify(guard_input.request)


# --- the properties -----------------------------------------------------------


@given(start=st.sampled_from(list(State)), stream=_event_stream)
def test_execute_never_entered_without_auto_class_or_valid_token(
    start: State, stream: list[tuple[Event, GuardInput]]
) -> None:
    """AC-07 / I15: 0 violations over generated sequences."""
    machine = MachineState(state=start)
    for event, guard_input in stream:
        before = machine.state
        machine = advance(machine, event, guard_input)
        if machine.state is not State.EXECUTE or before is State.EXECUTE:
            continue
        assert (before, event) in EXECUTE_ENTRY_EDGES
        if before is State.POLICY_CHECK:
            assert _classified(guard_input) in AUTO_CLASSES
        else:
            assert guard_input.token_verdict is TokenVerdict.VALID
            assert guard_input.approval_granted is True
            # N3: the token was minted at least as strictly as the reduced class
            required = reduced_class(guard_input)
            assert required is not None
            assert guard_input.token_class is not None
            assert rank(guard_input.token_class) >= rank(required)
        # N6: §4.7 authorized this specific action, on BOTH edges
        assert guard_input.replay is not None
        assert guard_input.replay.replay_verdict() == REPLAY_ALLOWED


@given(start=st.sampled_from(list(State)), stream=_event_stream)
def test_an_untrusted_turn_only_ever_executes_a_pure_read(
    start: State, stream: list[tuple[Event, GuardInput]]
) -> None:
    """§4.6 step 2 / seam defect S1, as a property: on an untrusted turn the
    only class that can still cross the POLICY_CHECK gate is AUTO_READ."""
    machine = MachineState(state=start)
    for event, guard_input in stream:
        before = machine.state
        machine = advance(machine, event, guard_input)
        if machine.state is not State.EXECUTE or before is not State.POLICY_CHECK:
            continue
        if guard_input.untrusted_turn:
            assert _classified(guard_input) is PermissionClass.AUTO_READ


@given(stream=_event_stream)
def test_execute_never_precedes_policy_check(stream: list[tuple[Event, GuardInput]]) -> None:
    """I15 'no implicit gate crossing': starting from RECEIVE, the machine can
    never be in EXECUTE without having passed through POLICY_CHECK first."""
    machine = MachineState(state=State.RECEIVE)
    seen_policy_check = False
    for event, guard_input in stream:
        machine = advance(machine, event, guard_input)
        if machine.state is State.POLICY_CHECK:
            seen_policy_check = True
        if machine.state is State.EXECUTE:
            assert seen_policy_check


@given(start=st.sampled_from(list(State)), stream=_event_stream)
def test_no_transition_escapes_the_state_set(
    start: State, stream: list[tuple[Event, GuardInput]]
) -> None:
    known = set(State)
    machine = MachineState(state=start)
    for event, guard_input in stream:
        machine = advance(machine, event, guard_input)
        assert machine.state in known


@given(start=st.sampled_from(sorted(TERMINAL_STATES)), stream=_event_stream)
def test_terminal_states_are_absorbing(
    start: State, stream: list[tuple[Event, GuardInput]]
) -> None:
    machine = MachineState(state=start)
    for event, guard_input in stream:
        assert step(start, event, guard_input) is None
        machine = advance(machine, event, guard_input)
        assert machine.state is start
        assert machine.emitted == ()


@given(start=st.sampled_from(list(State)), stream=_event_stream)
def test_terminal_state_is_never_left_mid_run(
    start: State, stream: list[tuple[Event, GuardInput]]
) -> None:
    machine = MachineState(state=start)
    for event, guard_input in stream:
        before = machine.state
        machine = advance(machine, event, guard_input)
        if before in TERMINAL_STATES:
            assert machine.state is before


#: States whose event carries a DECISION that has already been made, so exactly
#: one row must always fire. The remaining states legitimately stall on an
#: UNMEASURED fact (the child has not exited, the user has not answered) — a
#: WAIT the runner resolves by calling again, not a park.
TOTAL_DECISIONS: tuple[tuple[State, Event], ...] = (
    (State.GROUND, Event.CONTEXT_GATHERED),
    (State.PLAN, Event.PLAN_PROPOSED),
    (State.POLICY_CHECK, Event.POLICY_CLASSIFIED),
    (State.VERIFY, Event.POSTCONDITIONS_CHECKED),
)


@given(guard_input=guard_inputs())
def test_wired_decision_states_never_park(guard_input: GuardInput) -> None:
    """S2/S5 as a property, narrowed by N4: a decision state whose inputs were
    all MEASURED always moves. An unwired one stalls on purpose, and
    ``missing_measurements`` names why rather than inventing a cause."""
    for state, event in TOTAL_DECISIONS:
        if missing_measurements(state, guard_input):
            continue
        assert step(state, event, guard_input) is not None, f"{state} parked"


@given(guard_input=guard_inputs())
def test_verify_is_unconditionally_total(guard_input: GuardInput) -> None:
    """The one state that must never stall: a checked task always gets a verdict."""
    assert step(State.VERIFY, Event.POSTCONDITIONS_CHECKED, guard_input) is not None


@given(state=st.sampled_from(list(State)), event=st.sampled_from(list(Event)),
       guard_input=guard_inputs())
def test_n4_a_fired_cause_is_always_a_measured_one(
    state: State, event: Event, guard_input: GuardInput
) -> None:
    """N4 as a property: no transition ever names a cause the bundle did not
    actually measure. A stall is fine; a fabricated attribution is not."""
    transition = step(state, event, guard_input)
    if transition is None:
        return
    tags = set(transition.side_effect)
    if "exit_reason:grounding_failed" in tags:
        assert guard_input.ground_reads is not None
    if "exit_reason:malformed_model_output" in tags:
        assert guard_input.request is not None and guard_input.registry is not None
    if "exit_reason:policy_blocked" in tags:
        assert guard_input.policy is not None and guard_input.request is not None
    if "exit_reason:budget_exhausted" in tags:
        assert guard_input.budget is not None
    if "exit_reason:provider_unavailable" in tags:
        assert guard_input.provider is not None


@given(state=st.sampled_from(list(State)), event=st.sampled_from(list(Event)),
       guard_input=guard_inputs())
def test_n2_every_terminating_transition_obliges_a_verdict(
    state: State, event: Event, guard_input: GuardInput
) -> None:
    """N2 as a property: no generated input can end a turn without a verdict."""
    transition = step(state, event, guard_input)
    ending = {State.BLOCKED, State.CANCELLED, State.REPORT}
    if transition is None or transition.target not in ending:
        return
    assert "compute:verdict" in transition.side_effect
    if transition.target in TERMINAL_STATES:
        assert "audit:verdict" in transition.side_effect
        assert "journal:checkpoint" in transition.side_effect


@given(state=st.sampled_from(list(State)), event=st.sampled_from(list(Event)),
       guard_input=guard_inputs())
def test_n3_published_reduced_class_matches_the_public_function(
    state: State, event: Event, guard_input: GuardInput
) -> None:
    """The minting layer reads ``Transition.reduced_class``; it must equal what
    the machine gated on, for every generated bundle."""
    transition = step(state, event, guard_input)
    if transition is None:
        return
    assert transition.reduced_class == reduced_class(guard_input)


@given(
    state=st.sampled_from(list(State)),
    event=st.sampled_from(list(Event)),
    guard_input=guard_inputs(),
)
def test_step_is_pure_and_deterministic(
    state: State, event: Event, guard_input: GuardInput
) -> None:
    snapshot = dataclasses.asdict(guard_input)
    first = step(state, event, guard_input)
    second = step(state, event, guard_input)
    assert first == second
    assert dataclasses.asdict(guard_input) == snapshot
    if first is not None:
        assert first.source is state
        assert first.event is event


@given(
    state=st.sampled_from(list(State)),
    event=st.sampled_from(list(Event)),
    guard_input=guard_inputs(),
)
def test_terminal_targets_come_only_from_their_one_edge(
    state: State, event: Event, guard_input: GuardInput
) -> None:
    """§4.2: the only BLOCKED edge is POLICY_CHECK→BLOCKED (deny / no budget /
    no provider); the only CANCELLED edge is APPROVAL→CANCELLED."""
    transition = step(state, event, guard_input)
    if transition is None:
        return
    if transition.target is State.BLOCKED:
        assert (state, event) == (State.POLICY_CHECK, Event.POLICY_CLASSIFIED)
    if transition.target is State.CANCELLED:
        assert (state, event) == (State.APPROVAL, Event.APPROVAL_REFUSED)


@given(
    state=st.sampled_from(list(State)),
    event=st.sampled_from(list(Event)),
    guard_input=guard_inputs(),
)
def test_i12_holds_at_both_levels_for_every_generated_verdict(
    state: State, event: Event, guard_input: GuardInput
) -> None:
    """Seam defect S8 as a property: a turn never closes on a verdict that
    claims a VERIFIED result — top level OR per sub-goal — with no evidence."""
    transition = step(state, event, guard_input)
    if transition is None or transition.target is not State.RECEIVE:
        return
    verdict = guard_input.verdict
    assert verdict is not None
    if verdict.evidence_count() >= 1:
        return
    assert verdict.status() is not VerdictStatus.VERIFIED
    assert verdict.sub_goal_verified_count() == 0
