"""Kernel state-machine vocabulary: states and events (SPEC §4.1).

The §4.1 outer loop is
``RECEIVE → CLASSIFY → GROUND → PLAN → POLICY_CHECK → APPROVAL → EXECUTE →
OBSERVE → VERIFY → REPORT`` with the terminal pseudo-states ``BLOCKED`` and
``CANCELLED``; the inner loop ``EXECUTE → OBSERVE → VERIFY`` repeats per tool
call and may return to ``PLAN`` within budget.

:class:`Event` names the TRIGGER of each §4.2 row, so a transition is a
``(state, event)`` lookup guarded by a pure predicate (see ``machine.py``). The
table has 16 rows over 11 events: several events fan out to multiple targets
(``POLICY_CLASSIFIED`` to EXECUTE / APPROVAL / BLOCKED, ``POSTCONDITIONS_CHECKED``
to REPORT / PLAN, and ``CONTEXT_GATHERED`` / ``PLAN_PROPOSED`` each to REPORT on
the failure branch), disambiguated by guards, never by an implicit default.

TERMINAL ABSORPTION vs. the §4.1 mermaid diagram: the diagram draws
``BLOCKED → RECEIVE`` and ``CANCELLED → RECEIVE``, but the §4.2 TABLE — the
authoritative guard contract — contains no such rows. Those diagram edges are
the NEXT USER TURN re-entry (a new task starts a fresh machine at ``RECEIVE``),
not an in-task transition. Within one task the terminal states are therefore
ABSORBING: no event leaves them.

§2.2: pure vocabulary — stdlib ``enum`` only; no I/O, no clock, no randomness.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class State(StrEnum):
    """The §4.1 outer-loop states plus the two terminal pseudo-states."""

    RECEIVE = "RECEIVE"
    CLASSIFY = "CLASSIFY"
    GROUND = "GROUND"
    PLAN = "PLAN"
    POLICY_CHECK = "POLICY_CHECK"
    APPROVAL = "APPROVAL"
    EXECUTE = "EXECUTE"
    OBSERVE = "OBSERVE"
    VERIFY = "VERIFY"
    REPORT = "REPORT"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class Event(StrEnum):
    """What happened — the trigger column of the §4.2 transition table."""

    INTENT_CAPTURED = "intent_captured"
    TASK_TYPE_RESOLVED = "task_type_resolved"
    CONTEXT_GATHERED = "context_gathered"
    PLAN_PROPOSED = "plan_proposed"
    POLICY_CLASSIFIED = "policy_classified"
    APPROVAL_TOKEN_PRESENTED = "approval_token_presented"
    APPROVAL_REFUSED = "approval_refused"
    PROCESS_TERMINATED = "process_terminated"
    OUTPUT_CAPTURED = "output_captured"
    POSTCONDITIONS_CHECKED = "postconditions_checked"
    VERDICT_EMITTED = "verdict_emitted"


class ExecOutcome(StrEnum):
    """How an EXECUTE ended (§4.2 ``EXECUTE → OBSERVE``: exit OR timeout OR kill).

    All three are legitimate reasons to OBSERVE; the distinction feeds the
    verdict/ExitReason layer (T2.09), not the transition guard.
    """

    EXITED = "exited"
    TIMED_OUT = "timed_out"
    KILLED = "killed"


#: §4.1 outer-loop states, in order (excludes the terminal pseudo-states).
OUTER_LOOP: Final[tuple[State, ...]] = (
    State.RECEIVE,
    State.CLASSIFY,
    State.GROUND,
    State.PLAN,
    State.POLICY_CHECK,
    State.APPROVAL,
    State.EXECUTE,
    State.OBSERVE,
    State.VERIFY,
    State.REPORT,
)

#: §4.1 terminal pseudo-states. Absorbing within a task (see module docstring).
TERMINAL_STATES: Final[frozenset[State]] = frozenset({State.BLOCKED, State.CANCELLED})
