"""kernel/ — deterministic agent state machine, budgets, verdicts (SPEC §4).

TCB (§2.3). §2.2: may import ``policy`` / ``contracts`` / ``audit``; MUST NOT
import ``providers``, ``cli``, ``tutor`` or ``coding``, and performs no network
or subprocess I/O. Every module below is PURE — no filesystem, no clock, no
randomness on any decision path (the one unpredictable value, the §4.6 marker
id, is injected).

The package is assembled from five independently-built units (T2.07-T2.11),
decoupled BY CONSTRUCTION: :mod:`~lsassist.kernel.machine` declares what it
needs as ``typing.Protocol`` collaborators and imports none of its siblings, so
the state machine is exercisable with fakes and the concretes can evolve
without touching it.

- :mod:`~lsassist.kernel.states` / :mod:`~lsassist.kernel.machine` (§4.1-4.2) —
  the state/event vocabulary and the transition table as data with pure guards.
  ``EXECUTE`` has exactly two entry edges (an AUTO class, or a VALID token) and
  that count is re-derived from the table and checked at import (I15/AC-07).
- :mod:`~lsassist.kernel.budgets` (§4.3) — per-task budget accounting, output
  caps carrying a full-output digest, and the refund rule.
- :mod:`~lsassist.kernel.loopdetect` (§4.3) — an identical ``action_hash`` three
  times consecutively halts the task; the halt is absorbing.
- :mod:`~lsassist.kernel.verdict` (§4.4-4.5, I12) — folds sub-goal checks and
  evidence into the single verdict a REPORT carries. An under-evidenced
  VERIFIED is DOWNGRADED to UNVERIFIED, never raised.
- :mod:`~lsassist.kernel.idempotency` (§4.7) — per-request idempotency keys and
  the replay guard (an already-completed ``seq`` is never re-executed).
- :mod:`~lsassist.kernel.untrusted` (§4.6, I7) — the SOLE producer of the
  untrusted delimiter, plus the sticky untrusted-turn flag that arms policy R3.

COLLABORATOR WIRING (for the T5.12 session engine). The machine's Protocols are
satisfied as follows — all three are exercised against the REAL modules in
``tests/integration/test_kernel_seams.py``:

- ``BudgetView`` — :class:`~lsassist.contracts.budget.BudgetState` satisfies it
  verbatim (``exhausted_kind() -> str | None``); no adapter needed.
- ``PolicyView`` — a thin adapter over :func:`lsassist.policy.rules.classify`
  binding ``(context, manifest, stores)``; the kernel holds no ``PolicyStores``.
- ``VerdictView`` — an adapter IS required: ``contracts.Verdict`` supplies
  ``status`` but neither ``emitted()`` nor ``evidence_count()``.
- ``RegistryView`` / ``ProviderView`` — supplied by the T3.01 tool registry and
  the provider adapter respectively (both outside the kernel per §2.2).
"""

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
from lsassist.kernel.idempotency import (
    ActionRef,
    DuplicateCompletionError,
    ExecutionState,
    IdempotencyError,
    IdempotencyLedger,
    LedgerEntry,
    ReplayDecision,
    ReplayVerdict,
    SeqConflictError,
    SeqRegressionError,
    UnknownSeqError,
)
from lsassist.kernel.loopdetect import LOOP_THRESHOLD, LoopDetectionError, LoopTracker
from lsassist.kernel.machine import (
    EXECUTE_ENTRY_RULES,
    REPLAY_ALLOWED,
    TRANSITION_TABLE,
    BudgetView,
    GuardInput,
    MachineState,
    MachineTableError,
    PolicyView,
    ProviderView,
    RegistryView,
    ReplayView,
    Transition,
    TransitionRule,
    VerdictView,
    advance,
    missing_measurements,
    reduced_class,
    replay_block,
    step,
)
from lsassist.kernel.states import TERMINAL_STATES, Event, ExecOutcome, State
from lsassist.kernel.untrusted import (
    END_MARKER_PATTERN,
    START_MARKER_PATTERN,
    TurnTrust,
    UntrustedWrapError,
    compute_turn_trust,
    defang,
    ingest_untrusted_block,
    new_turn,
    wrap_untrusted,
)
from lsassist.kernel.verdict import (
    ADMISSIBLE_EVIDENCE_TYPES,
    CAPPED_EXIT_REASONS,
    LEGAL_PAIRS,
    TERMINAL_EXIT_STATUS,
    CheckOutcome,
    VerdictCoherenceError,
    compute_verdict,
    require_coherent_pair,
)

__all__ = [
    "ADMISSIBLE_EVIDENCE_TYPES",
    "CAPPED_EXIT_REASONS",
    "END_MARKER_PATTERN",
    "EXECUTE_ENTRY_RULES",
    "LEGAL_PAIRS",
    "LOOP_THRESHOLD",
    "REPLAY_ALLOWED",
    "START_MARKER_PATTERN",
    "TERMINAL_EXIT_STATUS",
    "TERMINAL_STATES",
    "TRANSITION_TABLE",
    "ActionRef",
    "BudgetError",
    "BudgetView",
    "CappedOutput",
    "CheckOutcome",
    "DuplicateCompletionError",
    "Event",
    "ExecOutcome",
    "ExecutionState",
    "Exhaustion",
    "GuardInput",
    "IdempotencyError",
    "IdempotencyLedger",
    "LedgerEntry",
    "LoopDetectionError",
    "LoopTracker",
    "MachineState",
    "MachineTableError",
    "PolicyView",
    "ProviderView",
    "RegistryView",
    "ReplayDecision",
    "ReplayVerdict",
    "ReplayView",
    "SeqConflictError",
    "SeqRegressionError",
    "State",
    "ToolCallOutcome",
    "Transition",
    "TransitionRule",
    "TurnTrust",
    "UnknownSeqError",
    "UntrustedWrapError",
    "VerdictCoherenceError",
    "VerdictView",
    "advance",
    "cap_output",
    "cap_stderr",
    "cap_stdout",
    "classify_exhaustion",
    "compute_turn_trust",
    "compute_verdict",
    "consume_plan_revision",
    "consume_tokens",
    "consume_tool_call",
    "defang",
    "default_budget",
    "ingest_untrusted_block",
    "missing_measurements",
    "new_turn",
    "observe_wall_clock",
    "reduced_class",
    "replay_block",
    "require_coherent_pair",
    "settle_tool_call",
    "step",
    "wrap_untrusted",
]
