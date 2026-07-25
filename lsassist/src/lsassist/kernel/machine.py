"""The §4.2 transition table as data + PURE guards (SPEC §4.1-4.2, I15, I12, AC-07).

A transition is a ``(source, event)`` lookup into :data:`TRANSITION_TABLE`
whose row guard — a pure predicate over an immutable :class:`GuardInput` — must
hold. :func:`step` returns the FIRST matching row's :class:`Transition`, or
``None``. There is NO permissive default anywhere: an unknown ``(state, event)``
pair, a falsified guard, or a missing collaborator all yield ``None`` (the
machine stalls) — never a jump forward. Rows sharing an event are ordered
fail-closed-FIRST: the three BLOCKED causes precede EXECUTE/APPROVAL on
``POLICY_CLASSIFIED``, and REPORT precedes PLAN on ``POSTCONDITIONS_CHECKED``,
so the safe outcome wins on ORDER and not only on guard disjointness. The
terminating-vs-advancing guards are mutually exclusive; the three BLOCKED
causes may overlap with each other, and are ordered so the reported cause is
the one §4.2 names first (see :data:`TRANSITION_TABLE`).

THE EXECUTE GATE (I15 / AC-07). Exactly two rows in the table have
``target is State.EXECUTE``:

1. ``POLICY_CHECK --POLICY_CLASSIFIED--> EXECUTE`` guarded by
   :func:`_g_auto_class` — the §4.6-REDUCED class must be in
   :data:`AUTO_CLASSES` (``AUTO_READ`` | ``AUTO_SCOPED_WRITE``) AND budget must
   remain AND the provider must be available AND the §4.7 replay verdict must
   be :data:`REPLAY_ALLOWED`;
2. ``APPROVAL --APPROVAL_TOKEN_PRESENTED--> EXECUTE`` guarded by
   :func:`_g_valid_token` — the §7.4 token verdict must be exactly
   :data:`~lsassist.policy.token.TokenVerdict.VALID` (HMAC match + TTL + uses
   left + re-canonicalization match, all decided inside ``TokenService.verify``)
   AND consent must be affirmative and still live AND the token's minted class
   must be at least as strict as the reduced class AND the §4.7 replay verdict
   must be :data:`REPLAY_ALLOWED`.

Every gate the SPEC names is now STRUCTURAL — policy, budget, provider, the
§4.6 reduction, the approval strength and the §4.7 replay guard each arrive
through an injected surface that must positively authorize, never through an
assumption that some caller checked.

Because ``step`` can only ever return a row that is IN the table, and the table
is checked AT IMPORT by :func:`_validate_execute_gate` (raising
:class:`MachineTableError` if any third EXECUTE-targeting row ever appears),
every other route into EXECUTE is structurally impossible — not merely untested.
``APPROVAL`` itself is reachable only from ``POLICY_CHECK``, so neither entry
edge bypasses classification (I15 "no implicit gate crossing").

§4.6 STEP 2 IS ENFORCED HERE TOO, not only in policy. :func:`reduced_class`
re-applies the untrusted-turn capability reduction over the classifier's answer,
because a ``PolicyView`` adapter's ``PolicyContext`` is bound at CONSTRUCTION
while a turn becomes untrusted MID-LOOP (the moment a tool's own output is
ingested). See its docstring.

PROTOCOL INJECTION (§2.2 purity). This module does ZERO I/O: no filesystem, no
subprocess, no network, no environment, no clock, no randomness. Everything the
guards consult arrives through the injected Protocols :class:`RegistryView`,
:class:`PolicyView`, :class:`BudgetView`, :class:`ProviderView` and
:class:`VerdictView`, or as plain data on :class:`GuardInput` — including
elapsed approval time (``approval_elapsed_s``), because reading a clock here
would break guard purity and determinism. It deliberately does NOT import
``kernel.budgets`` / ``kernel.verdict`` / ``kernel.idempotency`` /
``kernel.untrusted``: the machine depends on those SURFACES, not those modules.
``contracts`` and the finished, pure ``policy`` package are imported directly
(§2.2 allows ``kernel → policy, contracts``); ``providers`` is forbidden and is
reached only through :class:`ProviderView`.

FAIL-CLOSED ASYMMETRY. A missing collaborator is never read as permission —
every EXECUTE guard requires its evidence to be positively present. See
:class:`GuardInput` for the field-level polarity rule this rests on.

A MISSING COLLABORATOR IS NOT A CAUSE (N4). Fail-closed must not mean
fail-blaming: an absent ``RegistryView`` is a wiring bug, not
``malformed_model_output``; an uncounted GROUND is not ``grounding_failed``; an
absent ``PolicyView`` is not ``policy_blocked``. A wrong cause in the audit
journal is worse than no transition, because it is plausible and permanent. So
the failure rows fire ONLY on a MEASURED negative — a real over-cap number, a
registry that answered, a class that was actually computed — and an unwired
bundle STALLS instead. :func:`missing_measurements` makes that stall
distinguishable from a wait, so the runner can say "kernel misconfigured".

DEAD ENDS. Given a WIRED bundle, ``GROUND``, ``PLAN`` and ``POLICY_CHECK`` are
total, and ``VERIFY`` is total unconditionally — a checked task always gets a
verdict. ``VERIFY → REPORT`` is the one REPORT row with no ``exit_reason`` tag:
it fires for four different reasons and the runner derives which from the
budget/loop state it already holds, rather than the table inventing one.

RUNNER OBLIGATIONS (T5.12). The kernel is pure, so the accounting the SPEC
mandates is performed by the session engine, not here — but the transition
table NAMES each obligation as a side-effect tag so it is greppable and cannot
be silently nobody's job. On firing a row, the runner MUST discharge its tags:

- ``budget:consume_plan_revision`` + ``idempotency:begin`` (PLAN →
  POLICY_CHECK) — §4.3 revision cap, and the §4.7 ledger call. ORDERING (N6):
  ``begin`` is tagged HERE, one row BEFORE the gate, because it is what
  PRODUCES the replay verdict that :data:`GuardInput.replay` carries and both
  EXECUTE guards require. Tagging it on the EXECUTE rows would place the
  obligation after the machine had already committed to executing — the ledger
  must be consulted while refusing is still possible.
- ``budget:consume_tool_call`` (both EXECUTE rows) — §4.3 call cap.
- ``budget:settle_tool_call`` + ``idempotency:complete`` (EXECUTE → OBSERVE) —
  the §4.3 refund rule settles here, and the §4.7 ledger records completion.
- ``budget:cap_output`` (OBSERVE → VERIFY) — §4.3 stdout/stderr caps with the
  full-output digest.
- ``compute:verdict`` / ``exit_reason:*`` — §4.4/§4.5, on every row that ends a
  turn, including the absorbing BLOCKED/CANCELLED rows (N2).
- ``audit:*`` / ``prompt:*`` / ``enforce:*`` / ``journal:*`` — as named.

RESIDUAL, NOT FIXED (§4.7 human review). ``PARTIAL_EXECUTION`` — a crash
mid-exec — closes both EXECUTE edges here, which is correct but INCOMPLETE:
§4.7 requires escalating it to a human review prompt ("unknown side effects,
inspect checkpoint diff"), and §4.1 defines no state for that, just as §4.4
defines no exit reason for a replay stop. Routing it to BLOCKED would force a
fabricated cause (the N4 mistake) and adding a state would invent §4.1 wire
values, so NEITHER is done. Instead the turn stalls fail-closed and
:func:`replay_block` names the condition, so the runner can escalate rather
than retry forever. A §4.1/§4.4 amendment is required to close this properly.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Final, Protocol

from lsassist.contracts.enums import PermissionClass, VerdictStatus
from lsassist.contracts.intent import IntentRecord
from lsassist.contracts.tool_request import ToolRequest
from lsassist.kernel.states import Event, ExecOutcome, State
from lsassist.policy.classes import rank
from lsassist.policy.token import TokenVerdict


class MachineTableError(RuntimeError):
    """The transition table violates a structural invariant (I15 EXECUTE gate).

    Raised at IMPORT time — a mis-edited table fails the process, never a
    request.
    """


# --- injected collaborator surfaces (Protocols — no sibling imports) ---------


class RegistryView(Protocol):
    """The tool registry surface the ``PLAN → POLICY_CHECK`` guard needs (§6.2)."""

    def knows(self, tool: str) -> bool:
        """Whether ``tool`` names a registered manifest."""
        ...

    def args_valid(self, request: ToolRequest) -> bool:
        """Whether ``request.args`` validates against that manifest's input schema."""
        ...


class PolicyView(Protocol):
    """The §7.2 classification surface, with context/manifest/stores pre-bound.

    Production wiring is a thin adapter over
    :func:`lsassist.policy.rules.classify`; the kernel holds no ``PolicyStores``
    of its own, keeping this module free of policy configuration.
    """

    def classify(self, request: ToolRequest) -> PermissionClass:
        """The single deterministic permission class for ``request`` (§7.2)."""
        ...


class BudgetView(Protocol):
    """The §4.3 budget surface: which budget (if any) is exhausted."""

    def exhausted_kind(self) -> str | None:
        """The first exhausted §4.4 budget kind (``tool_calls`` | ``tokens`` |
        ``time`` | ``cost``), or ``None`` when every budget still has room."""
        ...


class ProviderView(Protocol):
    """Provider availability (§4.2 ``POLICY_CHECK → BLOCKED`` disjunct)."""

    def available(self) -> bool:
        """Whether a usable provider is currently available (§5.4)."""
        ...


class ReplayView(Protocol):
    """The §4.7 replay guard's answer for the action about to be executed.

    Typed as the WIRE VALUE (a ``str``), not as ``kernel.idempotency``'s enum:
    the machine must not import a sibling. ``ReplayVerdict`` is a ``StrEnum``,
    so its members satisfy this Protocol directly with no adapter, while the
    kernel keeps its Protocol-only decoupling. :data:`REPLAY_ALLOWED` is the one
    value that authorizes execution; every other value, and ``None``, refuses.
    """

    def replay_verdict(self) -> str | None:
        """The §4.7 verdict for the CURRENT action, or ``None`` if not consulted."""
        ...


class VerdictView(Protocol):
    """The computed verdict surface the ``REPORT → RECEIVE`` guard needs (§4.5)."""

    def emitted(self) -> bool:
        """Whether a verdict record has actually been emitted."""
        ...

    def status(self) -> VerdictStatus | None:
        """The §4.5 verdict status, or ``None`` when not yet computed."""
        ...

    def evidence_count(self) -> int:
        """How many deterministic evidence refs the verdict carries (I12)."""
        ...

    def sub_goal_verified_count(self) -> int:
        """How many SUB-GOALS the verdict marks ``VERIFIED`` (I12, §4.5 PARTIAL).

        The top-level status is not the only place a VERIFIED claim is made: a
        ``PARTIAL`` verdict asserts VERIFIED per sub-goal, and the contract's
        PARTIAL branch does not require evidence. The REPORT guard uses this to
        refuse closing a turn that claims a verified sub-goal with no evidence
        behind it.
        """
        ...


# --- the guard argument bundle ------------------------------------------------


#: §4.2 ``GROUND → PLAN``: default context-read cap.
DEFAULT_GROUND_READ_CAP: Final[int] = 40
#: §4.2 ``APPROVAL → CANCELLED``: default approval-prompt timeout, seconds.
DEFAULT_APPROVAL_TIMEOUT_S: Final[int] = 120
#: §4.2 ``CLASSIFY → GROUND``: the admissible task types.
TASK_TYPES: Final[frozenset[str]] = frozenset(
    {"coding", "tutor", "sysinfo", "memory", "skill", "meta"}
)
#: §7.1 classes that authorize execution WITHOUT a human gate (the I15 gate set).
AUTO_CLASSES: Final[frozenset[PermissionClass]] = frozenset(
    {PermissionClass.AUTO_READ, PermissionClass.AUTO_SCOPED_WRITE}
)
#: §7.1 classes that require consent — they route to APPROVAL, never to EXECUTE.
CONFIRM_CLASSES: Final[frozenset[PermissionClass]] = frozenset(
    {PermissionClass.CONFIRM_ONCE, PermissionClass.CONFIRM_EXACT}
)
#: The ONE §4.7 replay verdict that authorizes execution. Kept as a literal
#: rather than importing ``kernel.idempotency.ReplayVerdict.ALLOWED`` (sibling
#: decoupling); the unit suite pins this string against that enum so the two
#: can never drift apart silently.
REPLAY_ALLOWED: Final[str] = "ALLOWED"


@dataclass(frozen=True, slots=True)
class GuardInput:
    """Everything the §4.2 guards may read — the SPEC's
    ``(request, registry, policy, budget)`` tuple plus the per-row facts.

    Frozen: a guard cannot mutate its argument, so evaluating the table has no
    observable effect.

    POLARITY RULE (the property the omission matrix in
    ``tests/unit/kernel/test_machine.py`` enforces field by field): every
    OBSERVATION field defaults to the value that CANNOT open a gate, so omitting
    it never produces a transition that its adversarial value would refuse.
    Concretely, that forces AFFIRMATIVE polarity on facts a runner must go and
    measure:

    - ``untrusted_turn`` defaults to ``True`` — a turn is assumed untrusted
      until the caller states otherwise (§4.6 step 2);
    - ``loop_clear`` / ``approval_granted`` default to ``False`` — a loop
      detector that was never wired, or an approval that was never granted, is
      not evidence of safety;
    - ``ground_reads`` / ``approval_elapsed_s`` default to ``None`` meaning NO
      READING TAKEN, which is read as "over cap" / "timed out" rather than as
      zero. A forgotten counter must not read as a fresh budget.

    The only two fields exempt are ``ground_read_cap`` and
    ``approval_timeout_s``: those are §4.2 LIMITS, not observations. Their
    defaults are the SPEC values (40 reads, 120 s) and any change to them
    LOOSENS the guard, so a caller can only widen them deliberately.
    """

    # SPEC §4.2 guard tuple.
    request: ToolRequest | None = None
    registry: RegistryView | None = None
    policy: PolicyView | None = None
    budget: BudgetView | None = None
    # Additional injected surfaces.
    provider: ProviderView | None = None
    verdict: VerdictView | None = None
    #: §4.7 replay guard. Absent ⇒ never consulted ⇒ both EXECUTE edges refuse.
    replay: ReplayView | None = None
    # Per-row facts (pure data; no clock is ever read here).
    intent: IntentRecord | None = None
    task_type: str | None = None
    #: §4.6 step 2. The MACHINE's own view of turn trust, refreshed EVERY round
    #: from the current ``kernel.untrusted.TurnTrust`` — see ``reduced_class``.
    untrusted_turn: bool = True
    #: ``None`` = no reading taken (fail-closed: treated as over cap).
    ground_reads: int | None = None
    ground_read_cap: int = DEFAULT_GROUND_READ_CAP
    token_verdict: TokenVerdict | None = None
    #: The §7.1 class the presented token was MINTED at. ``None`` ⇒ unknown ⇒
    #: refuse: the machine cannot check the gate is strong enough (N3).
    token_class: PermissionClass | None = None
    #: The user AFFIRMATIVELY approved. Absence is not consent.
    approval_granted: bool = False
    approval_denied: bool = False
    #: ``None`` = no reading taken (fail-closed: treated as timed out).
    approval_elapsed_s: int | None = None
    approval_timeout_s: int = DEFAULT_APPROVAL_TIMEOUT_S
    exec_outcome: ExecOutcome | None = None
    output_captured: bool = False
    digests_computed: bool = False
    postconditions_ok: bool = False
    retryable_failure: bool = False
    unrecoverable_failure: bool = False
    plan_complete: bool = False
    #: The loop detector AFFIRMATIVELY reports no loop (§4.3). ``False`` — the
    #: default, and the value a tripped detector produces — routes VERIFY to
    #: REPORT, so a detected loop always reaches the §4.3 mandated halt.
    loop_clear: bool = False


Guard = Callable[[GuardInput], bool]


# --- shared fail-closed helpers ----------------------------------------------


def _budget_remains(inp: GuardInput) -> bool:
    """True only when a budget view is PRESENT and nothing is exhausted (§4.3)."""
    return inp.budget is not None and inp.budget.exhausted_kind() is None


def _provider_ok(inp: GuardInput) -> bool:
    """True only when a provider view is PRESENT and reports availability (§5.4)."""
    return inp.provider is not None and inp.provider.available()


def _classified(inp: GuardInput) -> PermissionClass | None:
    """The §7.2 class for the pending request, or ``None`` when undecidable.

    ``None`` (no policy view, or no request to classify) is NOT a class and
    never satisfies the AUTO gate — it routes to BLOCKED.
    """
    if inp.policy is None or inp.request is None:
        return None
    return inp.policy.classify(inp.request)


def reduced_class(inp: GuardInput) -> PermissionClass | None:
    """The §7.2 class AFTER the machine's own §4.6 step-2 capability reduction.

    Defense in depth, deliberately DUPLICATING policy rule R3: the machine does
    not assume the ``PolicyView`` adapter's ``PolicyContext`` is FRESH. An
    adapter is built once and reused, but ``untrusted_turn`` becomes true
    MID-TURN (the moment a tool's own output is ingested), so a request formed
    in a later inner-loop round would otherwise be classified against a stale,
    still-trusted context and keep its AUTO class — exactly the prompt-injection
    case §4.6 exists for. Applying the reduction here means the machine reaches
    the same answer whether or not the caller rebuilt the adapter.

    Monotone, mirroring R3: a pure read (``AUTO_READ``) is untouched, ``DENY``
    stays ``DENY``, and everything else is RAISED to ``CONFIRM_EXACT`` — the
    class is never lowered.

    PUBLIC (N3): this is the class the machine actually gated on, and it is also
    published on every :class:`Transition`. The layer that mints the
    ``ApprovalRecord`` MUST use it rather than re-asking the possibly-stale
    ``PolicyView`` — otherwise it would mint a CONFIRM_ONCE, multi-use token for
    an injected-turn action the machine reduced to CONFIRM_EXACT.
    """
    cls = _classified(inp)
    if cls is None or cls is PermissionClass.DENY_ALWAYS:
        return cls
    if inp.untrusted_turn and cls is not PermissionClass.AUTO_READ:
        return PermissionClass.CONFIRM_EXACT
    return cls


def _approval_timed_out(inp: GuardInput) -> bool:
    """True when the §4.2 prompt timeout elapsed — or was never measured."""
    return inp.approval_elapsed_s is None or inp.approval_elapsed_s >= inp.approval_timeout_s


def _approval_void(inp: GuardInput) -> bool:
    """True when the approval was denied or the §4.2 prompt timeout elapsed."""
    return inp.approval_denied or _approval_timed_out(inp)


# --- the §4.2 guards (pure predicates) ---------------------------------------


def _g_intent_captured(inp: GuardInput) -> bool:
    """RECEIVE → CLASSIFY: non-empty intent text in an immutable record."""
    return inp.intent is not None and inp.intent.text.strip() != ""


def _g_task_type_resolved(inp: GuardInput) -> bool:
    """CLASSIFY → GROUND: ``task_type`` ∈ the §4.2 set."""
    return inp.task_type in TASK_TYPES


def _g_context_gathered(inp: GuardInput) -> bool:
    """GROUND → PLAN: a read count was TAKEN and is within ``ground_read_cap``."""
    return inp.ground_reads is not None and 0 <= inp.ground_reads <= inp.ground_read_cap


def _g_grounding_failed(inp: GuardInput) -> bool:
    """GROUND → REPORT: a read count was TAKEN and OVERRAN the cap (§4.4
    ``grounding_failed``).

    N4: this is NOT the negation of :func:`_g_context_gathered`. A ``None``
    reading means the runner never counted, which is a WIRING bug — reporting
    it as ``grounding_failed`` would put a plausible, wrong cause in the audit
    journal. An unmeasured GROUND therefore STALLS (see
    :func:`missing_measurements`); only a real over-cap number reports.
    """
    return inp.ground_reads is not None and not (0 <= inp.ground_reads <= inp.ground_read_cap)


def _g_request_well_formed(inp: GuardInput) -> bool:
    """PLAN → POLICY_CHECK: schema-valid ``ToolRequest`` vs the registry."""
    if inp.request is None or inp.registry is None:
        return False
    return inp.registry.knows(inp.request.tool) and inp.registry.args_valid(inp.request)


def _g_planning_failed(inp: GuardInput) -> bool:
    """PLAN → REPORT: the REGISTRY ANSWERED and rejected the model's request
    (§4.4 ``malformed_model_output``).

    N4: an absent ``RegistryView`` (nothing implements one before T3.01) or an
    absent request must NOT be blamed on the model — that would convert every
    turn of a mis-wired runner into a verdict accusing the model of malformed
    output. Those cases STALL; only a registry that actually returned
    ``knows()``/``args_valid()`` False reports.

    SEMANTICS the runner must respect: the §4.3 refund loop (a schema-invalid
    request costs no tool call, so the model may be re-prompted) happens BEFORE
    ``PLAN_PROPOSED`` is emitted — the runner re-prompts and only emits the
    event for an attempt it is committing. This row is the terminal backstop so
    a persistently malformed model ends with a verdict instead of parking.
    """
    if inp.request is None or inp.registry is None:
        return False
    return not _g_request_well_formed(inp)


def _g_denied(inp: GuardInput) -> bool:
    """POLICY_CHECK → BLOCKED, cause 1 (§4.4 ``policy_blocked``): the reduced
    class is DENY_ALWAYS. An UNDECIDABLE class (no policy view / no request) is
    NOT a denial — it stalls (N4), because blaming policy for a missing adapter
    is a false attribution."""
    return reduced_class(inp) is PermissionClass.DENY_ALWAYS


def _g_budget_exhausted(inp: GuardInput) -> bool:
    """POLICY_CHECK → BLOCKED, cause 2 (§4.4 ``budget_exhausted``): a budget
    view is PRESENT and reports something exhausted."""
    return inp.budget is not None and inp.budget.exhausted_kind() is not None


def _g_provider_down(inp: GuardInput) -> bool:
    """POLICY_CHECK → BLOCKED, cause 3 (§4.4 ``provider_unavailable``): a
    provider view is PRESENT and reports unavailable."""
    return inp.provider is not None and not inp.provider.available()


def _g_replay_allowed(inp: GuardInput) -> bool:
    """§4.7 replay guard, required by BOTH EXECUTE edges.

    Fail-closed on absence: no ``ReplayView`` means the ledger was never
    consulted, which can never authorize execution. ``ALREADY_EXECUTED`` and
    ``PARTIAL_EXECUTION`` both refuse — §4.7 forbids re-executing a completed
    ``seq``, and a partial execution needs human review, not a silent retry.
    """
    return inp.replay is not None and inp.replay.replay_verdict() == REPLAY_ALLOWED


def _g_auto_class(inp: GuardInput) -> bool:
    """POLICY_CHECK → EXECUTE (I15 gate edge 1): AUTO class, budget, provider,
    and a §4.7 ALLOWED replay verdict.

    Reads the §4.6-REDUCED class, so on an untrusted turn only a pure
    ``AUTO_READ`` survives here; a scoped WRITE is raised out of the AUTO band
    and routed to APPROVAL by :func:`_g_needs_consent` instead.
    """
    return (
        reduced_class(inp) in AUTO_CLASSES
        and _budget_remains(inp)
        and _provider_ok(inp)
        and _g_replay_allowed(inp)
    )


def _g_needs_consent(inp: GuardInput) -> bool:
    """POLICY_CHECK → APPROVAL: class ∈ {CONFIRM_ONCE, CONFIRM_EXACT}."""
    return reduced_class(inp) in CONFIRM_CLASSES and _budget_remains(inp) and _provider_ok(inp)


def _g_valid_token(inp: GuardInput) -> bool:
    """APPROVAL → EXECUTE (I15 gate edge 2). Four independent conditions:

    1. ``TokenVerdict.VALID`` — every other verdict (HMAC mismatch, unknown,
       expired, exhausted) and its absence are refusals;
    2. AFFIRMATIVE consent that is still live (``approval_granted``, not denied,
       not past the §4.2 prompt timeout) — a bundle that merely forgot the deny
       flag or the elapsed reading cannot reopen this edge;
    3. N3 — the token must have been minted at a class AT LEAST AS STRICT as the
       machine's §4.6-reduced class. Without this, an injected turn whose stale
       ``PolicyView`` said CONFIRM_ONCE would be gated by a multi-use, long-TTL
       token where §4.6 demands CONFIRM_EXACT. ``token_class is None`` (unknown)
       refuses, and an undecidable reduced class refuses too — the machine will
       not wave through a gate whose required strength it cannot establish;
    4. §4.7 — an ALLOWED replay verdict, exactly as on the AUTO edge.
    """
    if inp.token_verdict is not TokenVerdict.VALID:
        return False
    if not inp.approval_granted or _approval_void(inp):
        return False
    required = reduced_class(inp)
    if required is None or inp.token_class is None:
        return False
    if rank(inp.token_class) < rank(required):
        return False
    return _g_replay_allowed(inp)


def _g_approval_denied(inp: GuardInput) -> bool:
    """APPROVAL → CANCELLED, cause 1 (§4.4 ``approval_denied``): the user said no."""
    return inp.approval_denied


def _g_approval_timed_out(inp: GuardInput) -> bool:
    """APPROVAL → CANCELLED, cause 2 (§4.4 ``approval_timeout``): the prompt
    timed out (or no elapsed reading was taken) and the user did not deny.
    Disjoint from :func:`_g_approval_denied` so the attributed cause is exact."""
    return not inp.approval_denied and _approval_timed_out(inp)


def _g_process_terminated(inp: GuardInput) -> bool:
    """EXECUTE → OBSERVE: the child exited, timed out, or was killed."""
    return inp.exec_outcome is not None


def _g_output_captured(inp: GuardInput) -> bool:
    """OBSERVE → VERIFY: output captured AND digests computed."""
    return inp.output_captured and inp.digests_computed


def _g_continue_plan(inp: GuardInput) -> bool:
    """VERIFY → PLAN: postconditions ok OR retryable failure; budget remains;
    the loop detector affirmatively clear; the plan neither complete nor
    unrecoverably failed.

    This is the ONLY affirmative way out of VERIFY that keeps the task running;
    :func:`_g_report_due` is its exact complement.
    """
    return (
        (inp.postconditions_ok or inp.retryable_failure)
        and _budget_remains(inp)
        and inp.loop_clear
        and not inp.plan_complete
        and not inp.unrecoverable_failure
    )


def _g_report_due(inp: GuardInput) -> bool:
    """VERIFY → REPORT: everything that is not an affirmative continuation.

    Defined as the EXACT COMPLEMENT of :func:`_g_continue_plan`, which makes
    VERIFY TOTAL on its event — exactly one of the two rows always fires, so a
    checked task can never be stranded without a verdict. The complement
    expands to §4.2's own disjuncts plus the two the SPEC leaves implicit:

    - ``plan_complete`` — §4.2 "plan complete";
    - budget exhausted (or no budget view at all) — §4.2 "budget exhausted";
    - ``unrecoverable_failure`` — §4.2 "unrecoverable failure";
    - NOT ``loop_clear`` — §4.3's "3x identical action_hash -> halt -> REPORT
      with ``loop_detected`` evidence". Without this, a tripped detector
      satisfied neither row and ``ExitReason.LOOP_DETECTED`` was structurally
      unreachable;
    - postconditions failed AND not retryable — a non-retryable check failure
      is a reason to report, not a reason to sit still.
    """
    return not _g_continue_plan(inp)


def _g_verdict_emitted(inp: GuardInput) -> bool:
    """REPORT → RECEIVE: a verdict was emitted, and I12 holds at BOTH levels.

    I12 defense in depth at the gate, independent of the (T2.09) verdict
    computation that is supposed to have downgraded already:

    1. a top-level ``VERIFIED`` with zero evidence refs never closes the turn;
    2. NOR does any verdict that claims a VERIFIED SUB-GOAL with zero evidence
       refs. The contract's ``PARTIAL`` branch requires a sub-goal map with at
       least one VERIFIED entry but requires NO evidence, so without this second
       check a turn could close asserting a verified sub-goal backed by nothing.
    """
    verdict = inp.verdict
    if verdict is None or not verdict.emitted():
        return False
    if verdict.evidence_count() >= 1:
        return True
    return not (
        verdict.status() is VerdictStatus.VERIFIED or verdict.sub_goal_verified_count() > 0
    )


# --- the table ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TransitionRule:
    """One §4.2 row: ``(source, event) --guard--> target`` + side-effect tags."""

    source: State
    event: Event
    target: State
    guard: Guard
    side_effect: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Transition:
    """A FIRED transition — the value :func:`step` returns. Carries only tags
    and the gating class; the machine performs no side effects itself.

    ``reduced_class`` (N3) publishes the §4.6-REDUCED class the machine actually
    gated on. The approval-minting layer MUST bind its ``ApprovalRecord`` to
    THIS value, not to a fresh ``PolicyView.classify`` call, because that view's
    context may be stale — that is the whole reason the reduction exists.
    ``None`` when the class was undecidable (no policy view / no request).
    """

    source: State
    event: Event
    target: State
    side_effect: tuple[str, ...] = ()
    reduced_class: PermissionClass | None = None


def _absorbing(reason: str, *lead: str) -> tuple[str, ...]:
    """Tags for a row into an ABSORBING terminal state (N2).

    ``BLOCKED``/``CANCELLED`` have no outgoing row, so unlike a route into
    ``REPORT`` — where ``REPORT → RECEIVE`` still emits the verdict — nothing
    follows to discharge §4.4/§4.5. These rows must therefore carry the WHOLE
    obligation themselves: compute it, name its exit reason, audit it, and
    checkpoint the journal.
    """
    return (
        *lead,
        "compute:verdict",
        f"exit_reason:{reason}",
        "audit:verdict",
        "journal:checkpoint",
    )


#: SPEC §4.2, in table order. Within a shared event the fail-closed targets are
#: listed FIRST (the three BLOCKED causes before EXECUTE/APPROVAL; REPORT before
#: PLAN) so ordering can never turn a stall into an advance.
#:
#: ONE ROW PER CAUSE (N2): §4.2 draws single ``POLICY_CHECK → BLOCKED`` and
#: ``APPROVAL → CANCELLED`` edges that each fire for several different reasons.
#: They are split here so every terminal row names ONE exact §4.4 exit reason
#: instead of making the runner re-derive which disjunct fired. The three
#: BLOCKED causes may overlap (a DENY request under an exhausted budget); they
#: are ordered by SPEC §4.2's own attribution order — DENY, then budget, then
#: provider — and the first match is the reported cause.
TRANSITION_TABLE: Final[tuple[TransitionRule, ...]] = (
    TransitionRule(
        State.RECEIVE, Event.INTENT_CAPTURED, State.CLASSIFY, _g_intent_captured, ("audit:intent",)
    ),
    TransitionRule(State.CLASSIFY, Event.TASK_TYPE_RESOLVED, State.GROUND, _g_task_type_resolved),
    TransitionRule(
        State.GROUND,
        Event.CONTEXT_GATHERED,
        State.REPORT,
        _g_grounding_failed,
        ("compute:verdict", "exit_reason:grounding_failed"),
    ),
    TransitionRule(
        State.GROUND, Event.CONTEXT_GATHERED, State.PLAN, _g_context_gathered, ("audit:ground",)
    ),
    TransitionRule(
        State.PLAN,
        Event.PLAN_PROPOSED,
        State.REPORT,
        _g_planning_failed,
        ("compute:verdict", "exit_reason:malformed_model_output"),
    ),
    TransitionRule(
        State.PLAN,
        Event.PLAN_PROPOSED,
        State.POLICY_CHECK,
        _g_request_well_formed,
        ("audit:plan_revision", "budget:consume_plan_revision", "idempotency:begin"),
    ),
    TransitionRule(
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        State.BLOCKED,
        _g_denied,
        _absorbing("policy_blocked", "audit:policy_decision(deny)"),
    ),
    TransitionRule(
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        State.BLOCKED,
        _g_budget_exhausted,
        _absorbing("budget_exhausted", "audit:policy_decision(deny)"),
    ),
    TransitionRule(
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        State.BLOCKED,
        _g_provider_down,
        _absorbing("provider_unavailable", "audit:policy_decision(deny)"),
    ),
    TransitionRule(
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        State.EXECUTE,
        _g_auto_class,
        ("audit:policy_decision", "budget:consume_tool_call"),
    ),
    TransitionRule(
        State.POLICY_CHECK,
        Event.POLICY_CLASSIFIED,
        State.APPROVAL,
        _g_needs_consent,
        ("prompt:approval_render",),
    ),
    TransitionRule(
        State.APPROVAL,
        Event.APPROVAL_TOKEN_PRESENTED,
        State.EXECUTE,
        _g_valid_token,
        ("audit:approval", "budget:consume_tool_call"),
    ),
    TransitionRule(
        State.APPROVAL,
        Event.APPROVAL_REFUSED,
        State.CANCELLED,
        _g_approval_denied,
        _absorbing("approval_denied", "audit:approval(denied)"),
    ),
    TransitionRule(
        State.APPROVAL,
        Event.APPROVAL_REFUSED,
        State.CANCELLED,
        _g_approval_timed_out,
        _absorbing("approval_timeout", "audit:approval(denied)"),
    ),
    TransitionRule(
        State.EXECUTE,
        Event.PROCESS_TERMINATED,
        State.OBSERVE,
        _g_process_terminated,
        (
            "enforce:rlimit_timeout",
            "budget:settle_tool_call",
            "idempotency:complete",
        ),
    ),
    TransitionRule(
        State.OBSERVE,
        Event.OUTPUT_CAPTURED,
        State.VERIFY,
        _g_output_captured,
        ("audit:tool_result(redacted)", "budget:cap_output"),
    ),
    TransitionRule(
        State.VERIFY,
        Event.POSTCONDITIONS_CHECKED,
        State.REPORT,
        _g_report_due,
        ("compute:verdict",),
    ),
    TransitionRule(State.VERIFY, Event.POSTCONDITIONS_CHECKED, State.PLAN, _g_continue_plan),
    TransitionRule(
        State.REPORT,
        Event.VERDICT_EMITTED,
        State.RECEIVE,
        _g_verdict_emitted,
        ("audit:verdict", "journal:checkpoint"),
    ),
)

#: The ONLY rows whose target is EXECUTE — the two I15 gate edges. Derived from
#: the table (never hand-listed), then structurally validated at import.
EXECUTE_ENTRY_RULES: Final[tuple[TransitionRule, ...]] = tuple(
    rule for rule in TRANSITION_TABLE if rule.target is State.EXECUTE
)

_EXPECTED_EXECUTE_EDGES: Final[frozenset[tuple[State, Event, Guard]]] = frozenset(
    {
        (State.POLICY_CHECK, Event.POLICY_CLASSIFIED, _g_auto_class),
        (State.APPROVAL, Event.APPROVAL_TOKEN_PRESENTED, _g_valid_token),
    }
)

#: Rows into an ABSORBING terminal state; each must carry the whole §4.4/§4.5
#: obligation because nothing follows them (N2). Checked at import.
_ABSORBING_TARGETS: Final[frozenset[State]] = frozenset({State.BLOCKED, State.CANCELLED})


def _validate_execute_gate() -> None:
    """Import-time I15 check: EXECUTE has exactly the two §4.2 entry edges.

    Any added, removed, retargeted or RE-GUARDED EXECUTE row fails the import —
    the gate cannot be widened by a table edit that slips through review.
    """
    actual = frozenset((r.source, r.event, r.guard) for r in EXECUTE_ENTRY_RULES)
    if len(EXECUTE_ENTRY_RULES) != 2 or actual != _EXPECTED_EXECUTE_EDGES:
        raise MachineTableError(
            "I15 violation: EXECUTE must be entered only by POLICY_CHECK/AUTO class "
            f"or APPROVAL/VALID token; table declares {sorted(map(str, actual))}"
        )
    if any(rule.source in _ABSORBING_TARGETS for rule in TRANSITION_TABLE):
        raise MachineTableError("terminal pseudo-states must be absorbing (no outgoing rows)")
    # N2: a row into an absorbing state is the LAST thing that happens to that
    # turn — if it does not carry the verdict obligation, nothing ever will.
    for rule in TRANSITION_TABLE:
        if rule.target in _ABSORBING_TARGETS and "compute:verdict" not in rule.side_effect:
            raise MachineTableError(
                f"{rule.source}->{rule.target} terminates without a compute:verdict obligation"
            )


_validate_execute_gate()


# --- evaluation ---------------------------------------------------------------


def step(state: State, event: Event, guard_input: GuardInput) -> Transition | None:
    """Evaluate the §4.2 table for ``(state, event)``. PURE — no I/O, no clock.

    Returns the FIRST row whose source/event match and whose guard holds, else
    ``None``. ``None`` means "no transition": an unknown pair, a falsified
    guard, a terminal state, or a missing collaborator — all fail-closed, all
    leaving the caller exactly where it was.
    """
    for rule in TRANSITION_TABLE:
        if rule.source is state and rule.event is event and rule.guard(guard_input):
            return Transition(
                source=rule.source,
                event=rule.event,
                target=rule.target,
                side_effect=rule.side_effect,
                reduced_class=reduced_class(guard_input),
            )
    return None


#: What each state's rows must be able to READ before they can decide. Used by
#: :func:`missing_measurements` to tell a WIRING stall from a WAIT (N4).
_REQUIRED_INPUTS: Final[dict[State, tuple[str, ...]]] = {
    State.GROUND: ("ground_reads",),
    State.PLAN: ("request", "registry"),
    State.POLICY_CHECK: ("request", "policy", "budget", "provider", "replay"),
    State.APPROVAL: ("request", "policy", "replay"),
    State.VERIFY: ("budget",),
    State.REPORT: ("verdict",),
}


def missing_measurements(state: State, guard_input: GuardInput) -> tuple[str, ...]:
    """Which inputs ``state``'s rows need but the bundle does not carry. PURE.

    This makes a fail-closed stall DISTINGUISHABLE (N4). A ``step`` that returns
    ``None`` means one of two very different things:

    - this returns a NON-EMPTY tuple → a collaborator or reading is absent: a
      WIRING bug. The runner should surface "kernel misconfigured: <names>",
      NOT a verdict blaming the model or policy — which is exactly why the
      GROUND/PLAN failure rows refuse to fire on an absent input;
    - this returns an EMPTY tuple → every input was present and the guards
      genuinely did not hold: a WAIT (the child has not exited, the user has not
      answered). The runner should call again when the fact changes.
    """
    return tuple(
        name for name in _REQUIRED_INPUTS.get(state, ()) if getattr(guard_input, name) is None
    )


def replay_block(guard_input: GuardInput) -> str | None:
    """The §4.7 verdict currently holding the EXECUTE edges shut, else ``None``.

    PURE. The third kind of stall (see :func:`missing_measurements`): the ledger
    WAS consulted and said ``ALREADY_EXECUTED`` or ``PARTIAL_EXECUTION``. Neither
    has a §4.4 exit reason or a §4.1 state, so the machine cannot route them
    anywhere without inventing wire values — but a silent stall would make the
    runner retry forever. Naming the condition lets it do what §4.7 requires:
    restore from the captured result, or escalate to human review.
    """
    if guard_input.replay is None:
        return None
    seen = guard_input.replay.replay_verdict()
    return None if seen is None or seen == REPLAY_ALLOWED else seen


@dataclass(frozen=True, slots=True)
class MachineState:
    """Where the machine is, plus the side-effect tags emitted so far.

    The kernel performs NO side effects itself: each fired row appends its §4.2
    tags here and the audit writer (Phase 4) binds them to real events.
    """

    state: State
    emitted: tuple[str, ...] = field(default=())


def advance(machine_state: MachineState, event: Event, guard_input: GuardInput) -> MachineState:
    """Apply ``event`` to ``machine_state``; return the new state, or the SAME
    object unchanged when no guard holds.

    A no-op is the fail-closed outcome — the machine never advances on an
    unrecognised or unguarded event, and a terminal state never moves at all.
    """
    transition = step(machine_state.state, event, guard_input)
    if transition is None:
        return machine_state
    return replace(
        machine_state,
        state=transition.target,
        emitted=machine_state.emitted + transition.side_effect,
    )
