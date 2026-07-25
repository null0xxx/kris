"""Verdict computation + ExitReason coherence (SPEC §4.4, §4.5, I12, AC-13).

:func:`compute_verdict` folds a per-sub-goal deterministic-check map and a bag
of structured evidence records into the single :class:`~lsassist.contracts.
verdict.Verdict` that every REPORT carries.

**I12 is a DOWNGRADE, never an exception.** If a run looks VERIFIED but is not
backed by ≥1 admissible evidence record, the verdict is emitted as UNVERIFIED
with the reason surfaced in ``missing_evidence`` — it is NOT signalled by
raising. Raising would make the I12 violation catchable, and a swallowed
exception could then read as success; a downgrade cannot. The ``contracts.
Verdict`` validator, which rejects an evidence-less VERIFIED at construction,
stays in place as the second, independent layer of the same invariant — this
module never relies on that rejection as control flow: everything is decided
before the model is constructed.

**Evidence is structural only.** Model confidence, a self-reported "done", or
any narrative claim is never evidence; it enters as :attr:`CheckOutcome.
UNKNOWN`, which never counts as a green deterministic check. Only the five
deterministic I12 types in :data:`ADMISSIBLE_EVIDENCE_TYPES` back a VERIFIED,
and the set is spelled out rather than derived from ``EvidenceType`` so that a
future non-deterministic member of that enum is not silently admitted.

**Every REPORT carries exactly one ExitReason (§4.4)**, and only some
(status, exit_reason) pairs are meaningful: a cancelled run is never VERIFIED,
a BLOCKED verdict must name the policy rule or the provider. The legal pairs
are data (:data:`LEGAL_PAIRS`); :func:`require_coherent_pair` enforces them and
is the last gate before construction, so an incoherent pair fails closed
(:class:`VerdictCoherenceError`) instead of being emitted.

**The pair set is aligned with the §4.2 state machine** (``kernel.machine``),
not derived from §4.5 alone: whichever terminal state a turn lands in, the
verdict must be able to say the same thing the machine said. Its
``APPROVAL --approval_refused--> CANCELLED`` row fires on a user deny AND on an
approval-prompt timeout, and its ``POLICY_CHECK --policy_classified--> BLOCKED``
row fires on an exhausted budget as well as on DENY_ALWAYS / provider down —
so those pairs are legal here. Anything narrower would force a runner to
mislabel a terminal turn (calling an approval denial ``user_cancelled``) or to
emit a status contradicting the machine.

Note (§4.4 wire form): ``budget_exhausted:<kind>`` carries a parameter that
``contracts.Verdict`` has no field for, so this function takes no argument for
it — nothing is accepted that cannot be carried. The report layer renders it
with :meth:`ExitReason.render`.

PURE (§2.2): no filesystem, network, clock, randomness or child processes —
pure folding over the contract models. TCB (§2.3): ``mypy --strict``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Final

from lsassist.contracts.enums import (
    PROVIDER_IDS,
    EvidenceType,
    ExitReason,
    VerdictStatus,
)
from lsassist.contracts.verdict import Evidence, Verdict


class VerdictCoherenceError(ValueError):
    """An incoherent (status, exit_reason) pair or exit-reason parameter set.

    Raised INSTEAD of emitting a verdict the kernel cannot justify (fail
    closed). This is a caller-contract error about the ExitReason (§4.4); it is
    never how an I12 evidence shortfall is reported — that is a downgrade.
    """


class CheckOutcome(StrEnum):
    """Result of the deterministic check on one sub-goal (SPEC §4.5).

    ``GREEN`` means a deterministic check actually ran and passed (test exit 0,
    diff hash match, postcondition ok). A model asserting success is not a
    check — that is ``UNKNOWN``.
    """

    GREEN = "green"
    RED = "red"
    UNKNOWN = "unknown"


# I12: the five deterministic evidence types admissible for VERIFIED (§4.5).
# Spelled out on purpose — see module docstring.
ADMISSIBLE_EVIDENCE_TYPES: Final[frozenset[EvidenceType]] = frozenset(
    {
        EvidenceType.TEST_RESULT,
        EvidenceType.EXIT_CODE,
        EvidenceType.DIFF_HASH,
        EvidenceType.FILE_SNAPSHOT,
        EvidenceType.COMMAND_OUTPUT_DIGEST,
    }
)

# §4.5 rows BLOCKED / CANCELLED: the stop itself dictates the status, whatever
# the sub-goal checks say. Aligned with the §4.2 machine (T2.07): its
# ``APPROVAL --approval_refused--> CANCELLED`` row fires on a user deny AND on
# a lapsed approval prompt, so both reasons land on the CANCELLED row here —
# letting the prompt time out IS the user declining to act (§4.5 "user action").
TERMINAL_EXIT_STATUS: Final[Mapping[ExitReason, VerdictStatus]] = {
    ExitReason.POLICY_BLOCKED: VerdictStatus.BLOCKED,
    ExitReason.PROVIDER_UNAVAILABLE: VerdictStatus.BLOCKED,
    ExitReason.USER_CANCELLED: VerdictStatus.CANCELLED,
    ExitReason.APPROVAL_DENIED: VerdictStatus.CANCELLED,
    ExitReason.APPROVAL_TIMEOUT: VerdictStatus.CANCELLED,
}

# Graded reasons that still forbid VERIFIED: the run was cut short or its
# verification is in doubt, so an all-green result is capped at PARTIAL
# (§4.3 budget exhaustion → forced REPORT, verdict PARTIAL).
#
# The approval reasons are deliberately NOT here: a reason cannot be both
# terminal and graded. Once ``approval_denied`` / ``approval_timeout`` dictate
# CANCELLED, the grading branch is unreachable for them, so leaving them capped
# would be dead data that also asserts a false pair — it would make
# (PARTIAL, approval_denied) legal, i.e. exactly the mislabelling the §4.2
# machine forbids by routing that turn to CANCELLED. Terminal and capped stay
# disjoint (asserted in the test suite).
CAPPED_EXIT_REASONS: Final[frozenset[ExitReason]] = frozenset(
    {
        ExitReason.BUDGET_EXHAUSTED,
        ExitReason.LOOP_DETECTED,
        ExitReason.MALFORMED_MODEL_OUTPUT,
        ExitReason.VERIFICATION_FAILED,
        ExitReason.GROUNDING_FAILED,
    }
)

_GRADED_REASONS: Final[frozenset[ExitReason]] = CAPPED_EXIT_REASONS | {ExitReason.COMPLETED}

# The legal (status, exit_reason) combinations (§4.4 + §4.5 + the §4.2 machine's
# terminal rows), as data. Every ExitReason appears at least once and every
# VerdictStatus is a key (asserted).
#
# ``budget_exhausted`` appears twice on purpose — WHERE the budget ran out
# decides the status. Exhausted at POLICY_CHECK, the machine routes to its
# BLOCKED terminal (nothing was executed): (BLOCKED, budget_exhausted).
# Exhausted at VERIFY, §4.3 forces a REPORT on work already done:
# (PARTIAL, budget_exhausted). :func:`compute_verdict` only ever emits the
# latter — see its docstring for why the former is the runner's to assemble.
LEGAL_PAIRS: Final[Mapping[VerdictStatus, frozenset[ExitReason]]] = {
    VerdictStatus.VERIFIED: frozenset({ExitReason.COMPLETED}),
    VerdictStatus.PARTIAL: _GRADED_REASONS,
    VerdictStatus.UNVERIFIED: _GRADED_REASONS,
    VerdictStatus.BLOCKED: frozenset(
        {
            ExitReason.POLICY_BLOCKED,
            ExitReason.PROVIDER_UNAVAILABLE,
            ExitReason.BUDGET_EXHAUSTED,
        }
    ),
    VerdictStatus.CANCELLED: frozenset(
        {
            ExitReason.USER_CANCELLED,
            ExitReason.APPROVAL_DENIED,
            ExitReason.APPROVAL_TIMEOUT,
        }
    ),
}

_NO_EVIDENCE_NOTE: Final[str] = "no admissible deterministic evidence (I12)"
_NO_SUB_GOALS_NOTE: Final[str] = "no sub-goal was checked (I12)"


def require_coherent_pair(status: VerdictStatus, exit_reason: ExitReason) -> None:
    """Raise :class:`VerdictCoherenceError` unless the pair is legal (§4.4/§4.5).

    Exposed for the state machine and the report layer, which must never
    assemble a REPORT whose verdict status and exit reason disagree (e.g.
    VERIFIED + ``user_cancelled``). It is the gate for the terminal records
    :func:`compute_verdict` does not build — notably
    (BLOCKED, ``budget_exhausted``) from the §4.2 ``POLICY_CHECK → BLOCKED``
    row. Fail-closed by contract: it raises, it never warns.
    """
    if exit_reason not in LEGAL_PAIRS[status]:
        legal = sorted(reason.value for reason in LEGAL_PAIRS[status])
        raise VerdictCoherenceError(
            f"incoherent verdict pair: status={status.value} with "
            f"exit_reason={exit_reason.value}; legal reasons for {status.value}: {legal}"
        )


def compute_verdict(
    *,
    sub_goal_checks: Mapping[str, CheckOutcome],
    evidence: Sequence[Evidence] = (),
    exit_reason: ExitReason = ExitReason.COMPLETED,
    policy_rule_id: str | None = None,
    provider: str | None = None,
    provider_status: str | None = None,
) -> Verdict:
    """Fold sub-goal checks + evidence into the §4.5 verdict for one REPORT.

    Args:
        sub_goal_checks: deterministic check outcome per sub-goal name. Empty
            means nothing was checked — which can never be VERIFIED.
        evidence: structured evidence records collected during the task.
            Records that are not I12-admissible are excluded from the verdict
            and listed in ``missing_evidence``; they never back a VERIFIED.
        exit_reason: why the loop reached REPORT (§4.4). Defaults to
            ``completed``; only ``completed`` can yield VERIFIED. The five
            reasons in :data:`TERMINAL_EXIT_STATUS` dictate the status outright
            (a refused approval is CANCELLED, not UNVERIFIED — §4.2 machine
            row ``APPROVAL → CANCELLED``). ``budget_exhausted`` is graded, not
            terminal: §4.3 makes it a forced REPORT on work already done, so it
            yields PARTIAL/UNVERIFIED here. The machine's OTHER budget route
            (exhausted at POLICY_CHECK → BLOCKED terminal, nothing executed)
            is a legal pair (:data:`LEGAL_PAIRS`) that this function cannot
            emit: the frozen ``contracts.Verdict`` BLOCKED row demands a rule
            id or provider status, and a budget stop has neither. That record
            is the runner's to assemble; use :func:`require_coherent_pair` to
            gate it.
        policy_rule_id: the blocking rule id — required by, and only legal
            with, ``policy_blocked``.
        provider: the unavailable provider id (``kimi``/``ollama``/``both``)
            and ``provider_status`` its status text — both required by, and
            only legal with, ``provider_unavailable``.
        provider_status: see ``provider``.

    Returns:
        A :class:`~lsassist.contracts.verdict.Verdict` whose status and exit
        reason are a legal pair.

    Raises:
        VerdictCoherenceError: the exit-reason parameters or the resulting
            (status, exit_reason) pair are incoherent — fail closed. An
            evidence shortfall is NOT reported this way: it downgrades.
    """
    _require_coherent_parameters(exit_reason, policy_rule_id, provider, provider_status)

    admissible, rejected = _split_evidence(evidence)
    notes = [*_unmet_notes(sub_goal_checks), *rejected]
    evidence_backed = bool(admissible)

    if exit_reason in TERMINAL_EXIT_STATUS:
        status = TERMINAL_EXIT_STATUS[exit_reason]
    else:
        status, capped_note = _grade(sub_goal_checks, exit_reason, evidence_backed)
        notes.extend(capped_note)
        if status is VerdictStatus.UNVERIFIED:
            notes.extend(_shortfall_notes(sub_goal_checks, evidence_backed))

    require_coherent_pair(status, exit_reason)
    return Verdict(
        status=status,
        exit_reason=exit_reason,
        evidence_refs=admissible,
        missing_evidence=notes,
        sub_goal_status=_project_sub_goals(sub_goal_checks, evidence_backed),
        policy_rule_id=policy_rule_id,
        provider=provider,
        provider_status=provider_status,
    )


def _require_coherent_parameters(
    exit_reason: ExitReason,
    policy_rule_id: str | None,
    provider: str | None,
    provider_status: str | None,
) -> None:
    """Enforce the §4.4 parameter rules before anything is computed."""
    if exit_reason is ExitReason.POLICY_BLOCKED:
        if not policy_rule_id:
            raise VerdictCoherenceError("policy_blocked requires a policy rule id (§4.4)")
    elif policy_rule_id is not None:
        raise VerdictCoherenceError(
            f"policy_rule_id is only legal with policy_blocked, got {exit_reason.value}"
        )

    if exit_reason is ExitReason.PROVIDER_UNAVAILABLE:
        if provider not in PROVIDER_IDS:
            raise VerdictCoherenceError(
                "provider_unavailable requires provider in "
                f"{sorted(PROVIDER_IDS)}, got {provider!r}"
            )
        if not provider_status:
            # §4.5 BLOCKED row: a provider stop must carry the provider status.
            raise VerdictCoherenceError("provider_unavailable requires a provider status")
    elif provider is not None or provider_status is not None:
        raise VerdictCoherenceError(
            "provider/provider_status are only legal with provider_unavailable, "
            f"got {exit_reason.value}"
        )


def _split_evidence(evidence: Sequence[Evidence]) -> tuple[list[Evidence], list[str]]:
    """Partition into I12-admissible records and rejection notes.

    A record is admissible only if its type is one of the five deterministic
    I12 types AND it carries a non-empty ref. Anything else is dropped from the
    verdict entirely — an inadmissible record must never travel in
    ``evidence_refs``, where a later reader would count it.
    """
    admissible: list[Evidence] = []
    rejected: list[str] = []
    for record in evidence:
        if record.type in ADMISSIBLE_EVIDENCE_TYPES and record.ref:
            admissible.append(record)
        else:
            rejected.append(
                f"inadmissible evidence rejected (I12): type={record.type!r} ref={record.ref!r}"
            )
    return admissible, rejected


def _grade(
    sub_goal_checks: Mapping[str, CheckOutcome],
    exit_reason: ExitReason,
    evidence_backed: bool,
) -> tuple[VerdictStatus, list[str]]:
    """Grade a non-terminal run: §4.5 VERIFIED / PARTIAL / UNVERIFIED."""
    greens = [name for name, outcome in sub_goal_checks.items() if outcome is CheckOutcome.GREEN]
    if not greens or not evidence_backed:
        # No green sub-goal, or nothing deterministic backing one: neither
        # VERIFIED nor PARTIAL is claimable (I12 downgrade path).
        return VerdictStatus.UNVERIFIED, []
    if len(greens) < len(sub_goal_checks):
        return VerdictStatus.PARTIAL, []
    if exit_reason in CAPPED_EXIT_REASONS:
        return VerdictStatus.PARTIAL, [
            f"capped at PARTIAL: exit reason {exit_reason.value} cannot yield VERIFIED"
        ]
    return VerdictStatus.VERIFIED, []


def _unmet_notes(sub_goal_checks: Mapping[str, CheckOutcome]) -> list[str]:
    """Explicit list of the sub-goals that are not deterministically green."""
    notes: list[str] = []
    for name, outcome in sub_goal_checks.items():
        if outcome is CheckOutcome.RED:
            notes.append(f"{name}: deterministic check failed (red)")
        elif outcome is not CheckOutcome.GREEN:
            notes.append(f"{name}: no deterministic check ran (self-report is not evidence)")
    return notes


def _shortfall_notes(
    sub_goal_checks: Mapping[str, CheckOutcome], evidence_backed: bool
) -> list[str]:
    """Why an otherwise-green run could not be VERIFIED (never empty overall)."""
    notes: list[str] = []
    if not sub_goal_checks:
        notes.append(_NO_SUB_GOALS_NOTE)
    if not evidence_backed:
        notes.append(_NO_EVIDENCE_NOTE)
    return notes


def _project_sub_goals(
    sub_goal_checks: Mapping[str, CheckOutcome], evidence_backed: bool
) -> dict[str, VerdictStatus]:
    """Per-sub-goal status map (§4.5 PARTIAL row).

    A sub-goal is VERIFIED only if its deterministic check is green AND the
    task carries admissible evidence — with no evidence, no per-sub-goal
    VERIFIED claim may be made either (I12 applies to the whole record).
    """
    return {
        name: VerdictStatus.VERIFIED
        if outcome is CheckOutcome.GREEN and evidence_backed
        else VerdictStatus.UNVERIFIED
        for name, outcome in sub_goal_checks.items()
    }
