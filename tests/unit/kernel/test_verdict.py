"""T2.09 RED: kernel verdict computation (SPEC §4.4, §4.5, invariant I12, AC-13).

TABLE-FORM tests for the PURE ``compute_verdict``. Coverage is exhaustive BY
CONSTRUCTION (``--cov`` unavailable, pytest-cov not installed): every §4.5 row,
every one of the eleven §4.4 ``ExitReason`` values, the full 5x11
(status, exit_reason) coherence cross-product, and a 3x3x4x11 sweep over
sub-goal outcomes / evidence shapes / exit reasons asserting the I12 invariant
globally.

I12 is implemented as a DOWNGRADE, never an exception: an under-evidenced
VERIFIED becomes UNVERIFIED with the missing-evidence list surfaced.
``test_i12_downgrade_does_not_raise`` asserts literally that ``pytest.raises``
does NOT fire, so the downgrade can never be reached via a caught exception
(exception-as-control-flow would let a swallowed error read as success).
The ``contracts.Verdict`` validator rejection stays asserted here too, as
defense-in-depth (see the ``defense in depth`` section at the bottom).

PURE (§2.2): no filesystem, network, clock, randomness or child processes —
these tests use literal in-memory objects only.
"""

from __future__ import annotations

import itertools

import pytest
from pydantic import ValidationError

from lsassist.contracts.enums import EvidenceType, ExitReason, VerdictStatus
from lsassist.contracts.verdict import Evidence, Verdict
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

# --- shorthands ---------------------------------------------------------------

GREEN = CheckOutcome.GREEN
RED = CheckOutcome.RED
UNKNOWN = CheckOutcome.UNKNOWN

VERIFIED = VerdictStatus.VERIFIED
PARTIAL = VerdictStatus.PARTIAL
UNVERIFIED = VerdictStatus.UNVERIFIED
BLOCKED = VerdictStatus.BLOCKED
CANCELLED = VerdictStatus.CANCELLED

# The §4.4 parameters each parameterized exit reason needs to be coherent.
REASON_PARAMS: dict[ExitReason, dict[str, str]] = {
    ExitReason.POLICY_BLOCKED: {"policy_rule_id": "R5"},
    ExitReason.PROVIDER_UNAVAILABLE: {
        "provider": "kimi",
        "provider_status": "connection refused",
    },
}


def ev(
    type_: EvidenceType = EvidenceType.TEST_RESULT,
    ref: str = "pytest tests/unit/kernel -q :: 12 passed",
) -> Evidence:
    """A well-formed, I12-admissible evidence record."""
    return Evidence(type=type_, ref=ref, digest="sha256:beef")


def rogue_evidence(type_value: str = "model_confidence") -> Evidence:
    """An evidence record whose type is NOT I12-admissible.

    ``model_construct`` bypasses pydantic validation on purpose: it simulates a
    record that reached the kernel *around* the contract boundary (a future
    non-deterministic ``EvidenceType`` member, a ``model_construct`` caller, or
    a model self-report — decision #5: model confidence is never evidence).
    The kernel must still refuse to emit VERIFIED, and must not raise.
    """
    return Evidence.model_construct(type=type_value, ref="the model said it worked")  # type: ignore[arg-type]


# --- §4.5 row: VERIFIED (all sub-goals green + >=1 admissible evidence) --------


def test_all_green_with_evidence_is_verified() -> None:
    verdict = compute_verdict(
        sub_goal_checks={"g1": GREEN, "g2": GREEN},
        evidence=[ev()],
        exit_reason=ExitReason.COMPLETED,
    )
    assert verdict.status is VERIFIED
    assert verdict.exit_reason is ExitReason.COMPLETED
    assert verdict.evidence_refs == [ev()]
    assert verdict.sub_goal_status == {"g1": VERIFIED, "g2": VERIFIED}
    assert verdict.missing_evidence == []


@pytest.mark.parametrize("evidence_type", list(EvidenceType))
def test_every_admissible_evidence_type_supports_verified(evidence_type: EvidenceType) -> None:
    verdict = compute_verdict(sub_goal_checks={"g1": GREEN}, evidence=[ev(evidence_type)])
    assert verdict.status is VERIFIED


def test_admissible_set_is_exactly_the_five_i12_types() -> None:
    # I12 pins the deterministic five; the kernel must NOT auto-admit a future
    # EvidenceType member (that is why the set is spelled out, not frozenset(EvidenceType)).
    assert set(ADMISSIBLE_EVIDENCE_TYPES) == {
        EvidenceType.TEST_RESULT,
        EvidenceType.EXIT_CODE,
        EvidenceType.DIFF_HASH,
        EvidenceType.FILE_SNAPSHOT,
        EvidenceType.COMMAND_OUTPUT_DIGEST,
    }


def test_default_exit_reason_is_completed() -> None:
    verdict = compute_verdict(sub_goal_checks={"g1": GREEN}, evidence=[ev()])
    assert verdict.exit_reason is ExitReason.COMPLETED


# --- I12: DOWNGRADE, never raise ----------------------------------------------


def test_i12_downgrade_does_not_raise() -> None:
    """The headline I12 proof: an under-evidenced VERIFIED must NOT raise.

    The inner ``pytest.raises`` must fail to fire — if ``compute_verdict``
    signalled the I12 violation by raising, the caller could catch it and
    fabricate a VERIFIED. Fail-closed downgrade is the only allowed shape.
    """
    # Read outside-in: the inner ``raises(Exception)`` must itself FAIL ("DID NOT
    # RAISE"), which the outer ``raises`` asserts. Any exception at all out of
    # compute_verdict would satisfy the inner block and fail this test.
    with (
        pytest.raises(pytest.fail.Exception, match="DID NOT RAISE"),
        pytest.raises(Exception),  # noqa: B017 - must NOT fire
    ):
        compute_verdict(sub_goal_checks={"g1": GREEN, "g2": GREEN}, evidence=[])


def test_all_green_without_evidence_downgrades_to_unverified() -> None:
    verdict = compute_verdict(sub_goal_checks={"g1": GREEN, "g2": GREEN}, evidence=[])
    assert verdict.status is UNVERIFIED
    assert verdict.exit_reason is ExitReason.COMPLETED
    assert verdict.evidence_refs == []
    assert verdict.missing_evidence, "downgrade must surface the missing-evidence list"
    assert any("I12" in note for note in verdict.missing_evidence)
    # No sub-goal may be claimed VERIFIED when nothing backs it.
    assert VERIFIED not in verdict.sub_goal_status.values()


def test_inadmissible_evidence_type_downgrades_and_does_not_raise() -> None:
    verdict = compute_verdict(sub_goal_checks={"g1": GREEN}, evidence=[rogue_evidence()])
    assert verdict.status is UNVERIFIED
    assert verdict.evidence_refs == [], "inadmissible record must never enter the verdict"
    assert any("model_confidence" in note for note in verdict.missing_evidence)


def test_empty_ref_evidence_is_inadmissible() -> None:
    blank = Evidence.model_construct(type=EvidenceType.EXIT_CODE, ref="")
    verdict = compute_verdict(sub_goal_checks={"g1": GREEN}, evidence=[blank])
    assert verdict.status is UNVERIFIED
    assert verdict.evidence_refs == []


def test_admissible_evidence_survives_alongside_a_rogue_record() -> None:
    verdict = compute_verdict(
        sub_goal_checks={"g1": GREEN},
        evidence=[rogue_evidence(), ev()],
    )
    assert verdict.status is VERIFIED
    assert verdict.evidence_refs == [ev()]
    assert any("model_confidence" in note for note in verdict.missing_evidence)


def test_no_sub_goals_checked_cannot_be_verified() -> None:
    verdict = compute_verdict(sub_goal_checks={}, evidence=[ev()])
    assert verdict.status is UNVERIFIED
    assert verdict.missing_evidence


@pytest.mark.parametrize("outcome", [RED, UNKNOWN])
def test_non_green_sub_goal_blocks_verified(outcome: CheckOutcome) -> None:
    verdict = compute_verdict(sub_goal_checks={"g1": outcome}, evidence=[ev()])
    assert verdict.status is UNVERIFIED


def test_self_reported_unknown_is_not_evidence() -> None:
    # Decision #5: a model's self-reported "done" is CheckOutcome.UNKNOWN, and
    # UNKNOWN never counts as a deterministic green check.
    verdict = compute_verdict(sub_goal_checks={"g1": UNKNOWN, "g2": UNKNOWN}, evidence=[ev()])
    assert verdict.status is UNVERIFIED
    assert all("self-report" in note for note in verdict.missing_evidence)


# --- §4.5 row: PARTIAL (>=1 sub-goal VERIFIED, rest listed explicitly) --------


def test_mixed_sub_goals_with_evidence_is_partial_with_unmet_listed() -> None:
    verdict = compute_verdict(
        sub_goal_checks={"g1": GREEN, "g2": RED, "g3": UNKNOWN},
        evidence=[ev()],
    )
    assert verdict.status is PARTIAL
    assert verdict.sub_goal_status == {"g1": VERIFIED, "g2": UNVERIFIED, "g3": UNVERIFIED}
    assert any(note.startswith("g2:") for note in verdict.missing_evidence)
    assert any(note.startswith("g3:") for note in verdict.missing_evidence)
    assert not any(note.startswith("g1:") for note in verdict.missing_evidence)


def test_mixed_sub_goals_without_evidence_is_unverified_not_partial() -> None:
    # Fail-closed: with no admissible evidence no sub-goal may be marked
    # VERIFIED, so the verdict cannot be PARTIAL either.
    verdict = compute_verdict(sub_goal_checks={"g1": GREEN, "g2": RED}, evidence=[])
    assert verdict.status is UNVERIFIED
    assert VERIFIED not in verdict.sub_goal_status.values()


# --- §4.5 row: BLOCKED (policy / provider stop) -------------------------------


def test_policy_stop_is_blocked_with_rule_id() -> None:
    verdict = compute_verdict(
        sub_goal_checks={"g1": GREEN},
        evidence=[ev()],
        exit_reason=ExitReason.POLICY_BLOCKED,
        policy_rule_id="R5",
    )
    assert verdict.status is BLOCKED
    assert verdict.exit_reason is ExitReason.POLICY_BLOCKED
    assert verdict.policy_rule_id == "R5"
    assert verdict.exit_reason.render(verdict.policy_rule_id) == "policy_blocked:R5"


def test_provider_stop_is_blocked_with_provider_status() -> None:
    verdict = compute_verdict(
        sub_goal_checks={"g1": UNKNOWN},
        exit_reason=ExitReason.PROVIDER_UNAVAILABLE,
        provider="ollama",
        provider_status="connection refused",
    )
    assert verdict.status is BLOCKED
    assert verdict.provider == "ollama"
    assert verdict.provider_status == "connection refused"
    assert verdict.exit_reason.render(verdict.provider) == "provider_unavailable:ollama"


def test_policy_blocked_without_rule_id_is_a_typed_error() -> None:
    with pytest.raises(VerdictCoherenceError):
        compute_verdict(sub_goal_checks={"g1": GREEN}, exit_reason=ExitReason.POLICY_BLOCKED)


def test_policy_rule_id_with_wrong_reason_is_a_typed_error() -> None:
    with pytest.raises(VerdictCoherenceError):
        compute_verdict(
            sub_goal_checks={"g1": GREEN},
            evidence=[ev()],
            exit_reason=ExitReason.COMPLETED,
            policy_rule_id="R5",
        )


@pytest.mark.parametrize("provider", [None, "", "gpt-5", "kimi ", "BOTH"])
def test_provider_unavailable_requires_a_known_provider_id(provider: str | None) -> None:
    with pytest.raises(VerdictCoherenceError):
        compute_verdict(
            sub_goal_checks={"g1": UNKNOWN},
            exit_reason=ExitReason.PROVIDER_UNAVAILABLE,
            provider=provider,
            provider_status="down",
        )


def test_provider_unavailable_requires_a_provider_status() -> None:
    with pytest.raises(VerdictCoherenceError):
        compute_verdict(
            sub_goal_checks={"g1": UNKNOWN},
            exit_reason=ExitReason.PROVIDER_UNAVAILABLE,
            provider="both",
        )


@pytest.mark.parametrize("field", ["provider", "provider_status"])
def test_provider_fields_with_wrong_reason_are_a_typed_error(field: str) -> None:
    with pytest.raises(VerdictCoherenceError):
        compute_verdict(
            sub_goal_checks={"g1": GREEN},
            evidence=[ev()],
            exit_reason=ExitReason.COMPLETED,
            **{field: "kimi"},
        )


# --- §4.5 row: CANCELLED (user action) ----------------------------------------


def test_user_stop_is_cancelled() -> None:
    verdict = compute_verdict(
        sub_goal_checks={"g1": GREEN, "g2": RED},
        evidence=[ev()],
        exit_reason=ExitReason.USER_CANCELLED,
    )
    assert verdict.status is CANCELLED
    assert verdict.exit_reason is ExitReason.USER_CANCELLED


def test_cancellation_wins_over_a_fully_green_run() -> None:
    # A cancelled run is never VERIFIED, however green it looked.
    verdict = compute_verdict(
        sub_goal_checks={"g1": GREEN},
        evidence=[ev()],
        exit_reason=ExitReason.USER_CANCELLED,
    )
    assert verdict.status is CANCELLED


# --- §4.4: every ExitReason maps to exactly one coherent status ---------------

EXPECTED_STATUS_ALL_GREEN_WITH_EVIDENCE: dict[ExitReason, VerdictStatus] = {
    ExitReason.COMPLETED: VERIFIED,
    ExitReason.BUDGET_EXHAUSTED: PARTIAL,
    ExitReason.LOOP_DETECTED: PARTIAL,
    ExitReason.POLICY_BLOCKED: BLOCKED,
    # §4.2 machine row APPROVAL --approval_refused--> CANCELLED covers BOTH a
    # user deny and a lapsed prompt, so neither may grade to PARTIAL here.
    ExitReason.APPROVAL_DENIED: CANCELLED,
    ExitReason.APPROVAL_TIMEOUT: CANCELLED,
    ExitReason.PROVIDER_UNAVAILABLE: BLOCKED,
    ExitReason.MALFORMED_MODEL_OUTPUT: PARTIAL,
    ExitReason.USER_CANCELLED: CANCELLED,
    ExitReason.VERIFICATION_FAILED: PARTIAL,
    ExitReason.GROUNDING_FAILED: PARTIAL,
}


def test_exit_reason_mapping_table_covers_every_enum_value() -> None:
    assert set(EXPECTED_STATUS_ALL_GREEN_WITH_EVIDENCE) == set(ExitReason)


@pytest.mark.parametrize(
    ("exit_reason", "expected"),
    sorted(EXPECTED_STATUS_ALL_GREEN_WITH_EVIDENCE.items()),
)
def test_status_for_each_exit_reason_all_green_with_evidence(
    exit_reason: ExitReason, expected: VerdictStatus
) -> None:
    verdict = compute_verdict(
        sub_goal_checks={"g1": GREEN, "g2": GREEN},
        evidence=[ev()],
        exit_reason=exit_reason,
        **REASON_PARAMS.get(exit_reason, {}),
    )
    assert verdict.status is expected


@pytest.mark.parametrize("exit_reason", sorted(ExitReason))
def test_status_for_each_exit_reason_without_evidence(exit_reason: ExitReason) -> None:
    verdict = compute_verdict(
        sub_goal_checks={"g1": GREEN, "g2": GREEN},
        evidence=[],
        exit_reason=exit_reason,
        **REASON_PARAMS.get(exit_reason, {}),
    )
    expected = TERMINAL_EXIT_STATUS.get(exit_reason, UNVERIFIED)
    assert verdict.status is expected


@pytest.mark.parametrize("exit_reason", sorted(CAPPED_EXIT_REASONS))
def test_capped_reasons_never_yield_verified(exit_reason: ExitReason) -> None:
    verdict = compute_verdict(
        sub_goal_checks={"g1": GREEN},
        evidence=[ev()],
        exit_reason=exit_reason,
    )
    assert verdict.status is PARTIAL
    assert any("capped" in note for note in verdict.missing_evidence)


def test_capped_reason_with_no_verifiable_sub_goal_falls_to_unverified() -> None:
    verdict = compute_verdict(
        sub_goal_checks={},
        evidence=[ev()],
        exit_reason=ExitReason.BUDGET_EXHAUSTED,
    )
    assert verdict.status is UNVERIFIED


# --- SEAM (T2.07 §4.2 machine <-> T2.09 §4.5 verdict) -------------------------
#
# The machine decides WHICH terminal state a turn lands in; LEGAL_PAIRS decides
# what a verdict may say about it. These must agree for all three terminal
# causes the machine actually produces, or a runner is forced to mislabel the
# outcome. Derived from machine.py's guards: ``_g_approval_refused`` (APPROVAL
# -> CANCELLED on deny OR 120 s timeout) and ``_g_policy_blocked``
# (POLICY_CHECK -> BLOCKED on DENY_ALWAYS OR exhausted budget OR provider down).


@pytest.mark.parametrize(
    "exit_reason", [ExitReason.APPROVAL_DENIED, ExitReason.APPROVAL_TIMEOUT]
)
def test_refused_approval_is_cancelled_like_the_machine_says(exit_reason: ExitReason) -> None:
    verdict = compute_verdict(
        sub_goal_checks={"g1": GREEN, "g2": RED},
        evidence=[ev()],
        exit_reason=exit_reason,
    )
    assert verdict.status is CANCELLED, "machine routes a refused approval to CANCELLED"
    assert verdict.exit_reason is exit_reason
    require_coherent_pair(CANCELLED, exit_reason)  # must not raise


@pytest.mark.parametrize(
    "exit_reason", [ExitReason.APPROVAL_DENIED, ExitReason.APPROVAL_TIMEOUT]
)
def test_refused_approval_never_grades_to_partial_or_unverified(
    exit_reason: ExitReason,
) -> None:
    # The old (pre-seam) behaviour: these graded to PARTIAL/UNVERIFIED, which
    # contradicted the machine calling the same turn CANCELLED.
    for status in (PARTIAL, UNVERIFIED, VERIFIED):
        with pytest.raises(VerdictCoherenceError):
            require_coherent_pair(status, exit_reason)


def test_budget_exhausted_at_policy_check_pairs_with_blocked() -> None:
    # §4.2 POLICY_CHECK --policy_classified--> BLOCKED fires on an exhausted
    # budget; the runner assembling that terminal record must be able to gate it.
    require_coherent_pair(BLOCKED, ExitReason.BUDGET_EXHAUSTED)  # must not raise


def test_budget_exhausted_at_verify_still_grades_to_partial() -> None:
    # §4.3: exhaustion mid-task forces a REPORT on work already done -> PARTIAL.
    verdict = compute_verdict(
        sub_goal_checks={"g1": GREEN},
        evidence=[ev()],
        exit_reason=ExitReason.BUDGET_EXHAUSTED,
    )
    assert verdict.status is PARTIAL
    require_coherent_pair(PARTIAL, ExitReason.BUDGET_EXHAUSTED)


def test_terminal_and_capped_reasons_are_disjoint() -> None:
    # A reason cannot be both status-dictating and graded, or one of the two
    # tables is dead data (the defect this seam pass fixed).
    assert not (set(TERMINAL_EXIT_STATUS) & CAPPED_EXIT_REASONS)


def test_every_terminal_mapping_is_itself_a_legal_pair() -> None:
    for exit_reason, status in TERMINAL_EXIT_STATUS.items():
        require_coherent_pair(status, exit_reason)


@pytest.mark.parametrize("exit_reason", sorted(CAPPED_EXIT_REASONS))
def test_every_capped_reason_is_legal_with_the_statuses_it_can_produce(
    exit_reason: ExitReason,
) -> None:
    require_coherent_pair(PARTIAL, exit_reason)
    require_coherent_pair(UNVERIFIED, exit_reason)
    with pytest.raises(VerdictCoherenceError):
        require_coherent_pair(VERIFIED, exit_reason)


# --- (status, exit_reason) coherence: the full 5x11 cross-product -------------


def test_legal_pairs_cover_every_status_and_every_exit_reason() -> None:
    assert set(LEGAL_PAIRS) == set(VerdictStatus)
    covered: set[ExitReason] = set()
    for reasons in LEGAL_PAIRS.values():
        covered |= set(reasons)
    assert covered == set(ExitReason)


def test_verified_pairs_only_with_completed() -> None:
    assert LEGAL_PAIRS[VERIFIED] == frozenset({ExitReason.COMPLETED})


@pytest.mark.parametrize(
    ("status", "exit_reason"),
    sorted(itertools.product(VerdictStatus, ExitReason)),
)
def test_pair_coherence_cross_product(status: VerdictStatus, exit_reason: ExitReason) -> None:
    if exit_reason in LEGAL_PAIRS[status]:
        require_coherent_pair(status, exit_reason)  # must not raise
    else:
        with pytest.raises(VerdictCoherenceError):
            require_coherent_pair(status, exit_reason)


@pytest.mark.parametrize(
    ("status", "exit_reason"),
    [
        (VERIFIED, ExitReason.USER_CANCELLED),
        (VERIFIED, ExitReason.BUDGET_EXHAUSTED),
        (VERIFIED, ExitReason.VERIFICATION_FAILED),
        (CANCELLED, ExitReason.COMPLETED),
        (BLOCKED, ExitReason.COMPLETED),
        (PARTIAL, ExitReason.POLICY_BLOCKED),
        (UNVERIFIED, ExitReason.USER_CANCELLED),
    ],
)
def test_incoherent_pairs_are_typed_errors(
    status: VerdictStatus, exit_reason: ExitReason
) -> None:
    with pytest.raises(VerdictCoherenceError):
        require_coherent_pair(status, exit_reason)


def test_coherence_error_is_a_value_error() -> None:
    assert issubclass(VerdictCoherenceError, ValueError)


# --- global I12 sweep: 3x3 outcomes x 4 evidence shapes x 11 exit reasons -----


@pytest.mark.parametrize("exit_reason", sorted(ExitReason))
def test_i12_invariant_holds_for_every_input_combination(exit_reason: ExitReason) -> None:
    evidence_shapes: tuple[list[Evidence], ...] = (
        [],
        [rogue_evidence()],
        [ev()],
        [rogue_evidence(), ev(EvidenceType.DIFF_HASH)],
    )
    verified_seen = 0
    for outcomes in itertools.product(CheckOutcome, repeat=2):
        for evidence in evidence_shapes:
            verdict = compute_verdict(
                sub_goal_checks=dict(zip(("g1", "g2"), outcomes, strict=True)),
                evidence=list(evidence),
                exit_reason=exit_reason,
                **REASON_PARAMS.get(exit_reason, {}),
            )
            # Emitted pair is always coherent, whatever the inputs.
            require_coherent_pair(verdict.status, verdict.exit_reason)
            assert all(e.type in ADMISSIBLE_EVIDENCE_TYPES for e in verdict.evidence_refs)
            if verdict.status is VERIFIED:
                verified_seen += 1
                assert verdict.exit_reason is ExitReason.COMPLETED
                assert verdict.evidence_refs, "I12: VERIFIED without evidence is impossible"
                assert all(o is GREEN for o in outcomes)
            if verdict.status is UNVERIFIED:
                assert verdict.missing_evidence
            if verdict.status is PARTIAL:
                assert VERIFIED in verdict.sub_goal_status.values()
    if exit_reason is ExitReason.COMPLETED:
        assert verified_seen, "sweep must actually reach VERIFIED (non-vacuous)"


# --- purity (§2.2) ------------------------------------------------------------


def test_compute_verdict_is_deterministic() -> None:
    kwargs = {"sub_goal_checks": {"g1": GREEN, "g2": RED}, "evidence": [ev()]}
    assert compute_verdict(**kwargs) == compute_verdict(**kwargs)  # type: ignore[arg-type]


def test_compute_verdict_does_not_mutate_its_inputs() -> None:
    checks = {"g1": GREEN, "g2": RED}
    evidence = [ev(), rogue_evidence()]
    compute_verdict(sub_goal_checks=checks, evidence=evidence)
    assert checks == {"g1": GREEN, "g2": RED}
    assert len(evidence) == 2


def test_returned_verdict_is_frozen() -> None:
    verdict = compute_verdict(sub_goal_checks={"g1": GREEN}, evidence=[ev()])
    with pytest.raises(ValidationError):
        verdict.status = UNVERIFIED  # type: ignore[misc]


# --- defense in depth: the contracts model still rejects at construction ------


def test_contract_still_rejects_evidence_less_verified() -> None:
    # I12 layer 2 (unchanged by T2.09): even if the kernel guard were bypassed,
    # constructing an evidence-less VERIFIED is impossible.
    with pytest.raises(ValidationError):
        Verdict(status=VerdictStatus.VERIFIED, evidence_refs=[])


def test_contract_still_rejects_inadmissible_evidence_type() -> None:
    with pytest.raises(ValidationError):
        Verdict(
            status=VerdictStatus.VERIFIED,
            evidence_refs=[Evidence(type="model_confidence", ref="chat turn 4")],  # type: ignore[arg-type]
        )
