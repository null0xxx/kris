"""T1.03 RED: Verdict / Evidence models enforcing SPEC §4.5 rows and I12.

I12 (AC-13 foundation): constructing an evidence-less VERIFIED verdict must be
impossible — the ``contracts.Verdict`` pydantic model raises ValidationError.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from lsassist.contracts.enums import EvidenceType, ExitReason, VerdictStatus
from lsassist.contracts.verdict import Evidence, Verdict


def _evidence(type_: EvidenceType = EvidenceType.TEST_RESULT) -> Evidence:
    return Evidence(type=type_, ref="pytest tests/unit/contracts", digest="sha256:00")


# --- §4.5 row: VERIFIED + I12 -------------------------------------------------


def test_verified_without_evidence_rejected() -> None:
    with pytest.raises(ValidationError):
        Verdict(status=VerdictStatus.VERIFIED, evidence_refs=[])


def test_verified_with_inadmissible_evidence_type_rejected() -> None:
    # I12: evidence type must be one of the five deterministic types.
    with pytest.raises(ValidationError):
        Verdict(
            status=VerdictStatus.VERIFIED,
            evidence_refs=[Evidence(type="model_says_so", ref="chat turn 4")],  # type: ignore[arg-type]
        )


def test_verified_with_valid_evidence_ok() -> None:
    verdict = Verdict(status=VerdictStatus.VERIFIED, evidence_refs=[_evidence()])
    assert verdict.status is VerdictStatus.VERIFIED
    assert len(verdict.evidence_refs) == 1


@pytest.mark.parametrize("evidence_type", list(EvidenceType))
def test_verified_accepts_every_i12_evidence_type(evidence_type: EvidenceType) -> None:
    verdict = Verdict(status=VerdictStatus.VERIFIED, evidence_refs=[_evidence(evidence_type)])
    assert verdict.evidence_refs[0].type is evidence_type


def test_evidence_requires_nonempty_ref() -> None:
    with pytest.raises(ValidationError):
        Evidence(type=EvidenceType.EXIT_CODE, ref="")


# --- §4.5 row: PARTIAL --------------------------------------------------------


def test_partial_requires_sub_goal_status_map() -> None:
    with pytest.raises(ValidationError):
        Verdict(status=VerdictStatus.PARTIAL, sub_goal_status={})


def test_partial_requires_at_least_one_verified_sub_goal() -> None:
    with pytest.raises(ValidationError):
        Verdict(
            status=VerdictStatus.PARTIAL,
            sub_goal_status={
                "g1": VerdictStatus.UNVERIFIED,
                "g2": VerdictStatus.BLOCKED,
            },
        )


def test_partial_with_verified_sub_goal_ok() -> None:
    verdict = Verdict(
        status=VerdictStatus.PARTIAL,
        sub_goal_status={
            "g1": VerdictStatus.VERIFIED,
            "g2": VerdictStatus.UNVERIFIED,
        },
        missing_evidence=["g2: no test output"],
    )
    assert verdict.sub_goal_status["g1"] is VerdictStatus.VERIFIED


# --- §4.5 row: UNVERIFIED -----------------------------------------------------


def test_unverified_requires_missing_evidence_list() -> None:
    with pytest.raises(ValidationError):
        Verdict(status=VerdictStatus.UNVERIFIED, missing_evidence=[])


def test_unverified_with_missing_evidence_ok() -> None:
    verdict = Verdict(
        status=VerdictStatus.UNVERIFIED,
        exit_reason=ExitReason.VERIFICATION_FAILED,
        missing_evidence=["test.run was never executed"],
    )
    assert verdict.missing_evidence == ["test.run was never executed"]


# --- §4.5 row: BLOCKED --------------------------------------------------------


def test_blocked_requires_rule_id_or_provider_status() -> None:
    with pytest.raises(ValidationError):
        Verdict(status=VerdictStatus.BLOCKED)


def test_blocked_with_policy_rule_id_ok() -> None:
    verdict = Verdict(
        status=VerdictStatus.BLOCKED,
        exit_reason=ExitReason.POLICY_BLOCKED,
        policy_rule_id="R7",
    )
    assert verdict.policy_rule_id == "R7"


def test_blocked_with_provider_status_ok() -> None:
    verdict = Verdict(
        status=VerdictStatus.BLOCKED,
        exit_reason=ExitReason.PROVIDER_UNAVAILABLE,
        provider="both",
        provider_status="kimi=quota, ollama=down",
    )
    assert verdict.provider_status is not None


# --- §4.5 row: CANCELLED ------------------------------------------------------


def test_cancelled_needs_no_evidence() -> None:
    verdict = Verdict(status=VerdictStatus.CANCELLED, exit_reason=ExitReason.USER_CANCELLED)
    assert verdict.evidence_refs == []
    assert verdict.missing_evidence == []


# --- §4.4 parameterized exit reasons: parameter lives in model fields ---------


def test_policy_blocked_exit_reason_requires_policy_rule_id() -> None:
    with pytest.raises(ValidationError):
        Verdict(
            status=VerdictStatus.BLOCKED,
            exit_reason=ExitReason.POLICY_BLOCKED,
            provider_status="unrelated",
        )


def test_provider_unavailable_exit_reason_requires_valid_provider() -> None:
    with pytest.raises(ValidationError):
        Verdict(
            status=VerdictStatus.BLOCKED,
            exit_reason=ExitReason.PROVIDER_UNAVAILABLE,
            provider_status="down",
        )
    with pytest.raises(ValidationError):
        Verdict(
            status=VerdictStatus.BLOCKED,
            exit_reason=ExitReason.PROVIDER_UNAVAILABLE,
            provider="openai",  # not in {kimi, ollama, both}
            provider_status="down",
        )


def test_parameter_fields_rejected_for_plain_exit_reasons() -> None:
    with pytest.raises(ValidationError):
        Verdict(status=VerdictStatus.CANCELLED, policy_rule_id="R7")
    with pytest.raises(ValidationError):
        Verdict(status=VerdictStatus.CANCELLED, provider="kimi")
