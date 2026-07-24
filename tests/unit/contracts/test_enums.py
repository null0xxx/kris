"""T1.03 RED: contract enums per SPEC §4.4 (ExitReason), §4.5 (VerdictStatus),
§6.2 (PermissionClass) and I12 (EvidenceType).

ExitReason parameterized members (``budget_exhausted:<kind>``,
``policy_blocked:<rule_id>``, ``provider_unavailable:<which>``) store only the
prefix as the enum value; the parameter is rendered via ``ExitReason.render()``
and carried in dedicated model fields (GREEN: ``Verdict.policy_rule_id`` /
``Verdict.provider``), never baked into the enum value itself.
"""

from __future__ import annotations

import pytest

from lsassist.contracts.enums import (
    EvidenceType,
    ExitReason,
    PermissionClass,
    VerdictStatus,
)

# Every value in the SPEC §4.4 list, exactly: (wire form, member, parameter).
SECTION_44_VALUES: list[tuple[str, ExitReason, str | None]] = [
    ("completed", ExitReason.COMPLETED, None),
    ("budget_exhausted:tool_calls", ExitReason.BUDGET_EXHAUSTED, "tool_calls"),
    ("budget_exhausted:tokens", ExitReason.BUDGET_EXHAUSTED, "tokens"),
    ("budget_exhausted:time", ExitReason.BUDGET_EXHAUSTED, "time"),
    ("budget_exhausted:cost", ExitReason.BUDGET_EXHAUSTED, "cost"),
    ("loop_detected", ExitReason.LOOP_DETECTED, None),
    ("policy_blocked:R7", ExitReason.POLICY_BLOCKED, "R7"),
    ("approval_denied", ExitReason.APPROVAL_DENIED, None),
    ("approval_timeout", ExitReason.APPROVAL_TIMEOUT, None),
    ("provider_unavailable:kimi", ExitReason.PROVIDER_UNAVAILABLE, "kimi"),
    ("provider_unavailable:ollama", ExitReason.PROVIDER_UNAVAILABLE, "ollama"),
    ("provider_unavailable:both", ExitReason.PROVIDER_UNAVAILABLE, "both"),
    ("malformed_model_output", ExitReason.MALFORMED_MODEL_OUTPUT, None),
    ("user_cancelled", ExitReason.USER_CANCELLED, None),
    ("verification_failed", ExitReason.VERIFICATION_FAILED, None),
    ("grounding_failed", ExitReason.GROUNDING_FAILED, None),
]


@pytest.mark.parametrize(("expected", "reason", "parameter"), SECTION_44_VALUES)
def test_exit_reason_spec_44_wire_value(
    expected: str, reason: ExitReason, parameter: str | None
) -> None:
    assert reason.render(parameter) == expected


def test_exit_reason_member_set_exact() -> None:
    assert {m.value for m in ExitReason} == {
        "completed",
        "budget_exhausted",
        "loop_detected",
        "policy_blocked",
        "approval_denied",
        "approval_timeout",
        "provider_unavailable",
        "malformed_model_output",
        "user_cancelled",
        "verification_failed",
        "grounding_failed",
    }


def test_exit_reason_parameterized_members() -> None:
    assert ExitReason.BUDGET_EXHAUSTED.parameterized
    assert ExitReason.POLICY_BLOCKED.parameterized
    assert ExitReason.PROVIDER_UNAVAILABLE.parameterized
    assert not ExitReason.COMPLETED.parameterized
    assert not ExitReason.USER_CANCELLED.parameterized


def test_exit_reason_render_rejects_missing_parameter() -> None:
    with pytest.raises(ValueError, match="requires a parameter"):
        ExitReason.BUDGET_EXHAUSTED.render()
    with pytest.raises(ValueError, match="requires a parameter"):
        ExitReason.POLICY_BLOCKED.render()


def test_exit_reason_render_rejects_unexpected_parameter() -> None:
    with pytest.raises(ValueError, match="takes no parameter"):
        ExitReason.COMPLETED.render("tool_calls")


def test_exit_reason_render_rejects_invalid_parameter() -> None:
    with pytest.raises(ValueError, match="invalid parameter"):
        ExitReason.BUDGET_EXHAUSTED.render("wall_clock")
    with pytest.raises(ValueError, match="invalid parameter"):
        ExitReason.PROVIDER_UNAVAILABLE.render("openai")


def test_permission_class_values_spec_62() -> None:
    assert {m.value for m in PermissionClass} == {
        "AUTO_READ",
        "AUTO_SCOPED_WRITE",
        "CONFIRM_ONCE",
        "CONFIRM_EXACT",
        "DENY_ALWAYS",
    }


def test_evidence_type_values_i12() -> None:
    # I12 / §4.5: the only evidence types admissible for a VERIFIED verdict.
    assert {m.value for m in EvidenceType} == {
        "test_result",
        "exit_code",
        "diff_hash",
        "file_snapshot",
        "command_output_digest",
    }


def test_verdict_status_values_spec_45() -> None:
    assert {m.value for m in VerdictStatus} == {
        "VERIFIED",
        "PARTIAL",
        "UNVERIFIED",
        "BLOCKED",
        "CANCELLED",
    }


def test_enums_are_str_enums() -> None:
    assert isinstance(ExitReason.COMPLETED, str)
    assert isinstance(PermissionClass.AUTO_READ, str)
    assert isinstance(EvidenceType.TEST_RESULT, str)
    assert isinstance(VerdictStatus.VERIFIED, str)
