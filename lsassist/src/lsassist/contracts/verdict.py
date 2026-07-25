"""Verdict and Evidence contract models (SPEC §4.5, kernel invariant I12).

I12 / AC-13 foundation: constructing an evidence-less VERIFIED verdict is
impossible — the model_validator below rejects it. The admissible evidence
types for VERIFIED are enforced structurally: ``Evidence.type`` is an
:class:`~lsassist.contracts.enums.EvidenceType`, so no other value can be
constructed.
"""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lsassist.contracts.enums import (
    PROVIDER_IDS,
    EvidenceType,
    ExitReason,
    VerdictStatus,
)


class Evidence(BaseModel):
    """One deterministic evidence record referenced by a verdict (I12)."""

    model_config = ConfigDict(frozen=True)

    type: EvidenceType
    ref: str = Field(min_length=1)
    digest: str | None = None


class Verdict(BaseModel):
    """Task verdict; every REPORT carries one (SPEC §4.4/§4.5).

    Enforces each §4.5 table row:
    - VERIFIED: ≥1 evidence ref, each of an admissible I12 type (I12).
    - PARTIAL: non-empty per-sub-goal status map with ≥1 VERIFIED sub-goal.
    - UNVERIFIED: non-empty missing-evidence list.
    - BLOCKED: a policy rule id or a provider status.
    - CANCELLED: no requirements.

    Parameterized exit reasons (§4.4) carry their parameter in
    ``policy_rule_id`` / ``provider``, never inside the enum value.
    """

    model_config = ConfigDict(frozen=True)

    status: VerdictStatus
    exit_reason: ExitReason = ExitReason.COMPLETED
    evidence_refs: list[Evidence] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    sub_goal_status: dict[str, VerdictStatus] = Field(default_factory=dict)
    policy_rule_id: str | None = None
    provider: str | None = None
    provider_status: str | None = None

    @model_validator(mode="after")
    def _enforce_verdict_rules(self) -> Self:
        self._check_status_row()
        self._check_exit_reason_parameters()
        return self

    def _check_status_row(self) -> None:
        match self.status:
            case VerdictStatus.VERIFIED:
                if not self.evidence_refs:
                    raise ValueError("VERIFIED requires >=1 evidence ref (I12)")
            case VerdictStatus.PARTIAL:
                if not self.sub_goal_status:
                    raise ValueError("PARTIAL requires a per-sub-goal status map")
                if VerdictStatus.VERIFIED not in self.sub_goal_status.values():
                    raise ValueError("PARTIAL requires >=1 VERIFIED sub-goal")
            case VerdictStatus.UNVERIFIED:
                if not self.missing_evidence:
                    raise ValueError("UNVERIFIED requires a missing-evidence list")
            case VerdictStatus.BLOCKED:
                if self.policy_rule_id is None and self.provider_status is None:
                    raise ValueError("BLOCKED requires a rule id or provider status")
            case VerdictStatus.CANCELLED:
                pass  # §4.5: user action, no evidence requirement

    def _check_exit_reason_parameters(self) -> None:
        if self.exit_reason is ExitReason.POLICY_BLOCKED:
            if not self.policy_rule_id:
                raise ValueError("policy_blocked exit reason requires policy_rule_id")
        elif self.policy_rule_id is not None:
            raise ValueError("policy_rule_id is only valid with exit reason policy_blocked")
        if self.exit_reason is ExitReason.PROVIDER_UNAVAILABLE:
            if self.provider not in PROVIDER_IDS:
                raise ValueError(
                    "provider_unavailable exit reason requires provider in "
                    f"{sorted(PROVIDER_IDS)}"
                )
        elif self.provider is not None:
            raise ValueError(
                "provider is only valid with exit reason provider_unavailable"
            )
