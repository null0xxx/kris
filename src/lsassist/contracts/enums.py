"""Contract enums: PermissionClass (SPEC §6.2), ExitReason (§4.4),
EvidenceType (I12 / §4.5), VerdictStatus (§4.5).

Pattern source: Hermes ``_turn_exit_reason`` — independently reimplemented as a
contracts enum (SPEC §4.4).
"""

from __future__ import annotations

from enum import StrEnum


class PermissionClass(StrEnum):
    """Tool permission classes (SPEC §6.2 tool manifest enum)."""

    AUTO_READ = "AUTO_READ"
    AUTO_SCOPED_WRITE = "AUTO_SCOPED_WRITE"
    CONFIRM_ONCE = "CONFIRM_ONCE"
    CONFIRM_EXACT = "CONFIRM_EXACT"
    DENY_ALWAYS = "DENY_ALWAYS"


class ExitReason(StrEnum):
    """Why a kernel loop reached REPORT (SPEC §4.4 — every REPORT carries one).

    Parameterized reasons store only the prefix as the enum value; the
    parameter travels in dedicated model fields (``Verdict.policy_rule_id`` /
    ``Verdict.provider``), never baked into the enum value, and is rendered to
    the §4.4 wire form by :meth:`render`.
    """

    COMPLETED = "completed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    LOOP_DETECTED = "loop_detected"
    POLICY_BLOCKED = "policy_blocked"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_TIMEOUT = "approval_timeout"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    MALFORMED_MODEL_OUTPUT = "malformed_model_output"
    USER_CANCELLED = "user_cancelled"
    VERIFICATION_FAILED = "verification_failed"
    GROUNDING_FAILED = "grounding_failed"

    @property
    def parameterized(self) -> bool:
        """True when the §4.4 wire form carries a ``:<parameter>`` suffix."""
        return self in _PARAMETER_ALLOWED

    def render(self, parameter: str | None = None) -> str:
        """Render the SPEC §4.4 wire form, e.g. ``budget_exhausted:tool_calls``.

        Raises ValueError if a required parameter is missing, an unexpected
        parameter is given, or the parameter is outside the allowed set.
        ``POLICY_BLOCKED`` accepts any free-form rule id.
        """
        allowed = _PARAMETER_ALLOWED.get(self)
        if allowed is None:
            if parameter is not None:
                raise ValueError(f"{self.value} takes no parameter")
            return self.value
        if parameter is None:
            raise ValueError(f"{self.value} requires a parameter")
        if allowed and parameter not in allowed:
            raise ValueError(f"invalid parameter {parameter!r} for {self.value}")
        return f"{self.value}:{parameter}"


# Allowed ``:<parameter>`` suffixes per SPEC §4.4. An empty frozenset means
# "parameterized, but free-form" (policy rule ids are not enumerable here).
_PARAMETER_ALLOWED: dict[ExitReason, frozenset[str]] = {
    ExitReason.BUDGET_EXHAUSTED: frozenset({"tool_calls", "tokens", "time", "cost"}),
    ExitReason.POLICY_BLOCKED: frozenset(),
    ExitReason.PROVIDER_UNAVAILABLE: frozenset({"kimi", "ollama", "both"}),
}

BUDGET_KINDS: frozenset[str] = _PARAMETER_ALLOWED[ExitReason.BUDGET_EXHAUSTED]
PROVIDER_IDS: frozenset[str] = _PARAMETER_ALLOWED[ExitReason.PROVIDER_UNAVAILABLE]


class EvidenceType(StrEnum):
    """Deterministic evidence types admissible for a VERIFIED verdict (I12)."""

    TEST_RESULT = "test_result"
    EXIT_CODE = "exit_code"
    DIFF_HASH = "diff_hash"
    FILE_SNAPSHOT = "file_snapshot"
    COMMAND_OUTPUT_DIGEST = "command_output_digest"


class VerdictStatus(StrEnum):
    """Task verdict values (SPEC §4.5 semantics table)."""

    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    UNVERIFIED = "UNVERIFIED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"
