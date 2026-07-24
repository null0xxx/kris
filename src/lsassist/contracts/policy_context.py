"""PolicyContext contract model — classification context for the policy engine.

Carried alongside every :class:`~lsassist.contracts.tool_request.ToolRequest`
into policy classification (§6.3 step 3, §7.2 rules):

- ``workspace_root``: canonical absolute workspace path. Canonicalization is
  enforced at validation (resolve + must be absolute + must equal its
  resolved form) so §7.2 path rules never compare against a symlinked or
  ``..``-bearing spelling of the scope root.
- ``untrusted_turn`` (§4.6/R3): ``True`` when the turn contains untrusted
  content; any non-AUTO_READ classification raises to CONFIRM_EXACT.
- ``skill_ceiling`` (§9.4): the active skill's ``permission_class_max``, or
  ``None`` when no skill is injected. A tool request exceeding the ceiling is
  raised/BLOCKED by policy.

§2.2: stdlib + pydantic only; no I/O, no child processes, no network.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, field_validator

from lsassist.contracts.enums import PermissionClass


class PolicyContext(BaseModel):
    """Per-request context for §7.2 deterministic classification."""

    model_config = ConfigDict(frozen=True)

    workspace_root: str
    untrusted_turn: bool = False
    skill_ceiling: PermissionClass | None = None

    @field_validator("workspace_root")
    @classmethod
    def _workspace_root_must_be_canonical_absolute(cls, value: str) -> str:
        path = Path(value)
        if not path.is_absolute():
            raise ValueError("workspace_root must be an absolute path")
        resolved = str(path.resolve())
        if resolved != value:
            raise ValueError(
                f"workspace_root must be canonical (resolved form {resolved!r})"
            )
        return value
