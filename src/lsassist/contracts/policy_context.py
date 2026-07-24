"""PolicyContext contract model — classification context for the policy engine.

Carried alongside every :class:`~lsassist.contracts.tool_request.ToolRequest`
into policy classification (§6.3 step 3, §7.2 rules):

- ``workspace_root``: absolute, lexically-normalized workspace path. The
  validator enforces absolute + lexically-normalized ONLY, purely on the string
  form (``os.path.isabs`` + ``os.path.normpath``) so §7.2 path rules never
  compare against a ``..``/``.``/``//``-bearing spelling of the scope root.
  Realpath/symlink canonicalization is the CALLER's responsibility — the
  dispatcher (§7.5 / §6.3 step 2, T3.02), where filesystem access is legitimate
  and TOCTOU parent-inode pinning already happens — NOT this pure contract.
- ``untrusted_turn`` (§4.6/R3): ``True`` when the turn contains untrusted
  content; any non-AUTO_READ classification raises to CONFIRM_EXACT.
- ``skill_ceiling`` (§9.4): the active skill's ``permission_class_max``, or
  ``None`` when no skill is injected. A tool request exceeding the ceiling is
  raised/BLOCKED by policy.

§2.2: stdlib + pydantic only; no I/O, no child processes, no network. The
``workspace_root`` validator is pure string manipulation via ``os.path.isabs``
and ``os.path.normpath`` — it performs no filesystem access whatsoever: no
symlink dereferencing, no path-existence checks, no inode inspection.
"""

from __future__ import annotations

import os

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
    def _workspace_root_must_be_absolute_normalized(cls, value: str) -> str:
        # PURE (§2.2): string-only checks — no filesystem I/O. Symlink
        # canonicalization is the caller's job (dispatcher, §7.5 / §6.3 step 2).
        if not os.path.isabs(value):
            raise ValueError("workspace_root must be an absolute path")
        normalized = os.path.normpath(value)
        if normalized != value:
            raise ValueError(
                "workspace_root must be lexically normalized "
                f"(normalized form {normalized!r})"
            )
        return value
