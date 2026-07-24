"""T1.11 RED: PolicyContext contract model (SPEC §7.2 R3, §9.4).

``PolicyContext`` carries the per-request classification context for the
policy engine: ``workspace_root`` (canonical absolute path), ``untrusted_turn``
(§4.6/R3 — any non-AUTO_READ raises to CONFIRM_EXACT) and ``skill_ceiling``
(§9.4 — the skill's ``permission_class_max`` for the current turn, or ``None``
when no skill is injected).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from lsassist.contracts.enums import PermissionClass
from lsassist.contracts.policy_context import PolicyContext


def _canonical_root(tmp_path: object) -> str:
    """Return the canonical (fully resolved) form of pytest's tmp_path."""
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    return str(tmp_path.resolve())


# --- (1) fields and defaults --------------------------------------------------------


def test_fields_and_defaults(tmp_path: object) -> None:
    root = _canonical_root(tmp_path)
    ctx = PolicyContext(workspace_root=root)
    assert ctx.workspace_root == root
    assert ctx.untrusted_turn is False  # §4.6/R3 default: turn is trusted
    assert ctx.skill_ceiling is None  # §9.4: no skill injected -> no ceiling


def test_all_fields_set(tmp_path: object) -> None:
    root = _canonical_root(tmp_path)
    ctx = PolicyContext(
        workspace_root=root,
        untrusted_turn=True,
        skill_ceiling=PermissionClass.AUTO_READ,
    )
    assert ctx.untrusted_turn is True
    assert ctx.skill_ceiling is PermissionClass.AUTO_READ


# --- (2) workspace_root must be a canonical absolute path ---------------------------


@pytest.mark.parametrize("relative", ["relative/path", ".", "..", "src/../x"])
def test_relative_workspace_root_rejected(relative: str) -> None:
    with pytest.raises(ValidationError):
        PolicyContext(workspace_root=relative)


def test_non_canonical_workspace_root_rejected(tmp_path: object) -> None:
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    root = str(tmp_path.resolve())
    # "/." suffix resolves away -> not canonical.
    with pytest.raises(ValidationError):
        PolicyContext(workspace_root=root + "/.")
    # ".." component resolves away -> not canonical.
    with pytest.raises(ValidationError):
        PolicyContext(workspace_root=root + "/sub/..")


# --- (3) skill_ceiling is a PermissionClass or None ----------------------------------


@pytest.mark.parametrize(
    "ceiling",
    [
        PermissionClass.AUTO_READ,
        PermissionClass.AUTO_SCOPED_WRITE,
        PermissionClass.CONFIRM_ONCE,
        PermissionClass.CONFIRM_EXACT,
        PermissionClass.DENY_ALWAYS,
        "AUTO_READ",  # enum-coercible wire value
        None,
    ],
)
def test_skill_ceiling_accepts_permission_class_or_none(
    tmp_path: object, ceiling: PermissionClass | str | None
) -> None:
    ctx = PolicyContext(workspace_root=_canonical_root(tmp_path), skill_ceiling=ceiling)
    assert ctx.skill_ceiling is None or isinstance(ctx.skill_ceiling, PermissionClass)


@pytest.mark.parametrize("bad_ceiling", ["not_a_class", "auto_read", "", 42])
def test_skill_ceiling_rejects_non_permission_class(
    tmp_path: object, bad_ceiling: object
) -> None:
    with pytest.raises(ValidationError):
        PolicyContext(workspace_root=_canonical_root(tmp_path), skill_ceiling=bad_ceiling)
