"""T1.11 RED: PolicyContext contract model (SPEC §7.2 R3, §9.4, §2.2).

``PolicyContext`` carries the per-request classification context for the
policy engine: ``workspace_root`` (absolute, lexically-normalized path),
``untrusted_turn`` (§4.6/R3 — any non-AUTO_READ raises to CONFIRM_EXACT) and
``skill_ceiling`` (§9.4 — the skill's ``permission_class_max`` for the current
turn, or ``None`` when no skill is injected).

The ``workspace_root`` validator is PURE (§2.2: stdlib + pydantic only; no I/O,
no child processes, no network). It enforces absolute + lexically-normalized
ONLY. Realpath/symlink canonicalization is the CALLER's responsibility (the
dispatcher, §7.5 / §6.3 step 2, T3.02), where filesystem access is legitimate.
These tests therefore use pure literal absolute paths — NOT ``tmp_path`` — so
the contract layer is exercised without any dependence on filesystem state.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from lsassist.contracts.enums import PermissionClass
from lsassist.contracts.policy_context import PolicyContext

# A pure literal absolute + lexically-normalized path. No filesystem access,
# no tmp_path: the contract validator must accept/reject on string form alone.
ROOT = "/ws/project"


# --- (1) fields and defaults --------------------------------------------------------


def test_fields_and_defaults() -> None:
    ctx = PolicyContext(workspace_root=ROOT)
    assert ctx.workspace_root == ROOT
    assert ctx.untrusted_turn is False  # §4.6/R3 default: turn is trusted
    assert ctx.skill_ceiling is None  # §9.4: no skill injected -> no ceiling


def test_all_fields_set() -> None:
    ctx = PolicyContext(
        workspace_root=ROOT,
        untrusted_turn=True,
        skill_ceiling=PermissionClass.AUTO_READ,
    )
    assert ctx.untrusted_turn is True
    assert ctx.skill_ceiling is PermissionClass.AUTO_READ


def test_frozen() -> None:
    ctx = PolicyContext(workspace_root=ROOT)
    with pytest.raises(ValidationError):
        ctx.workspace_root = "/ws/other"  # type: ignore[misc]


# --- (2) §2.2 purity: construction performs NO filesystem I/O -----------------------


def test_construction_does_no_filesystem_io(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ``workspace_root`` validator must not touch the filesystem (§2.2).

    ``Path.resolve`` and ``os.path.realpath`` are the symlink-resolving
    filesystem calls a canonicalizing validator would reach for; both are
    trip-wired here. Constructing a ``PolicyContext`` from a literal
    absolute+normalized path must succeed without firing either.

    (``os.stat``/``os.readlink`` are deliberately NOT patched: they are load-
    bearing for the Python runtime and pytest itself, so a global override
    corrupts the test session rather than the code under test. The two guards
    above are exactly the calls the pre-fix validator invoked.)
    """

    def _boom(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("filesystem I/O in pure contract layer")

    monkeypatch.setattr("pathlib.Path.resolve", _boom)
    monkeypatch.setattr("os.path.realpath", _boom)

    ctx = PolicyContext(workspace_root=ROOT)
    assert ctx.workspace_root == ROOT


# --- (3) workspace_root must be an absolute, lexically-normalized path ---------------


@pytest.mark.parametrize("relative", ["relative/path", ".", "..", "src/../x"])
def test_relative_workspace_root_rejected(relative: str) -> None:
    with pytest.raises(ValidationError):
        PolicyContext(workspace_root=relative)


@pytest.mark.parametrize(
    "non_normalized",
    [
        "/ws/project/.",  # trailing "/." — normpath collapses it
        "/ws/project/sub/..",  # ".." component — normpath collapses it
        "/ws//project",  # doubled slash — normpath collapses it
    ],
)
def test_non_normalized_workspace_root_rejected(non_normalized: str) -> None:
    # Purely lexical: no filesystem access required to reject these.
    with pytest.raises(ValidationError):
        PolicyContext(workspace_root=non_normalized)


# --- (4) skill_ceiling is a PermissionClass or None ----------------------------------


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
    ceiling: PermissionClass | str | None,
) -> None:
    ctx = PolicyContext(workspace_root=ROOT, skill_ceiling=ceiling)
    assert ctx.skill_ceiling is None or isinstance(ctx.skill_ceiling, PermissionClass)


@pytest.mark.parametrize("bad_ceiling", ["not_a_class", "auto_read", "", 42])
def test_skill_ceiling_rejects_non_permission_class(bad_ceiling: object) -> None:
    with pytest.raises(ValidationError):
        PolicyContext(workspace_root=ROOT, skill_ceiling=bad_ceiling)
