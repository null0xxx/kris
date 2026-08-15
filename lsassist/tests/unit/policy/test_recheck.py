"""T2.04: pre-exec re-canonicalization + invalidation vectors (§7.5 steps 1-3, I6).

Two test surfaces, per the design:

- REAL fs-mutation cases drive :class:`OsFsView` over ``tmp_path`` (the §7.5 I/O
  boundary): approve→snapshot a real file, then mutate the tree and assert the
  four I6 invalidation vectors (retarget / parent swap / node replace via
  rename-over / dangling) plus NODE_REPLACED-on-in-place-content-change (an
  in-place write bumps the node ``st_ctime_ns`` — a material change now
  invalidates the approval, per I6).
- PURE-logic cases drive :func:`recheck` / :func:`snapshot_paths` over a
  hand-written fake :class:`FsView` (no real I/O) to pin first-failure ORDER
  (both within one snapshot and across a sequence) deterministically.
- ``validate_session_remember`` is the §7.4 V1 "session-remember" rule.
- the FAIL-CLOSED ``OSError`` arms of :class:`OsFsView` are driven by really
  unlinking the node / its parent under ``tmp_path`` mid-flight (the racing
  ``unlink`` the boundary exists to survive), asserting the TYPED
  :class:`RecheckError` rather than a leaked ``OSError`` or a silent pass.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from lsassist.policy.recheck import (
    UNLIMITED_USES_SENTINEL,
    OsFsView,
    PathSnapshot,
    RecheckError,
    RecheckVerdict,
    recheck,
    snapshot_paths,
    validate_session_remember,
)

# ---------------------------------------------------------------------------
# A pure in-memory fake FsView for the deterministic logic/order cases.
# ---------------------------------------------------------------------------


@dataclass
class _FakeEntry:
    exists: bool
    realpath: str
    parent: tuple[int, int, int]  # dev, ino, ctime_ns
    node: tuple[int, int, int]


class FakeFsView:
    """Hand-written :class:`FsView` over a fixed dict — NO real I/O."""

    def __init__(self, entries: dict[str, _FakeEntry]) -> None:
        self._entries = entries

    def realpath(self, path: str) -> str:
        return self._entries[path].realpath

    def parent_ids(self, path: str) -> tuple[int, int, int]:
        return self._entries[path].parent

    def node_ids(self, path: str) -> tuple[int, int, int]:
        return self._entries[path].node

    def exists(self, path: str) -> bool:
        return self._entries[path].exists


def _snap(
    path: str, parent: tuple[int, int, int], node: tuple[int, int, int]
) -> PathSnapshot:
    return PathSnapshot(
        canonical_path=path,
        parent_dev=parent[0],
        parent_ino=parent[1],
        parent_ctime_ns=parent[2],
        node_dev=node[0],
        node_ino=node[1],
        node_ctime_ns=node[2],
    )


# ---------------------------------------------------------------------------
# REAL fs mutations over OsFsView + tmp_path (the §7.5 boundary).
# ---------------------------------------------------------------------------


def _approve(tmp_path: Path) -> tuple[Path, str, tuple[PathSnapshot, ...], OsFsView]:
    """Set up /d/file, canonicalize it, and snapshot it at 'approval' time."""
    parent = tmp_path / "d"
    parent.mkdir()
    target = parent / "file"
    target.write_text("original", encoding="utf-8")
    fs = OsFsView()
    canonical = os.path.realpath(target)
    snapshots = snapshot_paths([canonical], fs)
    return target, canonical, snapshots, fs


def test_recheck_valid_when_nothing_changed(tmp_path: Path) -> None:
    _target, _canonical, snapshots, fs = _approve(tmp_path)
    assert recheck(snapshots, fs) is RecheckVerdict.VALID


def test_recheck_path_retargeted_on_symlink_swap(tmp_path: Path) -> None:
    target, _canonical, snapshots, fs = _approve(tmp_path)
    other = tmp_path / "other"
    other.write_text("y", encoding="utf-8")
    # Replace the approved final component with a symlink to a DIFFERENT file:
    # the path still exists, but no longer re-resolves to itself (I6).
    target.unlink()
    target.symlink_to(other)
    assert recheck(snapshots, fs) is RecheckVerdict.PATH_RETARGETED


def test_recheck_parent_swapped_on_parent_rename_recreate(tmp_path: Path) -> None:
    target, _canonical, snapshots, fs = _approve(tmp_path)
    parent = target.parent
    # Rename the parent away (old inode kept alive as d_old) and recreate it +
    # the file with a FRESH parent inode: path exists and re-resolves to itself,
    # but the parent (dev, ino) changed (I6 — rename+recreate / mount swap).
    parent.rename(tmp_path / "d_old")
    new_parent = tmp_path / "d"
    new_parent.mkdir()
    (new_parent / "file").write_text("original", encoding="utf-8")
    assert recheck(snapshots, fs) is RecheckVerdict.PARENT_SWAPPED


def test_recheck_node_replaced_on_atomic_rename_over(tmp_path: Path) -> None:
    # C1 regression: an approved file atomically REPLACED by a different real
    # file of the same name in the same parent (write `.new` + `os.rename` over
    # -> NEW inode; realpath + parent (dev,ino) both unchanged). For READ/EXEC
    # tools there is NO downstream backstop (step-6 is write-only, SPEC:564), so
    # recheck MUST catch it here via the captured identities.
    target, _canonical, snapshots, fs = _approve(tmp_path)
    ino_before = os.stat(target).st_ino
    replacement = target.parent / "file.new"
    replacement.write_text("attacker-controlled content", encoding="utf-8")
    os.rename(replacement, target)  # atomic same-name swap
    assert os.stat(target).st_ino != ino_before  # genuinely a new inode
    assert os.path.realpath(target) == _canonical  # realpath unchanged
    # Staging `.new` inside the parent and renaming over it MODIFIES the parent
    # directory (a dirent is added/renamed), which bumps the parent's
    # st_ctime_ns — so under the three-field identity the FIRST failure is the
    # parent, and the verdict is PARENT_SWAPPED. Fail-closed either way; the
    # NODE-only vector (same parent ctime) is pinned deterministically by the
    # pure fake-view cases below and by the in-place-write case above.
    assert recheck(snapshots, fs) is RecheckVerdict.PARENT_SWAPPED


def test_recheck_dangling_on_delete(tmp_path: Path) -> None:
    target, _canonical, snapshots, fs = _approve(tmp_path)
    target.unlink()
    assert recheck(snapshots, fs) is RecheckVerdict.DANGLING


def test_recheck_rejects_inplace_content_change_same_inode(tmp_path: Path) -> None:
    target, _canonical, snapshots, fs = _approve(tmp_path)
    ino_before = os.stat(target).st_ino
    # IN-PLACE truncate+rewrite (open("w")) keeps the SAME inode but bumps the
    # node's st_ctime_ns -> a material change INVALIDATES the approval (I6) and
    # the recheck fails closed as NODE_REPLACED. This stricter reapproval
    # behavior is intentional: it is what closes the recycled-inode hole.
    target.write_text("COMPLETELY DIFFERENT AND LONGER CONTENT", encoding="utf-8")
    assert os.stat(target).st_ino == ino_before
    assert recheck(snapshots, fs) is RecheckVerdict.NODE_REPLACED


# ---------------------------------------------------------------------------
# PURE logic + deterministic first-failure ORDER over the fake FsView.
# ---------------------------------------------------------------------------


def test_snapshot_paths_captures_parent_and_node_ids_pure() -> None:
    fs = FakeFsView(
        {
            "/ws/a": _FakeEntry(True, "/ws/a", parent=(3, 7, 90), node=(3, 70, 100)),
            "/ws/b": _FakeEntry(True, "/ws/b", parent=(4, 8, 91), node=(4, 80, 101)),
        }
    )
    snaps = snapshot_paths(["/ws/a", "/ws/b"], fs)
    assert snaps == (
        _snap("/ws/a", parent=(3, 7, 90), node=(3, 70, 100)),
        _snap("/ws/b", parent=(4, 8, 91), node=(4, 80, 101)),
    )


def test_recheck_pure_all_clean_is_valid() -> None:
    p = "/ws/a"
    fs = FakeFsView({p: _FakeEntry(True, p, parent=(1, 1, 1), node=(1, 10, 1))})
    assert recheck([_snap(p, parent=(1, 1, 1), node=(1, 10, 1))], fs) is RecheckVerdict.VALID


def test_recheck_rejects_a_recycled_node_number() -> None:
    # The recycled-inode hole: SAME (dev, ino) as approved, but the node was
    # unlinked+recreated and the inode number was reused -> only the ctime
    # differs, and that alone must fail closed (I6).
    path = "/ws/a"
    approved = (3, 70, 100)
    fs = FakeFsView(
        {path: _FakeEntry(True, path, parent=(3, 7, 90), node=(3, 70, 200))}
    )
    assert recheck([_snap(path, parent=(3, 7, 90), node=approved)], fs) \
        is RecheckVerdict.NODE_REPLACED


def test_recheck_rejects_a_recycled_parent_number() -> None:
    path = "/ws/a"
    fs = FakeFsView(
        {path: _FakeEntry(True, path, parent=(3, 7, 200), node=(3, 70, 100))}
    )
    assert recheck([_snap(path, parent=(3, 7, 90), node=(3, 70, 100))], fs) \
        is RecheckVerdict.PARENT_SWAPPED


def test_recheck_pure_dangling_precedes_everything() -> None:
    # A snapshot that is SIMULTANEOUSLY vanished + retargeted + reparented +
    # node-replaced must report DANGLING (existence is checked first).
    p = "/ws/a"
    fs = FakeFsView({p: _FakeEntry(False, "/other", parent=(9, 9, 9), node=(9, 90, 9))})
    assert recheck([_snap(p, parent=(1, 1, 1), node=(1, 10, 1))], fs) is RecheckVerdict.DANGLING


def test_recheck_pure_retarget_precedes_parent_and_node() -> None:
    p = "/ws/a"
    fs = FakeFsView({p: _FakeEntry(True, "/other", parent=(9, 9, 9), node=(9, 90, 9))})
    assert (
        recheck([_snap(p, parent=(1, 1, 1), node=(1, 10, 1))], fs)
        is RecheckVerdict.PATH_RETARGETED
    )


def test_recheck_pure_parent_precedes_node() -> None:
    # Parent swapped AND node replaced -> PARENT_SWAPPED wins (checked first).
    p = "/ws/a"
    fs = FakeFsView({p: _FakeEntry(True, p, parent=(9, 9, 9), node=(9, 90, 9))})
    assert (
        recheck([_snap(p, parent=(1, 1, 1), node=(1, 10, 1))], fs)
        is RecheckVerdict.PARENT_SWAPPED
    )


def test_recheck_pure_node_only_is_node_replaced() -> None:
    # Exists, re-resolves to self, same parent, but the node's own inode changed
    # -> the atomic rename-over vector.
    p = "/ws/a"
    fs = FakeFsView({p: _FakeEntry(True, p, parent=(1, 1, 1), node=(9, 90, 9))})
    assert (
        recheck([_snap(p, parent=(1, 1, 1), node=(1, 10, 1))], fs)
        is RecheckVerdict.NODE_REPLACED
    )


def test_recheck_returns_first_failure_in_snapshot_order() -> None:
    p_ret = "/ws/ret"
    p_dang = "/ws/dang"
    fs = FakeFsView(
        {
            p_ret: _FakeEntry(True, "/other", parent=(1, 1, 1), node=(1, 10, 1)),
            p_dang: _FakeEntry(False, p_dang, parent=(2, 2, 2), node=(2, 20, 2)),
        }
    )
    snap_ret = _snap(p_ret, parent=(1, 1, 1), node=(1, 10, 1))
    snap_dang = _snap(p_dang, parent=(2, 2, 2), node=(2, 20, 2))
    # First failing snapshot in the given order wins (deterministic).
    assert recheck([snap_ret, snap_dang], fs) is RecheckVerdict.PATH_RETARGETED
    assert recheck([snap_dang, snap_ret], fs) is RecheckVerdict.DANGLING


def test_recheck_empty_snapshots_is_valid() -> None:
    fs = FakeFsView({})
    assert recheck([], fs) is RecheckVerdict.VALID


# ---------------------------------------------------------------------------
# §7.4 session-scoped "remember" (V1 compromise).
# ---------------------------------------------------------------------------


def test_session_remember_unlimited_at_session_ttl_allowed() -> None:
    assert (
        validate_session_remember(
            UNLIMITED_USES_SENTINEL, ttl_s=3600, session_ttl_s=3600, unlimited=True
        )
        is True
    )


def test_session_remember_unlimited_at_nonsession_ttl_rejected() -> None:
    assert (
        validate_session_remember(
            UNLIMITED_USES_SENTINEL, ttl_s=300, session_ttl_s=3600, unlimited=True
        )
        is False
    )


def test_session_remember_bounded_allowed_any_ttl() -> None:
    assert validate_session_remember(1, ttl_s=300, session_ttl_s=3600, unlimited=False) is True
    assert validate_session_remember(5, ttl_s=3600, session_ttl_s=3600, unlimited=False) is True


# ---------------------------------------------------------------------------
# OsFsView — the §7.5 I/O boundary must fail CLOSED on a racing OSError.
#
# These are REAL fs races, not injected ones: the probed node (or its parent)
# is genuinely unlinked between the approval-time snapshot and the probe, which
# is exactly the mid-check ``unlink`` the try/except exists for. The contract is
# that such a race raises the TYPED ``RecheckError`` — it must never leak a raw
# ``OSError`` into the policy path (where a caller might not read it as a
# refusal) and must never be mistaken for a passing recheck.
# ---------------------------------------------------------------------------


def test_osfsview_node_ids_raises_recheck_error_when_the_node_is_unlinked(
    tmp_path: Path,
) -> None:
    target = tmp_path / "f"
    target.write_text("x", encoding="utf-8")
    view = OsFsView()
    before = view.node_ids(str(target))  # baseline: the happy path really works
    info = os.stat(target)
    assert before == (info.st_dev, info.st_ino, info.st_ctime_ns)

    target.unlink()  # the racing unlink

    with pytest.raises(RecheckError) as excinfo:
        view.node_ids(str(target))
    assert "node stat failed" in str(excinfo.value)
    assert str(target) in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, OSError)


def test_osfsview_parent_ids_raises_recheck_error_when_the_parent_is_unlinked(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "d"
    parent.mkdir()
    target = parent / "f"
    target.write_text("x", encoding="utf-8")
    view = OsFsView()
    before = view.parent_ids(str(target))  # baseline: the happy path really works
    info = os.stat(parent)
    assert before == (info.st_dev, info.st_ino, info.st_ctime_ns)

    target.unlink()
    parent.rmdir()  # the racing unlink of the PARENT

    with pytest.raises(RecheckError) as excinfo:
        view.parent_ids(str(target))
    assert "parent stat failed" in str(excinfo.value)
    assert str(target) in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, OSError)


def test_snapshot_paths_over_the_real_boundary_fails_closed_on_a_racing_unlink(
    tmp_path: Path,
) -> None:
    """The typed failure PROPAGATES: a path that vanishes between approval and
    §7.5 step 2 aborts ``snapshot_paths`` instead of yielding a snapshot."""
    target = tmp_path / "f"
    target.write_text("x", encoding="utf-8")
    assert snapshot_paths([str(target)], OsFsView())  # baseline: snapshots fine

    target.unlink()

    with pytest.raises(RecheckError):
        snapshot_paths([str(target)], OsFsView())


def test_snapshot_paths_over_the_real_boundary_fails_closed_when_parent_vanishes(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "d"
    parent.mkdir()
    target = parent / "f"
    target.write_text("x", encoding="utf-8")
    assert snapshot_paths([str(target)], OsFsView())  # baseline: snapshots fine

    target.unlink()
    parent.rmdir()

    with pytest.raises(RecheckError):
        snapshot_paths([str(target)], OsFsView())
