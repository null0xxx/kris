"""Checks every read-only handler owes, in ONE place (T3.04).

``fs.read``, ``fs.list`` and ``fs.find`` each need the same four guarantees: the
call is bound to exactly one approved path, that path is not a §19 honeyfile, it
is not on the §7.3 DENY list, and the object actually opened is the object the
approval measured (§7.5 step 6). Three copies of a security check are three
places for the checks to drift apart, and the one that drifts is the one nobody
re-reads — so they live here and the handlers call them.
"""

from __future__ import annotations

import os
import stat as stat_module
import time
from typing import TYPE_CHECKING, Final

from lsassist.contracts.manifest import PathScope
from lsassist.policy.denylist import deny_match
from lsassist.tools.handlers import (
    CANARY_TRIPPED,
    DENY_PATH,
    READ_FAILED,
    TARGET_REPLACED,
    TIMED_OUT,
    WORKSPACE_SCOPE,
    HandlerRefused,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lsassist.tools.handlers import HandlerContext

__all__ = [
    "DIR_FLAGS",
    "FILE_FLAGS",
    "check_canary",
    "check_deadline",
    "check_denied",
    "check_within_workspace",
    "entry_is_allowed",
    "listdir_checked",
    "open_pinned_dir",
    "read_capped",
    "read_fd",
    "single_target",
    "verify_node",
]

#: Open a directory without following a symlink INTO it, so a swapped component
#: cannot redirect the traversal.
DIR_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

#: Open a file without following a symlink final component (§7.5 step 4).
FILE_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def single_target(context: HandlerContext) -> str:
    """The one canonical path this call was approved for."""
    paths = context.normalized.canonical_paths
    if len(paths) != 1:
        raise HandlerRefused(
            READ_FAILED,
            f"{context.manifest.name} is bound to exactly one approved path, got {len(paths)}",
        )
    return paths[0]


def check_canary(context: HandlerContext, path: str) -> None:
    """§19 scenario 1 — refuse BEFORE the file is opened, stat'd or digested.

    The detection value of a honeyfile is entirely in the attempt; a check that
    ran after the open would already have touched the decoy, and one that ran
    after the read could leak it.
    """
    if path in context.canary_paths:
        raise HandlerRefused(
            CANARY_TRIPPED,
            f"read attempt on canary honeyfile {path!r}; content is never returned",
        )


def check_denied(context: HandlerContext, path: str) -> None:
    """§7.3 handler-side double-check, delegated to the single authority."""
    if deny_match(path, context.environment.stores):
        raise HandlerRefused(DENY_PATH, f"{path!r} is on the §7.3 DENY_ALWAYS list")


def check_within_workspace(context: HandlerContext, path: str) -> None:
    """§6.2 ``path_scope`` — the check that made the declaration mean something.

    ``path_scope: workspace`` was on every read manifest and enforced NOWHERE:
    R2 fires only for ``{fs.write, fs.patch}``, ``AUTO_READ`` PROCEEDs at once,
    and ``canonicalize`` never sees a workspace. So the §7.3 blocklist was the
    only bound on a read, and everything outside its enumeration was readable —
    measured, not theorised: ``fs.read`` on ``~/.netrc`` returned the password.

    Segment-aware, so ``/ws-evil`` is not "inside" ``/ws``: a prefix comparison
    on the raw string would let a sibling directory pass by sharing characters.
    The workspace root itself IS inside itself — ``fs.list`` and ``fs.find`` are
    normally called on exactly that path.
    """
    if context.manifest.path_scope is not PathScope.WORKSPACE:
        return
    root = context.normalized.workspace_root
    if not root:
        raise HandlerRefused(
            WORKSPACE_SCOPE,
            f"{context.manifest.name} declares path_scope=workspace but no root was bound",
        )
    root_segments = [segment for segment in root.split("/") if segment]
    path_segments = [segment for segment in path.split("/") if segment]
    if path_segments[: len(root_segments)] != root_segments:
        raise HandlerRefused(
            WORKSPACE_SCOPE,
            f"{path!r} is outside the workspace {root!r} this tool is scoped to",
        )


def check_deadline(context: HandlerContext, what: str) -> None:
    """Stop if the manifest's ``timeout_s`` has elapsed.

    Called from inside the directory walks rather than once at entry: the whole
    failure mode is a walk that does not finish, so a check that only runs before
    it starts bounds nothing.
    """
    if context.deadline is not None and time.monotonic() > context.deadline:
        raise HandlerRefused(TIMED_OUT, f"{what} exceeded the {context.manifest.timeout_s}s budget")


def entry_is_allowed(context: HandlerContext, absolute: str) -> bool:
    """Per-entry §19 + §7.3 gate for a walk. Canary REFUSES; denied is skipped.

    A recursive tool inherits none of its root's checks, and both walks were
    asking these questions only once, at the top. Measured against this candidate:
    ``fs.find --mode name --pattern id_rsa`` returned a honeyfile's path with no
    alert, and ``--mode content`` opened and matched a nested ``proj/.env``.

    The two answers differ ON PURPOSE. A canary is a TRIPWIRE: reaching it is the
    event, so it raises and the whole call fails. A DENY path is simply not
    visible to this tool: skipping it silently is what "the tool cannot see it"
    means, and refusing the entire listing because one denied file exists
    somewhere below would make ``fs.list`` unusable in any real project (a
    workspace normally is a git checkout and commonly holds a ``.env``).
    """
    check_canary(context, absolute)
    return not deny_match(absolute, context.environment.stores)


def listdir_checked(fd: int, label: str) -> list[str]:
    """``os.listdir`` on a directory fd, converted to a typed refusal.

    Every other syscall in these handlers was already wrapped; this was the one
    the pattern missed, and an ``OSError`` from it escaped ``run()`` entirely —
    no ``ToolResult``, no §14.1 record. §6.3 step 9 has to journal every outcome,
    including the ones nobody planned for.
    """
    try:
        return os.listdir(fd)
    except OSError as exc:
        raise HandlerRefused(READ_FAILED, f"cannot list {label!r}: {exc!r}") from exc


def approved_identity(context: HandlerContext, target: str) -> tuple[int, int, int, int]:
    """``(parent_dev, parent_ino, node_dev, node_ino)`` captured at approval time.

    A missing snapshot is a REFUSAL, not a skipped check: the pin is the only
    thing standing between this call and a same-path swap, so "no baseline" must
    fail closed rather than proceed unverified.
    """
    for snapshot in context.normalized.path_snapshots:
        if snapshot.canonical_path == target:
            return (
                snapshot.parent_dev,
                snapshot.parent_ino,
                snapshot.node_dev,
                snapshot.node_ino,
            )
    raise HandlerRefused(
        TARGET_REPLACED,
        f"no approval-time snapshot for {target!r}; the inode pin cannot be verified",
    )


def verify_node(fd: int, want_dev: int, want_ino: int, target: str) -> os.stat_result:
    """§7.5 step 6: the object behind ``fd`` is the object approval measured."""
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino) != (want_dev, want_ino):
        raise HandlerRefused(
            TARGET_REPLACED,
            f"{target!r} is inode {info.st_ino} but was approved as {want_ino}",
        )
    return info


def open_pinned_dir(context: HandlerContext, target: str) -> int:
    """Open ``target`` as a directory, pinned to its approved identity.

    Both halves are checked: the PARENT the name resolves through, and the
    directory itself. Verifying only the leaf would let a swapped parent hand
    back a different tree whose root happened to match.

    :returns: an owned fd — the caller closes it.
    """
    parent = os.path.dirname(target)
    name = os.path.basename(target)
    if not parent or not name:
        raise HandlerRefused(READ_FAILED, f"{target!r} has no parent/name to open against")
    want_parent_dev, want_parent_ino, want_node_dev, want_node_ino = approved_identity(
        context, target
    )
    try:
        parent_fd = os.open(parent, DIR_FLAGS)
    except OSError as exc:
        raise HandlerRefused(READ_FAILED, f"cannot open parent of {target!r}: {exc!r}") from exc
    try:
        parent_info = os.fstat(parent_fd)
        if (parent_info.st_dev, parent_info.st_ino) != (want_parent_dev, want_parent_ino):
            raise HandlerRefused(
                TARGET_REPLACED,
                f"parent of {target!r} was swapped between approval and open",
            )
        try:
            fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            raise HandlerRefused(READ_FAILED, f"cannot open {target!r}: {exc!r}") from exc
    finally:
        os.close(parent_fd)
    try:
        info = verify_node(fd, want_node_dev, want_node_ino, target)
        if not stat_module.S_ISDIR(info.st_mode):
            raise HandlerRefused(READ_FAILED, f"{target!r} is not a directory")
    except HandlerRefused:
        os.close(fd)
        raise
    return fd


def read_fd(fd: int, limit: int, label: str) -> bytes:
    """Read at most ``limit`` bytes from an ALREADY-OPEN ``fd``.

    Taking an fd rather than a name is the whole point for a pinned read: the
    caller has already ``fstat``ed this descriptor against the approval-time
    identity, and re-opening by name to read would hand the bytes back from
    whatever the name means NOW — reopening the exact TOCTOU window the pin just
    closed.

    Loops because a single ``os.read`` may return short even on a regular file;
    trusting one call would make a prefix look like a whole file, which for
    ``fs.find --mode content`` is the difference between "no match" and "did not
    look".
    """
    chunks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        try:
            chunk = os.read(fd, remaining)
        except InterruptedError:  # pragma: no cover - retried, not observable
            continue
        except OSError as exc:
            raise HandlerRefused(READ_FAILED, f"cannot read {label!r}: {exc!r}") from exc
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_capped(dir_fd: int, name: str, limit: int, label: str) -> bytes:
    """Open ``name`` relative to ``dir_fd`` and read at most ``limit`` bytes.

    For callers with NO per-file approval to pin against — ``fs.find --mode
    content`` walks files the approval never named individually, so there is no
    inode identity for them to match. A caller that DOES hold a pinned fd must
    use :func:`read_fd` on it instead.
    """
    try:
        fd = os.open(name, FILE_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        raise HandlerRefused(READ_FAILED, f"cannot open {label!r}: {exc!r}") from exc
    try:
        return read_fd(fd, limit, label)
    finally:
        os.close(fd)
