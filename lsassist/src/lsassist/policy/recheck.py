"""§7.5 steps 1-3: pre-exec re-canonicalization + invalidation vectors (I6).

This module implements the POLICY side of the §7.5 TOCTOU chain, steps 1-3:

- step 1 (approval canonicalization) is done UPSTREAM by ``canonical.py``
  (``realpath`` + per-component ``lstat``); this module consumes its output;
- step 2 (token stores canonical paths + parent dir inode + node identity) is
  :func:`snapshot_paths` — it captures, per already-canonical path, the parent
  directory's ``(st_dev, st_ino)`` AND the node's OWN ``(st_dev, st_ino)`` at
  approval;
- step 3 (pre-exec re-canonicalization → identity compare) is :func:`recheck` —
  it re-resolves each snapshotted path just before execution and, fail-closed,
  reports the FIRST I6 invalidation it finds (dangling / retargeted / parent
  swapped / node replaced), else :data:`RecheckVerdict.VALID`.

Steps 4-7 (handler ``O_NOFOLLOW``/dirfd open, bwrap final view, post-exec
inode/hash verification, wildcard exclusion) are TOOLS/SANDBOX-phase concerns
and are OUT OF SCOPE here; step 8 (no command substitution) is structural
(argv exec, no shell — ADR-010). This module covers ONLY the policy-side
re-canonicalization gate.

BEST-EFFORT, NOT A CONTENT-INTEGRITY ORACLE (residual, documented honestly per
atlas §10): the node ``(dev, ino)`` check catches an atomic rename-over swap (a
DIFFERENT real file of the same name in the same parent — new inode), but it is
NOT complete: an ``unlink`` + recreate that REUSES the freed inode number keeps
the same ``(dev, ino)`` and is NOT caught here, and recheck never reads content.
FULL file-identity / content integrity is the HANDLER's job — §7.5 step 4 (open
``O_NOFOLLOW`` + ``dir_fd`` then ``fstat`` the SAME fd) and step 6 (post-exec
inode + sha256 compare). recheck is a pre-filter over path STRUCTURE + node
identity, not a byte-level oracle.

CROSS-PHASE FLAG (tools phase T3.x MUST close this): SPEC §7.5 step 6 post-exec
verification is currently scoped to WRITE tools (SPEC:564), so a same-path
file-swap has NO backstop for READ/EXEC tools once recheck passes. The tools
phase MUST either extend step 6 to read/exec, or have read/exec handlers
fstat-PIN the opened inode (open ``O_NOFOLLOW`` + ``dir_fd``, then ``fstat`` and
compare to the approval-time node identity captured here) — otherwise a
read/exec file-swap TOCTOU remains open. This is a SPEC/handler-phase concern
surfaced here; it is NOT fully closable inside recheck.

PURITY (§2.2): the recheck LOGIC (:func:`recheck`, :func:`snapshot_paths`,
:func:`validate_session_remember`) is PURE — it does NO filesystem I/O and
reaches the filesystem only through an injected :class:`FsView`. The SOLE
concrete, syscall-performing implementation is :class:`OsFsView`; that adapter
is the §7.5 I/O boundary, mirroring canonical.py's documented exception to the
package purity rule. Tests drive the pure logic with a hand-written fake
``FsView`` (no real I/O).
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol


class RecheckError(Exception):
    """A recheck fs probe hit an ``OSError`` (e.g. a mid-check ``unlink`` of the
    path or its parent). Raised FAIL-CLOSED by :class:`OsFsView` so a racing /
    vanished path surfaces as a clear typed error rather than an uncaught
    ``OSError`` — and is NEVER mistaken for a passing recheck (never VALID)."""


class FsView(Protocol):
    """The minimal read-only filesystem surface the §7.5 recheck depends on.

    Dependency-injected so the recheck logic stays PURE: :func:`recheck` and
    :func:`snapshot_paths` call only these methods and perform no syscalls
    themselves. Production wiring passes :class:`OsFsView`; tests pass a fake.
    """

    def realpath(self, path: str) -> str:
        """The fully-resolved real path of ``path`` (symlinks + ``..`` collapsed)."""
        ...

    def parent_ids(self, path: str) -> tuple[int, int]:
        """The ``(st_dev, st_ino)`` of the PARENT directory of ``path``."""
        ...

    def node_ids(self, path: str) -> tuple[int, int]:
        """The ``(st_dev, st_ino)`` of ``path`` ITSELF (the file's own inode)."""
        ...

    def exists(self, path: str) -> bool:
        """Whether ``path`` currently exists on the filesystem."""
        ...


class RecheckVerdict(StrEnum):
    """Fail-closed outcome of the pre-exec re-canonicalization (§7.5 step 3).

    Only :data:`VALID` authorizes proceeding to the handler phase (§7.5 step 4+).
    The four failure verdicts are the I6 invalidation vectors, each forcing
    re-approval.
    """

    VALID = "VALID"
    DANGLING = "DANGLING"
    PATH_RETARGETED = "PATH_RETARGETED"
    PARENT_SWAPPED = "PARENT_SWAPPED"
    NODE_REPLACED = "NODE_REPLACED"


@dataclass(frozen=True, slots=True)
class PathSnapshot:
    """Approval-time capture for ONE canonical path (§7.5 step 2).

    Stores the canonical path, its parent directory's ``(st_dev, st_ino)``, and
    the node's OWN ``(st_dev, st_ino)`` at approval time — so :func:`recheck` can
    later detect (a) a parent rename+recreate / mount swap that changed the
    parent inode and (b) an atomic rename-over that replaced the file with a new
    inode. Frozen — a snapshot is a value.
    """

    canonical_path: str
    parent_dev: int
    parent_ino: int
    node_dev: int
    node_ino: int


def snapshot_paths(canonical_paths: Sequence[str], fs_view: FsView) -> tuple[PathSnapshot, ...]:
    """Capture a :class:`PathSnapshot` per canonical path NOW (§7.5 step 2).

    PURE over ``fs_view`` (only the injected boundary performs any real I/O).
    Inputs are ALREADY-canonical paths (produced upstream by
    ``canonical.canonicalize``); this records each one's current parent
    ``(dev, ino)`` AND node ``(dev, ino)`` for the later pre-exec comparison,
    preserving input order.
    """
    snapshots: list[PathSnapshot] = []
    for path in canonical_paths:
        parent_dev, parent_ino = fs_view.parent_ids(path)
        node_dev, node_ino = fs_view.node_ids(path)
        snapshots.append(
            PathSnapshot(
                canonical_path=path,
                parent_dev=parent_dev,
                parent_ino=parent_ino,
                node_dev=node_dev,
                node_ino=node_ino,
            )
        )
    return tuple(snapshots)


def recheck(snapshots: Sequence[PathSnapshot], fs_view: FsView) -> RecheckVerdict:
    """Re-canonicalize each snapshot pre-exec and detect invalidation (§7.5 step 3).

    For EACH snapshot, in order, four fail-closed checks (I6), applied in this
    priority:

    1. ``exists`` is False -> :data:`RecheckVerdict.DANGLING`: a path present at
       approval that vanished. There is NO create-intent carve-out at RE-CHECK
       time for an existing-then-vanished path. (A token minted for a
       create-intent path that was never expected to exist yet is OUT OF SCOPE
       here — that recheck is the caller's / dispatcher's job; this function
       assumes every snapshotted path was present at approval.)
    2. re-resolution differs from the canonical path -> :data:`PATH_RETARGETED`:
       the path no longer resolves to itself, i.e. a component became or was
       retargeted to a symlink (I6).
    3. parent ``(dev, ino)`` differs from the snapshot -> :data:`PARENT_SWAPPED`:
       the parent dir was renamed+recreated / mount-swapped to a new inode (I6).
    4. node ``(dev, ino)`` differs from the snapshot -> :data:`NODE_REPLACED`:
       the file itself was atomically replaced (``.new`` + ``os.rename`` over the
       approved name → SAME path + SAME parent but a NEW inode) (I6).

    Returns the FIRST failing snapshot's verdict (deterministic snapshot order),
    else :data:`VALID`.

    An IN-PLACE CONTENT change at the SAME path+inode (truncate+rewrite,
    ``open("w")``) keeps the same node ``(dev, ino)`` -> passes check 4 -> stays
    :data:`VALID`: content is NOT a path-level invalidator; content integrity is
    the handler's job (§7.5 step 4). ONLY a file REPLACEMENT (new inode) trips
    :data:`NODE_REPLACED`. BEST-EFFORT residual (see module docstring): an
    inode-number-reusing ``unlink``+recreate is NOT caught here.
    """
    for snapshot in snapshots:
        canonical = snapshot.canonical_path
        if not fs_view.exists(canonical):
            return RecheckVerdict.DANGLING
        if fs_view.realpath(canonical) != canonical:
            return RecheckVerdict.PATH_RETARGETED
        if fs_view.parent_ids(canonical) != (snapshot.parent_dev, snapshot.parent_ino):
            return RecheckVerdict.PARENT_SWAPPED
        # §7.5 step-3 "resolve → compare" extended to the NODE's own identity:
        # catches an atomic same-name rename-over (new inode) that checks 2-3
        # miss. CROSS-PHASE (read/exec): passing here is only a pre-filter — a
        # same-path swap in the exec window has no post-exec backstop for
        # READ/EXEC tools (SPEC:564 = write-only); the handler phase (T3.x) must
        # fstat-pin the opened inode. See the module-level CROSS-PHASE FLAG.
        if fs_view.node_ids(canonical) != (snapshot.node_dev, snapshot.node_ino):
            return RecheckVerdict.NODE_REPLACED
    return RecheckVerdict.VALID


# DEFERRED CONTRACT DECISION: ``ApprovalRecord.max_uses`` is ``int`` with ``ge=1``
# (contracts/approval.py) — it has NO representation for the §7.4 "∞ uses" of a
# session-scoped "remember". Modelling unbounded uses at the CONTRACT level is
# deferred to a later contract revision; this task does NOT widen the contract.
# Until then the unlimited case is modelled with an explicit ``unlimited`` flag,
# and this sentinel documents the stand-in ``max_uses`` a caller passes then.
UNLIMITED_USES_SENTINEL: Final[int] = -1


def validate_session_remember(
    max_uses: int, ttl_s: int, *, session_ttl_s: int, unlimited: bool
) -> bool:
    """Validate a §7.4 session-scoped "remember" choice (V1 compromise). PURE.

    The V1 compromise (§7.4) lets the user choose "allow this exact action for
    the session": the SAME exact binding as a one-shot token, but with
    ``max_uses=∞`` and ``ttl = session end``. The enforced rule:

    - an UNLIMITED-uses token (``unlimited=True``) is permitted ONLY when its TTL
      is exactly the session end (``ttl_s == session_ttl_s``); an unlimited token
      with any OTHER TTL is REJECTED (that would be a durable/cross-session
      allowlist, which V1 forbids — ADR-006);
    - a bounded-uses token (``unlimited=False``) is always fine for any TTL,
      provided it carries a real (``>= 1``) use bound (a fail-closed floor; the
      contract already guarantees ``ge=1``).
    """
    if unlimited:
        return ttl_s == session_ttl_s
    return max_uses >= 1


class OsFsView:
    """The concrete os-backed :class:`FsView` — the §7.5 real-I/O boundary.

    This class is the ONLY place in ``recheck.py`` that performs filesystem
    syscalls (mirroring canonical.py's documented exception to the §2.2 purity
    rule). The pure :func:`recheck` / :func:`snapshot_paths` logic does no I/O of
    its own — it reaches the filesystem solely by calling through an injected
    :class:`FsView`, of which this is the production implementation. The
    ``os.stat`` probes are wrapped fail-closed: a mid-check ``OSError`` (e.g. a
    racing ``unlink``) raises :class:`RecheckError`, never a silent pass.
    """

    def realpath(self, path: str) -> str:
        return os.path.realpath(path)

    def parent_ids(self, path: str) -> tuple[int, int]:
        try:
            info = os.stat(os.path.dirname(path))
        except OSError as exc:  # racing unlink/rename of the parent — fail closed
            raise RecheckError(f"parent stat failed for {path!r}: {exc}") from exc
        return (info.st_dev, info.st_ino)

    def node_ids(self, path: str) -> tuple[int, int]:
        try:
            info = os.stat(path)
        except OSError as exc:  # racing unlink/rename of the node — fail closed
            raise RecheckError(f"node stat failed for {path!r}: {exc}") from exc
        return (info.st_dev, info.st_ino)

    def exists(self, path: str) -> bool:
        return os.path.exists(path)
