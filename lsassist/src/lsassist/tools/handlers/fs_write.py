"""``fs.write`` — §6.4's atomic single-file write, and the rollback it needs first.

§6.4 fixes four properties: "atomic: tmp+``fsync``+``rename``; ``O_NOFOLLOW`` final
component; checkpoint pre-write; overwrite requires ``intent=overwrite`` flag (else
create-only fails if exists)". Each one exists because of a specific way a write
goes wrong, and each is implemented here in the order that makes it true.

**THE ORDER IS THE DESIGN.** Every check that can refuse runs before anything is
created, and the snapshot runs before anything is modified:

1. deadline, canary, §7.3 DENY, §6.2 ``path_scope`` — pure refusals, no I/O on the
   target beyond an ``lstat``.
2. the target's current kind, via ``lstat``: a symlink is REFUSED, not followed
   and not replaced.
3. the create-only gate. It sits HERE, before the checkpoint, deliberately: a
   refusal must cost nothing, and a snapshot taken for a write that never happens
   would spend one of §14.4's 50 per-workspace slots on nothing. Moving this below
   the checkpoint is invisible to every content assertion and is exactly the kind
   of reordering a maintainer does while tidying.
4. §14.4's pre-write checkpoint, but only if the target EXISTS — a snapshot is the
   caller's licence to mutate, so a failure here must stop the write.
5. tmp file in the target's own directory, written and ``fsync``ed.
6. the publish, which is the only step that changes what a reader sees.

**TWO PUBLISH PRIMITIVES, ONE WRITE PATH.** §6.4 asks for tmp+``fsync``+``rename``,
which gives crash-atomicity; create-only additionally needs "fails if exists" to be
atomic with the publish, and ``rename`` cannot express that — it replaces
unconditionally. So the bytes are always written and ``fsync``ed to a temporary
file, and then:

* ``intent=overwrite`` → ``os.rename``, which replaces atomically;
* create-only → ``os.link``, which fails ``EEXIST`` atomically and never follows a
  symlink.

A ``stat``-then-write existence check would be a TOCTOU window in exactly the tool
whose job is not to clobber things, and ``renameat2(RENAME_NOREPLACE)`` — the one
call that does both at once — is not portably exposed by Python.

**WHY ``O_NOFOLLOW`` MEANS REFUSE.** ``rename`` and ``link`` act on the link
itself, so a symlink at the target would be silently swapped for a regular file
even without following it; and a handler that DID follow it would write wherever
the link points, which is how a workspace-scoped write leaves the workspace. §6.4
asks for the refusal, so the kind of the existing target is checked explicitly.
"""

from __future__ import annotations

import os
import stat as stat_module
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Final

from lsassist.recovery.manifest import TriggerKind
from lsassist.tools.handlers import (
    CHECKPOINT_FAILED,
    TARGET_EXISTS,
    WRITE_FAILED,
    Handler,
    HandlerContext,
    HandlerRefused,
)
from lsassist.tools.handlers._common import (
    check_canary,
    check_deadline,
    check_denied,
    check_within_workspace,
    single_target,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lsassist.recovery.checkpoints import CheckpointStore

__all__ = ["OVERWRITE", "make_writer", "write_file"]

#: The one ``intent`` value that permits replacing an existing file (§6.4).
OVERWRITE: Final = "overwrite"

#: Mode for a file this tool creates. 0600 rather than 0644: the tool writes on
#: the user's behalf into a workspace whose other readers it knows nothing about,
#: and a caller that wants it world-readable can widen it deliberately.
_FILE_MODE: Final = 0o600

#: Open a NEW file that must not already exist, never following a symlink.
_TMP_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


def _existing_kind(target: str) -> os.stat_result | None:
    """``lstat`` the target: its own kind, never the kind of what it points at."""
    try:
        return os.lstat(target)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise HandlerRefused(
            WRITE_FAILED, f"{target!r} cannot be inspected: {exc!r}"
        ) from exc


def _checkpoint(
    context: HandlerContext, store: CheckpointStore, target: str, trigger: TriggerKind
) -> None:
    """§14.4's pre-mutation snapshot. A failure here STOPS the mutation.

    Imported lazily-typed rather than duck-typed: the store's own
    ``CheckpointError`` is the single type it promises for every cause, so mapping
    exactly that to a refusal keeps the two contracts joined. Anything else
    escaping would be a bug in the store, not a condition to swallow here.
    """
    from lsassist.recovery.checkpoints import CheckpointError

    try:
        store.create(
            workspace=context.normalized.workspace_root,
            paths=[target],
            trigger=trigger,
            # §6.1 deliberately withholds session and task state from a handler,
            # so `action_hash` is the only task-scoped identifier available here —
            # and it is the RIGHT one: it makes the §14.1 `recovery` record
            # correlate with the `tool_result` record for this exact action.
            task_id=context.normalized.action_hash,
        )
    except CheckpointError as exc:
        raise HandlerRefused(
            CHECKPOINT_FAILED,
            f"no pre-{trigger.value} checkpoint for {target!r}, so the write must not "
            f"happen: {exc!r}",
        ) from exc


def publish(payload: bytes, target: str, *, replace: bool) -> None:
    """Write ``payload`` to a temporary file and publish it atomically.

    Shared with ``fs.patch`` because "atomic" has to mean the same thing for both
    and a second implementation is a second thing to get wrong. The temporary file
    lives in the target's OWN directory: ``rename`` and ``link`` are only atomic
    within a filesystem, and a temp directory elsewhere would silently degrade
    both into a copy.
    """
    directory = os.path.dirname(target) or "."
    temporary = os.path.join(directory, f".lsassist-tmp-{os.getpid()}-{os.urandom(8).hex()}")
    # The REPLACED file's mode is carried over, because publishing by rename means
    # the new inode's mode is whatever the temporary file had — so a 0755 script
    # edited by `fs.patch` would come back 0600 and stop being executable, with
    # nothing in the result saying so. A file being created has no prior mode to
    # inherit, and 0600 is the right default for one this tool invents.
    mode = _FILE_MODE
    if replace:
        try:
            mode = stat_module.S_IMODE(os.lstat(target).st_mode)
        except OSError:
            mode = _FILE_MODE
    try:
        handle = os.open(temporary, _TMP_FLAGS, mode)
    except OSError as exc:
        raise HandlerRefused(
            WRITE_FAILED, f"cannot create a temporary file beside {target!r}: {exc!r}"
        ) from exc
    try:
        with os.fdopen(handle, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.rename(temporary, target)
        else:
            # `link` fails EEXIST ATOMICALLY, which is the whole reason
            # create-only does not use `rename`. It also never follows a symlink.
            os.link(temporary, target)
    except FileExistsError as exc:
        _discard(temporary)
        raise HandlerRefused(
            TARGET_EXISTS,
            f"{target!r} already exists and the request did not carry intent={OVERWRITE}",
        ) from exc
    except OSError as exc:
        _discard(temporary)
        raise HandlerRefused(WRITE_FAILED, f"cannot publish {target!r}: {exc!r}") from exc
    finally:
        if not replace:
            _discard(temporary)


def _discard(temporary: str) -> None:
    """Remove a temporary file, best effort. Never masks the real failure."""
    try:
        os.unlink(temporary)
    except OSError:
        return


def write_file(context: HandlerContext, store: CheckpointStore) -> Mapping[str, Any]:
    """§6.4's ``fs.write``. See the module docstring for why the order is the design."""
    target = single_target(context)
    check_deadline(context, "fs.write")
    check_canary(context, target)
    check_denied(context, target)
    check_within_workspace(context, target)

    args = context.normalized.args
    replace = args.get("intent") == OVERWRITE
    payload = str(args.get("content", "")).encode("utf-8")

    existing = _existing_kind(target)
    if existing is not None:
        if stat_module.S_ISLNK(existing.st_mode):
            raise HandlerRefused(
                WRITE_FAILED,
                f"{target!r} is a symlink; §6.4 asks for O_NOFOLLOW on the final "
                "component, so it is refused rather than followed or replaced",
            )
        if not stat_module.S_ISREG(existing.st_mode):
            raise HandlerRefused(WRITE_FAILED, f"{target!r} is not a regular file")
        if not replace:
            raise HandlerRefused(
                TARGET_EXISTS,
                f"{target!r} exists and the request did not carry intent={OVERWRITE}",
            )
        # §14.4: "before `fs.write` on existing file". A brand-new path has
        # nothing to snapshot, and `CheckpointStore` refuses a missing file.
        _checkpoint(context, store, target, TriggerKind.PRE_WRITE)

    publish(payload, target, replace=replace)
    return {
        "path": target,
        "bytes_written": len(payload),
        "created": existing is None,
    }


def make_writer(store: CheckpointStore) -> Handler:
    """Bind the checkpoint store into a :data:`~lsassist.tools.handlers.Handler`.

    A CLOSURE rather than a new :class:`HandlerContext` field, because a field
    would mean editing ``tools/dispatcher.py`` — a ``tcb`` unit under SPEC §2.3's
    size budget, which is already over its Gate-4 target. This keeps the whole
    write batch at zero TCB lines while producing exactly the callable the
    dispatcher's in-process route already accepts.
    """

    def handler(context: HandlerContext) -> Mapping[str, Any]:
        return write_file(context, store)

    return handler
