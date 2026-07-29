"""``fs.read`` — §6.4's read-one-file tool, and the §7.5 step-6 pin for readers.

§6.4's contract for this tool is three clauses: "utf-8 errors=replace; binary →
hex head 4 KB; DENY paths (§7.3)". The first two are formatting. The third, plus
the inode pin below, are why this module is longer than "open, read, decode".

**THE WINDOW THIS CLOSES.** §7.5 step 6 is scoped to WRITE tools (SPEC:564), so
the dispatcher marks every read ``Verification.NOT_APPLICABLE`` and both
``policy/recheck.py`` and ``tools/dispatcher.py`` carry a cross-phase flag naming
T3.04 as the owner of the gap: between the dispatcher's step-3 re-canonicalization
and this ``open``, an attacker who can write the parent directory can replace the
approved file with a different one at the SAME path. Nothing downstream would
notice: the path still canonicalizes identically, and the content is just
"whatever the file said". The fix is to stop trusting the NAME. This module opens
relative to a pinned parent ``dir_fd`` with ``O_NOFOLLOW``, then ``fstat``s the
resulting FD and compares ``(st_dev, st_ino)`` against the identity captured at
approval time. Every byte returned comes from THAT fd — never from a second
``open`` of the same path, which would reopen the window it just closed.

The shared half of that machinery lives in :mod:`~lsassist.tools.handlers._common`,
because ``fs.list`` and ``fs.find`` owe exactly the same guarantees and three
copies of a security check are three places for them to drift apart.

**NAMED RESIDUAL — this function still duplicates that sequence.**
:func:`~lsassist.tools.handlers._common.open_pinned_dir` performs the same
open-parent, ``fstat``-compare, open-child, :func:`verify_node` chain; ``read_file``
repeats it inline, differing only in the open flags and in checking ``S_ISREG``
instead of ``S_ISDIR``. That is precisely the duplication ``_common``'s own
docstring warns about: a future fix to one copy (a retry on ``EINTR``, a
reordering) can silently miss the other. It was left in deliberately — factoring
a security-critical open sequence is not work to do inside a bounded correction
transaction — and is recorded here so the next reader finds it at the code rather
than in a review transcript.
"""

from __future__ import annotations

import os
import stat as stat_module
from typing import Any, Final

from lsassist.tools.handlers import (
    READ_FAILED,
    TARGET_REPLACED,
    HandlerContext,
    HandlerRefused,
)
from lsassist.tools.handlers._common import (
    DIR_FLAGS,
    FILE_FLAGS,
    approved_identity,
    check_canary,
    check_denied,
    check_within_workspace,
    read_fd,
    single_target,
    verify_node,
)

__all__ = ["HEX_HEAD_BYTES", "read_file"]

#: §6.4: "binary → hex head 4 KB". Bytes of the FILE, so the rendered field is
#: twice this many characters.
HEX_HEAD_BYTES: Final = 4096

#: A NUL byte within this prefix means "binary". This is git's own heuristic
#: (`buffer_is_binary` sniffs the first 8000 bytes) and is used here because
#: §6.4 asks for BOTH "utf-8 errors=replace" and "binary → hex head": with
#: `errors="replace"` no byte sequence can fail to decode, so undecodability
#: cannot be the discriminator and something else has to be. Choosing a
#: published convention keeps the boundary reviewable instead of ad hoc.
_BINARY_SNIFF_BYTES: Final = 8000


def _render(data: bytes) -> tuple[str, str]:
    """Return ``(content, encoding)`` per §6.4's two-way split."""
    if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
        return data[:HEX_HEAD_BYTES].hex(), "hex"
    return data.decode("utf-8", errors="replace"), "utf-8"


def read_file(context: HandlerContext) -> dict[str, Any]:
    """Read the approved file and return the §6.4 ``fs.read`` payload."""
    target = single_target(context)
    check_canary(context, target)
    check_denied(context, target)
    check_within_workspace(context, target)

    parent = os.path.dirname(target)
    name = os.path.basename(target)
    if not parent or not name:
        raise HandlerRefused(READ_FAILED, f"{target!r} has no parent/name to open against")

    want_parent_dev, want_parent_ino, want_node_dev, want_node_ino = approved_identity(
        context, target
    )
    limit = context.manifest.output_limits.max_result_chars

    try:
        dir_fd = os.open(parent, DIR_FLAGS)
    except OSError as exc:
        raise HandlerRefused(READ_FAILED, f"cannot open parent of {target!r}: {exc!r}") from exc
    try:
        parent_stat = os.fstat(dir_fd)
        if (parent_stat.st_dev, parent_stat.st_ino) != (want_parent_dev, want_parent_ino):
            # The directory the name resolves through is a different directory
            # than the one approval measured — the name now means something else.
            raise HandlerRefused(
                TARGET_REPLACED,
                f"parent of {target!r} was swapped between approval and read",
            )

        try:
            # O_NOFOLLOW refuses a symlink FINAL COMPONENT, and `dir_fd` pins the
            # directory the name is resolved in, so neither half of the path can
            # be redirected after the check above.
            fd = os.open(name, FILE_FLAGS, dir_fd=dir_fd)
        except OSError as exc:
            raise HandlerRefused(READ_FAILED, f"cannot open {target!r}: {exc!r}") from exc
        try:
            info = verify_node(fd, want_node_dev, want_node_ino, target)
            if not stat_module.S_ISREG(info.st_mode):
                raise HandlerRefused(READ_FAILED, f"{target!r} is not a regular file")
            # Read one byte past the limit so "exactly at the limit" is not
            # reported as truncated -- and read from THIS fd, the one just
            # verified. Re-opening by name to read would hand back whatever the
            # name means now, reopening the window the pin closed.
            data = read_fd(fd, limit + 1, target)
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)

    truncated = len(data) > limit
    kept = data[:limit] if truncated else data
    content, encoding = _render(kept)
    return {
        "content": content,
        "encoding": encoding,
        "bytes_read": len(kept),
        "truncated": truncated,
    }
