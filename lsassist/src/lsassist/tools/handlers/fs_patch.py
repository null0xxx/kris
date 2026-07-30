"""``fs.patch`` — §6.4's all-or-nothing search/replace, resolved before it is applied.

§6.4: "search/replace blocks with exact-match anchors; all-or-nothing (no partial);
checkpoint pre-patch". The plan states the observable form of it: a partial patch
leaves the tree hash IDENTICAL.

**"EXACT-MATCH ANCHOR" HAS TO MEAN "MATCHES EXACTLY ONCE".** Zero matches obviously
cannot be applied. More than one match is the interesting case, and it is also a
refusal: two occurrences mean the request never said WHERE, and a first-occurrence
guess would edit a place the caller never named while producing a plausible file
that nothing downstream can distinguish from the intended one. §6.4 says exact,
and an anchor matching twice matches nothing exactly.

**EVERY ANCHOR IS RESOLVED AGAINST THE ORIGINAL CONTENT.** Not against the result
of the previous block. Chaining would make the outcome depend on block ORDER, so
"all-or-nothing" would quietly become "all, in the order I happened to list them"
— a property neither a caller nor a rollback can reason about. Resolving against
the original also makes the whole set checkable before a single byte moves, which
is what lets the refusal be free of side effects.

**THE ATOMIC PUBLISH IS ``fs.write``'S.** Imported rather than reimplemented:
"atomic" must mean the same thing for both tools, and two implementations are two
things to get wrong. This module owns only the decision of WHAT the new bytes are.
"""

from __future__ import annotations

import itertools
import os
import stat as stat_module
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from lsassist.recovery.manifest import TriggerKind
from lsassist.tools.handlers import (
    ANCHOR_MISS,
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
from lsassist.tools.handlers.fs_write import _checkpoint, publish

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lsassist.recovery.checkpoints import CheckpointStore

__all__ = ["make_patcher", "patch_file"]


def _read_regular(target: str) -> str:
    """Read the file to patch, refusing anything that is not a regular file.

    ``lstat`` before the open, and the kind checked on the link itself: a symlink
    is refused for the same reason ``fs.write`` refuses one — following it writes
    outside the workspace the tool is scoped to.
    """
    try:
        info = os.lstat(target)
    except OSError as exc:
        raise HandlerRefused(
            WRITE_FAILED, f"{target!r} cannot be inspected: {exc!r}"
        ) from exc
    if stat_module.S_ISLNK(info.st_mode):
        raise HandlerRefused(
            WRITE_FAILED,
            f"{target!r} is a symlink; §6.4 asks for O_NOFOLLOW on the final component",
        )
    if not stat_module.S_ISREG(info.st_mode):
        raise HandlerRefused(WRITE_FAILED, f"{target!r} is not a regular file")
    try:
        with open(target, encoding="utf-8", errors="strict") as stream:
            return stream.read()
    except UnicodeDecodeError as exc:
        raise HandlerRefused(
            WRITE_FAILED,
            f"{target!r} is not valid utf-8; a patch cannot anchor in bytes it "
            f"cannot read exactly: {exc!r}",
        ) from exc
    except OSError as exc:
        raise HandlerRefused(WRITE_FAILED, f"{target!r} cannot be read: {exc!r}") from exc


def _resolved(original: str, blocks: Sequence[Mapping[str, Any]], target: str) -> str:
    """Apply every block, or raise before anything is written.

    Each anchor is counted in the ORIGINAL text, so a block whose anchor only
    appears after an earlier block ran is a miss — see the module docstring. The
    replacements are then applied by SPLICING at the located offsets rather than by
    ``str.replace``, because a replacement that happens to contain a later block's
    anchor must not become a match for it.
    """
    spans: list[tuple[int, int, str]] = []
    for index, block in enumerate(blocks):
        search = str(block["search"])
        occurrences = original.count(search)
        if occurrences != 1:
            raise HandlerRefused(
                ANCHOR_MISS,
                f"block {index} of {target!r} matched {occurrences} times, not exactly "
                "once; §6.4 asks for exact-match anchors and all-or-nothing, so nothing "
                "was written",
            )
        start = original.index(search)
        spans.append((start, start + len(search), str(block["replace"])))

    spans.sort()
    for earlier, later in itertools.pairwise(spans):
        if later[0] < earlier[1]:
            raise HandlerRefused(
                ANCHOR_MISS,
                f"two blocks of {target!r} overlap at offset {later[0]}; the result "
                "would depend on which was applied first, so nothing was written",
            )

    pieces: list[str] = []
    cursor = 0
    for start, end, replacement in spans:
        pieces.append(original[cursor:start])
        pieces.append(replacement)
        cursor = end
    pieces.append(original[cursor:])
    return "".join(pieces)


def patch_file(context: HandlerContext, store: CheckpointStore) -> Mapping[str, Any]:
    """§6.4's ``fs.patch``: resolve everything, snapshot, then publish once."""
    target = single_target(context)
    check_deadline(context, "fs.patch")
    check_canary(context, target)
    check_denied(context, target)
    check_within_workspace(context, target)

    blocks = context.normalized.args["blocks"]
    original = _read_regular(target)
    patched = _resolved(original, blocks, target)

    # §14.4: "before `fs.patch`". A patch always has an existing file — there is
    # nothing to anchor against otherwise — so unlike `fs.write` this is
    # unconditional, and a failure stops the patch.
    _checkpoint(context, store, target, TriggerKind.PRE_PATCH)

    payload = patched.encode("utf-8")
    publish(payload, target, replace=True)
    return {
        "path": target,
        "blocks_applied": len(blocks),
        "bytes_written": len(payload),
    }


def make_patcher(store: CheckpointStore) -> Handler:
    """Bind the checkpoint store into a handler — see ``fs_write.make_writer``."""

    def handler(context: HandlerContext) -> Mapping[str, Any]:
        return patch_file(context, store)

    return handler
