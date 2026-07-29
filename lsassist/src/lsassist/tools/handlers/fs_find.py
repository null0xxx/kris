"""``fs.find`` — §6.4's search tool: name, glob and content modes.

§6.4's clauses are "name/glob/content modes; regex size-capped; no `..` after
canonicalization". Two of the three are about keeping the SEARCH inside the tree
that was approved, and they are not the same guarantee:

* **No ``..``** stops the PATTERN from climbing out. ``glob`` with ``../*`` would
  otherwise be a way to name files above the approved root without ever asking
  the dispatcher to canonicalize them, so the §7.5 chain would never see them.
* **No symlink traversal** stops the WALK from climbing out. The pattern can be
  perfectly innocent and still land outside if the tree contains a link.

**THE CANARY AND DENY GATES ARE IN THE WALK, NOT IN THE MODE.** An earlier
revision put them in the ``content`` branch on the reasoning that content mode is
the dangerous one because it reads bytes. That reasoning was wrong in the way
that matters: ``--mode name --pattern id_rsa`` located a §19 honeyfile and
returned its PATH with no alert at all, and a path is exactly what the
reconnaissance was after. Both gates now run in the walk, per candidate, BEFORE
the mode is consulted — so no future mode can be added that quietly bypasses
them. :func:`_hit` is left with one job: matching.
"""

from __future__ import annotations

import fnmatch
import os
import stat as stat_module
from collections import deque
from typing import Any, Final

from lsassist.tools.handlers import READ_FAILED, HandlerContext, HandlerRefused
from lsassist.tools.handlers._common import (
    DIR_FLAGS,
    check_canary,
    check_deadline,
    check_denied,
    check_within_workspace,
    entry_is_allowed,
    listdir_checked,
    open_pinned_dir,
    read_capped,
    single_target,
)

__all__ = ["MAX_CONTENT_BYTES", "MAX_PATTERN_CHARS", "MAX_RESULTS", "find_files"]

#: §6.4: "regex size-capped". The manifest's `input_schema` says 256 too; this is
#: the second, independent statement, so a hand-built manifest cannot widen it.
MAX_PATTERN_CHARS: Final = 256

#: Default result cap when the caller names none.
MAX_RESULTS: Final = 1000

#: Per-file ceiling for ``content`` mode. Without it one large file decides how
#: much memory a search costs.
MAX_CONTENT_BYTES: Final = 1024 * 1024

#: The walk's own depth ceiling. `fs.find` has no depth argument in §6.4, but an
#: unbounded descent is an unbounded runtime, and the tool has a 30 s timeout it
#: would otherwise spend before returning nothing.
MAX_WALK_DEPTH: Final = 16


def _checked_pattern(context: HandlerContext) -> tuple[str, str]:
    """Return ``(mode, pattern)`` after the §6.4 refusals."""
    args = context.normalized.args
    mode = args.get("mode")
    pattern = args.get("pattern")
    if not isinstance(mode, str) or not isinstance(pattern, str):
        raise HandlerRefused(READ_FAILED, "fs.find requires a string mode and pattern")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise HandlerRefused(
            READ_FAILED, f"pattern exceeds the {MAX_PATTERN_CHARS}-character cap"
        )
    # §6.4: "no `..` after canonicalization". Checked on the SEGMENTS, so `..`
    # inside a filename ("a..b") is fine while a climbing component is not.
    if any(segment == ".." for segment in pattern.replace("\\", "/").split("/")):
        raise HandlerRefused(
            READ_FAILED, f"pattern {pattern!r} contains a '..' component"
        )
    if os.path.isabs(pattern):
        raise HandlerRefused(READ_FAILED, f"pattern {pattern!r} must be relative to the root")
    if mode not in {"name", "glob", "content"}:
        raise HandlerRefused(READ_FAILED, f"unknown fs.find mode {mode!r}")
    return mode, pattern


def find_files(context: HandlerContext) -> dict[str, Any]:
    """Search the approved directory and return the §6.4 ``fs.find`` payload."""
    root = single_target(context)
    check_canary(context, root)
    check_denied(context, root)
    check_within_workspace(context, root)
    mode, pattern = _checked_pattern(context)

    requested = context.normalized.args.get("max_results", MAX_RESULTS)
    cap = min(int(requested), MAX_RESULTS) if isinstance(requested, int) else MAX_RESULTS
    if cap < 1:
        raise HandlerRefused(READ_FAILED, f"max_results must be at least 1, got {cap}")

    needle = pattern.encode("utf-8") if mode == "content" else b""
    root_fd = open_pinned_dir(context, root)
    matches: list[str] = []
    truncated = False
    queue: deque[tuple[int, str, int]] = deque([(root_fd, "", 0)])
    try:
        while queue and not truncated:
            check_deadline(context, "fs.find")
            fd, prefix, level = queue.popleft()
            try:
                for name in sorted(listdir_checked(fd, prefix or root)):
                    # PER ENTRY: content mode reads up to MAX_CONTENT_BYTES per
                    # file, so a single wide directory is precisely where the
                    # budget gets spent — and where a per-directory check never
                    # looks.
                    check_deadline(context, "fs.find")
                    rel = f"{prefix}{name}"
                    # BEFORE the mode is even consulted. The canary check used to
                    # live in the `content` branch only, so `--mode name` matched
                    # a honeyfile and returned its PATH with no alert — and
                    # locating a decoy by name is the reconnaissance §19 exists to
                    # catch. DENY entries are skipped rather than refused: they
                    # are simply not visible to this tool.
                    if not entry_is_allowed(context, os.path.join(root, rel)):
                        continue
                    try:
                        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except OSError:
                        continue
                    if stat_module.S_ISDIR(info.st_mode) and level + 1 < MAX_WALK_DEPTH:
                        # Real directories only: `follow_symlinks=False` above
                        # means a link reports as a link, so it is never queued.
                        try:
                            child = os.open(name, DIR_FLAGS, dir_fd=fd)
                        except OSError:
                            continue
                        queue.append((child, f"{rel}/", level + 1))
                        continue
                    if not stat_module.S_ISREG(info.st_mode):
                        continue
                    if _hit(fd, name, rel, mode, pattern, needle):
                        matches.append(rel)
                        if len(matches) >= cap:
                            truncated = True
                            break
            finally:
                os.close(fd)
    finally:
        while queue:
            os.close(queue.popleft()[0])

    matches.sort()
    return {"matches": matches, "truncated": truncated}


def _hit(dir_fd: int, name: str, rel: str, mode: str, pattern: str, needle: bytes) -> bool:
    """True when this file matches. PURE with respect to policy.

    The canary and DENY gates deliberately do NOT live here any more. They ran in
    the ``content`` branch only, which meant they applied to the mode that reads
    bytes and to no other — while ``--mode name`` happily reported a honeyfile's
    path. Hoisting them into the walk makes them apply to every candidate before
    the mode is consulted, and leaves this function with one job: matching.
    """
    if mode == "name":
        return name == pattern
    if mode == "glob":
        return fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern)
    return needle in read_capped(dir_fd, name, MAX_CONTENT_BYTES, rel)
