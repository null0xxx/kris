"""``fs.list`` — §6.4's directory listing: sorted, depth ≤ 4, and escape-proof.

§6.4's contract is two clauses, "sorted, depth ≤ 4 default", and one of them is
not cosmetic. **Sorted** is what makes two runs of the same tool comparable — an
unordered listing turns every diff into noise and every assertion into a flake.
**Depth** is the only bound on a walk that would otherwise be as large as the
workspace.

**THE THIRD CLAUSE §6.4 DOES NOT WRITE DOWN.** A directory symlink is a way OUT
of the approved root: following one turns "list the workspace" into "list
whatever that link points at", with the approval still saying `workspace`. The
walk therefore descends only through directories opened with ``O_NOFOLLOW``
relative to a ``dir_fd`` it already holds, so no component of any path it visits
can be redirected after the check. Symlinks are REPORTED — a listing that hid
them would be lying about the tree — but never traversed.
"""

from __future__ import annotations

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
    single_target,
)

__all__ = ["DEFAULT_DEPTH", "MAX_DEPTH", "list_dir"]

#: Characters an entry costs BESIDES its path and its size digits — the braces,
#: the keys, the quoting and the separators of the widest rendered variant
#: (``type: "file"``, which is the only one carrying a ``size``).
#:
#: **PINNED BY A TEST, NOT BY COUNTING.** This constant was hand-counted twice
#: and wrong both times (44, then 42; the true value is 38), which is exactly
#: what hand-counted constants do. ``test_the_entry_overhead_constant_is_derived_
#: not_counted`` now derives it from ``json.dumps`` of the real entry shape and
#: fails if the two ever disagree, so the next person to change the payload
#: shape learns about it from a red test rather than from a truncation bug.
_ENTRY_OVERHEAD_CHARS: Final = 38

#: §6.4: "depth <= 4 default". Also the ceiling — the manifest's `input_schema`
#: caps the argument at 4, so a caller cannot ask for more and this constant is
#: the second, independent place that says so.
DEFAULT_DEPTH: Final = 4
MAX_DEPTH: Final = 4


def _entry_type(mode: int) -> str:
    if stat_module.S_ISLNK(mode):
        return "symlink"
    if stat_module.S_ISDIR(mode):
        return "dir"
    if stat_module.S_ISREG(mode):
        return "file"
    return "other"


def list_dir(context: HandlerContext) -> dict[str, Any]:
    """List the approved directory and return the §6.4 ``fs.list`` payload."""
    target = single_target(context)
    check_canary(context, target)
    check_denied(context, target)
    check_within_workspace(context, target)

    requested = context.normalized.args.get("depth", DEFAULT_DEPTH)
    depth = min(int(requested), MAX_DEPTH) if isinstance(requested, int) else DEFAULT_DEPTH
    if depth < 1:
        raise HandlerRefused(READ_FAILED, f"depth must be at least 1, got {depth}")

    root_fd = open_pinned_dir(context, target)
    entries: list[dict[str, Any]] = []
    limit = context.manifest.output_limits.max_result_chars
    budget = limit
    truncated = False
    # (fd, relative prefix, level) — the fd is OWNED and closed by this loop.
    queue: deque[tuple[int, str, int]] = deque([(root_fd, "", 0)])
    try:
        while queue and not truncated:
            check_deadline(context, "fs.list")
            fd, prefix, level = queue.popleft()
            try:
                for name in sorted(listdir_checked(fd, prefix or target)):
                    # PER ENTRY, not per directory. One wide directory used to be
                    # scanned to completion with the clock consulted once, before
                    # it was even entered — so the budget bounded the gaps between
                    # directories and not the work itself.
                    check_deadline(context, "fs.list")
                    rel = f"{prefix}{name}"
                    absolute = os.path.join(target, rel)
                    # A recursive tool inherits none of its root's checks: a
                    # honeyfile below the root used to be enumerable, and a
                    # nested `.env` used to be listed with its size.
                    if not entry_is_allowed(context, absolute):
                        continue
                    try:
                        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except OSError:
                        # Vanished mid-walk. A listing is a snapshot of a moving
                        # tree; one entry disappearing is not a reason to lose
                        # the rest of it.
                        continue
                    kind = _entry_type(info.st_mode)
                    entry: dict[str, Any] = {"path": rel, "type": kind}
                    if kind == "file":
                        entry["size"] = info.st_size
                    # Charge the REAL rendered size, not a per-entry estimate: a
                    # fixed guess is wrong by an order of magnitude on long paths,
                    # which is exactly where a listing gets big.
                    budget -= len(rel) + _ENTRY_OVERHEAD_CHARS + len(str(entry.get("size", "")))
                    if budget < 0:
                        truncated = True
                        break
                    entries.append(entry)
                    # Descend only into REAL directories, and only by opening
                    # them relative to the fd we already hold.
                    if kind == "dir" and level + 1 < depth:
                        try:
                            child = os.open(name, DIR_FLAGS, dir_fd=fd)
                        except OSError:
                            continue
                        queue.append((child, f"{rel}/", level + 1))
            finally:
                os.close(fd)
    finally:
        # Anything still queued when the walk stopped early still OWNS an fd.
        # This used to be preceded by `queue.clear()` on the truncation path,
        # which dropped those tuples so this drain closed nothing — measured at
        # 56 leaked descriptors in a single call over a wide tree.
        while queue:
            os.close(queue.popleft()[0])

    entries.sort(key=lambda item: str(item["path"]))
    return {"entries": entries, "truncated": truncated}
