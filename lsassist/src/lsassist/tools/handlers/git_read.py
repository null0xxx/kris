"""``git.read`` — §6.4's repository-state tool: five subcommands, nothing else.

§6.4 fixes the forms exactly: ``status --short --branch``, ``diff [--cached]
[path]``, ``log --oneline -N``, ``branch --show-current``, ``worktree list``; and
"repo = workspace". Everything destructive is absent from V1 by §6.4's own
"DENY by non-existence" rule — ``git.destructive`` (reset/clean/push --force) is
not a tool, so the way to keep it non-existent is for THIS module to have no
branch that can produce it.

**THE SUBCOMMAND IS SELECTED, NOT PASSED THROUGH.** `args['subcommand']` indexes
a table; its value never reaches the argv. That distinction is the whole guard:
a pass-through would make ``"status --short; reboot"`` a subcommand, and while
argv exec (§7.6 rule 8) means it would not be interpreted as a shell line, it
WOULD be handed to git as one opaque argument — and the audit record would then
show a command nobody can read at a glance.

**`-C <workspace>` rather than a cwd assumption.** §6.4 says "repo = workspace",
and `-C` states it in the argv itself, so the record shows which repository was
read instead of leaving it to whatever the sandbox's `--chdir` happened to be.
"""

from __future__ import annotations

import posixpath
from collections.abc import Mapping
from typing import Any, Final

from lsassist.tools.handlers import READ_FAILED, HandlerRefused
from lsassist.tools.result import ExecObservation

__all__ = ["ALLOWED_SUBCOMMANDS", "DEFAULT_LOG_COUNT", "MAX_LOG_COUNT", "build_argv", "result_of"]

GIT: Final = "/usr/bin/git"

#: §6.4's five forms. `diff` and `log` take the extra arguments below; the other
#: three are complete as written and accept nothing.
ALLOWED_SUBCOMMANDS: Final[frozenset[str]] = frozenset(
    {"status", "diff", "log", "branch", "worktree"}
)

DEFAULT_LOG_COUNT: Final = 20
MAX_LOG_COUNT: Final = 1000


def _checked_path(args: Mapping[str, Any], workspace_root: str) -> str | None:
    """A `diff` path argument: ABSOLUTE in, repo-relative out.

    The two ends of this want opposite things and the mismatch is load-bearing.
    §6.3 step 2 canonicalizes declared path arguments and REFUSES a relative one
    ("path must be absolute"), because the §7.5 chain has nothing to canonicalize
    otherwise — so by the time a path reaches here it is absolute and already
    checked. ``git``, given ``-C <repo>``, wants it relative to that repo. A
    handler that took the relative form would be taking a path the dispatcher
    never saw; one that passed the absolute form through would work only by
    accident of ``git`` resolving it. So: require absolute, verify containment,
    hand ``git`` the relative form.

    Containment is checked on SEGMENTS, so ``/w-evil/x`` is not inside ``/w``.
    """
    path = args.get("path")
    if path is None:
        return None
    if not isinstance(path, str) or not path:
        raise HandlerRefused(READ_FAILED, f"git.read path {path!r} is not a non-empty str")
    if not posixpath.isabs(path):
        raise HandlerRefused(
            READ_FAILED,
            f"git.read path {path!r} must be absolute; §6.3 step 2 canonicalizes it",
        )
    if any(segment == ".." for segment in path.split("/")):
        raise HandlerRefused(READ_FAILED, f"git.read path {path!r} contains a '..' component")
    root_segments = [s for s in workspace_root.split("/") if s]
    path_segments = [s for s in path.split("/") if s]
    if path_segments[: len(root_segments)] != root_segments or len(path_segments) == len(
        root_segments
    ):
        raise HandlerRefused(
            READ_FAILED, f"git.read path {path!r} is not inside the workspace"
        )
    return "/".join(path_segments[len(root_segments) :])


def _checked_count(args: Mapping[str, Any]) -> int:
    count = args.get("count", DEFAULT_LOG_COUNT)
    if isinstance(count, bool) or not isinstance(count, int):
        raise HandlerRefused(READ_FAILED, f"git.read count {count!r} is not an integer")
    if not 1 <= count <= MAX_LOG_COUNT:
        raise HandlerRefused(READ_FAILED, f"git.read count {count} is outside 1..{MAX_LOG_COUNT}")
    return count


def build_argv(args: Mapping[str, Any], *, workspace_root: str) -> tuple[str, ...]:
    """Build the §6.4 argv for ``args['subcommand']``, or refuse."""
    subcommand = args.get("subcommand")
    if not isinstance(subcommand, str) or subcommand not in ALLOWED_SUBCOMMANDS:
        raise HandlerRefused(
            READ_FAILED,
            f"git.read subcommand {subcommand!r} is not one of {sorted(ALLOWED_SUBCOMMANDS)}",
        )
    if not workspace_root:
        raise HandlerRefused(
            READ_FAILED, "git.read needs a workspace root (§6.4: repo = workspace)"
        )

    head: tuple[str, ...] = (GIT, "-C", workspace_root)
    if subcommand == "status":
        return (*head, "status", "--short", "--branch")
    if subcommand == "branch":
        return (*head, "branch", "--show-current")
    if subcommand == "worktree":
        return (*head, "worktree", "list")
    if subcommand == "log":
        return (*head, "log", "--oneline", f"-{_checked_count(args)}")
    # diff — the only form with two optional pieces, both validated above.
    tail: tuple[str, ...] = ("diff",)
    if args.get("cached") is True:
        tail = (*tail, "--cached")
    path = _checked_path(args, workspace_root)
    if path is not None:
        # `--` first: a path that begins with a dash would otherwise be read as
        # an option, and `git` has no way to tell them apart afterwards.
        tail = (*tail, "--", path)
    return (*head, *tail)


def result_of(observation: ExecObservation) -> dict[str, Any]:
    """Render the child's stdout into the §6.5 ``result`` payload."""
    return {
        "stdout": observation.stdout.decode("utf-8", errors="replace"),
        "exit_code": observation.exit_code,
    }
