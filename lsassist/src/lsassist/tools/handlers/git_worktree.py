"""``git.worktree`` — §6.4's one worktree form, and nothing that resembles it.

§6.4 fixes the tool exactly: "``git worktree add <path> -b <branch>`` only; path
inside workspace ``.lsassist/worktrees/``". Everything else ``git worktree`` can
do — ``remove``, ``prune``, ``move``, ``repair``, ``--force`` — is absent from V1
by §6.4's "DENY by non-existence" rule, and the way to keep it non-existent is
for this module to have no branch that can produce it. There is no subcommand
argument here at all: ``add`` is a literal.

**TWO CONVENTIONS INHERITED FROM ``git_read``, DELIBERATELY.** A second convention
for the same binary would be a second thing to review.

* argv[0] is the PINNED absolute path. ``sandbox/availability.py`` measured the
  reason: an early writable ``PATH`` entry is a shim, and a shimmed ``git`` writes
  wherever it likes — which for a tool whose whole job is creating a directory
  with a ``.git`` in it would be a particularly quiet compromise.
* ``-C <workspace>`` states the repository in the argv rather than relying on the
  sandbox's ``--chdir``, so the audit record shows which repository was modified.

**WHY THE BRANCH IS VALIDATED BY PATTERN AND THE PATH BY PLACEMENT.** ``--``
protects exactly one thing: the arguments after it. The path sits there, so a path
beginning with a dash is safe by placement. ``-b <branch>`` necessarily sits
BEFORE ``--``, so a branch named ``--force`` would be read as an option no matter
how the argv is assembled — placement cannot help, and only a pattern can. The
pattern is deliberately narrower than ``git check-ref-format``: this tool creates
branches for one purpose, so a name it would refuse is a name nobody needs, and
the cost of being conservative is zero.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping
from typing import Any, Final

from lsassist.tools.handlers import WORKSPACE_SCOPE, WRITE_FAILED, HandlerRefused
from lsassist.tools.result import ExecObservation

__all__ = ["BRANCH_PATTERN", "GIT", "WORKTREE_DIR", "build_argv", "result_of"]

GIT: Final = "/usr/bin/git"

#: §6.4: "path inside workspace ``.lsassist/worktrees/``". A constant rather than
#: a literal at the call site, so a test can assert it against the SPEC text.
WORKTREE_DIR: Final = ".lsassist/worktrees"

#: Narrower than ``git check-ref-format`` on purpose — see the module docstring.
#: Must start with an alphanumeric, so no name can be read as an option; ``.``,
#: ``..``, ``~``, ``^``, ``:``, ``?``, ``*``, ``[``, ``\``, whitespace, control
#: characters and a trailing ``.lock`` are all excluded by construction rather
#: than by enumeration.
BRANCH_PATTERN: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._/-]{0,254}\Z")


def _checked_branch(args: Mapping[str, Any]) -> str:
    branch = args.get("branch")
    if not isinstance(branch, str) or not BRANCH_PATTERN.match(branch):
        raise HandlerRefused(
            WRITE_FAILED,
            f"git.worktree branch {branch!r} is not an accepted branch name",
        )
    # `..` and a `/`-doubling would pass the character class but are refused by
    # `git check-ref-format`, so the tool must not build an argv git will reject.
    if ".." in branch or "//" in branch or branch.endswith((".", "/", ".lock")):
        raise HandlerRefused(
            WRITE_FAILED, f"git.worktree branch {branch!r} is not a valid git ref name"
        )
    # A FULLY QUALIFIED ref is refused even though it is a legal name. `-b` takes a
    # short name and prefixes it, so `refs/heads/x` would create
    # `refs/heads/refs/heads/x` — a branch the caller did not ask for, under a name
    # that reads as if it had worked.
    if branch.startswith("refs/"):
        raise HandlerRefused(
            WRITE_FAILED,
            f"git.worktree branch {branch!r} is fully qualified; `-b` takes a short "
            "name and would nest it under refs/heads/",
        )
    return branch


def _checked_path(args: Mapping[str, Any], workspace_root: str) -> str:
    """The new worktree's path: absolute in, and inside the reserved directory.

    Containment is checked on SEGMENTS, which is the trap ``git_read``'s own path
    check names: a prefix comparison on the raw string admits ``/ws-evil`` as
    inside ``/ws``. A ``..`` component is refused outright rather than resolved,
    because resolving it here would mean this module deciding a path question
    §6.3 step 2 already owns.
    """
    path = args.get("path")
    if not isinstance(path, str) or not path:
        raise HandlerRefused(
            WRITE_FAILED, f"git.worktree path {path!r} is not a non-empty str"
        )
    if not posixpath.isabs(path):
        raise HandlerRefused(
            WORKSPACE_SCOPE,
            f"git.worktree path {path!r} must be absolute; §6.3 step 2 canonicalizes it",
        )
    if any(segment == ".." for segment in path.split("/")):
        raise HandlerRefused(
            WORKSPACE_SCOPE, f"git.worktree path {path!r} contains a '..' component"
        )

    reserved = [s for s in workspace_root.split("/") if s]
    reserved += [s for s in WORKTREE_DIR.split("/") if s]
    segments = [s for s in path.split("/") if s]
    if segments[: len(reserved)] != reserved or len(segments) <= len(reserved):
        raise HandlerRefused(
            WORKSPACE_SCOPE,
            f"git.worktree path {path!r} is not inside "
            f"{posixpath.join(workspace_root, WORKTREE_DIR)}",
        )
    return path


def build_argv(args: Mapping[str, Any], *, workspace_root: str) -> tuple[str, ...]:
    """Build §6.4's single ``git worktree add`` form, or refuse."""
    if not workspace_root or not posixpath.isabs(workspace_root):
        raise HandlerRefused(
            WORKSPACE_SCOPE,
            f"git.worktree needs an absolute workspace root, got {workspace_root!r}",
        )
    branch = _checked_branch(args)
    path = _checked_path(args, workspace_root)
    # `--` before the path: a path beginning with a dash would otherwise be read
    # as an option, and `git` cannot tell them apart afterwards.
    return (GIT, "-C", workspace_root, "worktree", "add", "-b", branch, "--", path)


def _text(stream: Any) -> str:
    return stream.decode("utf-8", errors="replace") if isinstance(stream, bytes) else str(stream)


def result_of(observation: ExecObservation) -> dict[str, Any]:
    """Render the §6.5 ``result`` from what git DID, never from what was asked.

    Echoing the requested branch back would make the result agree with the request
    even when git did something else, which is the one thing a result exists to
    rule out. So the branch name is read out of the child's own output.

    **BOTH STREAMS, and stderr is the one that matters.** MEASURED on git 2.55.0:
    ``git worktree add -b feat -- <path>`` writes ``Preparing worktree (new branch
    'feat')`` to **stderr**, while stdout carries only ``HEAD is now at <sha>
    <subject>``. An earlier version of this function read stdout alone and would
    therefore have reported ``created: false`` for every SUCCESSFUL worktree — the
    exact "false for something that did happen" failure its own docstring claimed
    to prevent. Neither test caught it: the unit test fed a hand-authored stdout
    string it had invented, and the integration test ran real git but never called
    this function. git's progress and status messages conventionally go to stderr
    (as ``clone``, ``checkout -b`` and ``commit`` do), so reading both is the
    durable fix rather than swapping one hard-coded stream for the other.
    """
    combined = f"{_text(observation.stdout)}\n{_text(observation.stderr)}"
    found = re.search(r"new branch '([^']+)'", combined)
    return {
        "branch": found.group(1) if found is not None else "",
        "created": found is not None and observation.exit_code == 0,
    }
