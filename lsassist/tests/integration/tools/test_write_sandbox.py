"""T3.05 integration — the write batch against a REAL git and a REAL filesystem.

The unit suite injects git into the checkpoint store and stubs nothing else, so it
proves the handlers ASK for the right things. Only a real binary and real syscalls
can prove the two claims that matter after a write has already happened:

1. **A checkpoint taken before a write is really restorable.** The plan's
   verification line asks for exactly this: "integration test verifies checkpoint
   restore after a failed write". A snapshot whose objects cannot be read back is
   a rollback that fails at the one moment it is needed — after the workspace has
   been mutated. With git stubbed, a handler could record a manifest pointing at
   nothing and every unit assertion would still pass.
2. **The workspace's own `.git` never notices.** `fs.write` and `fs.patch` now
   call into the shadow store on every mutation of an existing file, which makes
   T4.04's headline §14.4 promise — "invisible to workspace `.git`" — a property
   of the WRITE path too, not just of the store's own tests.

`git.worktree` is the one tool in this batch that spawns, so its argv also has to
survive contact with a real repository: §6.4 admits `git worktree add <path> -b
<branch>` and nothing else, and a real `git` is the only thing that can confirm
the form is accepted rather than merely well-shaped.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from lsassist.audit.writer import AuditWriter
from lsassist.config.xdg import XdgPaths
from lsassist.contracts.manifest import ToolManifest
from lsassist.contracts.tool_request import ToolRequest
from lsassist.policy.stores import PolicyStores
from lsassist.recovery.checkpoints import CheckpointStore
from lsassist.tools.dispatcher import Decision, DispatchEnvironment, dispatch
from lsassist.tools.handlers import HandlerContext, HandlerRefused
from lsassist.tools.handlers.fs_patch import patch_file
from lsassist.tools.handlers.fs_write import write_file
from lsassist.tools.handlers.git_worktree import build_argv as worktree_argv
from lsassist.tools.registry import load_registry

REGISTRY = load_registry()

requires_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git is not installed on this host"
)

#: Nothing here may run unbounded: a hung integration test reports nothing.
BUDGET_S = 60


def git_binary() -> str:
    found = shutil.which("git")
    assert found is not None
    return found


def stores_for(home: Path) -> PolicyStores:
    return PolicyStores(
        home=str(home),
        audit_store=str(home / ".local/state/lsassist/audit"),
        policy_store=str(home / ".config/lsassist"),
        kernel_secret=str(home / ".local/state/lsassist/kernel.secret"),
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Iterator[Path]:
    """A REAL git repository outside /tmp — §8.1 masks /tmp with a tmpfs."""
    ws = Path.home() / ".cache" / "lsassist" / "t305-integration" / uuid.uuid4().hex / "ws"
    ws.mkdir(parents=True)
    (ws / "code.py").write_text("a = 1\nb = 2\n", encoding="utf-8")
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
    for argv in (
        ["git", "init", "-q", "-b", "main"],
        ["git", "-c", "user.email=t@e", "-c", "user.name=t", "add", "-A"],
        ["git", "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "init"],
    ):
        subprocess.run(argv, cwd=ws, check=True, timeout=BUDGET_S, env=env)
    try:
        yield ws
    finally:
        shutil.rmtree(ws.parent, ignore_errors=True)


@pytest.fixture
def environment(tmp_path: Path, workspace: Path) -> DispatchEnvironment:
    home = tmp_path / "home"
    home.mkdir(parents=True)
    return DispatchEnvironment(
        workspace_root=str(workspace),
        cwd=str(workspace),
        stores=stores_for(home),
        session_id="s-1",
    )


@pytest.fixture
def journal(tmp_path: Path) -> Iterator[AuditWriter]:
    with AuditWriter(directory=tmp_path / "audit", session_id="s-1") as writer:
        yield writer


@pytest.fixture
def store(tmp_path: Path, journal: AuditWriter) -> CheckpointStore:
    """The REAL store against the REAL git binary — no injected runner."""
    paths = XdgPaths(
        config_home=tmp_path / "c",
        data_home=tmp_path / "d",
        state_home=tmp_path / "s",
        cache_home=tmp_path / "h",
    )
    return CheckpointStore(paths, audit=journal, git_path=git_binary())


def context_for(
    environment: DispatchEnvironment,
    target: Path,
    *,
    tool: str,
    args_extra: dict[str, Any] | None = None,
) -> HandlerContext:
    manifest: ToolManifest = REGISTRY[tool]
    args: dict[str, Any] = {"path": str(target)}
    args.update(args_extra or {})
    request = ToolRequest(call_id="c1", tool=tool, args=args)
    decision = dispatch(
        request, manifest=manifest, environment=environment, path_args=["path"]
    )
    assert decision.decision is Decision.PROCEED, decision
    normalized = decision.normalized
    assert normalized is not None
    return HandlerContext(
        normalized=normalized, manifest=manifest, environment=environment
    )


def tree_of(directory: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            out[str(path.relative_to(directory))] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return out


def restore_from(
    store: CheckpointStore, xdg_root: Path, workspace: Path, checkpoint_id: str, rel: str
) -> bytes:
    """Read one file back out of the shadow store, by its manifest's own tree.

    Deliberately uses `git cat-file` rather than any lsassist code: the property
    under test is that the OBJECTS exist and are readable, and a reader written in
    the same module as the writer could share a defect with it.

    Two different roots, and confusing them silently returns nothing: manifests are
    keyed by the WORKSPACE they snapshot, while the object database lives under the
    XDG state root.
    """
    manifest = next(
        m for m in store.manifests(str(workspace)) if m.checkpoint_id == checkpoint_id
    )
    env = {
        "GIT_DIR": str(xdg_root / "s" / "lsassist" / "checkpoints" / "objects"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "PATH": "/usr/bin:/bin",
    }
    return subprocess.run(
        ["git", "cat-file", "-p", f"{manifest.tree}:{rel}"],
        capture_output=True, check=True, timeout=BUDGET_S, env=env,
    ).stdout


# ---------------------------------------------------------------------------
# The promise: a write is reversible, and the user's repo never notices
# ---------------------------------------------------------------------------


@requires_git
def test_the_pre_write_checkpoint_is_really_restorable(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore, tmp_path: Path
) -> None:
    """AC-06's precondition on the WRITE path, against real git objects.

    The file is overwritten for real, and the ORIGINAL is then read back out of
    the shadow store with `git cat-file`. A handler that recorded a manifest but
    never wrote the blobs passes every unit test and fails here.
    """
    target = workspace / "code.py"
    original = target.read_bytes()
    context = context_for(
        environment,
        target,
        tool="fs.write",
        args_extra={"content": "REPLACED\n", "intent": "overwrite"},
    )
    write_file(context, store)

    assert target.read_bytes() == b"REPLACED\n"
    stored = store.manifests(str(workspace))
    assert len(stored) == 1
    assert restore_from(store, tmp_path, workspace, stored[0].checkpoint_id, "code.py") == original


@requires_git
def test_a_failed_write_still_leaves_a_usable_checkpoint(
    environment: DispatchEnvironment,
    workspace: Path,
    store: CheckpointStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The plan's verification line: "checkpoint restore after a FAILED write".

    The snapshot is taken first, so when the publish then fails the workspace is
    unchanged AND the checkpoint exists — the state a recovery flow has to be able
    to act on. A handler that took the snapshot after a successful publish would
    leave nothing to restore from precisely when it is needed.
    """
    from lsassist.tools.handlers import fs_write as module

    original = (workspace / "code.py").read_bytes()
    before = tree_of(workspace)

    # `rename`, not `fsync`: `os` is a single module object, so patching
    # `fs_write.os.fsync` also breaks `CheckpointStore._persist`'s own fsync — the
    # snapshot then never lands and this test would assert its own artefact.
    # Failing the publish is the precise reproduction: the checkpoint completes,
    # the temporary file is written and fsynced, and only the step that changes
    # what a reader sees fails.
    def boom(src: object, dst: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(module.os, "rename", boom)
    context = context_for(
        environment,
        workspace / "code.py",
        tool="fs.write",
        args_extra={"content": "REPLACED\n", "intent": "overwrite"},
    )
    with pytest.raises(HandlerRefused):
        write_file(context, store)

    assert tree_of(workspace) == before
    stored = store.manifests(str(workspace))
    assert len(stored) == 1, "the pre-write snapshot did not survive the failed write"
    assert restore_from(store, tmp_path, workspace, stored[0].checkpoint_id, "code.py") == original


@requires_git
def test_the_workspace_git_directory_is_untouched_by_a_write(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore, tmp_path: Path
) -> None:
    """§14.4's headline promise, now a property of the WRITE path.

    Every file under `.git` is hashed before and after, plus the index's mtime. A
    checkpoint that leaked into the user's repository would show up here — and a
    write is the first operation where the tool has a reason to be near it.
    """
    before = tree_of(workspace / ".git")
    index_mtime = (workspace / ".git" / "index").stat().st_mtime_ns

    context = context_for(
        environment,
        workspace / "code.py",
        tool="fs.patch",
        args_extra={"blocks": [{"search": "a = 1", "replace": "a = 11"}]},
    )
    patch_file(context, store)

    assert (workspace / "code.py").read_text(encoding="utf-8") == "a = 11\nb = 2\n"
    assert tree_of(workspace / ".git") == before
    assert (workspace / ".git" / "index").stat().st_mtime_ns == index_mtime


@requires_git
def test_git_still_reports_only_the_change_we_made(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore, tmp_path: Path
) -> None:
    """The user-visible symptom of a leak is `git status` growing extra entries."""
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
    context = context_for(
        environment,
        workspace / "code.py",
        tool="fs.write",
        args_extra={"content": "only = 1\n", "intent": "overwrite"},
    )
    write_file(context, store)
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=workspace, capture_output=True, text=True, check=True,
        timeout=BUDGET_S, env=env,
    ).stdout
    assert status.split() == ["M", "code.py"], status


# ---------------------------------------------------------------------------
# git.worktree — the argv has to survive a real repository
# ---------------------------------------------------------------------------


@requires_git
def test_the_worktree_argv_is_accepted_by_a_real_git(
    workspace: Path, tmp_path: Path
) -> None:
    """A well-shaped argv that real git rejects is a tool that never works.

    Runs the handler's own argv verbatim, only substituting the pinned binary
    path, so the test cannot pass against a form the handler does not produce.
    """
    target = workspace / ".lsassist" / "worktrees" / "feat"
    argv = list(
        worktree_argv({"path": str(target), "branch": "feat"}, workspace_root=str(workspace))
    )
    argv[0] = git_binary()
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
    completed = subprocess.run(
        argv, cwd=workspace, capture_output=True, text=True, timeout=BUDGET_S, env=env
    )
    assert completed.returncode == 0, completed.stderr
    assert (target / ".git").exists()


@requires_git
def test_a_worktree_outside_the_reserved_directory_never_reaches_git(
    workspace: Path,
) -> None:
    """§6.4's path constraint, checked before anything is spawned."""
    with pytest.raises(HandlerRefused):
        worktree_argv(
            {"path": str(workspace / "elsewhere"), "branch": "feat"},
            workspace_root=str(workspace),
        )
    assert not (workspace / "elsewhere").exists()
