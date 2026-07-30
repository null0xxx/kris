"""T4.04 — the §14.4 shadow-git checkpoint store, with git stubbed out.

The store's job is to snapshot files into a git object database that is NOT the
workspace's own. Everything worth testing here follows from that one sentence:

* **The env isolation IS the feature.** `GIT_DIR`, `GIT_INDEX_FILE` and
  `GIT_WORK_TREE` are what keep the snapshot out of the user's repository. Get
  one wrong and `lsassist` writes objects, or worse an index, into a repository
  the user is mid-commit in — a tool that corrupts the thing it exists to protect.
  These tests assert the exact env of every child, and that the caller's own
  `GIT_*` variables cannot leak into it.
* **argv arrays, never a shell string (I2).** A path with a space, a quote or a
  `;` in it is ordinary on a real machine and catastrophic through `sh -c`.
* **Retention is a security property, not housekeeping.** §14.4 caps the store
  at 50 checkpoints and 2 GB with LRU eviction, and the one thing a pruner must
  never do is evict the checkpoint a rollback is about to use.

Git is injected here so the unit suite spawns nothing; `tests/integration/recovery`
runs the same store against a real `git` and asserts the workspace repository is
byte-for-byte untouched.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from lsassist.audit.writer import AuditWriter
from lsassist.config.xdg import XdgPaths
from lsassist.recovery.checkpoints import (
    MAX_CHECKPOINTS_PER_WORKSPACE,
    MAX_FILE_BYTES,
    MAX_STORE_BYTES,
    CheckpointError,
    CheckpointStore,
    GitResult,
)
from lsassist.recovery.manifest import ExclusionReason, TriggerKind

TREE = "a" * 40
STAMP = dt.datetime(2026, 7, 29, 12, 0, 0, tzinfo=dt.UTC)


# ---------------------------------------------------------------------------
# Doubles — recording, never asserting (an assert inside a fake is a failure the
# code under test could swallow)
# ---------------------------------------------------------------------------


class GitSpy:
    """Records every invocation and answers the plumbing calls the store makes."""

    def __init__(self, *, blob: str = "b" * 40, tree: str = TREE) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self._blob = blob
        self._tree = tree

    def __call__(self, argv: Sequence[str], env: dict[str, str]) -> GitResult:
        self.calls.append((tuple(argv), dict(env)))
        if "hash-object" in argv:
            return GitResult(0, self._blob, "")
        if "write-tree" in argv:
            return GitResult(0, self._tree, "")
        return GitResult(0, "", "")

    def env_of(self, needle: str) -> dict[str, str]:
        for argv, env in self.calls:
            if needle in argv:
                return env
        raise AssertionError(f"no git call contained {needle!r}: {self.calls}")


@pytest.fixture
def xdg(tmp_path: Path) -> XdgPaths:
    return XdgPaths(
        config_home=tmp_path / "config",
        data_home=tmp_path / "data",
        state_home=tmp_path / "state",
        cache_home=tmp_path / "cache",
    )


@pytest.fixture
def journal(tmp_path: Path) -> Any:
    with AuditWriter(directory=tmp_path / "audit", session_id="s-1") as writer:
        yield writer


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "a.py").write_text("print('a')\n", encoding="utf-8")
    (ws / "README.md").write_text("# proj\n", encoding="utf-8")
    return ws


def store(xdg: XdgPaths, journal: Any, git: GitSpy | None = None, **kw: Any) -> CheckpointStore:
    return CheckpointStore(xdg, audit=journal, git=git or GitSpy(), **kw)


def create(st: CheckpointStore, workspace: Path, *rel: str, **kw: Any) -> Any:
    kw.setdefault("trigger", TriggerKind.PRE_WRITE)
    kw.setdefault("task_id", "t-1")
    return st.create(workspace=str(workspace), paths=[str(workspace / r) for r in rel], **kw)


# ---------------------------------------------------------------------------
# A. Env isolation — the property the whole design exists for
# ---------------------------------------------------------------------------


def test_the_object_store_is_the_xdg_state_dir_not_the_workspace(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """§14.4: `GIT_DIR=$XDG_STATE_HOME/lsassist/checkpoints/objects`."""
    git = GitSpy()
    create(store(xdg, journal, git), workspace, "src/a.py")
    env = git.env_of("hash-object")
    assert env["GIT_DIR"] == str(xdg.state_home / "lsassist" / "checkpoints" / "objects")
    assert str(workspace) not in env["GIT_DIR"]


def test_the_work_tree_is_the_workspace_and_the_index_is_per_workspace(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """A shared index would let one workspace's snapshot stage another's files."""
    git = GitSpy()
    create(store(xdg, journal, git), workspace, "src/a.py")
    env = git.env_of("update-index")
    assert env["GIT_WORK_TREE"] == str(workspace.resolve())
    assert env["GIT_INDEX_FILE"].startswith(
        str(xdg.state_home / "lsassist" / "checkpoints")
    )
    assert str(workspace) not in env["GIT_INDEX_FILE"]


def test_two_workspaces_never_share_an_index_file(
    xdg: XdgPaths, journal: Any, tmp_path: Path
) -> None:
    seen = set()
    for name in ("one", "two"):
        ws = tmp_path / name
        ws.mkdir()
        (ws / "f.txt").write_text("x\n", encoding="utf-8")
        git = GitSpy()
        create(store(xdg, journal, git), ws, "f.txt")
        seen.add(git.env_of("update-index")["GIT_INDEX_FILE"])
    assert len(seen) == 2


def test_the_child_env_does_not_inherit_the_callers_git_variables(
    xdg: XdgPaths, journal: Any, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one variable that would redirect the whole snapshot into the user's repo.

    `git` reads `GIT_DIR` from the environment. A child that inherited the
    caller's would write checkpoint objects straight into whatever repository
    the user happened to be standing in.
    """
    monkeypatch.setenv("GIT_DIR", "/home/u/proj/.git")
    monkeypatch.setenv("GIT_WORK_TREE", "/home/u/proj")
    monkeypatch.setenv("GIT_INDEX_FILE", "/home/u/proj/.git/index")
    monkeypatch.setenv("GIT_AUTHOR_NAME", "someone")
    git = GitSpy()
    create(store(xdg, journal, git), workspace, "src/a.py")
    assert git.calls
    for _argv, env in git.calls:
        # `.get`, not `[...]`: the store-init call deliberately carries NO
        # GIT_DIR at all (git init takes its target from the argument), and the
        # property under test is "the caller's value never appears", which is
        # satisfied both by a different value and by absence.
        assert env.get("GIT_DIR") != "/home/u/proj/.git"
        assert env.get("GIT_WORK_TREE") != "/home/u/proj"
        assert env.get("GIT_INDEX_FILE") != "/home/u/proj/.git/index"
        # GIT_AUTHOR_NAME is now SET deliberately — `commit-tree` needs an
        # identity and the store's config is pinned to /dev/null so it has none to
        # read. The property under test is that the CALLER's value never reaches
        # the child, not that the key is absent; asserting absence would have
        # blocked a legitimate change while proving nothing extra.
        assert env.get("GIT_AUTHOR_NAME") != "someone"


def test_every_git_call_is_an_argv_list_never_a_shell_string(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """I2. A path containing a space or a `;` is ordinary and, through a shell, fatal."""
    git = GitSpy()
    create(store(xdg, journal, git), workspace, "src/a.py")
    assert git.calls
    for argv, _env in git.calls:
        assert isinstance(argv, tuple)
        assert all(isinstance(part, str) for part in argv)
        assert argv[0].endswith("git")
        assert not any(part in {"-c", "sh", "bash", "&&", "|", ";"} for part in argv[1:])


def test_a_path_with_shell_metacharacters_survives_verbatim(
    xdg: XdgPaths, journal: Any, tmp_path: Path
) -> None:
    ws = tmp_path / "ws2"
    ws.mkdir()
    nasty = "a b;rm -rf $HOME.txt"
    (ws / nasty).write_text("x\n", encoding="utf-8")
    git = GitSpy()
    manifest = create(store(xdg, journal, git), ws, nasty)
    assert [e.path for e in manifest.entries] == [nasty]
    assert any(nasty in argv for argv, _ in git.calls)


# ---------------------------------------------------------------------------
# B. What the manifest says
# ---------------------------------------------------------------------------


def test_a_checkpoint_records_every_requested_path(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    manifest = create(store(xdg, journal), workspace, "src/a.py", "README.md")
    assert [e.path for e in manifest.entries] == ["README.md", "src/a.py"]
    assert manifest.workspace == str(workspace.resolve())
    assert manifest.trigger is TriggerKind.PRE_WRITE
    assert manifest.tree == TREE


def test_a_path_outside_the_workspace_is_refused(
    xdg: XdgPaths, journal: Any, workspace: Path, tmp_path: Path
) -> None:
    """A checkpoint is workspace-scoped; a path outside it has no relative form."""
    outside = tmp_path / "elsewhere.txt"
    outside.write_text("x\n", encoding="utf-8")
    with pytest.raises(CheckpointError):
        store(xdg, journal).create(
            workspace=str(workspace),
            paths=[str(outside)],
            trigger=TriggerKind.MANUAL,
            task_id="t-1",
        )


def test_a_checkpoint_with_no_paths_is_refused(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """An empty snapshot restores nothing and would still consume retention."""
    with pytest.raises(CheckpointError):
        create(store(xdg, journal), workspace)


def test_a_missing_file_is_refused_rather_than_silently_skipped(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """A pre-write snapshot of a file that is not there yet is a caller bug.

    Skipping it silently would produce a manifest that looks complete, and a
    rollback would then treat the file as "absent at checkpoint time".
    """
    with pytest.raises(CheckpointError):
        create(store(xdg, journal), workspace, "src/nope.py")


# ---------------------------------------------------------------------------
# C. Exclusion — §14.4's 50 MB rule
# ---------------------------------------------------------------------------


def test_the_size_ceiling_is_the_14_4_number() -> None:
    assert MAX_FILE_BYTES == 50 * 1024 * 1024


def test_an_oversized_file_is_recorded_as_excluded_not_omitted(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """Omitting it would read, at restore time, as "this file did not exist"."""
    big = workspace / "big.bin"
    big.write_bytes(b"\0" * 16)
    st = store(xdg, journal, size_of=lambda _p: MAX_FILE_BYTES + 1)
    manifest = create(st, workspace, "big.bin")
    (only,) = manifest.entries
    assert only.excluded_because is ExclusionReason.OVERSIZE
    assert only.sha256 is None


def test_a_file_exactly_at_the_ceiling_is_still_stored(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """Off-by-one guard: §14.4 says "> 50 MB", so 50 MB itself is inside."""
    (workspace / "edge.bin").write_bytes(b"\0" * 16)
    st = store(xdg, journal, size_of=lambda _p: MAX_FILE_BYTES)
    (only,) = create(st, workspace, "edge.bin").entries
    assert only.excluded_because is None
    assert only.sha256 is not None


def test_an_excluded_file_is_never_handed_to_git(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """Excluding it from the manifest but hashing it anyway would store the bytes."""
    (workspace / "big.bin").write_bytes(b"\0" * 16)
    git = GitSpy()
    st = store(xdg, journal, git, size_of=lambda _p: MAX_FILE_BYTES + 1)
    create(st, workspace, "big.bin")
    assert not any("big.bin" in argv for argv, _ in git.calls)


# ---------------------------------------------------------------------------
# D. Retention — §14.4's 50 / 2 GB / LRU
# ---------------------------------------------------------------------------


def test_the_retention_numbers_are_the_14_4_numbers() -> None:
    assert MAX_CHECKPOINTS_PER_WORKSPACE == 50
    assert MAX_STORE_BYTES == 2 * 1024 * 1024 * 1024


def test_the_fifty_first_checkpoint_evicts_the_oldest(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    st = store(xdg, journal)
    made = [create(st, workspace, "src/a.py") for _ in range(MAX_CHECKPOINTS_PER_WORKSPACE)]
    assert len(st.manifests(str(workspace))) == MAX_CHECKPOINTS_PER_WORKSPACE

    create(st, workspace, "src/a.py")
    kept = {m.checkpoint_id for m in st.manifests(str(workspace))}
    assert len(kept) == MAX_CHECKPOINTS_PER_WORKSPACE
    assert made[0].checkpoint_id not in kept
    assert made[1].checkpoint_id in kept


def test_retention_is_per_workspace_not_global(
    xdg: XdgPaths, journal: Any, workspace: Path, tmp_path: Path
) -> None:
    """One busy workspace must not evict another's only checkpoint."""
    other = tmp_path / "other"
    other.mkdir()
    (other / "f.txt").write_text("x\n", encoding="utf-8")
    st = store(xdg, journal)
    keeper = create(st, other, "f.txt")
    for _ in range(MAX_CHECKPOINTS_PER_WORKSPACE + 5):
        create(st, workspace, "src/a.py")
    assert keeper.checkpoint_id in {m.checkpoint_id for m in st.manifests(str(other))}


def test_a_store_over_the_size_cap_is_pruned(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    st = store(xdg, journal, store_size=lambda: MAX_STORE_BYTES + 1)
    for _ in range(3):
        create(st, workspace, "src/a.py")
    assert len(st.manifests(str(workspace))) < 3


def test_the_checkpoint_just_created_is_never_the_one_pruned(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """§14.4's pruner must never evict what a rollback is about to use."""
    st = store(xdg, journal, store_size=lambda: MAX_STORE_BYTES + 1)
    newest = create(st, workspace, "src/a.py")
    assert newest.checkpoint_id in {m.checkpoint_id for m in st.manifests(str(workspace))}


def test_eviction_order_is_oldest_first(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    st = store(xdg, journal)
    ids = [create(st, workspace, "src/a.py").checkpoint_id for _ in range(52)]
    kept = [m.checkpoint_id for m in st.manifests(str(workspace))]
    assert kept == ids[-MAX_CHECKPOINTS_PER_WORKSPACE:]


# ---------------------------------------------------------------------------
# E. The audit trail
# ---------------------------------------------------------------------------


def test_creating_a_checkpoint_journals_a_recovery_event(
    xdg: XdgPaths, journal: Any, workspace: Path, tmp_path: Path
) -> None:
    create(store(xdg, journal), workspace, "src/a.py")
    journal.close()
    events = [
        line
        for path in sorted((tmp_path / "audit").glob("session-*.jsonl"))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert events
    assert all('"event":"recovery"' in e.replace(", ", ",") for e in events)


def test_pruning_journals_its_own_event(
    xdg: XdgPaths, journal: Any, workspace: Path, tmp_path: Path
) -> None:
    """A checkpoint that silently disappeared is a rollback that will fail later."""
    st = store(xdg, journal)
    for _ in range(MAX_CHECKPOINTS_PER_WORKSPACE + 1):
        create(st, workspace, "src/a.py")
    journal.close()
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((tmp_path / "audit").glob("session-*.jsonl"))
    )
    assert "prune" in text


def test_no_file_content_reaches_the_journal(
    xdg: XdgPaths, journal: Any, workspace: Path, tmp_path: Path
) -> None:
    """§14.1 records digests, never bodies — a checkpoint of a secret file
    must not put that secret in a permanent record."""
    (workspace / "secret.txt").write_text("SUPERSECRET-TOKEN\n", encoding="utf-8")
    create(store(xdg, journal), workspace, "secret.txt")
    journal.close()
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((tmp_path / "audit").glob("session-*.jsonl"))
    )
    assert "SUPERSECRET-TOKEN" not in text


# ---------------------------------------------------------------------------
# F. Failure is loud
# ---------------------------------------------------------------------------


def test_a_failing_git_call_is_a_typed_error_not_a_silent_partial(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """A checkpoint that half-happened is worse than none: the caller proceeds
    to mutate the workspace believing it can roll back."""

    class Failing(GitSpy):
        def __call__(self, argv: Sequence[str], env: dict[str, str]) -> GitResult:
            super().__call__(argv, env)
            return GitResult(128, "", "fatal: not a git repository")

    with pytest.raises(CheckpointError):
        create(store(xdg, journal, Failing()), workspace, "src/a.py")


def test_a_failed_checkpoint_leaves_no_manifest_behind(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    class Failing(GitSpy):
        def __call__(self, argv: Sequence[str], env: dict[str, str]) -> GitResult:
            super().__call__(argv, env)
            return GitResult(1, "", "boom")

    st = store(xdg, journal, Failing())
    with pytest.raises(CheckpointError):
        create(st, workspace, "src/a.py")
    assert st.manifests(str(workspace)) == ()


def test_a_git_binary_outside_the_trusted_directories_is_refused(
    xdg: XdgPaths, journal: Any
) -> None:
    """The same argument `sandbox/availability.py` measures: an early writable
    PATH entry is a shim, and a shimmed git writes wherever it likes."""
    with pytest.raises(CheckpointError):
        CheckpointStore(xdg, audit=journal, git=GitSpy(), git_path="/home/u/.local/bin/git")


def test_a_runner_that_returns_the_wrong_type_is_a_typed_error(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """An injected runner is a seam, and a seam is a place to hand back garbage.

    Written as a test rather than a `# pragma: no cover`: §23.1 forbids pragmas
    in a TCB package precisely because "this branch is hard to reach" is how an
    unreachable-looking branch stops being checked at all.
    """

    def wrong(argv: Sequence[str], env: dict[str, str]) -> Any:
        return ("not", "a", "GitResult")

    st = CheckpointStore(xdg, audit=journal, git=wrong)
    with pytest.raises(CheckpointError, match="GitResult"):
        create(st, workspace, "src/a.py")


def test_the_default_store_size_measures_the_object_database(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """The production `store_size` — the one the 2 GB cap actually consults."""
    st = store(xdg, journal)
    objects = xdg.state_home / "lsassist" / "checkpoints" / "objects" / "ab"
    objects.mkdir(parents=True)
    (objects / "cdef").write_bytes(b"x" * 4096)
    assert st.measure_store() == 4096


def test_the_default_store_size_is_zero_before_anything_is_stored(
    xdg: XdgPaths, journal: Any
) -> None:
    assert store(xdg, journal).measure_store() == 0


def test_manifests_are_empty_for_a_workspace_that_has_none(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    assert store(xdg, journal).manifests(str(workspace)) == ()


# ---------------------------------------------------------------------------
# G. Review findings, reproduced then closed
# ---------------------------------------------------------------------------


def test_each_create_gets_a_FRESH_index(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """THE reproduced CRITICAL, at unit level: one index per CALL, not per workspace.

    A persistent per-workspace index made `update-index --add` accumulate, so
    `write-tree` baked earlier calls' files into a later checkpoint's tree. The
    per-workspace design was added to stop a cross-workspace leak; a per-CALL
    index closes that AND the accumulation AND the two-process race, because no
    two calls ever touch the same file.
    """
    git = GitSpy()
    st = store(xdg, journal, git)
    create(st, workspace, "src/a.py")
    first = {env["GIT_INDEX_FILE"] for _a, env in git.calls if "GIT_INDEX_FILE" in env}
    git.calls.clear()
    create(st, workspace, "README.md")
    second = {env["GIT_INDEX_FILE"] for _a, env in git.calls if "GIT_INDEX_FILE" in env}

    assert len(first) == 1 and len(second) == 1
    assert first != second, "two create() calls shared one index file"


def test_the_index_file_is_removed_after_the_checkpoint(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """A per-call index left on disk is unbounded growth in the state directory."""
    git = GitSpy()
    create(store(xdg, journal, git), workspace, "src/a.py")
    used = next(env["GIT_INDEX_FILE"] for _a, env in git.calls if "GIT_INDEX_FILE" in env)
    assert not Path(used).exists()


def test_size_pressure_stops_as_soon_as_the_store_is_under_the_cap(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """THE BLOCKER, and the only shape that distinguishes the two behaviours.

    The old size branch took EVERY checkpoint but the newest in one go, and
    because nothing reclaimed git objects the cap could never clear — so every
    later create, for any workspace, repeated the wipe. §14.4 says "LRU prune",
    which is oldest-first UNTIL the store is under its cap.

    A stub that is permanently over-cap cannot tell the two apart: both converge
    on just the newest, and a first version of this test used exactly that stub
    and the mass-wipe mutant SURVIVED it. Here the store goes under as soon as one
    checkpoint is evicted, so "evict one, re-measure, stop" keeps three and
    "evict everything" keeps one.
    """
    state = {"bytes": 0}

    def store_size() -> int:
        if state["bytes"] > MAX_STORE_BYTES:
            state["bytes"] = 0  # one eviction is enough to get back under
            return MAX_STORE_BYTES + 1
        return 0

    st = store(xdg, journal, store_size=store_size)
    ids = [create(st, workspace, "src/a.py").checkpoint_id for _ in range(3)]
    assert len(st.manifests(str(workspace))) == 3

    state["bytes"] = MAX_STORE_BYTES + 1
    ids.append(create(st, workspace, "src/a.py").checkpoint_id)

    kept = [m.checkpoint_id for m in st.manifests(str(workspace))]
    assert ids[-1] in kept, "the newest must never be evicted"
    assert len(kept) == 3, f"expected exactly one eviction, kept {kept}"
    assert kept == ids[1:], "eviction must take the OLDEST first"


def test_the_newest_survives_even_under_sustained_size_pressure(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """The pruner's one inviolable rule, under a cap that never clears."""
    st = store(xdg, journal, store_size=lambda: MAX_STORE_BYTES + 1)
    ids = [create(st, workspace, "src/a.py").checkpoint_id for _ in range(3)]
    kept = [m.checkpoint_id for m in st.manifests(str(workspace))]
    assert kept == [ids[-1]]


def test_a_journal_failure_leaves_no_usable_checkpoint(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """A checkpoint whose creation reported failure must not be listed as usable.

    `_persist` ran before `_journal`, so a raising audit write left the manifest
    on disk while `create()` propagated an UNTYPED exception — and `manifests()`
    then offered that checkpoint to a rollback whose caller had been told the
    snapshot failed.
    """

    class Refusing:
        def write(self, *a: Any, **k: Any) -> Any:
            raise RuntimeError("journal is full")

    st = CheckpointStore(xdg, audit=Refusing(), git=GitSpy())  # type: ignore[arg-type]
    with pytest.raises(CheckpointError):
        create(st, workspace, "src/a.py")
    assert st.manifests(str(workspace)) == ()


def test_one_corrupt_manifest_does_not_hide_the_others(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """`manifests()` validated every file with no isolation, so one truncated
    file denied a rollback its ENTIRE recovery history for that workspace."""
    st = store(xdg, journal)
    good = [create(st, workspace, "src/a.py").checkpoint_id for _ in range(2)]
    directory = next(
        p for p in (xdg.state_home / "lsassist" / "checkpoints" / "manifests").iterdir()
    )
    (directory / "cp-00000000000000000001.json").write_text("{tru", encoding="utf-8")

    kept = [m.checkpoint_id for m in st.manifests(str(workspace))]
    assert sorted(kept) == sorted(good)


def test_a_manifest_is_written_atomically(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """`write_bytes` leaves a truncated file if the process dies mid-write.

    §6.4's own `fs.write` row mandates tmp + fsync + rename for the USER's files;
    a checkpoint manifest — the thing a rollback trusts — deserves no less.
    """
    st = store(xdg, journal)
    create(st, workspace, "src/a.py")
    directory = next(
        p for p in (xdg.state_home / "lsassist" / "checkpoints" / "manifests").iterdir()
    )
    leftovers = [p.name for p in directory.iterdir() if not p.name.endswith(".json")]
    assert leftovers == [], f"temporary files left behind: {leftovers}"


def test_every_store_directory_is_0700_all_the_way_down(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """MEASURED: `Path.mkdir(mode=..., parents=True)` only reaches the LEAF.

    With umask 022 the ancestors came out 0o755, including the `checkpoints/`
    directory §12.1 pins at 0700. `config/xdg.py`'s `_ensure_dir` already walks
    components one at a time for exactly this reason.
    """
    import stat as stat_module

    create(store(xdg, journal), workspace, "src/a.py")
    root = xdg.state_home / "lsassist" / "checkpoints"
    for path in [root, *(p for p in root.rglob("*") if p.is_dir())]:
        mode = stat_module.S_IMODE(path.stat().st_mode)
        assert mode == 0o700, f"{path} is {oct(mode)}, not 0o700"


def test_two_checkpoints_in_one_clock_tick_get_different_ids(
    xdg: XdgPaths, journal: Any, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tie-break exists because `_persist` writes to `{checkpoint_id}.json`.

    A duplicate id silently OVERWRITES the earlier manifest — no error, no prune
    record. The branch had no test, so a plain `time.time_ns()` would have passed.
    """
    from lsassist.recovery import checkpoints as module

    monkeypatch.setattr(module.time, "time_ns", lambda: 1_700_000_000_000_000_000)
    st = store(xdg, journal)
    first = create(st, workspace, "src/a.py")
    second = create(st, workspace, "src/a.py")
    assert first.checkpoint_id != second.checkpoint_id
    assert len(st.manifests(str(workspace))) == 2


def test_a_file_where_a_store_directory_belongs_is_a_typed_error(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """An ancestor occupied by a file makes mkdir raise NotADirectoryError.

    Raw, that escapes as an untyped OSError and the caller never learns its
    rollback does not exist.
    """
    (xdg.state_home).mkdir(parents=True)
    (xdg.state_home / "lsassist").write_text("not a directory\n", encoding="utf-8")
    with pytest.raises(CheckpointError):
        create(store(xdg, journal), workspace, "src/a.py")


def test_a_failed_manifest_write_is_a_typed_error(
    xdg: XdgPaths, journal: Any, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The atomic write's own failure path: fsync is where a full disk shows up."""
    from lsassist.recovery import checkpoints as module

    def boom(fd: int) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(module.os, "fsync", boom)
    with pytest.raises(CheckpointError):
        create(store(xdg, journal), workspace, "src/a.py")


def test_a_failing_ref_delete_does_not_mask_the_original_failure(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """`_discard` runs while unwinding, so its own error must not replace the cause.

    The journal failure is what the caller needs to hear about; a secondary
    "update-ref -d exited 1" would bury it.
    """

    class RefDeleteFails(GitSpy):
        def __call__(self, argv: Sequence[str], env: dict[str, str]) -> GitResult:
            super().__call__(argv, env)
            if "-d" in argv:
                return GitResult(1, "", "cannot delete ref")
            return GitResult(0, "b" * 40 if "hash-object" in argv else TREE, "")

    class Refusing:
        def write(self, *a: Any, **k: Any) -> Any:
            raise RuntimeError("journal is full")

    st = CheckpointStore(xdg, audit=Refusing(), git=RefDeleteFails())  # type: ignore[arg-type]
    with pytest.raises(CheckpointError, match="journalled"):
        create(st, workspace, "src/a.py")


def test_pruning_to_a_ceiling_above_the_count_evicts_nothing(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """Asking to keep more than exist must be a no-op, not an empty gc cycle."""
    st = store(xdg, journal)
    create(st, workspace, "src/a.py")
    assert st.prune_to(str(workspace), keep_last=10, task_id="t-1") == ()
    assert len(st.manifests(str(workspace))) == 1


# ---------------------------------------------------------------------------
# K. What the SECOND isolated review found. Every test here is named by the
#    defect it reproduces, because each one passed a 100%-branch suite.
# ---------------------------------------------------------------------------


def test_hash_object_never_lets_the_workspace_choose_the_stored_bytes(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """`--path` selects gitattributes-driven filters; `--no-filters` refuses them.

    MEASURED on git 2.55.0 in `tests/integration/recovery`: with `* text=auto` in
    the workspace and a 20-byte CRLF file, `--path` stored 18 bytes while the
    manifest digest stayed the raw 20-byte hash. The stored object stopped being
    the file a rollback has to reproduce.

    Asserted structurally as well as behaviourally because the behaviour needs a
    real git: the argv is the whole defence, and a mutation putting `--path` back
    must fail here even with git stubbed.
    """
    spy = GitSpy()
    create(store(xdg, journal, spy), workspace, "src/a.py")
    argv = next(a for a, _ in spy.calls if "hash-object" in a)
    assert "--no-filters" in argv, f"hash-object ran without --no-filters: {argv}"
    assert "--path" not in argv, f"--path lets the workspace rewrite the blob: {argv}"


def test_a_git_runner_that_hangs_is_a_typed_error_not_an_untyped_escape(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """`subprocess.run(timeout=...)` RAISES; `_invoke` only checked the return value.

    A caller written to this module's contract catches `CheckpointError` and
    nothing else, so a hung git left it believing its snapshot existed.
    """
    import subprocess

    def hangs(argv: Sequence[str], env: dict[str, str]) -> GitResult:
        raise subprocess.TimeoutExpired(list(argv), 60)

    st = CheckpointStore(xdg, audit=journal, git=hangs)
    with pytest.raises(CheckpointError, match="could not be run"):
        create(st, workspace, "src/a.py")


def test_a_missing_git_binary_is_a_typed_error(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """The other half of the same gap: `OSError`, not `SubprocessError`."""

    def absent(argv: Sequence[str], env: dict[str, str]) -> GitResult:
        raise FileNotFoundError(2, "No such file or directory", argv[0])

    st = CheckpointStore(xdg, audit=journal, git=absent)
    with pytest.raises(CheckpointError, match="could not be run"):
        create(st, workspace, "src/a.py")


def test_the_real_git_runner_reports_status_and_streams(tmp_path: Path) -> None:
    """`_default_git` is the ONLY code that spawns git, and no unit test called it.

    The §23.1 blocking coverage gate runs `tests/unit tests/property` — not
    `tests/integration` — so every line of the real runner sat outside the floor
    that is supposed to certify it. Exercised with `/bin/true` and `/bin/false`
    rather than git so the assertion is about the runner, not about git.
    """
    from lsassist.recovery import checkpoints as module

    assert module._default_git(("/bin/true",), {}) == GitResult(0, "", "")
    assert module._default_git(("/bin/false",), {}).returncode == 1
    printed = module._default_git(("/bin/sh", "-c", "printf hi; printf oops >&2"), {})
    assert (printed.stdout, printed.stderr) == ("hi", "oops")


def test_the_real_git_runner_passes_the_constructed_env_and_nothing_else(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """The env IS the isolation, and the test that claimed to prove it could not.

    Its assertions used `/bin/true`, `/bin/false` and a literal `printf` — none of
    which reads any environment variable — so they were identical whether the
    constructed dict or the inherited environment was passed, while its docstring
    claimed a regression to `env=None` would fail. That is the same defect class
    as the CRITICAL it was written to close: a behaviour proven only outside the
    blocking gate. This asserts BOTH directions with a child that actually reads
    its environment: the constructed value arrives, and the caller's does not.
    """
    from lsassist.recovery import checkpoints as module

    monkeypatch.setenv("GIT_DIR", "/home/u/proj/.git")
    monkeypatch.setenv("LSASSIST_LEAK_CANARY", "leaked")
    result = module._default_git(
        ("/bin/sh", "-c", 'printf "%s|%s" "$MARK" "$LSASSIST_LEAK_CANARY"'),
        {"MARK": "constructed"},
    )
    assert result.stdout == "constructed|", (
        f"env passthrough or isolation is broken: {result.stdout!r} "
        "(left of | must be the constructed value, right must be empty)"
    )


def test_the_real_git_runner_survives_output_that_is_not_valid_utf8() -> None:
    """MEASURED: `text=True` alone decodes STRICTLY and raises on one bad byte.

    `UnicodeDecodeError` is a `ValueError`, so it was neither of the two types
    `_invoke` used to catch — a git diagnostic quoting a non-UTF-8 filename could
    replace the diagnosis with a decode crash escaping `create()` untyped. Linux
    filenames are byte strings; this is an ordinary input, not an exotic one.
    """
    from lsassist.recovery import checkpoints as module

    result = module._default_git(("/bin/sh", "-c", r"printf 'caf\351 broken'"), {})
    assert result.returncode == 0
    assert "broken" in result.stdout


def test_a_runner_raising_anything_at_all_is_a_typed_error(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """The runner is INJECTABLE, so no catch tuple can enumerate what it raises.

    A `ValueError` is neither `OSError` nor `SubprocessError`, and it was exactly
    what `subprocess.run` produced in practice. The guard is now `Exception`;
    `BaseException` is left alone so Ctrl+C still interrupts.
    """

    def raises_a_value_error(argv: Sequence[str], env: dict[str, str]) -> GitResult:
        raise ValueError("not an OSError and not a SubprocessError")

    st = CheckpointStore(xdg, audit=journal, git=raises_a_value_error)
    with pytest.raises(CheckpointError, match="could not be run"):
        create(st, workspace, "src/a.py")


def test_every_checkpoint_gets_a_commit_and_a_ref_so_its_objects_are_reachable(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """`GitSpy` answers any unmatched argv with success, which hid this entirely.

    `manifest.tree` comes from `write-tree` alone, so deleting `commit-tree` and
    `update-ref` changed no field any unit test inspected — and the reachability
    property was proven ONLY in `tests/integration`, which the §23.1 blocking gate
    does not run and which skips itself when git is absent. Unreferenced objects
    are objects `gc` is entitled to delete, so this is the whole reason the
    snapshots survive at all.
    """
    spy = GitSpy()
    manifest = create(store(xdg, journal, spy), workspace, "src/a.py")
    verbs = [a for a, _ in spy.calls]
    commit = next((a for a in verbs if "commit-tree" in a), None)
    ref = next((a for a in verbs if "update-ref" in a and "-d" not in a), None)
    assert commit is not None, f"no commit-tree call: {verbs}"
    assert ref is not None, f"no update-ref call, so the objects are unreachable: {verbs}"
    assert manifest.tree in commit, f"commit-tree did not commit this manifest's tree: {commit}"
    assert manifest.checkpoint_id in ref[2], f"the ref does not name the checkpoint: {ref}"


def test_eviction_reclaims_space_without_pruning_a_concurrent_snapshot(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """Two properties in one, because they are in tension and both are real.

    Eviction MUST run a `gc` — refs alone free nothing, and that is half the
    reason every checkpoint has one. But it must NOT be `--prune=now`: one object
    database is shared by every workspace, `create()` writes blobs before
    `update-ref` makes them reachable, and `--prune=now` waives exactly the grace
    period git documents as protecting a concurrent unfinished write. Neither
    property was asserted anywhere inside the blocking gate.
    """
    from lsassist.recovery.checkpoints import _GC_PRUNE_EXPIRY

    spy = GitSpy()
    st = store(xdg, journal, spy)
    create(st, workspace, "src/a.py")
    create(st, workspace, "README.md")
    st.prune_to(str(workspace), keep_last=1, task_id="t-1")

    gc = next((a for a in (argv for argv, _ in spy.calls) if "gc" in a), None)
    assert gc is not None, "eviction ran no gc, so the space it freed is not reclaimable"
    assert f"--prune={_GC_PRUNE_EXPIRY}" in gc, f"gc pruned with the wrong expiry: {gc}"
    assert "--prune=now" not in gc, (
        "--prune=now waives the grace period that protects a concurrent create()'s "
        f"not-yet-referenced objects: {gc}"
    )


def test_a_manifest_whose_workspace_field_lies_is_ignored(
    xdg: XdgPaths, journal: Any, workspace: Path, tmp_path: Path
) -> None:
    """`_all_stored` takes the OWNER from the directory, never from the file.

    Both the refname and the manifest path `_remove` deletes are derived from that
    value, so a manifest under one workspace's directory claiming to belong to
    another would have aimed eviction at the other one's real ref and manifest.
    Nothing but this store writes there, so this is a trust boundary rather than a
    live attack — but it cost one comparison to close.
    """
    st = store(xdg, journal)
    honest = create(st, workspace, "src/a.py")
    manifests_root = xdg.state_home / "lsassist" / "checkpoints" / "manifests"
    real_dir = next(manifests_root.iterdir())

    # The same record, byte for byte, in a DIFFERENT workspace's directory. Its
    # `workspace` field still names the real owner, so honouring the field would
    # aim eviction at that owner's ref while honouring the directory ignores it.
    forged_dir = manifests_root / ("f" * 32)
    forged_dir.mkdir(mode=0o700)
    (forged_dir / f"{honest.checkpoint_id}.json").write_bytes(
        (real_dir / f"{honest.checkpoint_id}.json").read_bytes()
    )

    owners = st._all_stored()
    assert owners == ((honest.workspace, honest.checkpoint_id),), (
        f"a manifest was trusted over the directory it was read from: {owners}"
    )


def test_the_real_git_runner_enforces_its_own_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without this, deleting `timeout=_GIT_TIMEOUT_S` is a silent mutant.

    `_invoke` maps the raised `TimeoutExpired` to `CheckpointError`; this test is
    about the runner actually arming the clock in the first place.
    """
    import subprocess

    from lsassist.recovery import checkpoints as module

    monkeypatch.setattr(module, "_GIT_TIMEOUT_S", 0.3)
    with pytest.raises(subprocess.TimeoutExpired):
        module._default_git(("/bin/sleep", "5"), {})


@pytest.mark.parametrize("component", ["objects", "index", "manifests"])
def test_a_symlinked_store_directory_is_refused_fail_closed(
    xdg: XdgPaths, journal: Any, workspace: Path, tmp_path: Path, component: str
) -> None:
    """`config/xdg.py` lstat-fail-closes; `_ensure_dir_chain` claimed parity and lied.

    `Path.exists()` and `Path.stat()` both FOLLOW symlinks, and xdg.py's `LAYOUT`
    table stops at `checkpoints/` — these three subdirectories are created here and
    appear in no table, so nothing else in the system ever checks them. A link
    planted at any of them redirected every object and manifest write out of the
    0700 store.
    """
    root = xdg.state_home / "lsassist" / "checkpoints"
    root.mkdir(parents=True)
    elsewhere = tmp_path / f"elsewhere-{component}"
    elsewhere.mkdir()
    (root / component).symlink_to(elsewhere, target_is_directory=True)

    # Matched on the REASON, with its punctuation, and never on the bare word:
    # pytest's `tmp_path` embeds the test's own name, so this test is called
    # ...symlinked... and `match="symlink"` matched the PATH inside the message
    # rather than the diagnosis. It passed with the check deleted — a tautology,
    # and the exact failure shape an isolated review flagged in this suite.
    with pytest.raises(CheckpointError, match=r"symlink \(fail-closed\)"):
        create(store(xdg, journal), workspace, "src/a.py")
    assert list(elsewhere.iterdir()) == [], "the redirected write was not prevented"


@pytest.mark.parametrize("component", ["index", "manifests"])
def test_a_file_where_a_dynamic_store_directory_belongs_is_a_typed_error(
    xdg: XdgPaths, journal: Any, workspace: Path, component: str
) -> None:
    """The `_fresh_index` and `_persist` call sites had NO handler at all.

    Only `_ensure_store` wrapped `_ensure_dir_chain`, so an ordinary
    `NotADirectoryError` under `index/` or `manifests/` escaped `create()`
    untyped. The mapping now lives inside `_ensure_dir_chain`, once.
    """
    root = xdg.state_home / "lsassist" / "checkpoints"
    root.mkdir(parents=True)
    (root / component).write_text("not a directory\n", encoding="utf-8")
    with pytest.raises(CheckpointError, match="not a directory"):
        create(store(xdg, journal), workspace, "src/a.py")


requires_unprivileged = pytest.mark.skipif(
    hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0,
    reason="root ignores directory permissions, so the denial cannot be provoked",
)


@requires_unprivileged
def test_a_store_path_that_cannot_be_inspected_is_a_typed_error(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """An unreadable ancestor makes the store probe raise EACCES, not ENOENT.

    Provoked with real permissions rather than a patched `lstat`, because the
    branch exists for a real filesystem condition and a patch would prove only
    that the handler is spelled correctly. Writing it this way immediately found
    a second unguarded call: `_ensure_store`'s own `HEAD.is_file()` probe runs
    BEFORE the chain walk, and `Path.is_file()` swallows ENOENT and ENOTDIR but
    NOT EACCES — so this reproduces whichever of the two is reached first.
    """
    blocked = xdg.state_home / "lsassist"
    blocked.mkdir(parents=True)
    blocked.chmod(0o000)
    try:
        with pytest.raises(CheckpointError, match="cannot inspect"):
            create(store(xdg, journal), workspace, "src/a.py")
    finally:
        blocked.chmod(0o700)  # or pytest cannot clean up its own tmp_path


@requires_unprivileged
def test_an_unsearchable_manifest_parent_is_a_typed_error(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """The chain walk's own EACCES branch, reached past `_ensure_store`'s probe.

    Ordering is the point: with the whole store unreadable, `_ensure_store` fails
    first and the walk is never entered. Denying only `manifests/` after the store
    exists is the case where every earlier guard passes and `lstat` on the leaf is
    what raises — which is also how a hardened deployment would actually present.
    """
    st = store(xdg, journal)
    create(st, workspace, "src/a.py")
    blocked = xdg.state_home / "lsassist" / "checkpoints" / "manifests"
    blocked.chmod(0o000)
    try:
        with pytest.raises(CheckpointError, match="cannot inspect the store path"):
            create(st, workspace, "README.md")
    finally:
        blocked.chmod(0o700)


@requires_unprivileged
def test_a_store_directory_that_cannot_be_created_is_a_typed_error(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """The other half: the chain walks fine, then `mkdir` is refused.

    A read-only parent is the shape a hardened or full filesystem presents, and
    it is the case where the ancestors all exist so only the leaf creation fails.
    """
    parent = xdg.state_home / "lsassist" / "checkpoints"
    parent.mkdir(parents=True)
    parent.chmod(0o500)
    try:
        with pytest.raises(CheckpointError, match="cannot create the store path"):
            create(store(xdg, journal), workspace, "src/a.py")
    finally:
        parent.chmod(0o700)


def test_a_directory_that_already_exists_too_loosely_is_tightened(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """The retroactive chmod branch had no test, so removing it changed nothing.

    §12.1 asks for the directory's MODE, not for a fact about who created it, and
    a pre-existing 0755 store directory is exactly the case the walk cannot fix by
    passing `mode=` to `mkdir`.
    """
    import stat as stat_module

    loose = xdg.state_home / "lsassist" / "checkpoints" / "index"
    loose.mkdir(parents=True)
    loose.chmod(0o755)
    create(store(xdg, journal), workspace, "src/a.py")
    assert stat_module.S_IMODE(loose.stat().st_mode) == 0o700


def test_an_existing_store_is_not_initialised_twice(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """`_ensure_store`'s early return was never taken by a unit test.

    Its cost is not cosmetic: `git init` on every call is a write to the object
    database on a path that only needed a read, and the branch is the one that
    decides whether the store is created once or repeatedly.
    """

    class InitialisingSpy(GitSpy):
        def __call__(self, argv: Sequence[str], env: dict[str, str]) -> GitResult:
            result = super().__call__(argv, env)
            if "init" in argv:
                head = Path(argv[-1]) / "HEAD"
                head.parent.mkdir(parents=True, exist_ok=True)
                head.write_text("ref: refs/heads/main\n", encoding="utf-8")
            return result

    spy = InitialisingSpy()
    st = store(xdg, journal, spy)
    create(st, workspace, "src/a.py")
    create(st, workspace, "README.md")
    inits = [a for a, _ in spy.calls if "init" in a]
    assert len(inits) == 1, f"the store was initialised {len(inits)} times: {inits}"


def test_a_path_with_a_nul_byte_is_a_typed_error(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """`Path.resolve` raises `ValueError`, which is neither an OSError nor typed."""
    st = store(xdg, journal)
    with pytest.raises(CheckpointError, match="cannot be resolved"):
        st.create(
            workspace=str(workspace),
            paths=[f"{workspace}/sr\x00c/a.py"],
            trigger=TriggerKind.PRE_WRITE,
            task_id="t-1",
        )


def test_a_file_that_vanishes_mid_inspection_is_a_typed_error(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """A file removed between `is_file()` and the size read is a race, not a crash.

    Driven through the injected `size_of`, which is `Path.stat().st_size` in
    production — so an `OSError` out of it IS the race, and it is the one shape a
    unit test can pin deterministically. Note `Path.is_file()` swallows `OSError`
    itself and answers False, which is why patching `stat` cannot reach this branch.
    """

    def vanishing(target: Path) -> int:
        raise FileNotFoundError(2, "No such file or directory", str(target))

    st = store(xdg, journal, size_of=vanishing)
    with pytest.raises(CheckpointError, match="cannot be inspected"):
        create(st, workspace, "src/a.py")


def test_containment_is_checked_before_the_filesystem_is_asked(
    xdg: XdgPaths, journal: Any, workspace: Path, tmp_path: Path
) -> None:
    """An out-of-workspace path must not become an existence oracle.

    Ordering, not just outcome: stat-ing first answers "does this exist" for a
    path the caller was never entitled to name, and the error it produces leaks
    which of the two it was.
    """
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    st = store(xdg, journal)
    with pytest.raises(CheckpointError, match="outside the workspace"):
        st.create(
            workspace=str(workspace),
            paths=[str(outside)],
            trigger=TriggerKind.PRE_WRITE,
            task_id="t-1",
        )


def test_a_retention_failure_does_not_void_a_checkpoint_that_exists(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """`_prune` runs AFTER the manifest is durable and journalled.

    Letting its exception propagate told the caller "no checkpoint was made" about
    a checkpoint sitting on disk, fully restorable — and that caller's whole
    contract is that it may only mutate once it has one.
    """

    def exploding_size() -> int:
        raise OSError(5, "Input/output error")

    st = store(xdg, journal, store_size=exploding_size)
    # TWO checkpoints on purpose. `_prune`'s size loop is `while candidates and
    # self._store_size() > cap`, so with a single checkpoint the candidate list is
    # empty and `_store_size` is never called — a one-checkpoint version of this
    # test passes without the fix and proves nothing.
    create(st, workspace, "src/a.py")
    manifest = create(st, workspace, "README.md")
    held = {m.checkpoint_id for m in st.manifests(str(workspace))}
    assert manifest.checkpoint_id in held


def test_a_retention_failure_is_journalled_rather_than_swallowed(
    xdg: XdgPaths, journal: Any, workspace: Path, tmp_path: Path
) -> None:
    """Not voiding the checkpoint must not mean hiding the failure.

    The store being over its cap is an operator problem; an operator who cannot
    see it has no way to act on it.
    """

    def exploding_size() -> int:
        raise OSError(5, "Input/output error")

    st = store(xdg, journal, store_size=exploding_size)
    create(st, workspace, "src/a.py")
    create(st, workspace, "README.md")  # see the sibling test: one is not enough
    journal.close()
    body = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((tmp_path / "audit").glob("session-*.jsonl"))
    )
    assert "prune_failed" in body, f"the retention failure was not journalled: {body}"


def test_an_audit_failure_while_reporting_a_retention_failure_still_yields_the_checkpoint(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """The last line of the same argument, and the easiest one to get wrong.

    Once the caller has been promised a usable checkpoint, NOTHING on the way out
    may retract that promise — including the audit write that reports retention
    broke. Refuses only the `prune_failed` record, so the ordinary `create` record
    still lands and the discard-on-journal-failure path is not what is being tested.
    """

    class RefusesOnlyTheRetentionNote:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def write(self, event: str, payload: dict[str, Any], **kw: Any) -> Any:
            if payload.get("action") == "prune_failed":
                raise RuntimeError("journal is full")
            return self._inner.write(event, payload, **kw)

    def exploding_size() -> int:
        raise OSError(5, "Input/output error")

    st = CheckpointStore(
        xdg,
        audit=RefusesOnlyTheRetentionNote(journal),  # type: ignore[arg-type]
        git=GitSpy(),
        store_size=exploding_size,
    )
    create(st, workspace, "src/a.py")
    manifest = create(st, workspace, "README.md")
    assert manifest.checkpoint_id in {m.checkpoint_id for m in st.manifests(str(workspace))}


def test_a_failed_ref_delete_during_routine_eviction_is_not_reported_as_removed(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """Eviction shared `create`'s best-effort discard, and that was the defect.

    A swallowed `update-ref -d` leaves a ref with no manifest. `manifests()`
    enumerates manifest FILES, so no later eviction can ever rediscover that id;
    its objects stay reachable and `gc`-immune, and the 2 GB cap can never be
    brought back under. Silence made the store report space it had not reclaimed.
    """

    class RefDeleteFails(GitSpy):
        def __call__(self, argv: Sequence[str], env: dict[str, str]) -> GitResult:
            super().__call__(argv, env)
            if "-d" in argv:
                return GitResult(1, "", "cannot delete ref")
            return GitResult(0, "b" * 40 if "hash-object" in argv else TREE, "")

    st = store(xdg, journal, RefDeleteFails())
    create(st, workspace, "src/a.py")
    create(st, workspace, "README.md")
    with pytest.raises(CheckpointError, match="update-ref -d"):
        st.prune_to(str(workspace), keep_last=1, task_id="t-1")


def test_a_failed_ref_delete_leaves_the_checkpoint_rediscoverable(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """ORDER, not just outcome: the ref goes first so a failure loses nothing.

    Removing the manifest first and then failing to delete the ref produces the
    one unrecoverable shape — a ref no code path can find again, because
    `manifests()` enumerates manifest FILES. Its objects stay reachable, so `gc`
    can never reclaim them and the 2 GB cap can never be brought back under. This
    test pins the order by asserting the manifest SURVIVES a failed ref delete,
    which is what makes the next retention pass able to finish the job.
    """

    class RefDeleteFails(GitSpy):
        def __call__(self, argv: Sequence[str], env: dict[str, str]) -> GitResult:
            super().__call__(argv, env)
            if "-d" in argv:
                return GitResult(1, "", "cannot delete ref")
            return GitResult(0, "b" * 40 if "hash-object" in argv else TREE, "")

    st = store(xdg, journal, RefDeleteFails())
    oldest = create(st, workspace, "src/a.py")
    create(st, workspace, "README.md")
    with pytest.raises(CheckpointError):
        st.prune_to(str(workspace), keep_last=1, task_id="t-1")

    held = {m.checkpoint_id for m in st.manifests(str(workspace))}
    assert oldest.checkpoint_id in held, (
        "the manifest was removed before the ref, so the ref is now an orphan "
        "no later eviction can rediscover"
    )


def test_a_manifest_that_cannot_be_unlinked_fails_the_eviction_loudly(
    xdg: XdgPaths, journal: Any, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_remove` deletes the manifest FIRST, and that step must be able to fail.

    Swallowing it inverts the ordering guarantee: the ref would be gone while the
    manifest stayed, so `manifests()` keeps offering a checkpoint whose objects
    are now unreachable — a rollback that fails at the one moment it is needed.
    Returning silently also reports reclaimed space that was never reclaimed.
    """
    st = store(xdg, journal)
    create(st, workspace, "src/a.py")
    create(st, workspace, "README.md")

    real = Path.unlink

    def refuses(self: Path, *a: Any, **kw: Any) -> None:
        if self.name.startswith("cp-"):
            raise PermissionError(13, "Permission denied", str(self))
        real(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", refuses)
    with pytest.raises(CheckpointError, match="cannot remove manifest"):
        st.prune_to(str(workspace), keep_last=1, task_id="t-1")


def test_size_pressure_can_evict_across_workspaces_so_the_cap_can_clear(
    xdg: XdgPaths, journal: Any, tmp_path: Path
) -> None:
    """§14.4 caps the STORE at 2 GB; the object database is shared by every workspace.

    Reading the size globally while only ever evicting the CALLING workspace's
    checkpoints could not converge: a workspace that had filled the store was
    unreachable, so an unrelated workspace's next `create()` deleted its own
    entire history and the store was still over. Here the heavy workspace is the
    one that must give way, and it does so oldest-first.
    """
    # `zzz-` and `aaa-` on purpose: the heavy workspace is created FIRST but sorts
    # LAST, so a mutation that sorts the cross-workspace candidates by workspace
    # path instead of by checkpoint id no longer produces the same eviction. The
    # earlier names ("heavy", "light") sorted in creation order by coincidence and
    # could not tell the two keys apart.
    heavy = tmp_path / "zzz-heavy"
    heavy.mkdir()
    (heavy / "big.bin").write_text("x" * 64, encoding="utf-8")
    light = tmp_path / "aaa-light"
    light.mkdir()
    (light / "small.txt").write_text("y\n", encoding="utf-8")

    # Derived from real store state, never a constant: a stub that is permanently
    # over the cap cannot tell "evict one, re-measure, stop" from "evict
    # everything", and that exact weakness let a surviving mutant through once.
    # Over the cap above two checkpoints, under it at or below — so converging
    # needs exactly one eviction, and it has to come from the heavy workspace.
    manifests_root = xdg.state_home / "lsassist" / "checkpoints" / "manifests"

    def store_size() -> int:
        held = len(list(manifests_root.glob("*/cp-*.json")))
        return MAX_STORE_BYTES + 1 if held > 2 else 0

    st = store(xdg, journal, store_size=store_size)
    first = create(st, heavy, "big.bin")
    second = create(st, heavy, "big.bin")
    assert len(st.manifests(str(heavy))) == 2

    create(st, light, "small.txt")

    survivors = [m.checkpoint_id for m in st.manifests(str(heavy))]
    assert first.checkpoint_id not in survivors, "the oldest checkpoint was not evicted"
    assert second.checkpoint_id in survivors, "eviction went past what the cap needed"
    assert len(st.manifests(str(light))) == 1, "the caller's own checkpoint was evicted"


def test_one_corrupt_manifest_does_not_block_size_eviction(
    xdg: XdgPaths, journal: Any, workspace: Path, tmp_path: Path
) -> None:
    """`_all_stored` reads every workspace's manifests, so it meets corrupt ones too.

    `manifests()` already skips a damaged file rather than denying a rollback its
    whole history; the store-wide enumeration the size cap depends on must be at
    least as robust, or one truncated byte anywhere freezes retention for EVERY
    workspace and the 2 GB cap stops being enforceable at all.
    """
    manifests_root = xdg.state_home / "lsassist" / "checkpoints" / "manifests"

    def store_size() -> int:
        held = len(list(manifests_root.glob("*/cp-*.json")))
        return MAX_STORE_BYTES + 1 if held > 1 else 0

    st = store(xdg, journal, store_size=store_size)
    oldest = create(st, workspace, "src/a.py")
    directory = next(manifests_root.iterdir())
    (directory / "cp-99999999999999999999.json").write_text("{ truncated", encoding="utf-8")

    create(st, workspace, "README.md")
    assert oldest.checkpoint_id not in {m.checkpoint_id for m in st.manifests(str(workspace))}


def test_a_store_exactly_at_the_cap_is_left_alone(
    xdg: XdgPaths, journal: Any, workspace: Path
) -> None:
    """§14.4 says "size-capped 2 GB", so at 2 GB the store is AT its cap, not over it.

    Every existing size test used `MAX_STORE_BYTES + 1`, which cannot tell `>`
    from `>=`. This one names the boundary.
    """
    st = store(xdg, journal, store_size=lambda: MAX_STORE_BYTES)
    first = create(st, workspace, "src/a.py")
    create(st, workspace, "README.md")
    kept = [m.checkpoint_id for m in st.manifests(str(workspace))]
    assert first.checkpoint_id in kept, "a store exactly at the cap was pruned"
