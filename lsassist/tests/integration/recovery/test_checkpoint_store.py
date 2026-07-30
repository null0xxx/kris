"""T4.04 integration — the checkpoint store against a REAL git.

The unit suite injects git, so it proves the store ASKS for the right thing. Only
a real binary can prove the two claims that matter operationally:

1. **The workspace's own repository is untouched.** This is the headline promise
   of §14.4 ("invisible to workspace `.git`") and the one whose failure mode is
   catastrophic and silent: a tool that corrupts the repository it exists to
   protect. Asserted as byte-level equality of every file under `.git`, plus the
   index's mtime, plus `git status --porcelain` before and after.
2. **The stored objects are really restorable.** A checkpoint whose objects
   cannot be read back is a rollback that fails at the one moment it is needed —
   after the workspace has already been mutated. AC-06's precondition.

The real `_default_git` runner is exercised here and nowhere else, which is also
why `recovery`'s 100 % branch floor needs this file to run: SPEC §23.1 counts the
whole package.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from lsassist.audit.writer import AuditWriter
from lsassist.config.xdg import XdgPaths
from lsassist.recovery.checkpoints import CheckpointError, CheckpointStore
from lsassist.recovery.manifest import TriggerKind

requires_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git is not installed on this host"
)

#: Nothing here may run unbounded: a hung integration test reports nothing.
BUDGET_S = 60


def git_binary() -> str:
    found = shutil.which("git")
    assert found is not None
    return found


@pytest.fixture
def xdg(tmp_path: Path) -> XdgPaths:
    return XdgPaths(
        config_home=tmp_path / "config",
        data_home=tmp_path / "data",
        state_home=tmp_path / "state",
        cache_home=tmp_path / "cache",
    )


@pytest.fixture
def journal(tmp_path: Path) -> Iterator[AuditWriter]:
    with AuditWriter(directory=tmp_path / "audit", session_id="s-1") as writer:
        yield writer


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A REAL git repository, because that is the thing that must survive."""
    ws = tmp_path / "repo"
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "a.py").write_text("print('before')\n", encoding="utf-8")
    (ws / "README.md").write_text("# proj\n", encoding="utf-8")
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
    for argv in (
        ["git", "init", "-q", "-b", "main"],
        ["git", "-c", "user.email=t@e", "-c", "user.name=t", "add", "-A"],
        ["git", "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "init"],
    ):
        subprocess.run(argv, cwd=ws, check=True, timeout=BUDGET_S, env=env)
    return ws


def tree_of(directory: Path) -> dict[str, str]:
    """Every file under ``directory``, keyed by relative path, valued by digest."""
    out: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            out[str(path.relative_to(directory))] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return out


def store(xdg: XdgPaths, journal: AuditWriter, **kw: Any) -> CheckpointStore:
    return CheckpointStore(xdg, audit=journal, git_path=git_binary(), **kw)


# ---------------------------------------------------------------------------
# The promise: the user's repository never notices
# ---------------------------------------------------------------------------


@requires_git
def test_the_workspace_git_directory_is_byte_identical_afterwards(
    xdg: XdgPaths, journal: AuditWriter, repo: Path
) -> None:
    """§14.4: "invisible to workspace `.git`" — asserted, not assumed.

    Every file under `.git` is hashed before and after. A single object written
    into the wrong database, or an index rewritten, shows up here.
    """
    before = tree_of(repo / ".git")
    index_mtime = (repo / ".git" / "index").stat().st_mtime_ns

    store(xdg, journal).create(
        workspace=str(repo),
        paths=[str(repo / "src" / "a.py")],
        trigger=TriggerKind.PRE_WRITE,
        task_id="t-1",
    )

    assert tree_of(repo / ".git") == before
    assert (repo / ".git" / "index").stat().st_mtime_ns == index_mtime


@requires_git
def test_the_workspace_stays_clean_according_to_git_itself(
    xdg: XdgPaths, journal: AuditWriter, repo: Path, tmp_path: Path
) -> None:
    """The user-visible symptom of a corrupted index is `git status` changing."""
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
    before = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo, capture_output=True, text=True, check=True, timeout=BUDGET_S, env=env,
    ).stdout

    store(xdg, journal).create(
        workspace=str(repo),
        paths=[str(repo / "src" / "a.py"), str(repo / "README.md")],
        trigger=TriggerKind.PRE_PATCH,
        task_id="t-1",
    )

    after = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo, capture_output=True, text=True, check=True, timeout=BUDGET_S, env=env,
    ).stdout
    assert after == before == ""


@requires_git
def test_the_objects_land_in_the_xdg_state_store(
    xdg: XdgPaths, journal: AuditWriter, repo: Path
) -> None:
    objects = xdg.state_home / "lsassist" / "checkpoints" / "objects"
    store(xdg, journal).create(
        workspace=str(repo),
        paths=[str(repo / "src" / "a.py")],
        trigger=TriggerKind.MANUAL,
        task_id="t-1",
    )
    assert objects.is_dir()
    assert any(p.is_file() for p in objects.rglob("*"))


# ---------------------------------------------------------------------------
# The point: the bytes come back
# ---------------------------------------------------------------------------


@requires_git
def test_a_checkpointed_file_is_restorable_byte_for_byte(
    xdg: XdgPaths, journal: AuditWriter, repo: Path, tmp_path: Path
) -> None:
    """AC-06's precondition: a checkpoint nobody can read back is not a checkpoint.

    The file is MUTATED after the snapshot, exactly as a real `fs.write` would
    do, and the original is then read out of the shadow store with `git cat-file`
    against the manifest's own tree.
    """
    original = (repo / "src" / "a.py").read_bytes()
    manifest = store(xdg, journal).create(
        workspace=str(repo),
        paths=[str(repo / "src" / "a.py")],
        trigger=TriggerKind.PRE_WRITE,
        task_id="t-1",
    )
    (repo / "src" / "a.py").write_text("print('AFTER')\n", encoding="utf-8")

    env = {
        "GIT_DIR": str(xdg.state_home / "lsassist" / "checkpoints" / "objects"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "PATH": "/usr/bin:/bin",
    }
    restored = subprocess.run(
        ["git", "cat-file", "-p", f"{manifest.tree}:src/a.py"],
        capture_output=True, check=True, timeout=BUDGET_S, env=env,
    ).stdout
    assert restored == original
    assert (repo / "src" / "a.py").read_bytes() != original


@requires_git
def test_the_manifest_digest_matches_the_file_on_disk(
    xdg: XdgPaths, journal: AuditWriter, repo: Path
) -> None:
    """The manifest records the FILE's sha256, not git's blob id.

    git hashes `blob <len>\\0` + content, so a reader comparing the manifest
    against `sha256sum` would otherwise get a different answer and reasonably
    conclude the file had changed.
    """
    manifest = store(xdg, journal).create(
        workspace=str(repo),
        paths=[str(repo / "src" / "a.py")],
        trigger=TriggerKind.MANUAL,
        task_id="t-1",
    )
    (only,) = manifest.entries
    assert only.sha256 == hashlib.sha256((repo / "src" / "a.py").read_bytes()).hexdigest()


@requires_git
def test_a_path_with_a_space_and_a_semicolon_round_trips(
    xdg: XdgPaths, journal: AuditWriter, repo: Path
) -> None:
    """I2, against a real binary: argv arrays make this a boring filename."""
    nasty = repo / "a b;c $HOME.txt"
    nasty.write_text("payload\n", encoding="utf-8")
    manifest = store(xdg, journal).create(
        workspace=str(repo),
        paths=[str(nasty)],
        trigger=TriggerKind.MANUAL,
        task_id="t-1",
    )
    assert [e.path for e in manifest.entries] == ["a b;c $HOME.txt"]

    env = {
        "GIT_DIR": str(xdg.state_home / "lsassist" / "checkpoints" / "objects"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "PATH": "/usr/bin:/bin",
    }
    restored = subprocess.run(
        ["git", "cat-file", "-p", f"{manifest.tree}:a b;c $HOME.txt"],
        capture_output=True, check=True, timeout=BUDGET_S, env=env,
    ).stdout
    assert restored == b"payload\n"


@requires_git
def test_two_checkpoints_of_the_same_content_share_one_object(
    xdg: XdgPaths, journal: AuditWriter, repo: Path
) -> None:
    """Content-addressed, as §14.4 says — otherwise the 2 GB cap is meaningless."""
    st = store(xdg, journal)
    first = st.create(
        workspace=str(repo), paths=[str(repo / "src" / "a.py")],
        trigger=TriggerKind.MANUAL, task_id="t-1",
    )
    second = st.create(
        workspace=str(repo), paths=[str(repo / "src" / "a.py")],
        trigger=TriggerKind.MANUAL, task_id="t-1",
    )
    assert first.tree == second.tree
    assert first.checkpoint_id != second.checkpoint_id


@requires_git
def test_a_real_git_failure_is_a_typed_error(
    xdg: XdgPaths, journal: AuditWriter, tmp_path: Path
) -> None:
    """The default runner's failure path, against the real binary.

    The object store path is occupied by a FILE, so `git init --bare` cannot
    create a repository there. Chosen over "an empty directory" deliberately:
    an empty directory is now initialised on demand, which is the correct
    behaviour and the reason an earlier version of this test stopped failing.
    """
    ws = tmp_path / "notrepo"
    ws.mkdir()
    target = ws / "f.txt"
    target.write_text("x\n", encoding="utf-8")
    objects = xdg.state_home / "lsassist" / "checkpoints" / "objects"
    objects.parent.mkdir(parents=True)
    objects.write_text("not a repository\n", encoding="utf-8")

    with pytest.raises(CheckpointError):
        store(xdg, journal).create(
            workspace=str(ws), paths=[str(target)],
            trigger=TriggerKind.MANUAL, task_id="t-1",
        )


@requires_git
def test_the_shadow_store_is_initialised_only_once(
    xdg: XdgPaths, journal: AuditWriter, repo: Path
) -> None:
    """Idempotent: the second checkpoint must not re-init over the first's objects."""
    st = store(xdg, journal)
    first = st.create(
        workspace=str(repo), paths=[str(repo / "src" / "a.py")],
        trigger=TriggerKind.MANUAL, task_id="t-1",
    )
    objects = xdg.state_home / "lsassist" / "checkpoints" / "objects"
    before = {p.name for p in objects.rglob("*") if p.is_file()}

    (repo / "src" / "a.py").write_text("print('changed')\n", encoding="utf-8")
    second = st.create(
        workspace=str(repo), paths=[str(repo / "src" / "a.py")],
        trigger=TriggerKind.MANUAL, task_id="t-1",
    )
    after = {p.name for p in objects.rglob("*") if p.is_file()}

    assert first.tree != second.tree
    assert before <= after, "re-initialising would have discarded the first snapshot"


# ---------------------------------------------------------------------------
# Review findings, reproduced then closed
# ---------------------------------------------------------------------------


def ls_tree(xdg: XdgPaths, tree: str) -> list[str]:
    env = {
        "GIT_DIR": str(xdg.state_home / "lsassist" / "checkpoints" / "objects"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "PATH": "/usr/bin:/bin",
    }
    out = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", tree],
        capture_output=True, text=True, check=True, timeout=BUDGET_S, env=env,
    ).stdout
    return sorted(out.split())


@requires_git
def test_a_checkpoints_tree_contains_exactly_what_its_manifest_claims(
    xdg: XdgPaths, journal: AuditWriter, repo: Path
) -> None:
    """THE reproduced CRITICAL: the index accumulated across calls.

    Measured against real git before the fix: `create(one.txt)` then
    `create(two.txt)` produced manifest entries `['two.txt']` and a tree of
    `['one.txt', 'two.txt']`. `update-index --add` never clears unrelated entries
    and `write-tree` serialises the WHOLE index, so a persistent per-workspace
    index made every checkpoint a superset of its predecessors.

    Two calls with DISJOINT path sets is the only shape that shows it, and no
    test had that shape: every earlier repeated `create()` reused one path.
    """
    (repo / "one.txt").write_text("ONE\n", encoding="utf-8")
    (repo / "two.txt").write_text("TWO\n", encoding="utf-8")
    st = store(xdg, journal)

    first = st.create(
        workspace=str(repo), paths=[str(repo / "one.txt")],
        trigger=TriggerKind.MANUAL, task_id="t-1",
    )
    second = st.create(
        workspace=str(repo), paths=[str(repo / "two.txt")],
        trigger=TriggerKind.MANUAL, task_id="t-1",
    )

    assert ls_tree(xdg, first.tree) == sorted(e.path for e in first.entries)
    assert ls_tree(xdg, second.tree) == sorted(e.path for e in second.entries)
    assert "one.txt" not in ls_tree(xdg, second.tree)


@requires_git
def test_a_checkpoints_objects_are_reachable_from_a_ref(
    xdg: XdgPaths, journal: AuditWriter, repo: Path
) -> None:
    """Unreferenced trees are trees any `git gc` is entitled to delete.

    The store writes objects and then pointed nothing at them, so the checkpoints
    survived only because nothing had run a gc yet. A ref per checkpoint makes
    them reachable, which is also what lets the store reclaim space on eviction
    instead of growing forever.
    """
    manifest = store(xdg, journal).create(
        workspace=str(repo), paths=[str(repo / "src" / "a.py")],
        trigger=TriggerKind.MANUAL, task_id="t-1",
    )
    env = {
        "GIT_DIR": str(xdg.state_home / "lsassist" / "checkpoints" / "objects"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "PATH": "/usr/bin:/bin",
    }
    refs = subprocess.run(
        ["git", "for-each-ref", "--format=%(refname)"],
        capture_output=True, text=True, check=True, timeout=BUDGET_S, env=env,
    ).stdout.split()
    assert any(manifest.checkpoint_id in ref for ref in refs), refs

    # And an aggressive gc must not be able to destroy the snapshot.
    subprocess.run(
        ["git", "gc", "--prune=now", "--quiet"],
        check=True, timeout=BUDGET_S, env=env,
    )
    assert ls_tree(xdg, manifest.tree) == ["src/a.py"]


@requires_git
def test_evicting_a_checkpoint_also_drops_its_ref(
    xdg: XdgPaths, journal: AuditWriter, repo: Path
) -> None:
    """A ref left behind after eviction pins the objects the prune meant to free."""
    st = store(xdg, journal)
    ids = [
        st.create(
            workspace=str(repo), paths=[str(repo / "src" / "a.py")],
            trigger=TriggerKind.MANUAL, task_id="t-1",
        ).checkpoint_id
        for _ in range(2)
    ]
    st.prune_to(str(repo), keep_last=1, task_id="t-1")

    env = {
        "GIT_DIR": str(xdg.state_home / "lsassist" / "checkpoints" / "objects"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "PATH": "/usr/bin:/bin",
    }
    refs = subprocess.run(
        ["git", "for-each-ref", "--format=%(refname)"],
        capture_output=True, text=True, check=True, timeout=BUDGET_S, env=env,
    ).stdout
    assert ids[0] not in refs
    assert ids[1] in refs


# ---------------------------------------------------------------------------
# The workspace must not be able to choose what the store records
# ---------------------------------------------------------------------------


@requires_git
@pytest.mark.parametrize("attributes", ["* text=auto\n", "* text eol=lf\n", "*.py text\n"])
def test_a_workspace_gitattributes_cannot_rewrite_the_stored_bytes(
    xdg: XdgPaths, journal: AuditWriter, repo: Path, attributes: str
) -> None:
    """The defect an isolated review found, reproduced against real git.

    `hash-object --path <rel>` looks like a way to tell git the workspace-relative
    name. git-hash-object(1) says it selects the attribute-driven filters that
    "actually affect the generated hash value" — so a `.gitattributes` the
    WORKSPACE controls decided what the STORE recorded, while the manifest digest
    came from `_blob_digest` reading the raw bytes. Measured on git 2.55.0: 18
    stored bytes against a 20-byte CRLF file, i.e. the stored object was no longer
    the file a rollback has to reproduce, and nothing cross-checked the two.

    `GIT_DIR` pointing away from the workspace does NOT prevent this: attributes
    are read off disk relative to the work tree. Verified here by asserting that
    git DOES see the attribute (otherwise the test would pass for the wrong
    reason) and that the stored blob is the raw file anyway.
    """
    target = repo / "src" / "crlf.py"
    raw = b"first = 1\r\nsecond = 2\r\n"
    target.write_bytes(raw)
    (repo / ".gitattributes").write_text(attributes, encoding="utf-8")

    env = {
        "GIT_DIR": str(xdg.state_home / "lsassist" / "checkpoints" / "objects"),
        "GIT_WORK_TREE": str(repo),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "PATH": "/usr/bin:/bin",
    }
    manifest = store(xdg, journal).create(
        workspace=str(repo), paths=[str(target)],
        trigger=TriggerKind.PRE_WRITE, task_id="t-1",
    )

    seen = subprocess.run(
        ["git", "check-attr", "text", "--", "src/crlf.py"],
        cwd=repo, capture_output=True, text=True, check=True, timeout=BUDGET_S, env=env,
    ).stdout
    assert "text: unspecified" not in seen, f"git never saw the attribute: {seen!r}"

    stored = subprocess.run(
        ["git", "cat-file", "blob", f"{manifest.tree}:src/crlf.py"],
        capture_output=True, check=True, timeout=BUDGET_S, env=env,
    ).stdout
    assert stored == raw, f"the store recorded {len(stored)} bytes, the file has {len(raw)}"
    entry = next(e for e in manifest.entries if e.path == "src/crlf.py")
    assert entry.sha256 == hashlib.sha256(stored).hexdigest()


@requires_git
def test_a_symlinked_store_object_directory_is_refused_by_the_real_store(
    xdg: XdgPaths, journal: AuditWriter, repo: Path, tmp_path: Path
) -> None:
    """Fail-closed, and nothing written through the link — end to end.

    The unit suite proves the check fires; this proves the redirected directory
    stays empty when it does, which is the property that actually matters.
    """
    root = xdg.state_home / "lsassist" / "checkpoints"
    root.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "objects").symlink_to(elsewhere, target_is_directory=True)

    # The reason with its punctuation, not the bare word: `tmp_path` carries this
    # test's own name, which contains "symlink", so the loose form matched the path
    # in the message and passed with the check removed.
    with pytest.raises(CheckpointError, match=r"symlink \(fail-closed\)"):
        store(xdg, journal).create(
            workspace=str(repo), paths=[str(repo / "src" / "a.py")],
            trigger=TriggerKind.MANUAL, task_id="t-1",
        )
    assert list(elsewhere.iterdir()) == []
