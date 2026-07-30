"""§14.4 shadow-git checkpoint store — snapshots that the user's repo never sees.

The store writes file contents into a content-addressed git object database that
is **not** the workspace's own. That one sentence is the whole design, and every
guard below follows from it.

**THE ENVIRONMENT IS THE ISOLATION.** ``git`` decides which repository it is
talking to from ``GIT_DIR``, ``GIT_WORK_TREE`` and ``GIT_INDEX_FILE``. Getting one
wrong does not degrade the feature — it writes objects, or an index, into a
repository the user may be mid-commit in, which is a tool corrupting the thing it
exists to protect. So the child environment is CONSTRUCTED, never inherited: the
same reasoning ``sandbox/profiles.py`` records for ``--clearenv``, with one extra
edge, because here the dangerous variable (``GIT_DIR``) is one a developer
legitimately exports.

**ARGV ARRAYS, NEVER A SHELL STRING (I2).** A workspace path containing a space,
a quote or a ``;`` is ordinary on a real machine and catastrophic through
``sh -c``. Every call here is a list, and the git binary is pinned to a trusted
directory for the reason ``sandbox/availability.py`` measured: an early writable
``PATH`` entry is a shim, and a shimmed ``git`` writes wherever it likes.

**A HALF-MADE CHECKPOINT IS WORSE THAN NONE.** Its caller proceeds to mutate the
workspace believing it can roll back. Every failure — git, audit, or filesystem —
therefore raises :class:`CheckpointError` and leaves nothing a rollback would
mistake for a usable snapshot.

## Four things an isolated review found here, and what each one cost

1. **A per-workspace index was the wrong optimisation.** It existed to stop one
   workspace's snapshot staging another's files, and it did — but ``update-index
   --add`` never clears unrelated entries and ``write-tree`` serialises the WHOLE
   index, so every checkpoint became a superset of its predecessors. Measured
   against real git: ``create(one.txt)`` then ``create(two.txt)`` produced a
   manifest saying ``['two.txt']`` and a tree containing both. A FRESH index per
   CALL fixes the accumulation, keeps the cross-workspace guarantee, and removes
   the two-process race over a shared index file — one change, three problems.
2. **Unreferenced objects are objects git may delete.** ``write-tree`` alone
   leaves the tree unreachable, so the snapshots survived only because nothing had
   run a ``gc`` yet. Each checkpoint now gets a commit and a ref, which is also
   what makes eviction able to RECLAIM space.
3. **The size cap could never clear.** Pruning unlinked manifests and nothing
   reclaimed git objects, so ``measure_store()`` never shrank and every later
   ``create()`` — for any workspace — re-entered the size branch and wiped every
   checkpoint but the newest. §14.4 says "LRU prune", meaning oldest-first until
   the store is under its cap, not "delete everything".
4. **``Path.mkdir(mode=…, parents=True)`` only reaches the LEAF.** Measured with
   umask 022: the ancestors, including the ``checkpoints/`` directory §12.1 pins
   at 0700, came out 0755. :func:`_ensure_dir_chain` walks components, mirroring
   what ``config/xdg.py`` already does for the static layout.

## Five more the SECOND isolated review found, after all four above were fixed

5. **``hash-object --path`` let the workspace choose the stored bytes.** ``--path``
   reads like "tell git the relative name"; git-hash-object(1) says it selects
   attribute-driven filters that affect the hash. A workspace ``.gitattributes``
   with ``* text=auto`` made the stored blob 18 bytes for a 20-byte CRLF file
   while the manifest digest stayed the raw 20-byte hash. ``--no-filters`` now.
6. **The runner may RAISE, not only return.** ``subprocess.run(timeout=…)`` raises
   on a hang and ``OSError`` on a missing binary; :meth:`CheckpointStore._invoke`
   inspected only the return value, so both escaped :meth:`CheckpointStore.create`
   past the single-error-type contract.
7. **``_ensure_dir_chain`` followed symlinks and had no error contract.** It
   claimed parity with ``config/xdg.py``'s ``_ensure_dir`` and had neither its
   ``lstat`` fail-closed check nor a typed error; two of its three call sites had
   no handler at all.
8. **A retention failure reported "no checkpoint was made".** ``_prune`` runs after
   the manifest is durable, so its exception voided a checkpoint that existed and
   was usable. Now journalled as ``prune_failed`` and the manifest is returned.
9. **Routine eviction shared ``create``'s best-effort discard.** A failed
   ``update-ref -d`` during an ordinary LRU trim counted as removed, leaving a ref
   with no manifest — unreachable by :meth:`CheckpointStore.manifests`, so no later
   eviction could ever find it, its objects ``gc``-immune, and the cap unclearable.
   Eviction now uses the strict :meth:`CheckpointStore._remove`.

## Named residuals — real, and NOT this task's to fix

* **Orphan refs from a crash between ``update-ref`` and the manifest write.** The
  window is one process death wide and leaves exactly the ref/no-manifest shape
  item 9 describes. Closing it needs a ``for-each-ref`` reconciler, which is new
  machinery beyond §14.4's "retention (50/workspace, 2 GB, LRU)". T4.06 owns crash
  recovery (``kill -9`` mid-write, stale tmp discard) but its file list —
  ``resume.py``, ``signals.py``, ``watermark.py`` — does not include the store, so
  this currently has NO owner and is recorded in ``.atlas/GATE4_PROGRESS.md``.
* **Orphan per-call index files and manifest temp files.** Same crash window;
  explicitly T4.06's ("stale tmp discard", IMPLEMENTATION_PLAN.md T4.06 scope).
* **``checkpoint_id`` collision between two OS processes.** :meth:`_next_id`'s
  monotonic tie-break is per instance, so two processes at the same nanosecond
  could collide and the second ``os.replace`` would overwrite the first manifest.
  Cross-process id allocation is a locking design, not a §14.4 requirement.
* **``ExclusionReason.BINARY`` is declared and never produced.** §14.4 names only
  the size rule; binary detection has no §14.4 threshold to implement against, so
  the enum member is schema surface a later task fills in.
"""

from __future__ import annotations

import hashlib
import os
import stat as stat_module
import subprocess
import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, NamedTuple, final

from lsassist.audit.schema import AuditEvent
from lsassist.audit.writer import AuditWriter
from lsassist.config.xdg import XdgPaths
from lsassist.recovery.manifest import (
    CheckpointEntry,
    CheckpointManifest,
    ExclusionReason,
    TriggerKind,
    canonical_bytes,
    manifest_digest,
)

__all__ = [
    "MAX_CHECKPOINTS_PER_WORKSPACE",
    "MAX_FILE_BYTES",
    "MAX_STORE_BYTES",
    "CheckpointError",
    "CheckpointStore",
    "GitResult",
]

#: §14.4: "50 checkpoints per workspace", "size-capped 2 GB",
#: "Large binaries > 50 MB excluded by default". Constants so a test can assert
#: them against the SPEC rather than against a magic number.
MAX_CHECKPOINTS_PER_WORKSPACE: Final = 50
MAX_STORE_BYTES: Final = 2 * 1024 * 1024 * 1024
MAX_FILE_BYTES: Final = 50 * 1024 * 1024

#: Same allowlist, and the same argument, as `sandbox/availability.py`'s.
_TRUSTED_BIN_DIRS: Final[frozenset[str]] = frozenset({"/usr/bin", "/bin", "/usr/local/bin"})

_DEFAULT_GIT: Final = "/usr/bin/git"

#: Wall-clock cap for any single git plumbing call.
_GIT_TIMEOUT_S: Final = 60

#: How old an unreachable object must be before eviction's ``gc`` may reclaim it.
#: Sized to be generously longer than any single ``create()``, whose per-call git
#: invocations are each capped by :data:`_GIT_TIMEOUT_S`, so a concurrent
#: snapshot's not-yet-referenced objects are never inside the prunable window.
_GC_PRUNE_EXPIRY: Final = "1.hour.ago"

#: `100644` — a regular non-executable blob. A checkpoint restores CONTENT; mode
#: restoration is the rollback task's concern (T4.05) and belongs in the manifest,
#: not smuggled through the index.
_BLOB_MODE: Final = "100644"

#: §12.1 pins every lsassist store directory at 0700.
_DIR_MODE: Final = 0o700

#: A fixed identity for the checkpoint commits. The store's config is pinned to
#: `/dev/null`, so `commit-tree` has no `user.name` to read and would refuse; and
#: a FIXED identity plus a fixed date keeps a commit a pure function of its tree
#: and checkpoint id, which is what makes the store content-addressed rather than
#: merely content-hashed.
_IDENTITY: Final[dict[str, str]] = {
    "GIT_AUTHOR_NAME": "lsassist",
    "GIT_AUTHOR_EMAIL": "lsassist@localhost",
    "GIT_COMMITTER_NAME": "lsassist",
    "GIT_COMMITTER_EMAIL": "lsassist@localhost",
    "GIT_AUTHOR_DATE": "1700000000 +0000",
    "GIT_COMMITTER_DATE": "1700000000 +0000",
}


class GitResult(NamedTuple):
    """What an injected git runner must return."""

    returncode: int
    stdout: str
    stderr: str


class CheckpointError(RuntimeError):
    """A checkpoint could not be made, so the caller must NOT proceed to mutate.

    Deliberately one type for every cause. A caller that distinguished "git
    failed" from "the path was outside the workspace" would be a caller deciding
    which failures are safe to ignore, and none of them are: in every case the
    rollback it was counting on does not exist.
    """


def _default_git(argv: Sequence[str], env: dict[str, str]) -> GitResult:
    """Run one git plumbing command as an argv LIST with a constructed env."""
    # `errors="replace"`, because `text=True` alone decodes STRICTLY. Measured:
    # a child emitting one 0xe9 byte raises `UnicodeDecodeError` out of
    # `subprocess.run` itself — a `ValueError`, so neither of the two types
    # :meth:`CheckpointStore._invoke` used to catch. Linux filenames need not be
    # valid UTF-8 and git echoes the raw path into stderr on failure, so a
    # diagnostic message was able to replace the diagnosis with a decode crash.
    completed = subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=_GIT_TIMEOUT_S,
        check=False,
        env=env,
    )
    return GitResult(completed.returncode, completed.stdout, completed.stderr)


def _workspace_key(workspace: str) -> str:
    """A filesystem-safe, collision-resistant name for a workspace path."""
    return hashlib.sha256(workspace.encode("utf-8")).hexdigest()[:32]


def _ensure_dir_chain(path: Path) -> None:
    """Create ``path`` and every missing ancestor at 0700, fail-closed on a symlink.

    ``Path.mkdir(mode=…, parents=True)`` applies the mode to the LEAF ONLY — every
    ancestor it creates gets the umask default. Measured here with umask 022:
    ``state``, ``state/lsassist`` and ``state/lsassist/checkpoints`` all came out
    0755, and the last of those is a directory §12.1 pins at 0700.

    **THE SYMLINK CHECK IS NOT OPTIONAL, AND THE REASON IS A MEASURED GAP.**
    ``config/xdg.py``'s ``_ensure_dir`` ``os.lstat``-s every component and raises
    on ``S_ISLNK`` (§7.5, fail-closed), but its ``LAYOUT`` table enumerates only
    ``state/lsassist/checkpoints`` — ``objects/``, ``index/`` and
    ``manifests/<hash>/`` are created HERE and appear in no table, so nothing else
    in the system ever lstat-checks them. This function claimed parity with that
    one and did not have it: ``Path.exists()`` and ``Path.stat()`` both FOLLOW
    symlinks, so a link planted at any component was silently honoured and every
    later object and manifest write followed it out of the 0700 store.

    Every failure is a :class:`CheckpointError`, raised here rather than at the
    three call sites. Two of those sites had no handler at all, which turned an
    ordinary ``NotADirectoryError`` into an untyped escape from :meth:`create` —
    and the module's contract is that a checkpoint failure has exactly one type.
    """
    # No filesystem-root guard: the loop terminates because `/` always exists,
    # so `current.lstat()` succeeds before `current.parent == current` can be. A
    # defensive `break` there was dead code — untestable, and in a §23.1 package
    # untestable code is code the branch floor will not let anyone verify.
    missing: list[Path] = []
    current = path
    while True:
        try:
            existing = current.lstat()
        except FileNotFoundError:
            missing.append(current)
            current = current.parent
            continue
        # An ancestor occupied by a non-directory surfaces HERE, as ENOTDIR on the
        # child's own lstat, not as a kind check on the ancestor — so it gets the
        # same message the kind check below gives, because it is the same defect.
        except NotADirectoryError as exc:
            raise CheckpointError(f"store path is not a directory: {current}") from exc
        except OSError as exc:
            raise CheckpointError(f"cannot inspect the store path {current}: {exc!r}") from exc
        if stat_module.S_ISLNK(existing.st_mode):
            raise CheckpointError(f"store path is a symlink (fail-closed): {current}")
        if not stat_module.S_ISDIR(existing.st_mode):
            raise CheckpointError(f"store path is not a directory: {current}")
        break
    try:
        for directory in reversed(missing):
            directory.mkdir(mode=_DIR_MODE)
        # A directory that already existed too loosely is tightened too: what
        # §12.1 asks for is the directory's mode, not who created it.
        if stat_module.S_IMODE(path.lstat().st_mode) != _DIR_MODE:
            path.chmod(_DIR_MODE)
    except OSError as exc:
        raise CheckpointError(f"cannot create the store path {path}: {exc!r}") from exc


@final
class CheckpointStore:
    """§14.4's content-addressed snapshot store."""

    __slots__ = (
        "_audit",
        "_git",
        "_git_path",
        "_last_ns",
        "_root",
        "_size_of",
        "_store_size",
    )

    def __init__(
        self,
        paths: XdgPaths,
        *,
        audit: AuditWriter,
        git: Callable[[Sequence[str], dict[str, str]], GitResult] = _default_git,
        git_path: str = _DEFAULT_GIT,
        size_of: Callable[[Path], int] | None = None,
        store_size: Callable[[], int] | None = None,
    ) -> None:
        """:raises CheckpointError: ``git_path`` is not a trusted absolute path."""
        if not os.path.isabs(git_path) or os.path.dirname(git_path) not in _TRUSTED_BIN_DIRS:
            raise CheckpointError(
                f"git_path {git_path!r} is not in {sorted(_TRUSTED_BIN_DIRS)}; an early "
                "writable PATH entry is a shim, and a shimmed git writes wherever it likes"
            )
        self._audit = audit
        self._git = git
        self._git_path = git_path
        self._root = paths.state_home / "lsassist" / "checkpoints"
        self._size_of = size_of if size_of is not None else (lambda p: p.stat().st_size)
        self._store_size = store_size if store_size is not None else self.measure_store
        self._last_ns = 0

    # -- paths -------------------------------------------------------------

    @property
    def _objects(self) -> Path:
        return self._root / "objects"

    def _fresh_index(self) -> Path:
        """A NEW index file for one ``create()`` call, and one call only.

        The earlier design kept one index per workspace. It was chosen to stop a
        shared index staging one workspace's files into another's snapshot, and it
        did — but a PERSISTENT index accumulates: ``update-index --add`` leaves
        unrelated entries alone and ``write-tree`` writes the whole index, so each
        checkpoint's tree quietly became a superset of every earlier one for that
        workspace while its manifest still claimed only this call's files. A fresh
        file per call keeps the isolation, removes the accumulation, and makes two
        concurrent calls impossible to interleave.
        """
        directory = self._root / "index"
        _ensure_dir_chain(directory)
        return directory / f"{uuid.uuid4().hex}.idx"

    def _manifest_dir(self, workspace: str) -> Path:
        return self._root / "manifests" / _workspace_key(workspace)

    @staticmethod
    def _ref_for(workspace: str, checkpoint_id: str) -> str:
        return f"refs/lsassist/{_workspace_key(workspace)}/{checkpoint_id}"

    # -- git ---------------------------------------------------------------

    def _env(self, workspace: str, index: Path) -> dict[str, str]:
        """The child's COMPLETE environment — constructed, never inherited.

        Absence is as deliberate as presence. Nothing else git reads is set, so
        ``GIT_OBJECT_DIRECTORY``, ``GIT_ALTERNATE_OBJECT_DIRECTORIES``,
        ``GIT_COMMON_DIR`` and ``GIT_CEILING_DIRECTORIES`` cannot arrive from the
        caller's shell and redirect the snapshot.

        * ``GIT_DIR`` matters most and is the one a developer most plausibly has
          exported; inheriting it would send every checkpoint object into whatever
          repository the user was standing in.
        * ``GIT_CONFIG_GLOBAL``/``GIT_CONFIG_SYSTEM`` are ``/dev/null`` so a user
          ``core.hooksPath``, a clean/smudge ``filter`` or an ``init.templateDir``
          cannot run code inside our snapshot.
        * ``GIT_TERMINAL_PROMPT=0`` because a plumbing call that stopped to ask for
          credentials would hang a pre-write checkpoint, and a hang before a write
          is indistinguishable to the user from a crash.
        * ``LC_ALL=C`` so the stdout this code parses (an object id) is not
          localised, and an error message quoted into an audit record reads the
          same on every host.
        """
        return {
            "GIT_DIR": str(self._objects),
            "GIT_WORK_TREE": workspace,
            "GIT_INDEX_FILE": str(index),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            **_IDENTITY,
        }

    def _admin_env(self) -> dict[str, str]:
        """For calls that address the store itself — no work tree, no index.

        ``git init`` and ``git gc`` take their target from ``GIT_DIR`` or from an
        argument; real git REFUSES outright when a work tree is named without a
        matching git dir ("GIT_WORK_TREE ... not allowed without specifying
        GIT_DIR"), which is exactly how the first version of the initialiser failed.
        """
        return {
            "GIT_DIR": str(self._objects),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
        }

    def _invoke(self, argv: Sequence[str], env: dict[str, str], *, what: str) -> str:
        """The ONLY place a git result is validated.

        Every git call comes through here. An earlier version checked the runner's
        return type in two places, which left one copy unreachable — and an
        unreachable guard inside a TCB package is a guard nobody has executed,
        which §23.1's 100% branch floor exists to surface.

        The runner is also allowed to RAISE rather than return, and that is not an
        exotic case: :func:`_default_git` passes ``timeout=`` to
        ``subprocess.run``, so a hung git raises ``subprocess.TimeoutExpired``, and
        a missing or unexecutable binary raises ``OSError``. Checking only the
        returned value let both escape :meth:`create` untyped, past the one
        promise every caller is written against.
        """
        # `Exception`, not a tuple. A tuple has to enumerate what the runner may
        # raise, and the runner is INJECTABLE — public API — so that enumeration
        # cannot be complete by construction. It was already incomplete:
        # `subprocess.run` raised `UnicodeDecodeError`, a `ValueError`, which the
        # `(OSError, SubprocessError)` tuple did not name. `BaseException` is
        # deliberately left alone so Ctrl+C still interrupts.
        try:
            result = self._git(argv, env)
        except Exception as exc:
            raise CheckpointError(f"{what} could not be run: {exc!r}") from exc
        if not isinstance(result, GitResult):
            raise CheckpointError(
                f"{what}: git runner returned {type(result).__name__}, not GitResult"
            )
        if result.returncode != 0:
            raise CheckpointError(
                f"{what} exited {result.returncode}: {result.stderr.strip()[:200]}"
            )
        return result.stdout.strip()

    def _ensure_store(self) -> None:
        """Create the shadow object database if it is not there yet.

        ``GIT_DIR`` pointing at an empty directory is not a repository — real git
        answers "fatal: not a git repository" and every plumbing call fails. The
        stubbed unit suite could not see this because a fake git answers anything;
        the integration suite against a real binary found it on the first run.

        ``--bare`` because this database has no work tree of its own: the work
        tree is whichever workspace is being snapshotted, and it arrives per call.
        """
        # `Path.is_file()` swallows ENOENT and ENOTDIR but NOT EACCES, so an
        # unreadable ancestor escapes here as a raw PermissionError — measured, and
        # ahead of every other guard in this method.
        try:
            initialised = (self._objects / "HEAD").is_file()
        except OSError as exc:
            raise CheckpointError(f"cannot inspect the checkpoint store: {exc!r}") from exc
        if initialised:
            return
        # No try/except here: :func:`_ensure_dir_chain` owns the OSError ->
        # CheckpointError mapping for all three of its call sites. Wrapping it at
        # one site was how the other two came to have no handler at all.
        _ensure_dir_chain(self._objects)
        self._invoke(
            (self._git_path, "init", "--bare", "-q", "--", str(self._objects)),
            self._admin_env(),
            what="checkpoint store initialisation",
        )

    # -- create ------------------------------------------------------------

    def _next_id(self) -> tuple[str, datetime]:
        """A strictly increasing id, so lexicographic order IS chronological.

        Two checkpoints in the same clock tick would otherwise share an id, and
        because :meth:`_persist` writes to ``{checkpoint_id}.json`` the second
        would silently OVERWRITE the first — no error, no prune record, one
        checkpoint simply gone.
        """
        now_ns = max(time.time_ns(), self._last_ns + 1)
        self._last_ns = now_ns
        return f"cp-{now_ns:020d}", datetime.fromtimestamp(now_ns / 1e9, tz=UTC)

    def create(
        self,
        *,
        workspace: str,
        paths: Sequence[str],
        trigger: TriggerKind,
        task_id: str,
    ) -> CheckpointManifest:
        """Snapshot ``paths`` and return the §14.4 manifest.

        The ``tree`` contains exactly the STORED entries — never a file this call
        did not stage, which is why the index is fresh per call rather than shared
        per workspace. ``entries`` is a superset of it by design: an oversize file
        is RECORDED as excluded and never staged, so a rollback can tell "absent at
        checkpoint time" from "present but not stored". An earlier version of this
        line claimed the two sets were identical, which was false the moment any
        file was excluded.

        :raises CheckpointError: no paths, a path outside the workspace, a missing
            file, any git failure, or a journal failure. In every case nothing is
            left that a rollback would mistake for a usable checkpoint.
        """
        root = Path(workspace).resolve()
        if not paths:
            raise CheckpointError("a checkpoint with no paths restores nothing")

        self._ensure_store()
        checkpoint_id, created_at = self._next_id()
        index = self._fresh_index()
        try:
            env = self._env(str(root), index)
            entries, staged = self._collect(root, paths, env)
            for blob, rel in staged:
                self._invoke(
                    (
                        self._git_path, "update-index", "--add",
                        "--cacheinfo", _BLOB_MODE, blob, rel,
                    ),
                    env,
                    what="git update-index",
                )
            tree = self._invoke((self._git_path, "write-tree"), env, what="git write-tree")
            # A commit and a ref, so the objects are REACHABLE. `write-tree` alone
            # leaves the tree unreferenced, which means any `git gc` in this store
            # is entitled to delete every checkpoint — and it is also what stops
            # eviction from ever reclaiming space.
            commit = self._invoke(
                (
                    self._git_path, "commit-tree", tree,
                    "-m", f"lsassist checkpoint {checkpoint_id} ({trigger.value})",
                ),
                env,
                what="git commit-tree",
            )
            self._invoke(
                (self._git_path, "update-ref", self._ref_for(str(root), checkpoint_id), commit),
                env,
                what="git update-ref",
            )
        finally:
            index.unlink(missing_ok=True)

        manifest = CheckpointManifest(
            checkpoint_id=checkpoint_id,
            workspace=str(root),
            trigger=trigger,
            created_at=created_at,
            entries=tuple(entries),
            tree=tree,
        )
        self._persist(manifest)
        try:
            self._journal("create", manifest, task_id)
        # Broad on purpose. A checkpoint whose creation reported failure must not
        # survive as a usable manifest: the caller has been told the snapshot did
        # not happen, and `manifests()` would otherwise offer it to a rollback.
        except Exception as exc:
            self._discard(str(root), checkpoint_id)
            raise CheckpointError(
                f"checkpoint {checkpoint_id} could not be journalled: {exc!r}"
            ) from exc
        # Retention runs AFTER the manifest is durable and journalled, so from here
        # on a valid, restorable checkpoint exists. Letting a housekeeping failure
        # propagate told the caller "no checkpoint was made" — the one thing that
        # makes it skip its mutation, or worse, mutate believing it cannot roll
        # back — about a checkpoint that is in fact on disk and usable. The failure
        # is real and must be visible, so it is journalled rather than dropped; the
        # store being over its cap is an operator problem, not this caller's.
        try:
            self._prune(str(root), keep=checkpoint_id, task_id=task_id)
        # Broad on purpose, and narrower would be wrong: the point is not which
        # failure retention hit, it is that NO failure here may retract a promise
        # the caller has already been given.
        except Exception as exc:
            self._journal_retention_failure(str(root), checkpoint_id, exc, task_id)
        return manifest

    def _collect(
        self, root: Path, paths: Sequence[str], env: dict[str, str]
    ) -> tuple[list[CheckpointEntry], list[tuple[str, str]]]:
        """Validate every path, hash what is storable, record what is not.

        The filesystem calls are guarded because the inputs are not trusted: a NUL
        byte in a path makes ``Path.resolve`` raise ``ValueError``, an unreadable
        parent makes ``stat`` raise ``PermissionError``, and a file deleted between
        two of these calls raises ``FileNotFoundError``. Each of those used to leave
        this module as itself, which contradicts the one-error-type contract
        :class:`CheckpointError` exists to keep.
        """
        entries: list[CheckpointEntry] = []
        staged: list[tuple[str, str]] = []
        for raw in paths:
            try:
                target = Path(raw).resolve()
            except (OSError, ValueError) as exc:
                raise CheckpointError(f"{raw!r} cannot be resolved: {exc!r}") from exc
            # Containment BEFORE any stat: asking the filesystem about a path
            # outside the workspace answers "does this exist" for a path the caller
            # was never entitled to name.
            try:
                relative = target.relative_to(root)
            except ValueError as exc:
                raise CheckpointError(f"{raw!r} is outside the workspace {root}") from exc
            try:
                if not target.is_file():
                    raise CheckpointError(f"{raw!r} is not an existing regular file")
                info = target.stat()
                size = self._size_of(target)
            except OSError as exc:
                raise CheckpointError(f"{raw!r} cannot be inspected: {exc!r}") from exc

            rel = relative.as_posix()
            if size > MAX_FILE_BYTES:
                # RECORDED, not omitted: a manifest that left the file out would be
                # indistinguishable from one taken before it existed, and a rollback
                # would delete it as "absent at checkpoint time".
                entries.append(
                    CheckpointEntry(
                        path=rel,
                        size=size,
                        mtime_ns=info.st_mtime_ns,
                        excluded_because=ExclusionReason.OVERSIZE,
                    )
                )
                continue
            # `--no-filters`, and NOT `--path`. `--path` looks the harmless way to
            # tell git the workspace-relative name, but git-hash-object(1) says it
            # selects the attribute-driven filters that "actually affect the
            # generated hash value" — so a `.gitattributes` in the workspace was an
            # attacker-influenced input to what the store recorded. Measured on git
            # 2.55.0 with this module's own env, `* text=auto` plus a 20-byte CRLF
            # file: `--path` stored 18 bytes, `--no-filters` stored 20. The manifest
            # digest comes from `_blob_digest`, which reads the raw bytes, so the
            # stored object silently stopped matching the digest that identifies it
            # and the file a rollback would have to reproduce.
            #
            # `GIT_DIR` pointing away from the workspace does NOT protect this:
            # gitattributes are read off disk relative to the work tree, so the
            # isolation that makes the store invisible to the workspace does not
            # make the workspace invisible to the store.
            blob = self._invoke(
                (self._git_path, "hash-object", "-w", "--no-filters", "--", str(target)),
                env,
                what="git hash-object",
            )
            entries.append(
                CheckpointEntry(
                    path=rel, size=size, mtime_ns=info.st_mtime_ns, sha256=_blob_digest(target)
                )
            )
            staged.append((blob, rel))
        return entries, staged

    # -- persistence -------------------------------------------------------

    def _persist(self, manifest: CheckpointManifest) -> None:
        """Write the manifest atomically: temp file, fsync, then rename.

        A plain ``write_bytes`` leaves a truncated file if the process dies
        mid-write, and a truncated manifest is one a rollback cannot parse. §6.4's
        own ``fs.write`` row mandates tmp + fsync + rename for the USER's files;
        the record a rollback trusts deserves no less.
        """
        directory = self._manifest_dir(manifest.workspace)
        _ensure_dir_chain(directory)
        final = directory / f"{manifest.checkpoint_id}.json"
        temporary = directory / f".{manifest.checkpoint_id}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("wb") as handle:
                handle.write(canonical_bytes(manifest))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, final)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise CheckpointError(f"cannot persist the manifest: {exc!r}") from exc

    def manifests(self, workspace: str) -> tuple[CheckpointManifest, ...]:
        """Every READABLE manifest for ``workspace``, oldest first.

        Named ``manifests`` rather than ``list``: a method called ``list`` inside
        this class shadows the builtin for every annotation in the class body,
        which mypy --strict rejects.

        An unreadable or corrupt manifest is SKIPPED rather than raised. One
        truncated file used to raise out of the whole call, denying a rollback its
        entire recovery history for that workspace because of a single damaged
        byte. The failure mode has to be "that one checkpoint is gone", not "all of
        them are".
        """
        directory = self._manifest_dir(str(Path(workspace).resolve()))
        if not directory.is_dir():
            return ()
        found: list[CheckpointManifest] = []
        for path in sorted(directory.glob("cp-*.json")):
            try:
                found.append(CheckpointManifest.model_validate_json(path.read_bytes()))
            except (OSError, ValueError):
                continue
        return tuple(found)

    def measure_store(self) -> int:
        """Total bytes in the shadow object database — what the 2 GB cap reads.

        Public because it is the production default for ``store_size``, and a gate
        only ever reached through an injected double is a gate nobody has measured.
        """
        if not self._objects.is_dir():
            return 0
        return sum(p.stat().st_size for p in self._objects.rglob("*") if p.is_file())

    # -- retention ---------------------------------------------------------

    def _remove(self, workspace: str, checkpoint_id: str) -> None:
        """Remove one checkpoint's ref and then its manifest, raising on either failure.

        **REF FIRST, MANIFEST SECOND**, because the two half-failures are not
        symmetric and only one of them is recoverable:

        * Manifest gone, ref left behind — UNRECOVERABLE. :meth:`manifests`
          enumerates manifest FILES, so no later eviction can ever rediscover that
          id; its objects stay reachable and therefore ``gc``-immune, and the 2 GB
          cap can never be brought back under. This is the shape an isolated review
          named, and doing the manifest first is what produces it.
        * Ref gone, manifest left behind — recoverable. The manifest still
          enumerates, so the next retention pass retries this method and finishes
          the job, and until then a rollback that reads that manifest fails loudly
          on missing objects rather than restoring something wrong.

        So the destructive-but-recoverable step goes first and the one that makes a
        checkpoint invisible goes last. Both must succeed; a caller that needs the
        old swallow-everything behaviour is :meth:`_discard`, and it is exactly one
        caller wide.
        """
        self._invoke(
            (self._git_path, "update-ref", "-d", self._ref_for(workspace, checkpoint_id)),
            self._admin_env(),
            what="git update-ref -d",
        )
        manifest_path = self._manifest_dir(workspace) / f"{checkpoint_id}.json"
        try:
            manifest_path.unlink(missing_ok=True)
        except OSError as exc:
            raise CheckpointError(f"cannot remove manifest {manifest_path}: {exc!r}") from exc

    def _discard(self, workspace: str, checkpoint_id: str) -> None:
        """:meth:`_remove`, but swallowing every failure. Never raises.

        The ONLY caller is :meth:`create`'s unwind path, where a secondary error
        would replace the real cause with its own. Routine eviction calls
        :meth:`_remove` instead: it used to share this method, so a failed
        ``update-ref -d`` during an ordinary LRU trim was treated as a completed
        removal — the store reported space it had not reclaimed, and the ref it
        left behind kept the objects alive with no manifest to find them by.
        """
        try:
            self._remove(workspace, checkpoint_id)
        except CheckpointError:
            return

    def prune_to(self, workspace: str, *, keep_last: int, task_id: str) -> tuple[str, ...]:
        """Evict oldest-first until at most ``keep_last`` checkpoints remain.

        Public so a caller — or a test — can ask for retention explicitly rather
        than only as a side effect of :meth:`create`.

        :raises CheckpointError: a failed ``update-ref -d`` or manifest unlink
            during eviction, or a failed ``gc``. Eviction is deliberately STRICT
            here: a swallowed failure would report space it had not reclaimed.
        """
        root = str(Path(workspace).resolve())
        stored = [m.checkpoint_id for m in self.manifests(root)]
        return self._evict(root, stored[: max(0, len(stored) - keep_last)], task_id)

    def _all_stored(self) -> tuple[tuple[str, str], ...]:
        """``(workspace, checkpoint_id)`` for every readable manifest, oldest first.

        The 2 GB cap in §14.4 is a property of the STORE, and the store is one
        content-addressed object database shared by every workspace — but the count
        rule ("50 checkpoints per workspace") is per workspace. Reading the size
        globally while only ever evicting the CALLING workspace's checkpoints made
        the size loop unable to converge: a workspace that had pushed the shared
        store over the cap could not be reached, so an unrelated workspace's next
        ``create()`` deleted its own entire history and the store was still over.
        "LRU prune" is oldest-first across the store, which is what this enumerates.

        Ids sort chronologically by construction (:meth:`_next_id` builds them from
        a nanosecond clock), so a lexical sort on the id IS the LRU order and needs
        no manifest parse to establish it.
        """
        # No `is_dir()` guard, deliberately. The only caller is :meth:`_prune`,
        # which runs after :meth:`_persist` has created this directory, so the
        # guard was unreachable — and `Path.glob` on a missing directory yields
        # nothing rather than raising, so it bought nothing either. Unreachable
        # defensive code in a §23.1 package is code the 100 % branch floor will
        # not let anyone verify, and a coverage-exclusion comment is banned here —
        # so the honest move is deletion, not suppression.
        found: list[tuple[str, str]] = []
        for manifest in (self._root / "manifests").glob("*/cp-*.json"):
            try:
                record = CheckpointManifest.model_validate_json(manifest.read_bytes())
            except (OSError, ValueError):
                continue
            # The OWNER comes from the directory, never from the file. A manifest
            # under `manifests/<hash of A>/` claiming ``workspace: B`` would
            # otherwise send :meth:`_remove` at B's real ref and B's real manifest,
            # because both are derived from this value. Nothing but this store
            # writes here, so the mismatch is not an attack an adversary needs —
            # it is a trust boundary that cost nothing to close and would have made
            # any future writer of this directory able to redirect deletions.
            if _workspace_key(record.workspace) != manifest.parent.name:
                continue
            found.append((record.workspace, record.checkpoint_id))
        return tuple(sorted(found, key=lambda pair: pair[1]))

    def _evict(self, workspace: str, doomed: Sequence[str], task_id: str) -> tuple[str, ...]:
        if not doomed:
            return ()
        for checkpoint_id in doomed:
            self._remove(workspace, checkpoint_id)
        # Objects only become reclaimable once their refs are gone, which is the
        # other half of why every checkpoint has one.
        #
        # NOT `--prune=now`. One object database is shared by every workspace
        # (§14.4), and `create()` writes blobs with `hash-object -w` well before
        # `update-ref` makes them reachable. `--prune=now` waives exactly the grace
        # period git documents as the protection for a concurrent, unfinished
        # write — so an eviction here could delete another process's in-flight
        # objects, or leave a just-written manifest pointing at objects that are
        # already gone: a checkpoint that reports success and cannot be restored.
        # A bounded expiry still reclaims what eviction freed, because LRU evicts
        # the OLDEST checkpoints and their objects are older than the window.
        self._invoke(
            (self._git_path, "gc", f"--prune={_GC_PRUNE_EXPIRY}", "--quiet"),
            self._admin_env(),
            what="git gc",
        )
        self._journal_prune(workspace, doomed, task_id)
        return tuple(doomed)

    def _prune(self, workspace: str, *, keep: str, task_id: str) -> None:
        """§14.4 retention: 50 per workspace, 2 GB total, LRU, never ``keep``.

        ``keep`` is excluded by CONSTRUCTION rather than by trusting the ordering
        to put it last: the pruner's one inviolable rule is that it must not evict
        the checkpoint a rollback is about to use, and "the newest sorts last" is
        an ordering property, not a guarantee.

        The size branch evicts OLDEST-FIRST, one at a time, re-measuring after each
        ``gc``. It used to take everything at once, which — combined with never
        reclaiming objects — meant the cap could never clear and every later
        ``create()`` wiped the store down to one checkpoint, permanently.

        The COUNT rule is per workspace and the SIZE rule is per store, because
        §14.4 words them that way: "50 checkpoints per workspace, size-capped
        2 GB". So the two branches read different candidate sets, and the size
        branch spans every workspace — see :meth:`_all_stored` for why reading the
        size globally and evicting locally could not converge.
        """
        stored = [m.checkpoint_id for m in self.manifests(workspace) if m.checkpoint_id != keep]

        over_count = max(0, len(stored) + 1 - MAX_CHECKPOINTS_PER_WORKSPACE)
        if over_count:
            self._evict(workspace, stored[:over_count], task_id)

        under_pressure = [pair for pair in self._all_stored() if pair[1] != keep]
        while under_pressure and self._store_size() > MAX_STORE_BYTES:
            owner, doomed = under_pressure[0]
            self._evict(owner, (doomed,), task_id)
            under_pressure = under_pressure[1:]

    # -- audit -------------------------------------------------------------

    def _journal(self, action: str, manifest: CheckpointManifest, task_id: str) -> None:
        """§14.1: digests and counts, never file bodies.

        A checkpoint of a secrets file must not put that secret into a permanent
        record — the snapshot exists so the bytes can be restored, not read.
        """
        self._audit.write(
            AuditEvent.RECOVERY.value,
            {
                "action": action,
                "checkpoint_id": manifest.checkpoint_id,
                "workspace": manifest.workspace,
                "trigger": manifest.trigger.value,
                "tree": manifest.tree,
                "manifest_digest": manifest_digest(manifest),
                "file_count": len(manifest.entries),
                "excluded_count": sum(
                    1 for e in manifest.entries if e.excluded_because is not None
                ),
            },
            task_id=task_id,
        )

    def _journal_retention_failure(
        self, workspace: str, checkpoint_id: str, cause: BaseException, task_id: str
    ) -> None:
        """Record that retention failed while the checkpoint itself succeeded.

        Best effort, and deliberately so: this runs on a path where the caller has
        already been promised a usable checkpoint, so an audit failure here must not
        turn that promise into an exception. The ``repr`` of the cause is recorded
        rather than its message alone because §14.1 asks for enough to diagnose, and
        an ``OSError``'s type is most of the diagnosis.
        """
        try:
            self._audit.write(
                AuditEvent.RECOVERY.value,
                {
                    "action": "prune_failed",
                    "workspace": workspace,
                    "checkpoint_id": checkpoint_id,
                    "cause": repr(cause)[:200],
                },
                task_id=task_id,
            )
        except Exception:
            return

    def _journal_prune(self, workspace: str, evicted: Sequence[str], task_id: str) -> None:
        """A checkpoint that vanished silently is a rollback that fails later.

        ``store_bytes`` is recorded so an operator can tell a routine one-off LRU
        trim from sustained size pressure, which read identically before.
        """
        self._audit.write(
            AuditEvent.RECOVERY.value,
            {
                "action": "prune",
                "workspace": workspace,
                "evicted": list(evicted),
                "evicted_count": len(evicted),
                "store_bytes": self._store_size(),
            },
            task_id=task_id,
        )


def _blob_digest(target: Path) -> str:
    """The file's own sha256 — the manifest's identity for it.

    Deliberately NOT git's blob id: git hashes ``blob <len>\\0`` + content, so a
    reader comparing a manifest entry against a file on disk with ``sha256sum``
    would get a different answer and reasonably conclude the file had changed.
    """
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
