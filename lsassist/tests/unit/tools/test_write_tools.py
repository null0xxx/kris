"""T3.05 — the §6.4 WRITE tool batch: `fs.write`, `fs.patch`, `git.worktree`.

**WHAT ONLY THIS SUITE CAN PROVE.** T3.04's suite proved the read handlers and the
in-process route. These three tools are the first that MUTATE, and mutation makes
four properties load-bearing that a reader never had to satisfy:

1. **Atomicity is a promise about what a CRASH leaves behind** (§6.4: "atomic:
   tmp+`fsync`+`rename`"). A test that only checks the happy-path bytes cannot
   tell an atomic publish from a `write()` straight onto the target — both end
   with the right content. So every failure test here asserts the ORIGINAL bytes
   survive, and no temporary file is left under the workspace.
2. **`intent=overwrite` is a gate, not a hint** (§6.4). Without it an existing
   path must fail and stay untouched. The check has to be atomic with the publish:
   a `stat`-then-write is a TOCTOU window, so the assertions are written so a
   racing implementation fails them.
3. **All-or-nothing is the whole of `fs.patch`** (§6.4, and the plan's expected
   result "partial patch → file unchanged, tree hash identical"). One missed
   anchor must touch nothing. An AMBIGUOUS anchor is also a miss: a
   first-occurrence guess would silently edit the wrong place, and nothing
   downstream could detect it.
4. **A write may only proceed once a rollback exists** (§14.4: checkpoint before
   `fs.write`/`fs.patch` on an existing file). So a checkpoint FAILURE must abort
   the write — the caller's whole contract is that it may mutate because it can
   undo. A handler that snapshots after writing, or that ignores the snapshot's
   failure, passes every content assertion and fails these.

**The store is injected by CLOSURE, deliberately.** `Handler` is
`Callable[[HandlerContext], Mapping[str, Any]]`, so `make_writer(store)` fits the
existing type and needs NO new `HandlerContext` field — which would mean editing
`tools/dispatcher.py`, a `tcb` unit, while SPEC §2.3's TCB budget is already over
its Gate-4 target. T3.05 therefore adds zero TCB lines, and these tests call both
the closure and the underlying pure function so neither drifts from the other.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from lsassist.audit.writer import AuditWriter
from lsassist.contracts.manifest import ToolManifest
from lsassist.contracts.tool_request import ToolRequest
from lsassist.policy.stores import PolicyStores
from lsassist.recovery.checkpoints import CheckpointError, CheckpointStore, GitResult
from lsassist.recovery.manifest import TriggerKind
from lsassist.tools.dispatcher import Decision, DispatchEnvironment, dispatch
from lsassist.tools.handlers import (
    ANCHOR_MISS,
    CANARY_TRIPPED,
    CHECKPOINT_FAILED,
    DENY_PATH,
    TARGET_EXISTS,
    TIMED_OUT,
    WORKSPACE_SCOPE,
    WRITE_FAILED,
    HandlerContext,
    HandlerRefused,
)
from lsassist.tools.handlers.fs_patch import make_patcher, patch_file
from lsassist.tools.handlers.fs_write import make_writer, write_file
from lsassist.tools.handlers.git_worktree import GIT, WORKTREE_DIR
from lsassist.tools.handlers.git_worktree import build_argv as worktree_argv
from lsassist.tools.handlers.git_worktree import result_of as worktree_result
from lsassist.tools.registry import load_registry

REGISTRY = load_registry()
CANARY_BODY = "sk-kimi-DECOY-0123456789abcdef"


# ---------------------------------------------------------------------------
# Fixtures — a workspace outside /tmp (§8.1 masks it with a tmpfs)
# ---------------------------------------------------------------------------


def stores_for(home: Path) -> PolicyStores:
    return PolicyStores(
        home=str(home),
        audit_store=str(home / ".local/state/lsassist/audit"),
        policy_store=str(home / ".config/lsassist"),
        kernel_secret=str(home / ".local/state/lsassist/kernel.secret"),
    )


@pytest.fixture
def workspace() -> Iterator[Path]:
    ws = Path.home() / ".cache" / "lsassist" / "t305-tests" / uuid.uuid4().hex / "ws"
    ws.mkdir(parents=True)
    (ws / "existing.txt").write_text("BEFORE\n", encoding="utf-8")
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
def audit_dir(tmp_path: Path) -> Path:
    return tmp_path / "audit"


@pytest.fixture
def journal(audit_dir: Path) -> Iterator[AuditWriter]:
    with AuditWriter(directory=audit_dir, session_id="s-1") as writer:
        yield writer


class GitSpy:
    """Records every shadow-git invocation and answers the store's plumbing."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Any, env: dict[str, str]) -> GitResult:
        self.calls.append(tuple(argv))
        if "hash-object" in argv:
            return GitResult(0, "b" * 40, "")
        if "write-tree" in argv:
            return GitResult(0, "a" * 40, "")
        return GitResult(0, "", "")


@pytest.fixture
def store(tmp_path: Path, journal: AuditWriter) -> CheckpointStore:
    """A REAL CheckpointStore with git stubbed — T4.04's own injection seam."""
    from lsassist.config.xdg import XdgPaths

    paths = XdgPaths(
        config_home=tmp_path / "c",
        data_home=tmp_path / "d",
        state_home=tmp_path / "s",
        cache_home=tmp_path / "h",
    )
    return CheckpointStore(paths, audit=journal, git=GitSpy())


class RefusingStore:
    """A store whose snapshot always fails — the case a write MUST abort on."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...], TriggerKind]] = []

    def create(
        self, *, workspace: str, paths: Any, trigger: TriggerKind, task_id: str
    ) -> Any:
        self.calls.append((workspace, tuple(paths), trigger))
        raise CheckpointError("the shadow store is unavailable")


class RecordingStore:
    """Records what was snapshotted, and when, without touching a filesystem."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...], TriggerKind]] = []
        self.observed: list[bytes] = []

    def create(
        self, *, workspace: str, paths: Any, trigger: TriggerKind, task_id: str
    ) -> Any:
        targets = tuple(paths)
        self.calls.append((workspace, targets, trigger))
        # Capture the bytes AS THEY ARE AT SNAPSHOT TIME. This is what makes
        # "checkpoint BEFORE the write" testable: a handler that snapshots
        # afterwards records the NEW content and every content assertion still
        # passes.
        for target in targets:
            self.observed.append(Path(target).read_bytes())
        return object()


requires_unprivileged_t305 = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root ignores directory permissions, so the denial cannot be provoked",
)


def manifest_for(tool: str) -> ToolManifest:
    """The REAL shipped manifest — never a hand-built stub.

    A test that invents its own manifest cannot catch a manifest whose class,
    caps or limits drifted from the §6.4 table.
    """
    return REGISTRY[tool]


def context_for(
    environment: DispatchEnvironment,
    target: Path,
    *,
    tool: str,
    args_extra: dict[str, Any] | None = None,
    canary_paths: frozenset[str] = frozenset(),
    deadline: float | None = None,
) -> HandlerContext:
    """A handler context carrying a REAL normalized request from `dispatch`.

    Every arg goes through the same `dispatch` call, so an `intent` or a `blocks`
    shape the manifest's `input_schema` would reject never reaches a handler in a
    test either.

    `create_if_missing` is on for `fs.write` and off for `fs.patch`, which is the
    dispatcher's OWN §6.3 step-2 carve-out and not a convenience here: a create
    target has no node identity to snapshot yet, so `_snapshot_targets` measures
    its PARENT instead, and a swapped parent is exactly how a file gets created
    somewhere other than where it was approved. A patch has no such carve-out —
    it must anchor in bytes that already exist.
    """
    manifest = manifest_for(tool)
    args: dict[str, Any] = {"path": str(target)}
    args.update(args_extra or {})
    request = ToolRequest(call_id="c1", tool=tool, args=args)
    decision = dispatch(
        request,
        manifest=manifest,
        environment=environment,
        path_args=["path"],
        create_if_missing=(tool == "fs.write"),
    )
    assert decision.decision is Decision.PROCEED, decision
    normalized = decision.normalized
    assert normalized is not None
    return HandlerContext(
        normalized=normalized,
        manifest=manifest,
        environment=environment,
        canary_paths=canary_paths,
        deadline=deadline,
    )


def digest_of(root: Path) -> dict[str, str]:
    """Every file under `root`, keyed by relative path — the "tree hash" oracle.

    Used by the all-or-nothing tests: comparing whole-tree digests catches a
    partial write, a stray temporary file and a touched sibling in one assertion,
    where checking only the target's content would miss all three.
    """
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() or path.is_symlink():
            out[str(path.relative_to(root))] = hashlib.sha256(
                path.read_bytes() if path.is_file() else os.readlink(path).encode()
            ).hexdigest()
    return out


# ==========================================================================
# A. fs.write — the bytes, and the create-only/overwrite gate
# ==========================================================================


def test_a_new_file_is_created_with_exactly_the_requested_bytes(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    target = workspace / "new.txt"
    context = context_for(
        environment, target, tool="fs.write", args_extra={"content": "hello\n"}
    )
    result = write_file(context, store)
    assert target.read_bytes() == b"hello\n"
    assert result["bytes_written"] == 6
    assert result["created"] is True


def test_create_only_refuses_an_existing_path_and_leaves_it_byte_identical(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """§6.4: "overwrite requires `intent=overwrite` (else create-only fails if exists)".

    The refusal is only half the property. If the handler had already opened the
    target with O_TRUNC before discovering it existed, the content assertion is
    what catches it.
    """
    target = workspace / "existing.txt"
    before = digest_of(workspace)
    context = context_for(
        environment, target, tool="fs.write", args_extra={"content": "AFTER\n"}
    )
    with pytest.raises(HandlerRefused) as caught:
        write_file(context, store)
    assert caught.value.kind == TARGET_EXISTS
    assert digest_of(workspace) == before


def test_intent_overwrite_replaces_the_content(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    target = workspace / "existing.txt"
    context = context_for(
        environment,
        target,
        tool="fs.write",
        args_extra={"content": "AFTER\n", "intent": "overwrite"},
    )
    result = write_file(context, store)
    assert target.read_bytes() == b"AFTER\n"
    assert result["created"] is False


def test_an_unknown_intent_never_reaches_the_handler(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """The manifest's `input_schema` owns the enum, so `dispatch` must reject it.

    Asserted here rather than trusted: an `intent` the schema admits but the
    handler does not understand would be a third, undefined write mode.
    """
    manifest = manifest_for("fs.write")
    request = ToolRequest(
        call_id="c1",
        tool="fs.write",
        args={"path": str(workspace / "x.txt"), "content": "x", "intent": "append"},
    )
    decision = dispatch(
        request, manifest=manifest, environment=environment, path_args=["path"]
    )
    assert decision.decision is not Decision.PROCEED


def test_no_temporary_file_survives_a_successful_write(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """tmp+fsync+rename must leave the tmp nowhere — not even hidden."""
    target = workspace / "new.txt"
    context = context_for(
        environment, target, tool="fs.write", args_extra={"content": "hello\n"}
    )
    write_file(context, store)
    leftovers = [p.name for p in workspace.rglob("*") if p.name not in {"existing.txt", "new.txt"}]
    assert leftovers == [], f"temporary files left behind: {leftovers}"


def test_a_failed_publish_leaves_the_original_bytes_and_no_temporary_file(
    environment: DispatchEnvironment,
    workspace: Path,
    store: CheckpointStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """This is the test that distinguishes atomic from "write onto the target".

    The publish is the failure point, not `fsync`: `os` is a single module object,
    so patching `fs_write.os.fsync` also breaks `CheckpointStore._persist`'s own
    fsync, which runs first — the refusal then arrives as `checkpoint_failed` and
    the test proves something else entirely. Patching `rename` is precise: the
    checkpoint completes, the temporary file is written and fsynced, and only the
    step that changes what a reader sees fails. A handler writing straight to the
    target would have truncated it long before this point.
    """
    from lsassist.tools.handlers import fs_write as module

    def boom(src: Any, dst: Any) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(module.os, "rename", boom)
    target = workspace / "existing.txt"
    before = digest_of(workspace)
    context = context_for(
        environment,
        target,
        tool="fs.write",
        args_extra={"content": "AFTER\n", "intent": "overwrite"},
    )
    with pytest.raises(HandlerRefused) as caught:
        write_file(context, store)
    assert caught.value.kind == WRITE_FAILED
    assert digest_of(workspace) == before


def test_the_publish_fsyncs_before_it_renames() -> None:
    """`fsync`'s value is what a CRASH leaves behind, so no behaviour can observe it.

    Structural, and deliberately so — the same technique T3.04 needed for its
    pinned read. Deleting `os.fsync` from `publish` leaves every byte assertion in
    this file passing, because the content is correct either way; only the
    durability guarantee §6.4 asks for is gone. An AST assertion is the one thing
    that can fail, and it fails for exactly the right reason.
    """
    import ast
    import inspect

    from lsassist.tools.handlers import fs_write as module

    tree = ast.parse(inspect.getsource(module.publish))
    # ORDER, not membership. A set discards sequence, so an implementation that
    # fsynced AFTER renaming produced the identical set and this test — named for
    # the ordering — passed anyway. §6.4 and the plan's human-review checkpoint
    # both name the SEQUENCE ("tmp+fsync+rename order"), so line position is the
    # thing to assert.
    calls = [
        (node.lineno, ast.unparse(node.func))
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    names = [name for _, name in calls]
    assert "os.fsync" in names, f"publish() no longer fsyncs: {sorted(set(names))}"
    fsync_at = min(line for line, name in calls if name == "os.fsync")
    for publisher in ("os.rename", "os.link"):
        assert publisher in names, sorted(set(names))
        at = min(line for line, name in calls if name == publisher)
        assert fsync_at < at, f"{publisher} is published before the fsync ({at} <= {fsync_at})"


def test_a_target_created_DURING_the_write_is_refused_not_clobbered(
    environment: DispatchEnvironment,
    workspace: Path,
    store: CheckpointStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The race the create-only gate exists for, reproduced deterministically.

    The `lstat` gate and the publish primitive are TWO independent defences, and
    only this test can reach the second: `lstat` is made to report the target as
    absent, so the handler believes it is creating a new file while the file is
    really there. `os.link` then refuses with EEXIST — atomically, which is why
    create-only does not use `rename`. Swap `link` for `rename` and the original
    bytes are silently destroyed, which is what the final assertion catches.
    """
    from lsassist.tools.handlers import fs_write as module

    target = workspace / "existing.txt"
    context = context_for(
        environment, target, tool="fs.write", args_extra={"content": "AFTER\n"}
    )
    monkeypatch.setattr(module, "_existing_kind", lambda _target: None)

    with pytest.raises(HandlerRefused) as caught:
        write_file(context, store)
    assert caught.value.kind == TARGET_EXISTS
    assert target.read_bytes() == b"BEFORE\n", "the publish clobbered an existing file"
    leftovers = [p.name for p in workspace.rglob("*") if ".lsassist-tmp-" in p.name]
    assert leftovers == [], f"temporary files left behind: {leftovers}"


@requires_unprivileged_t305
def test_an_unreadable_target_is_a_typed_error_not_a_silent_create(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """`_existing_kind` must distinguish ENOENT from every other lstat failure.

    Merging the two `except` clauses into one that returns `None` would make an
    unreadable target look ABSENT — and on the overwrite path that skips the whole
    `if existing is not None:` block, including §14.4's mandatory checkpoint,
    before `os.rename` replaces the file anyway. A permission error is the shape
    that reproduces it.
    """
    blocked = workspace / "locked"
    blocked.mkdir()
    target = blocked / "file.txt"
    target.write_text("MINE\n", encoding="utf-8")
    context = context_for(
        environment,
        target,
        tool="fs.write",
        args_extra={"content": "THEIRS\n", "intent": "overwrite"},
    )
    blocked.chmod(0o000)
    try:
        with pytest.raises(HandlerRefused) as caught:
            write_file(context, store)
        assert caught.value.kind == WRITE_FAILED
        assert "cannot be inspected" in caught.value.detail
    finally:
        blocked.chmod(0o700)


def test_an_overwrite_keeps_the_targets_original_mode(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """Publishing by rename means the NEW inode's mode is the temp file's.

    So a 0755 script edited by `fs.write` or `fs.patch` came back 0600 and stopped
    being executable, with nothing in the result payload saying so. The mode is
    carried over from the file being replaced; a file being CREATED has no prior
    mode and keeps the tool's own 0600 default.
    """
    import stat as stat_module

    target = workspace / "script.sh"
    target.write_text("#!/bin/sh\necho old\n", encoding="utf-8")
    target.chmod(0o755)
    context = context_for(
        environment,
        target,
        tool="fs.write",
        args_extra={"content": "#!/bin/sh\necho new\n", "intent": "overwrite"},
    )
    write_file(context, store)
    assert stat_module.S_IMODE(target.stat().st_mode) == 0o755


def test_a_created_file_gets_the_tools_own_restrictive_mode(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """Nothing to inherit, so 0600: the tool must not invent a permissive file."""
    import stat as stat_module

    target = workspace / "fresh.txt"
    context = context_for(
        environment, target, tool="fs.write", args_extra={"content": "hi\n"}
    )
    write_file(context, store)
    assert stat_module.S_IMODE(target.stat().st_mode) == 0o600


def test_a_symlink_SWAPPED_IN_after_approval_is_refused(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """The real shape of §6.4's "`O_NOFOLLOW` final component", and it is a TOCTOU.

    §6.3 step 2 CANONICALIZES the path, so a symlink named in the request is
    already resolved by the time a handler sees it — the canonical path is not a
    symlink by construction, and a test that passes a link straight in proves
    nothing about the handler. The threat that remains is a link swapped in AFTER
    approval, which is the same window T3.04's step-6 pin closes for readers.

    Both halves matter: the refusal, and the victim's bytes. `rename` and `link`
    act on the link itself, so an unchecked publish silently replaces the link;
    a handler that followed it would write wherever the link points, which is how
    a workspace-scoped write leaves the workspace.
    """
    target = workspace / "swapped.txt"
    target.write_text("ORIGINAL\n", encoding="utf-8")
    context = context_for(
        environment,
        target,
        tool="fs.write",
        args_extra={"content": "AFTER\n", "intent": "overwrite"},
    )
    victim = workspace / "victim.txt"
    victim.write_text("VICTIM\n", encoding="utf-8")
    target.unlink()
    target.symlink_to(victim)
    before = digest_of(workspace)

    with pytest.raises(HandlerRefused) as caught:
        write_file(context, store)
    assert caught.value.kind == WRITE_FAILED
    # The DIAGNOSIS, not just the kind: with the S_ISLNK check removed the very
    # next check (`not S_ISREG`) still refuses with the same kind, so a
    # kind-only assertion cannot tell the symlink guard from its neighbour.
    assert "symlink" in caught.value.detail
    assert digest_of(workspace) == before
    assert victim.read_bytes() == b"VICTIM\n"


@pytest.mark.parametrize("exists", [False, True])
def test_a_write_outside_the_workspace_is_escalated_by_policy_rule_R2(
    environment: DispatchEnvironment, tmp_path: Path, exists: bool
) -> None:
    """The FIRST barrier is policy, not the handler — and it is a stronger one.

    R2 raises an out-of-workspace write to `CONFIRM_EXACT`, so the pipeline stops
    at `NEEDS_APPROVAL` and no handler runs at all. Asserted for both an existing
    and a missing target, because `create_if_missing` changes whether step 2 can
    canonicalize it and must not change whether policy escalates it.
    """
    outside = tmp_path / "outside.txt"
    if exists:
        outside.write_text("THEIRS\n", encoding="utf-8")
    args: dict[str, Any] = {"path": str(outside), "content": "OURS\n"}
    if exists:
        args["intent"] = "overwrite"
    decision = dispatch(
        ToolRequest(call_id="c1", tool="fs.write", args=args),
        manifest=manifest_for("fs.write"),
        environment=environment,
        path_args=["path"],
        create_if_missing=not exists,
    )
    assert decision.decision is Decision.NEEDS_APPROVAL, decision
    assert decision.permission_class.value == "CONFIRM_EXACT"
    assert "R2" in decision.matched_rules
    assert outside.exists() is exists


def test_the_handler_still_refuses_an_out_of_workspace_write_on_its_own(
    environment: DispatchEnvironment, tmp_path: Path, store: CheckpointStore
) -> None:
    """§6.2 `path_scope` as the LAST link, reached the only way it can be.

    Policy escalates this to `CONFIRM_EXACT`, so the pipeline never hands such a
    request to a handler — which means the handler's own check can only be
    exercised by constructing the request the pipeline would have stopped. That is
    precisely the scenario a double-check exists for, and it is the same technique
    T3.04 used for the §7.3 handler-side test. The read batch proved this
    declaration was enforced NOWHERE and `fs.read` on `~/.netrc` returned the
    password; a write escaping the workspace is strictly worse.
    """
    from lsassist.tools.dispatcher import NormalizedRequest

    outside = tmp_path / "outside.txt"
    outside.write_text("THEIRS\n", encoding="utf-8")
    normalized = NormalizedRequest(
        tool="fs.write",
        args={"path": str(outside), "content": "OURS\n", "intent": "overwrite"},
        canonical_paths=(str(outside),),
        workspace_root=environment.workspace_root,
        cwd_real=environment.cwd,
        env={},
        env_digest="sha256:" + "0" * 64,
        action_hash="sha256:" + "1" * 64,
    )
    context = HandlerContext(
        normalized=normalized, manifest=manifest_for("fs.write"), environment=environment
    )
    with pytest.raises(HandlerRefused) as caught:
        write_file(context, store)
    assert caught.value.kind == WORKSPACE_SCOPE
    assert outside.read_bytes() == b"THEIRS\n"


def test_writing_to_a_canary_honeyfile_is_refused_before_any_byte_lands(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """§19 scenario 1 applies to a write attempt too, and more urgently.

    Overwriting a honeyfile would destroy the very tripwire whose purpose is to
    record that something reached it.
    """
    canary = workspace / "credentials.txt"
    canary.write_text(CANARY_BODY, encoding="utf-8")
    before = digest_of(workspace)
    context = context_for(
        environment,
        canary,
        tool="fs.write",
        args_extra={"content": "AFTER\n", "intent": "overwrite"},
        canary_paths=frozenset({str(canary.resolve())}),
    )
    with pytest.raises(HandlerRefused) as caught:
        write_file(context, store)
    assert caught.value.kind == CANARY_TRIPPED
    assert digest_of(workspace) == before
    assert CANARY_BODY not in str(caught.value)


def test_a_deny_listed_target_is_refused_by_the_handler_itself(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """§7.3's handler-side double-check: the window between step 3 and the open."""
    target = workspace / "existing.txt"
    context = context_for(
        environment,
        target,
        tool="fs.write",
        args_extra={"content": "AFTER\n", "intent": "overwrite"},
    )
    stores = environment.stores
    object.__setattr__(stores, "kernel_secret", str(target))
    with pytest.raises(HandlerRefused) as caught:
        write_file(context, store)
    assert caught.value.kind == DENY_PATH


def test_an_elapsed_deadline_stops_the_write(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """A budget nothing consults is a number in a manifest, not a bound."""
    target = workspace / "new.txt"
    context = context_for(
        environment,
        target,
        tool="fs.write",
        args_extra={"content": "hello\n"},
        deadline=time.monotonic() - 1.0,
    )
    with pytest.raises(HandlerRefused) as caught:
        write_file(context, store)
    assert caught.value.kind == TIMED_OUT
    assert not target.exists()


# ==========================================================================
# B. fs.write — the checkpoint, which is what makes the write reversible
# ==========================================================================


def test_an_existing_file_is_checkpointed_BEFORE_it_is_overwritten(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§14.4: "before `fs.write`/`fs.patch` on existing file".

    `RecordingStore` reads the target's bytes at snapshot time, so a handler that
    snapshots AFTER writing records `AFTER` and fails here while passing every
    content assertion in section A.
    """
    recorder = RecordingStore()
    target = workspace / "existing.txt"
    context = context_for(
        environment,
        target,
        tool="fs.write",
        args_extra={"content": "AFTER\n", "intent": "overwrite"},
    )
    write_file(context, recorder)  # type: ignore[arg-type]
    assert len(recorder.calls) == 1
    _ws, paths, trigger = recorder.calls[0]
    assert paths == (str(target.resolve()),)
    assert trigger is TriggerKind.PRE_WRITE
    assert recorder.observed == [b"BEFORE\n"], "the snapshot captured the NEW bytes"


def test_a_create_only_refusal_takes_no_checkpoint(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """A write that is going to be refused must not spend a checkpoint first.

    This is what distinguishes the TWO create-only defences, which otherwise raise
    the same kind: the `lstat` gate refuses BEFORE §14.4's snapshot, while the
    `os.link` EEXIST layer can only refuse after it. Both are wanted — the second
    closes the race the first cannot — but only the first avoids consuming a slot
    of the 50-per-workspace retention budget for a mutation that never happens.
    Without this assertion, deleting the early gate is invisible.
    """
    recorder = RecordingStore()
    context = context_for(
        environment,
        workspace / "existing.txt",
        tool="fs.write",
        args_extra={"content": "AFTER\n"},
    )
    with pytest.raises(HandlerRefused) as caught:
        write_file(context, recorder)  # type: ignore[arg-type]
    assert caught.value.kind == TARGET_EXISTS
    assert recorder.calls == [], "a refused create-only write still took a checkpoint"


def test_a_brand_new_file_takes_no_checkpoint(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§14.4 scopes the trigger to an EXISTING file, and it has to.

    `CheckpointStore._collect` refuses a path that is not an existing regular
    file, so snapshotting a path about to be created would turn every create into
    a failure — and there is nothing to restore anyway.
    """
    recorder = RecordingStore()
    context = context_for(
        environment, workspace / "new.txt", tool="fs.write", args_extra={"content": "hi\n"}
    )
    write_file(context, recorder)  # type: ignore[arg-type]
    assert recorder.calls == []


def test_a_failed_checkpoint_aborts_the_write(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """The caller may only mutate BECAUSE it can undo. No snapshot, no write.

    This is the property `CheckpointError`'s own docstring exists for: "a caller
    that distinguished which failures are safe to ignore would be a caller
    deciding which failures are safe to ignore, and none of them are".
    """
    target = workspace / "existing.txt"
    before = digest_of(workspace)
    context = context_for(
        environment,
        target,
        tool="fs.write",
        args_extra={"content": "AFTER\n", "intent": "overwrite"},
    )
    with pytest.raises(HandlerRefused) as caught:
        write_file(context, RefusingStore())  # type: ignore[arg-type]
    assert caught.value.kind == CHECKPOINT_FAILED
    assert digest_of(workspace) == before


def test_the_closure_and_the_pure_function_do_the_same_thing(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """`make_writer` is what the dispatcher receives, so it must not drift.

    A closure that forgot to pass the store, or reordered the checks, would be
    invisible to every other test in this file.
    """
    handler = make_writer(store)
    target = workspace / "viaclosure.txt"
    context = context_for(
        environment, target, tool="fs.write", args_extra={"content": "hello\n"}
    )
    via_closure = dict(handler(context))
    # Create-only, so the second call must see the same starting state as the
    # first — otherwise it would legitimately refuse with TARGET_EXISTS and the
    # comparison would be measuring the fixture rather than the two code paths.
    target.unlink()
    assert via_closure == dict(write_file(context, store))


# ==========================================================================
# C. fs.patch — all-or-nothing, and what "exact-match anchor" has to mean
# ==========================================================================


def patch_context(
    environment: DispatchEnvironment, target: Path, blocks: list[dict[str, str]]
) -> HandlerContext:
    return context_for(environment, target, tool="fs.patch", args_extra={"blocks": blocks})


def test_one_block_replaces_exactly_its_anchor(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    target = workspace / "code.py"
    target.write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
    context = patch_context(environment, target, [{"search": "b = 2", "replace": "b = 22"}])
    result = patch_file(context, store)
    assert target.read_text(encoding="utf-8") == "a = 1\nb = 22\nc = 3\n"
    assert result["blocks_applied"] == 1


def test_every_block_applies_or_none_do(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    target = workspace / "code.py"
    target.write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
    context = patch_context(
        environment,
        target,
        [{"search": "a = 1", "replace": "a = 11"}, {"search": "c = 3", "replace": "c = 33"}],
    )
    patch_file(context, store)
    assert target.read_text(encoding="utf-8") == "a = 11\nb = 2\nc = 33\n"


def test_one_missing_anchor_leaves_the_whole_tree_identical(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """The plan's expected result, verbatim: "partial patch → tree hash identical".

    Whole-tree digests rather than the target's content: this one assertion also
    catches a temporary file left behind and a sibling touched in passing.
    """
    target = workspace / "code.py"
    target.write_text("a = 1\nb = 2\n", encoding="utf-8")
    before = digest_of(workspace)
    context = patch_context(
        environment,
        target,
        [{"search": "a = 1", "replace": "a = 11"}, {"search": "nowhere", "replace": "x"}],
    )
    with pytest.raises(HandlerRefused) as caught:
        patch_file(context, store)
    assert caught.value.kind == ANCHOR_MISS
    assert digest_of(workspace) == before


def test_an_ambiguous_anchor_is_a_miss_not_a_first_match(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """Two occurrences means the request did not say WHERE.

    A first-occurrence guess edits a place the caller never named, produces a
    plausible file, and nothing downstream can tell it happened. §6.4 says
    "exact-match anchors", and an anchor matching twice matches nothing exactly.
    """
    target = workspace / "code.py"
    target.write_text("x = 0\nx = 0\n", encoding="utf-8")
    before = digest_of(workspace)
    context = patch_context(environment, target, [{"search": "x = 0", "replace": "x = 1"}])
    with pytest.raises(HandlerRefused) as caught:
        patch_file(context, store)
    assert caught.value.kind == ANCHOR_MISS
    assert digest_of(workspace) == before


def test_an_anchor_that_only_matches_after_an_earlier_block_ran_is_still_a_miss(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """Blocks are resolved against the ORIGINAL content, not against each other.

    Otherwise the outcome depends on block order, and "all-or-nothing" would mean
    "all, in the order I happened to list them" — which is not a property a caller
    can reason about, and not one a rollback can either.
    """
    target = workspace / "code.py"
    target.write_text("a = 1\n", encoding="utf-8")
    before = digest_of(workspace)
    context = patch_context(
        environment,
        target,
        [{"search": "a = 1", "replace": "b = 2"}, {"search": "b = 2", "replace": "c = 3"}],
    )
    with pytest.raises(HandlerRefused) as caught:
        patch_file(context, store)
    assert caught.value.kind == ANCHOR_MISS
    assert digest_of(workspace) == before


def test_two_blocks_that_merely_TOUCH_are_both_applied(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """The boundary of the overlap check: `later[0] < earlier[1]`, not `<=`.

    Two adjacent anchors that abut but do not overlap are a legitimate patch, and
    widening the comparison to `<=` would refuse it — a false rejection nothing
    else in this file would catch, because every other overlap case is a strict one.
    """
    target = workspace / "code.py"
    target.write_text("abcdef\n", encoding="utf-8")
    context = patch_context(
        environment,
        target,
        [{"search": "abc", "replace": "X"}, {"search": "def", "replace": "Y"}],
    )
    result = patch_file(context, store)
    assert target.read_text(encoding="utf-8") == "XY\n"
    assert result["blocks_applied"] == 2


def test_two_blocks_that_overlap_are_refused(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """Two anchors covering the same bytes have no defined result.

    Each matches exactly once, so the per-anchor check passes — and then splicing
    them both would either drop one or corrupt the other depending on order. This
    is the one branch of the resolver that the per-anchor counting cannot reach,
    and nothing else in this file exercises it.
    """
    target = workspace / "code.py"
    target.write_text("abcdef\n", encoding="utf-8")
    before = digest_of(workspace)
    context = patch_context(
        environment,
        target,
        [{"search": "abcd", "replace": "X"}, {"search": "cdef", "replace": "Y"}],
    )
    with pytest.raises(HandlerRefused) as caught:
        patch_file(context, store)
    assert caught.value.kind == ANCHOR_MISS
    assert "overlap" in caught.value.detail
    assert digest_of(workspace) == before


def test_patching_a_file_that_is_not_valid_utf8_is_refused(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """An anchor is an EXACT byte match, so undecodable input cannot be anchored.

    `fs.read` deliberately decodes with `errors="replace"` — a reader may show
    approximate text. A patch may not: replacing bytes it could not read exactly
    would silently rewrite the parts it guessed at.
    """
    target = workspace / "binary.py"
    target.write_bytes(b"a = 1\n\xe9\xff\n")
    before = digest_of(workspace)
    context = patch_context(environment, target, [{"search": "a = 1", "replace": "a = 2"}])
    with pytest.raises(HandlerRefused) as caught:
        patch_file(context, store)
    assert caught.value.kind == WRITE_FAILED
    assert digest_of(workspace) == before


@pytest.mark.parametrize("tool", ["fs.write", "fs.patch"])
def test_a_directory_where_a_file_belongs_is_refused(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore, tool: str
) -> None:
    """Not a symlink and not absent — a third kind, and it must not be published over.

    `rename` onto a non-empty directory fails with ENOTEMPTY, which would arrive as
    an opaque publish failure after a checkpoint had already been taken. Refusing on
    the KIND keeps the diagnosis where the caller can act on it.
    """
    target = workspace / "adir"
    target.mkdir()
    (target / "inside.txt").write_text("keep\n", encoding="utf-8")
    before = digest_of(workspace)
    extra: dict[str, Any] = (
        {"content": "x\n", "intent": "overwrite"}
        if tool == "fs.write"
        else {"blocks": [{"search": "a", "replace": "b"}]}
    )
    context = context_for(environment, target, tool=tool, args_extra=extra)
    with pytest.raises(HandlerRefused) as caught:
        if tool == "fs.write":
            write_file(context, store)
        else:
            patch_file(context, store)
    assert caught.value.kind == WRITE_FAILED
    assert "not a regular file" in caught.value.detail
    assert digest_of(workspace) == before


def test_a_temporary_file_that_cannot_be_created_is_a_typed_error(
    environment: DispatchEnvironment,
    workspace: Path,
    store: CheckpointStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The publish's first step, and the one a read-only directory fails at.

    Provoked through `os.open` rather than by chmod-ing the workspace, because the
    checkpoint store writes elsewhere and must still succeed — the property under
    test is that the TARGET's directory being unwritable is a typed refusal, not an
    untyped OSError out of `create()`.
    """
    from lsassist.tools.handlers import fs_write as module

    real = module.os.open

    def refuse(path: Any, flags: int, mode: int = 0o777, **kw: Any) -> int:
        if isinstance(path, str) and ".lsassist-tmp-" in path:
            raise OSError(13, "Permission denied", path)
        return real(path, flags, mode, **kw)  # type: ignore[no-any-return]

    monkeypatch.setattr(module.os, "open", refuse)
    target = workspace / "existing.txt"
    before = digest_of(workspace)
    context = context_for(
        environment,
        target,
        tool="fs.write",
        args_extra={"content": "AFTER\n", "intent": "overwrite"},
    )
    with pytest.raises(HandlerRefused) as caught:
        write_file(context, store)
    assert caught.value.kind == WRITE_FAILED
    assert digest_of(workspace) == before


def test_a_patch_checkpoints_with_the_pre_patch_trigger(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§14.4 names four triggers and no fifth; a patch is not a write."""
    recorder = RecordingStore()
    target = workspace / "code.py"
    target.write_text("a = 1\n", encoding="utf-8")
    context = patch_context(environment, target, [{"search": "a = 1", "replace": "a = 2"}])
    patch_file(context, recorder)  # type: ignore[arg-type]
    assert [call[2] for call in recorder.calls] == [TriggerKind.PRE_PATCH]
    assert recorder.observed == [b"a = 1\n"]


def test_a_failed_checkpoint_aborts_the_patch(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    target = workspace / "code.py"
    target.write_text("a = 1\n", encoding="utf-8")
    before = digest_of(workspace)
    context = patch_context(environment, target, [{"search": "a = 1", "replace": "a = 2"}])
    with pytest.raises(HandlerRefused) as caught:
        patch_file(context, RefusingStore())  # type: ignore[arg-type]
    assert caught.value.kind == CHECKPOINT_FAILED
    assert digest_of(workspace) == before


def test_patching_a_path_a_symlink_was_swapped_into_is_refused(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    """Same TOCTOU as `fs.write`'s: the canonical path is not a link at approval.

    A patch reads before it writes, so following a swapped-in link would leak the
    victim's bytes into the anchor matching as well as write to it.
    """
    target = workspace / "code.py"
    target.write_text("a = 1\n", encoding="utf-8")
    context = patch_context(environment, target, [{"search": "a = 1", "replace": "a = 2"}])
    victim = workspace / "victim.py"
    victim.write_text("a = 1\n", encoding="utf-8")
    target.unlink()
    target.symlink_to(victim)
    before = digest_of(workspace)

    with pytest.raises(HandlerRefused) as caught:
        patch_file(context, store)
    assert caught.value.kind == WRITE_FAILED
    assert "symlink" in caught.value.detail
    assert digest_of(workspace) == before


def test_patching_a_missing_file_never_reaches_the_handler(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """`fs.patch` gets NO `create_if_missing` carve-out, and that is the point.

    A patch anchors in bytes that already exist, so §6.3 step 2 refusing a missing
    path is the correct and earlier defence — creating the file is `fs.write`'s
    job. Asserted against `dispatch` rather than the handler, because a handler
    check would be dead code behind a dispatcher that already refuses.
    """
    request = ToolRequest(
        call_id="c1",
        tool="fs.patch",
        args={
            "path": str(workspace / "absent.py"),
            "blocks": [{"search": "a", "replace": "b"}],
        },
    )
    with pytest.raises(Exception) as caught:
        dispatch(
            request,
            manifest=manifest_for("fs.patch"),
            environment=environment,
            path_args=["path"],
        )
    assert "canonicalize" in str(caught.value)


def test_the_patch_closure_and_the_pure_function_do_the_same_thing(
    environment: DispatchEnvironment, workspace: Path, store: CheckpointStore
) -> None:
    target = workspace / "code.py"
    target.write_text("a = 1\n", encoding="utf-8")
    handler = make_patcher(store)
    context = patch_context(environment, target, [{"search": "a = 1", "replace": "a = 2"}])
    first = dict(handler(context))
    target.write_text("a = 1\n", encoding="utf-8")
    assert first == dict(patch_file(context, store))


# ==========================================================================
# D. git.worktree — a fixed argv table and one path constraint
# ==========================================================================


def test_the_worktree_argv_is_the_only_form_6_4_allows() -> None:
    """§6.4: "`git worktree add <path> -b <branch>` only".

    Asserted as an exact argv tuple, not a membership test: a subcommand that
    slipped in (`remove`, `prune`, `--force`) would pass "contains worktree add".

    Two details are inherited from `git.read` rather than invented here, because a
    second convention for the same binary is a second thing to review: argv[0] is
    the PINNED absolute path (an early writable `PATH` entry is a shim, and a
    shimmed git writes wherever it likes), and `-C <workspace>` states the
    repository in the argv itself instead of relying on the sandbox's `--chdir`.
    """
    argv = worktree_argv(
        {"path": "/ws/.lsassist/worktrees/feat", "branch": "feat"}, workspace_root="/ws"
    )
    assert argv == (
        GIT,
        "-C",
        "/ws",
        "worktree",
        "add",
        "-b",
        "feat",
        "--",
        "/ws/.lsassist/worktrees/feat",
    )
    assert isinstance(argv, tuple)


def test_the_worktree_binary_is_pinned_not_resolved_through_PATH() -> None:
    """The same argument `sandbox/availability.py` measured, applied to this tool."""
    assert GIT == "/usr/bin/git"
    argv = worktree_argv(
        {"path": "/ws/.lsassist/worktrees/f", "branch": "f"}, workspace_root="/ws"
    )
    assert argv[0].startswith("/"), argv


@pytest.mark.parametrize(
    "branch",
    ["-b", "--force", "-", "a b", "a..b", "a\nb", "", "refs/heads/x", "a~1", "a^", "a:b"],
)
def test_a_branch_name_git_would_reinterpret_is_refused(branch: str) -> None:
    """A leading `-` is an option, and the rest are names `git check-ref-format` rejects.

    The `--` separator protects the PATH argument; `-b <branch>` sits before it,
    so the branch has to be validated by pattern rather than by placement.
    """
    with pytest.raises(HandlerRefused):
        worktree_argv(
            {"path": "/ws/.lsassist/worktrees/x", "branch": branch}, workspace_root="/ws"
        )


@pytest.mark.parametrize("path", [None, 42, "", "relative/feat"])
def test_a_worktree_path_that_is_not_an_absolute_string_is_refused(path: Any) -> None:
    """§6.3 step 2 hands over an absolute canonical path, so anything else is a bug.

    Refused rather than coerced: a handler that repaired a relative path would be
    resolving it against a cwd the dispatcher never validated.
    """
    with pytest.raises(HandlerRefused):
        worktree_argv({"path": path, "branch": "feat"}, workspace_root="/ws")


@pytest.mark.parametrize("root", ["", "relative/ws"])
def test_a_worktree_without_an_absolute_workspace_root_is_refused(root: str) -> None:
    """Containment is meaningless against a root that is not itself absolute."""
    with pytest.raises(HandlerRefused) as caught:
        worktree_argv(
            {"path": "/ws/.lsassist/worktrees/f", "branch": "f"}, workspace_root=root
        )
    assert caught.value.kind == WORKSPACE_SCOPE


@pytest.mark.parametrize(
    "relative",
    ["other/feat", "../escape", ".lsassist/feat", ".lsassist/worktrees/../../escape"],
)
def test_a_worktree_path_outside_lsassist_worktrees_is_refused(relative: str) -> None:
    """§6.4: "path inside workspace `.lsassist/worktrees/`" — the whole constraint."""
    with pytest.raises(HandlerRefused) as caught:
        worktree_argv({"path": f"/ws/{relative}", "branch": "feat"}, workspace_root="/ws")
    assert caught.value.kind == WORKSPACE_SCOPE


def test_the_reserved_directory_itself_is_not_a_worktree_path() -> None:
    """`len(segments) <= len(reserved)`, not `<`. §6.4 says INSIDE the directory.

    A path equal to `.lsassist/worktrees` would make git try to create the shared
    parent as a worktree, clobbering every sibling worktree's home. The `<` mutant
    admits exactly that case and no other test reaches the boundary.
    """
    with pytest.raises(HandlerRefused) as caught:
        worktree_argv(
            {"path": f"/ws/{WORKTREE_DIR}", "branch": "feat"}, workspace_root="/ws"
        )
    assert caught.value.kind == WORKSPACE_SCOPE


def test_a_worktree_path_in_another_workspace_is_refused() -> None:
    """Containment is checked on SEGMENTS, so `/ws-evil` is not inside `/ws`.

    The same trap `git.read`'s own path check names: a prefix comparison on the
    raw string admits any sibling directory whose name starts with the root's.
    """
    with pytest.raises(HandlerRefused) as caught:
        worktree_argv(
            {"path": "/ws-evil/.lsassist/worktrees/feat", "branch": "feat"},
            workspace_root="/ws",
        )
    assert caught.value.kind == WORKSPACE_SCOPE


def test_the_reserved_worktree_directory_is_the_6_4_one() -> None:
    """§6.4 names the directory, so it is a constant here rather than a literal."""
    assert WORKTREE_DIR == ".lsassist/worktrees"


def test_the_worktree_result_reports_what_git_actually_did() -> None:
    """§6.5: the result is assembled from the OBSERVATION, never from the request.

    The observed branch is deliberately DIFFERENT from any name used elsewhere in
    this file. An earlier version used "feat" on both sides, so a handler that
    echoed the request back passed — the same tautology shape T4.04 was burned by,
    where the assertion matched a value the test itself had supplied twice.
    """
    # MEASURED on git 2.55.0: `git worktree add` writes the confirmation to
    # STDERR and puts only "HEAD is now at <sha> <subject>" on stdout. An earlier
    # version of this test invented a stdout string, so a handler reading stdout
    # alone passed here while reporting created=false for every real success.
    observation = type(
        "Obs",
        (),
        {
            "stdout": "HEAD is now at c5b721f init\n",
            "stderr": "Preparing worktree (new branch 'observed-only')\n",
            "exit_code": 0,
        },
    )()
    result = worktree_result(observation)
    assert result["branch"] == "observed-only"
    assert result["created"] is True


def test_a_worktree_git_did_not_create_is_not_reported_as_created() -> None:
    """No "new branch" line, or a non-zero exit, means it did not happen."""
    for stderr, code in (("", 0), ("Preparing worktree (new branch 'x')\n", 1)):
        observation = type("Obs", (), {"stdout": "", "stderr": stderr, "exit_code": code})()
        assert worktree_result(observation)["created"] is False


# ==========================================================================
# E. The manifests must be the §6.4 table, not a paraphrase of it
# ==========================================================================


@pytest.mark.parametrize(
    ("tool", "proc", "timeout", "result_chars"),
    [
        ("fs.write", "none", 30, 10000),
        ("fs.patch", "none", 30, 10000),
        ("git.worktree", "spawn_argv", 60, 20000),
    ],
)
def test_each_write_manifest_matches_the_6_4_row(
    tool: str, proc: str, timeout: int, result_chars: int
) -> None:
    manifest = manifest_for(tool)
    assert manifest.permission_class.value == "AUTO_SCOPED_WRITE"
    assert manifest.capabilities.fs.value == "write_scoped"
    assert manifest.capabilities.net.value == "none"
    assert manifest.capabilities.proc.value == proc
    assert manifest.timeout_s == timeout
    assert manifest.output_limits.max_result_chars == result_chars
    assert manifest.path_scope.value == "workspace"


def test_the_two_in_process_write_tools_are_the_first_proc_none_writers() -> None:
    """The routing decision T3.04 left open, pinned so it cannot drift silently.

    `dispatcher.run()` takes the in-process branch on `proc is NONE **and** a
    handler was supplied`. These two manifests are what make that branch fire for
    a MUTATING tool, which is a design decision and not an implementation detail.
    """
    assert manifest_for("fs.write").capabilities.proc.value == "none"
    assert manifest_for("fs.patch").capabilities.proc.value == "none"
    assert manifest_for("git.worktree").capabilities.proc.value == "spawn_argv"


def test_the_write_tools_declare_a_rollback_and_are_not_idempotent() -> None:
    """§6.2's `rollback` and `idempotent` fields are what a resume has to read.

    A write claiming `idempotent: true` would let §4.7's replay re-run it, and a
    write claiming `rollback: none` tells a recovery flow it cannot be undone —
    both false for a checkpointed write, and neither is caught by any other test.
    """
    for tool in ("fs.write", "fs.patch"):
        manifest = manifest_for(tool)
        assert manifest.idempotent is False, tool
        assert manifest.rollback.value == "checkpoint", tool
