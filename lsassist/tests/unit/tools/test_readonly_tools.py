"""T3.04 — the §6.4 read-only tool batch, and the in-process route it needs.

**WHAT THESE TESTS ARE FOR.** The dispatcher's own suite proves the §6.3 pipeline;
these prove the two things only a HANDLER can prove, and one thing only the
dispatcher's new branch can.

1. **The §7.5 step-6 pin for READERS.** Both ``policy/recheck.py`` and
   ``tools/dispatcher.py`` carry a cross-phase flag naming T3.04 as the owner of
   a real gap: step 6 is scoped to write tools (SPEC:564), so a same-path file
   swap in the window between the step-3 re-canonicalization and the ``open`` has
   no backstop for a read. These tests take the approval snapshot, THEN swap the
   file, THEN call the handler — the only ordering that can distinguish a handler
   which pins the inode from one that merely re-resolves the name. A handler that
   re-``stat``s the path instead of ``fstat``ing its own fd passes every other
   test in this file and fails these.
2. **§19 scenario 1.** A read ATTEMPT on a honeyfile is the signal. The assertions
   check not only that the call is refused but that no byte of the decoy appears
   anywhere in what comes back — a refusal that leaked the content in its message
   would defeat the thing it was protecting.
3. **The in-process route.** ``fs.read``/``fs.list``/``fs.find`` declare
   ``capabilities.proc = none`` (§6.4), so they must run without a sandbox spawn
   while still reaching the SAME §6.3 step 8-9 code — one result validation, one
   cap, one journal entry. Two pipelines would be two places to forget an audit
   record.
"""

from __future__ import annotations

import json
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
from lsassist.policy.recheck import OsFsView, snapshot_paths
from lsassist.policy.stores import PolicyStores
from lsassist.tools.dispatcher import (
    HANDLER_FAILED,
    HANDLER_UNAVAILABLE,
    Decision,
    DispatchEnvironment,
    dispatch,
    run,
)
from lsassist.tools.handlers import (
    CANARY_TRIPPED,
    DENY_PATH,
    READ_FAILED,
    TARGET_REPLACED,
    TIMED_OUT,
    WORKSPACE_SCOPE,
    HandlerContext,
    HandlerRefused,
)
from lsassist.tools.handlers import git_read as git_read_module
from lsassist.tools.handlers.fs_find import find_files
from lsassist.tools.handlers.fs_list import list_dir
from lsassist.tools.handlers.fs_read import HEX_HEAD_BYTES, read_file
from lsassist.tools.handlers.git_read import build_argv as git_read_argv
from lsassist.tools.handlers.git_read import result_of as git_read_result
from lsassist.tools.handlers.pkg_query import build_argv as pkg_query_argv
from lsassist.tools.handlers.pkg_query import result_of as pkg_query_result
from lsassist.tools.handlers.sys_info import build_argv as sys_info_argv
from lsassist.tools.handlers.sys_info import result_of as sys_info_result
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
    ws = Path.home() / ".cache" / "lsassist" / "t304-tests" / uuid.uuid4().hex / "ws"
    ws.mkdir(parents=True)
    (ws / "a.txt").write_text("hello\n", encoding="utf-8")
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


def journal_records(audit_dir: Path) -> list[dict[str, Any]]:
    """Every record actually on disk, so "journalled" is read back, not assumed.

    ``audit_seq`` is 0-based, so asserting on the returned number proves nothing:
    a run that wrote no record at all and one that wrote the first record both
    report 0. The only honest check is to open the journal.
    """
    records: list[dict[str, Any]] = []
    for path in sorted(audit_dir.glob("session-*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
    return records


def manifest_for(tool: str) -> ToolManifest:
    """The REAL shipped manifest — never a hand-built stub.

    A test that invents its own manifest cannot catch a manifest whose caps,
    class or capabilities drifted from the §6.4 table.
    """
    return REGISTRY[tool]


def context_for(
    environment: DispatchEnvironment,
    target: Path,
    *,
    tool: str = "fs.read",
    canary_paths: frozenset[str] = frozenset(),
    stale_snapshots: tuple[Any, ...] | None = None,
    args_extra: dict[str, Any] | None = None,
) -> HandlerContext:
    """A handler context carrying a REAL normalized request from `dispatch`.

    ``args_extra`` goes through the SAME dispatch call, so a mode or pattern that
    the manifest's ``input_schema`` would reject never reaches a handler in a
    test either.
    """
    manifest = manifest_for(tool)
    args: dict[str, Any] = {"path": str(target)}
    args.update(args_extra or {})
    request = ToolRequest(call_id="c1", tool=tool, args=args)
    decision = dispatch(
        request, manifest=manifest, environment=environment, path_args=["path"]
    )
    assert decision.decision is Decision.PROCEED, decision
    normalized = decision.normalized
    assert normalized is not None
    if stale_snapshots is not None:
        object.__setattr__(normalized, "path_snapshots", stale_snapshots)
    return HandlerContext(
        normalized=normalized,
        manifest=manifest,
        environment=environment,
        canary_paths=canary_paths,
    )



def find(
    environment: DispatchEnvironment,
    root: Path,
    *,
    mode: str,
    pattern: str,
    max_results: int | None = None,
    canary_paths: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Run `fs.find` end to end from a REAL dispatch of the whole arg set."""
    extra: dict[str, Any] = {"mode": mode, "pattern": pattern}
    if max_results is not None:
        extra["max_results"] = max_results
    context = context_for(
        environment, root, tool="fs.find", args_extra=extra, canary_paths=canary_paths
    )
    return find_files(context)


# ==========================================================================
# A. fs.read — §6.4 rendering
# ==========================================================================


def test_a_text_file_is_returned_as_utf8(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    payload = read_file(context_for(environment, workspace / "a.txt"))
    assert payload == {
        "content": "hello\n",
        "encoding": "utf-8",
        "bytes_read": 6,
        "truncated": False,
    }


def test_undecodable_bytes_are_replaced_not_rejected(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§6.4 says errors=replace, so a lone bad byte must not fail the read."""
    target = workspace / "latin.txt"
    target.write_bytes(b"caf\xe9 time\n")
    payload = read_file(context_for(environment, target))
    assert payload["encoding"] == "utf-8"
    assert "�" in payload["content"]
    assert "time" in payload["content"]


def test_a_nul_byte_makes_it_binary_and_it_comes_back_as_hex(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    target = workspace / "b.bin"
    target.write_bytes(b"\x00\x01\x02ok")
    payload = read_file(context_for(environment, target))
    assert payload["encoding"] == "hex"
    assert payload["content"] == "0001026f6b"


def test_the_hex_head_is_capped_at_4_kb_of_FILE_bytes(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§6.4: "binary -> hex head 4 KB" — of the file, so twice that in chars."""
    target = workspace / "big.bin"
    target.write_bytes(b"\x00" + b"\xff" * 20000)
    payload = read_file(context_for(environment, target))
    assert payload["encoding"] == "hex"
    assert len(payload["content"]) == HEX_HEAD_BYTES * 2


def test_a_file_over_the_result_cap_is_truncated_and_says_so(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    limit = manifest_for("fs.read").output_limits.max_result_chars
    target = workspace / "long.txt"
    target.write_bytes(b"x" * (limit + 500))
    payload = read_file(context_for(environment, target))
    assert payload["truncated"] is True
    assert payload["bytes_read"] == limit


def test_a_file_exactly_at_the_cap_is_not_reported_as_truncated(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """Off-by-one guard: `== limit` is complete, `limit + 1` is not."""
    limit = manifest_for("fs.read").output_limits.max_result_chars
    target = workspace / "exact.txt"
    target.write_bytes(b"x" * limit)
    payload = read_file(context_for(environment, target))
    assert payload["truncated"] is False
    assert payload["bytes_read"] == limit


def test_a_large_file_is_read_whole_not_one_syscall_worth(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """A single `os.read` may return short; trusting it publishes a PREFIX.

    The failure mode this guards is silent: a short read reports
    ``truncated=False`` and the caller believes it has the whole file.
    """
    target = workspace / "chunky.txt"
    body = b"".join(b"%08d\n" % n for n in range(20000))
    target.write_bytes(body)
    payload = read_file(context_for(environment, target))
    assert payload["truncated"] is False
    assert payload["bytes_read"] == len(body)
    assert payload["content"].endswith("00019999\n")


# ==========================================================================
# B. §7.5 step 6 — the inode pin. THE reason this handler is not a one-liner.
# ==========================================================================


def test_a_same_path_swap_after_approval_is_refused(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """Snapshot, THEN swap, THEN read — the ordering that catches a name-truster.

    A handler that re-resolves the path instead of `fstat`ing its own fd returns
    the attacker's content here with no error at all.
    """
    target = workspace / "a.txt"
    context = context_for(environment, target)
    target.unlink()
    target.write_text("ATTACKER\n", encoding="utf-8")

    with pytest.raises(HandlerRefused) as excinfo:
        read_file(context)
    assert excinfo.value.kind == TARGET_REPLACED
    assert "ATTACKER" not in str(excinfo.value)


def test_a_swapped_PARENT_directory_is_refused(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """The name resolves through a different directory than approval measured."""
    sub = workspace / "sub"
    sub.mkdir()
    target = sub / "f.txt"
    target.write_text("original\n", encoding="utf-8")
    context = context_for(environment, target)

    shutil.rmtree(sub)
    sub.mkdir()
    (sub / "f.txt").write_text("ATTACKER\n", encoding="utf-8")

    with pytest.raises(HandlerRefused) as excinfo:
        read_file(context)
    assert excinfo.value.kind == TARGET_REPLACED


def test_the_pinned_read_never_reopens_the_file_by_name() -> None:
    """STRUCTURAL, because no behavioural test can reach this window.

    The swap that would expose a re-open has to land between the `fstat` and the
    `read`, which no test can schedule deterministically — so a handler that
    verifies one fd and then re-opens the path to read it passes every other test
    in this file while having reopened the exact TOCTOU window the pin closed.
    (Measured: this was true of a real intermediate version of this module.)

    Asserted on the AST rather than by grepping: a substring search for
    `read_capped(` matches its own definition and comments, and would still pass
    with zero call sites. Counting `os.open` calls pins the shape — parent dir,
    then file, and nothing else.
    """
    import ast

    from lsassist.tools.handlers import fs_read as module

    source = Path(str(module.__file__)).read_text(encoding="utf-8")
    tree_ = ast.parse(source)
    read_fn = next(
        node
        for node in ast.walk(tree_)
        if isinstance(node, ast.FunctionDef) and node.name == "read_file"
    )
    called = {
        node.func.id
        for node in ast.walk(read_fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    opens = [
        node
        for node in ast.walk(read_fn)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "open"
    ]
    assert "read_fd" in called, "the pinned read must read from the fd it verified"
    assert "read_capped" not in called, "read_capped re-opens by NAME; that is the window"
    assert len(opens) == 2, f"expected exactly parent+file opens, got {len(opens)}"


def test_a_missing_approval_snapshot_fails_closed(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """No baseline is not "skip the check" — the pin is the only backstop."""
    context = context_for(environment, workspace / "a.txt", stale_snapshots=())
    with pytest.raises(HandlerRefused) as excinfo:
        read_file(context)
    assert excinfo.value.kind == TARGET_REPLACED


def test_a_symlink_final_component_is_refused(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """`O_NOFOLLOW` on the final component, verified against a real symlink."""
    victim = workspace / "secret.txt"
    victim.write_text("classified\n", encoding="utf-8")
    link = workspace / "link.txt"
    link.write_text("decoy\n", encoding="utf-8")
    context = context_for(environment, link)
    link.unlink()
    link.symlink_to(victim)

    with pytest.raises(HandlerRefused) as excinfo:
        read_file(context)
    assert excinfo.value.kind in {READ_FAILED, TARGET_REPLACED}
    assert "classified" not in str(excinfo.value)


def test_a_directory_is_not_a_readable_subject(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    sub = workspace / "sub"
    sub.mkdir()
    with pytest.raises(HandlerRefused) as excinfo:
        read_file(context_for(environment, sub))
    assert excinfo.value.kind in {READ_FAILED, TARGET_REPLACED}


# ==========================================================================
# C. §19 scenario 1 — the canary is a tripwire, not a file
# ==========================================================================


def test_reading_a_canary_honeyfile_is_refused(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    decoy = workspace / "id_rsa"
    decoy.write_text(CANARY_BODY, encoding="utf-8")
    context = context_for(environment, decoy, canary_paths=frozenset({str(decoy)}))

    with pytest.raises(HandlerRefused) as excinfo:
        read_file(context)
    assert excinfo.value.kind == CANARY_TRIPPED


def test_a_tripped_canary_leaks_no_byte_of_the_decoy(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """The whole value of a honeyfile is that reaching it returns nothing."""
    decoy = workspace / "id_rsa"
    decoy.write_text(CANARY_BODY, encoding="utf-8")
    context = context_for(environment, decoy, canary_paths=frozenset({str(decoy)}))

    with pytest.raises(HandlerRefused) as excinfo:
        read_file(context)
    rendered = f"{excinfo.value!r} {excinfo.value.detail}"
    assert CANARY_BODY not in rendered
    assert "DECOY" not in rendered


def test_the_canary_is_checked_before_the_file_is_even_opened(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§19 makes the ATTEMPT the signal, so a honeyfile must not be touched.

    Registered as a canary but absent from disk: a handler that opened first
    would raise READ_FAILED and the tripwire would never fire.
    """
    decoy = workspace / "id_rsa"
    decoy.write_text(CANARY_BODY, encoding="utf-8")
    context = context_for(environment, decoy, canary_paths=frozenset({str(decoy)}))
    decoy.unlink()

    with pytest.raises(HandlerRefused) as excinfo:
        read_file(context)
    assert excinfo.value.kind == CANARY_TRIPPED


# ==========================================================================
# D. §7.3 — the handler-side double-check
# ==========================================================================


def test_a_deny_listed_path_is_refused_by_the_handler_itself(
    environment: DispatchEnvironment, tmp_path: Path
) -> None:
    """§7.5's chain is only as strong as its last link.

    The dispatcher already refuses these at step 3; the handler re-asks because
    it is the last code that runs before bytes leave the machine.
    """
    home = Path(environment.stores.home)
    ssh = home / ".ssh"
    ssh.mkdir(parents=True, exist_ok=True)
    key = ssh / "id_rsa"
    key.write_text("PRIVATE KEY MATERIAL\n", encoding="utf-8")

    snapshots = snapshot_paths((str(key),), OsFsView())
    normalized = _bare_normalized(str(key), snapshots)
    context = HandlerContext(
        normalized=normalized,
        manifest=manifest_for("fs.read"),
        environment=environment,
    )
    with pytest.raises(HandlerRefused) as excinfo:
        read_file(context)
    assert excinfo.value.kind == DENY_PATH
    assert "PRIVATE KEY MATERIAL" not in str(excinfo.value)


def _bare_normalized(target: str, snapshots: tuple[Any, ...]) -> Any:
    """A normalized request the DISPATCHER would never issue.

    §7.3 paths are refused at step 3, so the only way to reach the handler with
    one is to hand it a request the pipeline would have stopped — which is
    exactly the scenario the double-check exists for.
    """
    from lsassist.tools.dispatcher import NormalizedRequest

    parent = os.path.dirname(target)
    return NormalizedRequest(
        tool="fs.read",
        args={"path": target},
        canonical_paths=(target,),
        workspace_root=parent,
        cwd_real=parent,
        env={},
        env_digest="sha256:" + "0" * 64,
        action_hash="sha256:" + "0" * 64,
        path_snapshots=snapshots,
    )


def test_exactly_one_approved_path_is_required(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    context = context_for(environment, workspace / "a.txt")
    object.__setattr__(context.normalized, "canonical_paths", ())
    with pytest.raises(HandlerRefused) as excinfo:
        read_file(context)
    assert excinfo.value.kind == READ_FAILED


# ==========================================================================
# E. The in-process route inside dispatcher.run()
# ==========================================================================


def test_a_proc_none_tool_runs_without_spawning_anything(
    environment: DispatchEnvironment,
    workspace: Path,
    journal: AuditWriter,
    audit_dir: Path,
    tmp_path: Path,
) -> None:
    """`fs.read` declares `proc: none` (§6.4): no child, and no sandbox probe."""
    manifest = manifest_for("fs.read")
    request = ToolRequest(
        call_id="c1", tool="fs.read", args={"path": str(workspace / "a.txt")}
    )
    decision = dispatch(
        request, manifest=manifest, environment=environment, path_args=["path"]
    )
    assert decision.decision is Decision.PROCEED

    def exploding_probe() -> Any:
        raise AssertionError("a proc:none tool must not probe the sandbox")

    def exploding_runner(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a proc:none tool must not spawn")

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=str(tmp_path / "cache"),
        task_id="t-1",
        argv=(),
        audit=journal,
        probe_fn=exploding_probe,
        runner=exploding_runner,
        handler=read_file,
    )
    assert outcome.decision is Decision.PROCEED
    assert outcome.result.result["content"] == "hello\n"
    journal.close()
    records = journal_records(audit_dir)
    assert [r["event"] for r in records] == ["tool_result"]
    assert records[0]["payload"]["tool"] == "fs.read"


def test_a_refusing_handler_is_BLOCKED_and_still_journalled(
    environment: DispatchEnvironment,
    workspace: Path,
    journal: AuditWriter,
    audit_dir: Path,
    tmp_path: Path,
) -> None:
    """A refusal is an event. Losing its record would lose the canary alert."""
    manifest = manifest_for("fs.read")
    decoy = workspace / "id_rsa"
    decoy.write_text(CANARY_BODY, encoding="utf-8")
    request = ToolRequest(call_id="c1", tool="fs.read", args={"path": str(decoy)})
    decision = dispatch(
        request, manifest=manifest, environment=environment, path_args=["path"]
    )
    assert decision.decision is Decision.PROCEED

    def tripwire(context: HandlerContext) -> dict[str, Any]:
        raise HandlerRefused(CANARY_TRIPPED, "read attempt on canary honeyfile")

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=str(tmp_path / "cache"),
        task_id="t-1",
        argv=(),
        audit=journal,
        handler=tripwire,
    )
    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == CANARY_TRIPPED
    assert outcome.result.result == {}
    # THE alert. §19 asks for an audit record on a canary read, and a refusal
    # that never reached the journal would be a tripwire nobody hears.
    journal.close()
    records = journal_records(audit_dir)
    assert [r["event"] for r in records] == ["tool_result"]
    assert records[0]["payload"]["status"] == "error"
    assert CANARY_BODY not in json.dumps(records[0])


def test_a_proc_none_tool_without_a_handler_is_BLOCKED(
    environment: DispatchEnvironment,
    workspace: Path,
    journal: AuditWriter,
    audit_dir: Path,
    tmp_path: Path,
) -> None:
    """Fail closed: no handler is not "fall back to spawning something"."""
    manifest = manifest_for("fs.read")
    request = ToolRequest(
        call_id="c1", tool="fs.read", args={"path": str(workspace / "a.txt")}
    )
    decision = dispatch(
        request, manifest=manifest, environment=environment, path_args=["path"]
    )
    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=str(tmp_path / "cache"),
        task_id="t-1",
        argv=(),
        audit=journal,
        handler=None,
    )
    assert outcome.decision is Decision.BLOCKED
    journal.close()
    assert [r["event"] for r in journal_records(audit_dir)] == ["tool_result"]


def test_a_spawning_tool_ignores_the_handler_and_takes_the_sandbox_route(
    environment: DispatchEnvironment,
    workspace: Path,
    journal: AuditWriter,
    audit_dir: Path,
    tmp_path: Path,
) -> None:
    """The branch must key on the MANIFEST, not on whether a handler was passed.

    Keying on "a handler was supplied" would let any caller turn a `spawn_argv`
    tool into an unsandboxed in-process call by passing one.
    """
    manifest = manifest_for("sys.info")
    request = ToolRequest(call_id="c1", tool="sys.info", args={"query": "uname"})
    decision = dispatch(request, manifest=manifest, environment=environment)
    assert decision.decision is Decision.PROCEED

    seen: list[str] = []

    def spy_handler(context: HandlerContext) -> dict[str, Any]:
        seen.append("handler")
        return {"stdout": "", "exit_code": 0}

    def refusing_probe() -> Any:
        seen.append("probe")
        raise AssertionError("stop here: the sandbox route was taken")

    with pytest.raises(AssertionError, match="the sandbox route was taken"):
        run(
            decision,
            manifest=manifest,
            environment=environment,
            cache_dir=str(tmp_path / "cache"),
            task_id="t-1",
            argv=("/usr/bin/uname", "-a"),
            audit=journal,
            probe_fn=refusing_probe,
            handler=spy_handler,
        )
    assert seen == ["probe"]


def test_the_in_process_route_refuses_a_non_empty_argv(
    environment: DispatchEnvironment,
    workspace: Path,
    journal: AuditWriter,
    audit_dir: Path,
    tmp_path: Path,
) -> None:
    """An argv nobody runs would be a lie in the journal's env/action binding."""
    manifest = manifest_for("fs.read")
    request = ToolRequest(
        call_id="c1", tool="fs.read", args={"path": str(workspace / "a.txt")}
    )
    decision = dispatch(
        request, manifest=manifest, environment=environment, path_args=["path"]
    )
    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=str(tmp_path / "cache"),
        task_id="t-1",
        argv=("/bin/cat", "a.txt"),
        audit=journal,
        handler=read_file,
    )
    assert outcome.decision is Decision.BLOCKED


# ==========================================================================
# F. The shipped manifests ARE the §6.4 table
# ==========================================================================


@pytest.mark.parametrize(
    ("tool", "fs_cap", "proc_cap", "timeout_s", "result_cap"),
    [
        ("fs.read", "read_scoped", "none", 10, 200000),
        ("fs.list", "read_scoped", "none", 10, 50000),
        ("fs.find", "read_scoped", "none", 30, 200000),
        ("sys.info", "none", "spawn_argv", 10, 50000),
        ("pkg.query", "none", "spawn_argv", 20, 100000),
        ("git.read", "read_scoped", "spawn_argv", 20, 200000),
    ],
)
def test_manifest_matches_the_6_4_catalog_row(
    tool: str, fs_cap: str, proc_cap: str, timeout_s: int, result_cap: int
) -> None:
    manifest = manifest_for(tool)
    assert manifest.permission_class.value == "AUTO_READ"
    assert manifest.capabilities.fs.value == fs_cap
    assert manifest.capabilities.net.value == "none"
    assert manifest.capabilities.proc.value == proc_cap
    assert manifest.timeout_s == timeout_s
    assert manifest.output_limits.max_result_chars == result_cap


def test_the_batch_is_exactly_the_six_read_only_tools() -> None:
    """A seventh tool appearing here is a catalog change, not an accident."""
    assert set(REGISTRY.names) == {
        "fs.read",
        "fs.list",
        "fs.find",
        "sys.info",
        "pkg.query",
        "git.read",
    }


def test_every_input_schema_forbids_additional_properties() -> None:
    """The dispatcher REFUSES a manifest without it (step 1), so pin it here."""
    for name in REGISTRY.names:
        schema = REGISTRY[name].input_schema
        assert schema.get("additionalProperties") is False, name
        assert schema.get("type") == "object", name


def test_no_read_only_tool_can_write_or_reach_the_network() -> None:
    for name in REGISTRY.names:
        capabilities = REGISTRY[name].capabilities
        assert capabilities.fs.value != "write_scoped", name
        assert capabilities.net.value == "none", name


def test_the_manifest_directory_is_packaged() -> None:
    """`manifests/` has no `__init__.py`, so a bare `*.json` glob misses it."""
    assert os.path.isdir(REGISTRY.source)
    assert REGISTRY.source.name == "manifests"


# ==========================================================================
# G. fs.list — sorted, depth-bounded, and unable to walk out of the root
# ==========================================================================


def tree(root: Path) -> None:
    """A small fixed tree: two levels, mixed types, deliberately unsorted names."""
    (root / "zeta.txt").write_text("z\n", encoding="utf-8")
    (root / "alpha.txt").write_text("a\n", encoding="utf-8")
    (root / "mid").mkdir()
    (root / "mid" / "inner.txt").write_text("i\n", encoding="utf-8")
    (root / "mid" / "deeper").mkdir()
    (root / "mid" / "deeper" / "bottom.txt").write_text("b\n", encoding="utf-8")


def listed(payload: dict[str, Any]) -> list[str]:
    return [entry["path"] for entry in payload["entries"]]


def test_entries_come_back_sorted(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§6.4 says "sorted". Sorted output is what makes two runs comparable."""
    root = workspace / "t"
    root.mkdir()
    tree(root)
    payload = list_dir(context_for(environment, root, tool="fs.list"))
    assert listed(payload) == sorted(listed(payload))
    assert "alpha.txt" in " ".join(listed(payload))


def test_the_default_depth_is_four_and_is_enforced(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    root = workspace / "t"
    root.mkdir()
    deep = root
    for level in range(6):
        deep = deep / f"L{level}"
        deep.mkdir()
    (deep / "buried.txt").write_text("x\n", encoding="utf-8")

    payload = list_dir(context_for(environment, root, tool="fs.list"))
    assert not any("buried.txt" in path for path in listed(payload))
    assert not any("/L4/" in path or path.endswith("/L4") for path in listed(payload))


def test_a_symlink_is_reported_but_never_walked_through(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """A directory symlink is a way OUT of the approved root; listing must not take it."""
    outside = workspace / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("classified\n", encoding="utf-8")
    root = workspace / "t"
    root.mkdir()
    (root / "escape").symlink_to(outside, target_is_directory=True)

    payload = list_dir(context_for(environment, root, tool="fs.list"))
    types = {entry["path"]: entry["type"] for entry in payload["entries"]}
    assert any(path.endswith("escape") for path in types)
    assert all(types[path] == "symlink" for path in types if path.endswith("escape"))
    assert not any("secret.txt" in path for path in listed(payload))


def test_listing_a_file_instead_of_a_directory_is_refused(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    with pytest.raises(HandlerRefused) as excinfo:
        list_dir(context_for(environment, workspace / "a.txt", tool="fs.list"))
    assert excinfo.value.kind == READ_FAILED


def test_a_swapped_root_directory_is_refused_by_fs_list(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """The §7.5 pin is not a `fs.read` feature — every reader owes it."""
    root = workspace / "t"
    root.mkdir()
    tree(root)
    context = context_for(environment, root, tool="fs.list")
    shutil.rmtree(root)
    root.mkdir()
    (root / "planted.txt").write_text("x\n", encoding="utf-8")

    with pytest.raises(HandlerRefused) as excinfo:
        list_dir(context)
    assert excinfo.value.kind == TARGET_REPLACED


# ==========================================================================
# H. fs.find — three modes, and the one that reads bytes
# ==========================================================================


def test_name_mode_matches_on_the_basename(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    root = workspace / "t"
    root.mkdir()
    tree(root)
    payload = find(environment, root, mode="name", pattern="inner.txt")
    assert [m for m in payload["matches"] if m.endswith("inner.txt")]
    assert not [m for m in payload["matches"] if m.endswith("zeta.txt")]


def test_glob_mode_matches_a_pattern(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    root = workspace / "t"
    root.mkdir()
    tree(root)
    payload = find(environment, root, mode="glob", pattern="*.txt")
    assert len(payload["matches"]) >= 3


def test_content_mode_finds_the_file_that_holds_the_text(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    root = workspace / "t"
    root.mkdir()
    (root / "hay.txt").write_text("nothing here\n", encoding="utf-8")
    (root / "needle.txt").write_text("the NEEDLE is here\n", encoding="utf-8")
    payload = find(environment, root, mode="content", pattern="NEEDLE")
    assert [m for m in payload["matches"] if m.endswith("needle.txt")]
    assert not [m for m in payload["matches"] if m.endswith("hay.txt")]


def test_content_mode_never_opens_a_canary_honeyfile(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """The mode that READS BYTES is the one that can walk into the decoy.

    A canary check that lives only in `fs.read` leaves `fs.find --mode content`
    as an unmonitored way to reach the same file — and worse, a matching pattern
    would report its PATH, which is itself the signal an attacker wanted.
    """
    root = workspace / "t"
    root.mkdir()
    decoy = root / "id_rsa"
    decoy.write_text(CANARY_BODY, encoding="utf-8")
    with pytest.raises(HandlerRefused) as excinfo:
        find(
            environment,
            root,
            mode="content",
            pattern="sk-kimi",
            canary_paths=frozenset({str(decoy)}),
        )
    assert excinfo.value.kind == CANARY_TRIPPED
    assert CANARY_BODY not in str(excinfo.value)


def test_a_dotdot_in_the_pattern_is_refused(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§6.4: no `..` after canonicalization — the pattern must not climb out."""
    root = workspace / "t"
    root.mkdir()
    tree(root)
    with pytest.raises(HandlerRefused) as excinfo:
        find(environment, root, mode="glob", pattern="../*")
    assert excinfo.value.kind == READ_FAILED


def test_matches_are_capped_and_the_cap_is_reported(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    root = workspace / "t"
    root.mkdir()
    for n in range(30):
        (root / f"f{n:03d}.txt").write_text("x\n", encoding="utf-8")
    payload = find(environment, root, mode="glob", pattern="*.txt", max_results=10)
    assert len(payload["matches"]) == 10
    assert payload["truncated"] is True


def test_find_never_walks_through_a_directory_symlink(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    outside = workspace / "outside"
    outside.mkdir()
    (outside / "target.txt").write_text("x\n", encoding="utf-8")
    root = workspace / "t"
    root.mkdir()
    (root / "escape").symlink_to(outside, target_is_directory=True)

    payload = find(environment, root, mode="name", pattern="target.txt")
    assert payload["matches"] == []


def test_find_results_are_sorted_so_two_runs_compare(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    root = workspace / "t"
    root.mkdir()
    tree(root)
    payload = find(environment, root, mode="glob", pattern="*.txt")
    assert payload["matches"] == sorted(payload["matches"])


# ==========================================================================
# I. The three SPAWN tools — argv is assembled from a table, never from input
#
# `sys.info`, `pkg.query` and `git.read` declare `proc: spawn_argv`, so they take
# the T3.03 sandbox route and plug into `run()`'s existing `argv=`/`result_of=`
# seam. Their whole security story is the argv: §6.4 gives each a FIXED list, and
# the only user-supplied token that may ever reach it is one that passed a
# validated slot. These tests attack that boundary.
# ==========================================================================


def observation_of(stdout: bytes, exit_code: int = 0) -> Any:
    from lsassist.tools.result import ExecObservation, sha256_digest

    return ExecObservation(
        exit_code=exit_code,
        duration_ms=1,
        stdout=stdout,
        stderr=b"",
        stdout_digest=sha256_digest(stdout),
        stderr_digest=sha256_digest(b""),
        stdout_truncated=False,
        stderr_truncated=False,
        stdout_bytes=len(stdout),
        stderr_bytes=0,
        timed_out=False,
    )


@pytest.mark.parametrize(
    ("query", "expected_tail"),
    [
        ("uname", ("uname", "-a")),
        ("lscpu", ("lscpu",)),
        ("free", ("free", "-h")),
        ("df", ("df", "-h")),
    ],
)
def test_sys_info_argv_comes_from_the_6_4_allowlist(
    query: str, expected_tail: tuple[str, ...]
) -> None:
    argv = sys_info_argv({"query": query})
    # argv[0] absolute: a bare name is re-resolved against PATH at spawn time.
    assert argv[0].startswith("/")
    assert (os.path.basename(argv[0]), *argv[1:]) == expected_tail


def test_sys_info_os_release_reads_the_path_the_sandbox_can_actually_see() -> None:
    """§8.1 binds `/usr` but NOT `/etc`, so `/etc/os-release` is not in the view.

    Measured on this host: `/etc/os-release` is a symlink to
    `/usr/lib/os-release`, which IS reachable under the §8.1 `--ro-bind /usr`.
    Naming the `/etc` path would produce a tool that is correct on paper and
    ENOENT in the sandbox every single time.
    """
    argv = sys_info_argv({"query": "os_release"})
    assert "/usr/lib/os-release" in argv
    assert "/etc/os-release" not in argv


@pytest.mark.parametrize("bad", ["", "uname -a", "reboot", "uname;reboot", None, 7])
def test_sys_info_refuses_anything_outside_the_allowlist(bad: Any) -> None:
    with pytest.raises(HandlerRefused):
        sys_info_argv({"query": bad})


def test_pkg_query_puts_the_name_in_a_slot_never_in_a_string() -> None:
    argv = pkg_query_argv({"action": "dpkg_query", "name": "bash"})
    assert "bash" in argv
    assert not any(" " in part for part in argv[1:])


@pytest.mark.parametrize(
    "bad",
    ["bash;reboot", "bash && reboot", "../etc/passwd", "bash|tee", "$(id)", "a b", "`id`"],
)
def test_pkg_query_refuses_a_name_the_6_4_regex_rejects(bad: str) -> None:
    """§6.4: name arg validated `^[a-zA-Z0-9+._:-]+$`.

    The manifest's `input_schema` carries the same pattern; this is the SECOND,
    independent statement of it, so a hand-built or drifted manifest cannot make
    the handler accept a shell metacharacter.
    """
    with pytest.raises(HandlerRefused):
        pkg_query_argv({"action": "dpkg_query", "name": bad})


def test_pkg_query_pip_list_uses_the_workspace_venv() -> None:
    argv = pkg_query_argv({"action": "pip_list"}, workspace_root="/w")
    assert argv[0] == "/w/.venv/bin/pip"
    assert "list" in argv


@pytest.mark.parametrize(
    ("subcommand", "expected"),
    [
        ("status", ("status", "--short", "--branch")),
        ("branch", ("branch", "--show-current")),
        ("worktree", ("worktree", "list")),
    ],
)
def test_git_read_subcommands_are_the_6_4_fixed_forms(
    subcommand: str, expected: tuple[str, ...]
) -> None:
    argv = git_read_argv({"subcommand": subcommand}, workspace_root="/w")
    assert tuple(argv[-len(expected) :]) == expected
    assert "-C" in argv and "/w" in argv


def test_git_read_log_count_is_a_bounded_integer_not_a_string() -> None:
    argv = git_read_argv({"subcommand": "log", "count": 5}, workspace_root="/w")
    assert "--oneline" in argv
    assert "-5" in argv or "5" in argv


def test_git_read_diff_cached_is_a_flag_not_free_text() -> None:
    argv = git_read_argv({"subcommand": "diff", "cached": True}, workspace_root="/w")
    assert "--cached" in argv


@pytest.mark.parametrize("bad", ["push", "reset", "clean", "status --short; reboot", "", None])
def test_git_read_refuses_a_subcommand_outside_the_allowlist(bad: Any) -> None:
    """§6.4 names five subcommands; `git.destructive` is DENY by non-existence."""
    with pytest.raises(HandlerRefused):
        git_read_argv({"subcommand": bad}, workspace_root="/w")


@pytest.mark.parametrize(
    "outside", ["/etc/passwd", "/w/../etc/passwd", "/w-evil/x", "/w", "relative/x"]
)
def test_git_read_diff_path_must_be_absolute_and_inside_the_workspace(outside: str) -> None:
    """§6.3 step 2 hands handlers ABSOLUTE canonical paths; git wants relative.

    Both halves matter. Refusing the absolute form would make `diff <path>`
    undispatchable, because the dispatcher refuses a relative path argument
    outright. Accepting one outside the workspace would name a file `-C <repo>`
    cannot reach and the approval never covered. `/w-evil/x` is the segment-
    prefix trap; `/w` itself is the root, not a path within it.
    """
    with pytest.raises(HandlerRefused):
        git_read_argv({"subcommand": "diff", "path": outside}, workspace_root="/w")


def test_every_spawn_tool_renders_stdout_with_errors_replace() -> None:
    """A tool that raised on undecodable output would be killable by its subject."""
    observation = observation_of(b"caf\xe9\n")
    for build in (sys_info_result, pkg_query_result, git_read_result):
        payload = build(observation)
        assert "�" in payload["stdout"]
        assert payload["exit_code"] == 0


def test_a_nonzero_exit_is_reported_not_hidden() -> None:
    payload = git_read_result(observation_of(b"", exit_code=128))
    assert payload["exit_code"] == 128


# ==========================================================================
# J. Refusal paths — every branch that says "no" is a branch worth executing
#
# These are not coverage padding: each one is a REFUSAL, and a refusal that was
# never executed is a refusal nobody has evidence works. The project has four
# precedents where a fully covered file still shipped a CRITICAL, so the value
# here is the assertion on the OUTCOME, not the line being reached.
# ==========================================================================


@pytest.mark.parametrize("bad", [0, 1001, True, "5", None, -1])
def test_git_read_log_count_outside_the_bound_is_refused(bad: Any) -> None:
    """`True` is an `int` in Python; a bool count would render `-True`."""
    with pytest.raises(HandlerRefused):
        git_read_argv({"subcommand": "log", "count": bad}, workspace_root="/w")


def test_git_read_log_without_a_count_uses_the_documented_default() -> None:
    argv = git_read_argv({"subcommand": "log"}, workspace_root="/w")
    assert f"-{git_read_module.DEFAULT_LOG_COUNT}" in argv


@pytest.mark.parametrize("bad", ["", 7, b"/w/x", []])
def test_git_read_diff_path_must_be_a_non_empty_string(bad: Any) -> None:
    with pytest.raises(HandlerRefused):
        git_read_argv({"subcommand": "diff", "path": bad}, workspace_root="/w")


def test_git_read_separates_a_diff_path_with_a_double_dash() -> None:
    """A path beginning with '-' would otherwise be read by git as an option."""
    argv = git_read_argv({"subcommand": "diff", "path": "/w/src/a.py"}, workspace_root="/w")
    assert argv[-2:] == ("--", "src/a.py")


def test_git_read_without_a_workspace_root_is_refused() -> None:
    with pytest.raises(HandlerRefused):
        git_read_argv({"subcommand": "status"}, workspace_root="")


def test_pkg_query_apt_cache_show_requires_a_name() -> None:
    with pytest.raises(HandlerRefused):
        pkg_query_argv({"action": "apt_cache_show"})


def test_pkg_query_dpkg_without_a_name_lists_everything() -> None:
    argv = pkg_query_argv({"action": "dpkg_query"})
    assert argv == ("/usr/bin/dpkg-query", "-W")


@pytest.mark.parametrize("bad", [7, b"bash", ["bash"], {"name": "bash"}])
def test_pkg_query_rejects_a_non_string_name(bad: Any) -> None:
    """`None` is NOT here: it means "no name" and has its own test.

    A skipped case inside a parametrize reads as coverage while proving nothing —
    this repository has already been bitten by two silently skipping e2e tests.
    """
    with pytest.raises(HandlerRefused):
        pkg_query_argv({"action": "dpkg_query", "name": bad})


def test_pkg_query_pip_list_without_a_workspace_is_refused() -> None:
    with pytest.raises(HandlerRefused):
        pkg_query_argv({"action": "pip_list"})


@pytest.mark.parametrize("bad", ["", "install", None, 7])
def test_pkg_query_rejects_an_unknown_action(bad: Any) -> None:
    with pytest.raises(HandlerRefused):
        pkg_query_argv({"action": bad})


def test_fs_list_rejects_a_depth_below_one(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """The manifest floors this at 1; the handler says so a second time."""
    root = workspace / "t"
    root.mkdir()
    context = context_for(environment, root, tool="fs.list")
    object.__setattr__(context.normalized, "args", {"path": str(root), "depth": 0})
    with pytest.raises(HandlerRefused) as excinfo:
        list_dir(context)
    assert excinfo.value.kind == READ_FAILED


def test_fs_list_ignores_a_non_integer_depth_rather_than_crashing(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    root = workspace / "t"
    root.mkdir()
    tree(root)
    context = context_for(environment, root, tool="fs.list")
    object.__setattr__(context.normalized, "args", {"path": str(root), "depth": "deep"})
    payload = list_dir(context)
    assert payload["entries"]


def test_fs_list_reports_truncation_when_the_result_cap_is_reached(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    root = workspace / "t"
    root.mkdir()
    for n in range(4000):
        (root / f"f{n:05d}.txt").write_text("x", encoding="utf-8")
    payload = list_dir(context_for(environment, root, tool="fs.list"))
    assert payload["truncated"] is True
    assert len(payload["entries"]) < 4000


def test_fs_list_survives_an_entry_that_vanishes_mid_walk(
    environment: DispatchEnvironment, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A listing is a snapshot of a MOVING tree; one racing entry is not fatal."""
    root = workspace / "t"
    root.mkdir()
    tree(root)
    context = context_for(environment, root, tool="fs.list")
    real_stat = os.stat
    calls = {"n": 0}

    def flaky_stat(*args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 2:
            raise FileNotFoundError(2, "vanished")
        return real_stat(*args, **kwargs)

    monkeypatch.setattr(os, "stat", flaky_stat)
    payload = list_dir(context)
    assert payload["entries"]


@pytest.mark.parametrize(
    ("mode", "pattern"),
    [("name", "x" * 300), ("glob", "/abs/*"), ("bogus", "x"), (7, "x"), ("name", 7)],
)
def test_fs_find_refuses_a_malformed_mode_or_pattern(
    environment: DispatchEnvironment, workspace: Path, mode: Any, pattern: Any
) -> None:
    root = workspace / "t"
    root.mkdir()
    context = context_for(
        environment, root, tool="fs.find", args_extra={"mode": "name", "pattern": "x"}
    )
    object.__setattr__(
        context.normalized, "args", {"path": str(root), "mode": mode, "pattern": pattern}
    )
    with pytest.raises(HandlerRefused) as excinfo:
        find_files(context)
    assert excinfo.value.kind == READ_FAILED


def test_fs_find_rejects_a_max_results_below_one(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    root = workspace / "t"
    root.mkdir()
    context = context_for(
        environment, root, tool="fs.find", args_extra={"mode": "name", "pattern": "x"}
    )
    object.__setattr__(
        context.normalized,
        "args",
        {"path": str(root), "mode": "name", "pattern": "x", "max_results": 0},
    )
    with pytest.raises(HandlerRefused):
        find_files(context)


def test_a_dotdot_inside_a_filename_is_not_a_climbing_component(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """`a..b` is a legal name; only a `..` SEGMENT climbs out."""
    root = workspace / "t"
    root.mkdir()
    (root / "a..b.txt").write_text("x\n", encoding="utf-8")
    payload = find(environment, root, mode="name", pattern="a..b.txt")
    assert payload["matches"] == ["a..b.txt"]


def test_opening_a_root_with_no_parent_is_refused(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """`/` now fails CONTAINMENT first, which is the stronger refusal.

    Before `check_within_workspace` existed this reached the open and failed on
    "no parent/name". Both are refusals, but the containment one says the true
    reason: the path was never in scope, so the tool had no business opening it.
    """
    context = context_for(environment, workspace / "a.txt")
    object.__setattr__(context.normalized, "canonical_paths", ("/",))
    with pytest.raises(HandlerRefused) as excinfo:
        read_file(context)
    assert excinfo.value.kind == WORKSPACE_SCOPE


def test_a_read_from_a_broken_descriptor_is_a_typed_refusal() -> None:
    """Every OSError in a handler must arrive as HandlerRefused, never raw."""
    from lsassist.tools.handlers._common import read_fd

    read_end, write_end = os.pipe()
    os.close(read_end)
    os.close(write_end)
    with pytest.raises(HandlerRefused) as excinfo:
        read_fd(read_end, 16, "closed-pipe")
    assert excinfo.value.kind == READ_FAILED


# ==========================================================================
# K. What the isolated 4R review found — every one of these was REPRODUCED
#    against the candidate before the fix, and each assertion names the
#    measurement, not the intention.
# ==========================================================================


def outside_context(
    environment: DispatchEnvironment,
    target: Path,
    *,
    tool: str,
    extra: dict[str, Any] | None = None,
) -> HandlerContext:
    """A context for a path OUTSIDE the workspace that `dispatch` still PROCEEDs.

    It PROCEEDs because `AUTO_READ` short-circuits §6.3 step 3 and no upstream
    stage compares the path to the workspace — which is precisely the hole.
    """
    manifest = manifest_for(tool)
    args: dict[str, Any] = {"path": str(target)}
    args.update(extra or {})
    decision = dispatch(
        ToolRequest(call_id="c1", tool=tool, args=args),
        manifest=manifest,
        environment=environment,
        path_args=["path"],
    )
    assert decision.decision is Decision.PROCEED, decision
    assert decision.normalized is not None
    return HandlerContext(
        normalized=decision.normalized, manifest=manifest, environment=environment
    )


def test_fs_read_refuses_a_path_outside_the_workspace(
    environment: DispatchEnvironment, tmp_path: Path
) -> None:
    """THE BLOCKER, reproduced: `~/.netrc` is not on the §7.3 list and was read.

    `path_scope: "workspace"` is declared on every manifest and was consumed by
    nothing in `src/`. R2's `_WRITE_INTENT_TOOLS` is `{fs.write, fs.patch}`, so
    it never fires for a reader; `AUTO_READ` PROCEEDs immediately; `canonicalize`
    takes no workspace argument. The narrow §7.3 blocklist was the ONLY bound,
    leaving `~/.kube/config`, `~/.npmrc`, `~/.docker/config.json` and the rest
    readable in-process and unsandboxed.
    """
    secret = Path(environment.stores.home) / ".netrc"
    secret.write_text("machine api.example.com password HUNTER2\n", encoding="utf-8")
    with pytest.raises(HandlerRefused) as excinfo:
        read_file(outside_context(environment, secret, tool="fs.read"))
    assert excinfo.value.kind == WORKSPACE_SCOPE
    assert "HUNTER2" not in str(excinfo.value)


def test_fs_list_refuses_a_root_outside_the_workspace(
    environment: DispatchEnvironment, tmp_path: Path
) -> None:
    outside = Path(environment.stores.home) / "elsewhere"
    outside.mkdir()
    (outside / "x.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(HandlerRefused) as excinfo:
        list_dir(outside_context(environment, outside, tool="fs.list"))
    assert excinfo.value.kind == WORKSPACE_SCOPE


def test_fs_find_refuses_a_root_outside_the_workspace(
    environment: DispatchEnvironment, tmp_path: Path
) -> None:
    outside = Path(environment.stores.home) / "elsewhere"
    outside.mkdir()
    (outside / "x.txt").write_text("secret\n", encoding="utf-8")
    context = outside_context(
        environment, outside, tool="fs.find", extra={"mode": "content", "pattern": "secret"}
    )
    with pytest.raises(HandlerRefused) as excinfo:
        find_files(context)
    assert excinfo.value.kind == WORKSPACE_SCOPE


def test_a_workspace_prefix_is_not_containment(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """`/ws-evil` starts with `/ws` as a STRING and is not inside it."""
    sibling = workspace.parent / f"{workspace.name}-evil"
    sibling.mkdir()
    (sibling / "x.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(HandlerRefused) as excinfo:
        read_file(outside_context(environment, sibling / "x.txt", tool="fs.read"))
    assert excinfo.value.kind == WORKSPACE_SCOPE


def test_fs_find_by_NAME_still_trips_the_canary(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """CRITICAL, reproduced: name/glob modes had no canary check at all.

    `_hit` tested the canary only in the `content` branch, so
    `fs.find --mode name --pattern id_rsa` returned `['id_rsa']` with no alert —
    and locating a honeyfile by name is the reconnaissance §19 exists to catch.
    """
    decoy = workspace / "id_rsa"
    decoy.write_text(CANARY_BODY, encoding="utf-8")
    with pytest.raises(HandlerRefused) as excinfo:
        find(
            environment,
            workspace,
            mode="name",
            pattern="id_rsa",
            canary_paths=frozenset({str(decoy)}),
        )
    assert excinfo.value.kind == CANARY_TRIPPED


def test_fs_find_by_GLOB_still_trips_the_canary(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    decoy = workspace / "id_rsa"
    decoy.write_text(CANARY_BODY, encoding="utf-8")
    with pytest.raises(HandlerRefused) as excinfo:
        find(
            environment,
            workspace,
            mode="glob",
            pattern="id_*",
            canary_paths=frozenset({str(decoy)}),
        )
    assert excinfo.value.kind == CANARY_TRIPPED


def test_a_canary_NESTED_below_the_root_trips_fs_find(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """The canary is rarely at the root; the walk has to carry the check down."""
    deep = workspace / "a" / "b"
    deep.mkdir(parents=True)
    decoy = deep / "id_rsa"
    decoy.write_text(CANARY_BODY, encoding="utf-8")
    with pytest.raises(HandlerRefused) as excinfo:
        find(
            environment,
            workspace,
            mode="name",
            pattern="id_rsa",
            canary_paths=frozenset({str(decoy)}),
        )
    assert excinfo.value.kind == CANARY_TRIPPED


def test_a_canary_that_does_NOT_match_the_pattern_still_trips_content_mode(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """Gating the canary on a successful match would pass every earlier test.

    Every prior canary test used a pattern that also matched the decoy's body,
    so a regression reading the file FIRST and checking the canary only on a hit
    would look identical. Here the pattern cannot match, so only a check that
    runs BEFORE the read can fire.
    """
    decoy = workspace / "id_rsa"
    decoy.write_text(CANARY_BODY, encoding="utf-8")
    with pytest.raises(HandlerRefused) as excinfo:
        find(
            environment,
            workspace,
            mode="content",
            pattern="ZZZ-NEVER-MATCHES",
            canary_paths=frozenset({str(decoy)}),
        )
    assert excinfo.value.kind == CANARY_TRIPPED


def test_a_canary_below_the_root_trips_fs_list(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """`fs.list` checked the canary only on the walk ROOT, so a honeyfile
    anywhere below it was silently enumerable — path, type and size."""
    deep = workspace / "a"
    deep.mkdir()
    decoy = deep / "id_rsa"
    decoy.write_text(CANARY_BODY, encoding="utf-8")
    context = context_for(
        environment, workspace, tool="fs.list", canary_paths=frozenset({str(decoy)})
    )
    with pytest.raises(HandlerRefused) as excinfo:
        list_dir(context)
    assert excinfo.value.kind == CANARY_TRIPPED


def test_fs_find_content_will_not_read_a_nested_deny_listed_file(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """CRITICAL, reproduced: `fs.find --mode content` returned `['proj/.env']`.

    `deny_match` matches `.env` by SEGMENT at any depth, so the rule was already
    there — the walk just never asked it below the root. A workspace normally IS
    a git checkout and commonly holds a `.env`, so this is the ordinary case.
    """
    project = workspace / "proj"
    project.mkdir()
    (project / ".env").write_text("AWS_SECRET_ACCESS_KEY=TOPSECRET123\n", encoding="utf-8")
    payload = find(environment, workspace, mode="content", pattern="TOPSECRET")
    assert payload["matches"] == []


def test_fs_list_does_not_enumerate_a_nested_deny_listed_path(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    project = workspace / "proj"
    project.mkdir()
    (project / ".env").write_text("SECRET=1\n", encoding="utf-8")
    payload = list_dir(context_for(environment, workspace, tool="fs.list"))
    assert not any(entry["path"].endswith(".env") for entry in payload["entries"])


def test_fs_list_leaks_no_file_descriptor_when_it_truncates(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """CRITICAL, MEASURED: 56 leaked fds in one call.

    The truncation path called `queue.clear()`, dropping every already-open child
    directory fd; the `finally` drain then ran on an emptied queue and closed
    nothing. `fs_find.py` hits the same condition WITHOUT `clear()` and is
    correct — the divergence is what proves this was a defect, not a tradeoff.
    """
    root = workspace / "wide"
    root.mkdir()
    for i in range(40):
        sub = root / f"d{i:03d}"
        sub.mkdir()
        for j in range(200):
            (sub / f"f{j:04d}.txt").write_text("x", encoding="utf-8")

    before = len(os.listdir("/proc/self/fd"))
    payload = list_dir(context_for(environment, root, tool="fs.list"))
    after = len(os.listdir("/proc/self/fd"))
    assert payload["truncated"] is True
    assert after == before, f"leaked {after - before} descriptors"


def test_an_unreadable_directory_is_a_typed_refusal_not_a_raw_OSError(
    environment: DispatchEnvironment, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CRITICAL: an unguarded `os.listdir(fd)` escaped `run()` past the journal.

    Every other syscall in these handlers is wrapped and converted; `os.listdir`
    was the one call the hardening pattern missed. §6.3 step 9 has to journal
    EVERY outcome, and an exception that escapes `run()` produces no ToolResult
    and no record at all.
    """
    root = workspace / "t"
    root.mkdir()
    tree(root)
    context = context_for(environment, root, tool="fs.list")

    def boom(fd: Any) -> list[str]:
        raise OSError(5, "EIO")

    monkeypatch.setattr(os, "listdir", boom)
    with pytest.raises(HandlerRefused) as excinfo:
        list_dir(context)
    assert excinfo.value.kind == READ_FAILED


def test_a_handler_that_raises_a_bare_OSError_is_still_journalled(
    environment: DispatchEnvironment,
    workspace: Path,
    journal: AuditWriter,
    audit_dir: Path,
    tmp_path: Path,
) -> None:
    """`run()` caught only `HandlerRefused`; anything else escaped past step 9."""
    manifest = manifest_for("fs.read")
    decision = dispatch(
        ToolRequest(call_id="c1", tool="fs.read", args={"path": str(workspace / "a.txt")}),
        manifest=manifest,
        environment=environment,
        path_args=["path"],
    )

    def explode(context: HandlerContext) -> dict[str, Any]:
        raise OSError(5, "EIO")

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=str(tmp_path / "cache"),
        task_id="t-1",
        argv=(),
        audit=journal,
        handler=explode,
    )
    assert outcome.decision is Decision.BLOCKED
    journal.close()
    assert [r["event"] for r in journal_records(audit_dir)] == ["tool_result"]


def test_the_in_process_route_enforces_the_manifest_timeout(
    environment: DispatchEnvironment,
    workspace: Path,
    journal: AuditWriter,
    tmp_path: Path,
) -> None:
    """The spawn route passes `timeout_s` to the runner; the in-process route
    passed it nowhere, so `timeout_s` was recorded and never honored."""
    import time as time_module

    manifest = manifest_for("fs.read")
    decision = dispatch(
        ToolRequest(call_id="c1", tool="fs.read", args={"path": str(workspace / "a.txt")}),
        manifest=manifest,
        environment=environment,
        path_args=["path"],
    )

    def slow(context: HandlerContext) -> dict[str, Any]:
        deadline = context.deadline
        assert deadline is not None, "the handler must be given a deadline to honour"
        assert deadline > time_module.monotonic()
        return {"content": "", "encoding": "utf-8", "bytes_read": 0, "truncated": False}

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=str(tmp_path / "cache"),
        task_id="t-1",
        argv=(),
        audit=journal,
        handler=slow,
    )
    assert outcome.decision is Decision.PROCEED


def test_a_walk_that_outlives_its_deadline_is_refused(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """A deadline nothing checks is a number in a manifest, not a bound."""
    root = workspace / "t"
    root.mkdir()
    for i in range(50):
        sub = root / f"d{i:03d}"
        sub.mkdir()
        (sub / "f.txt").write_text("x", encoding="utf-8")
    context = context_for(environment, root, tool="fs.list")
    object.__setattr__(context, "deadline", 0.0)  # already expired
    with pytest.raises(HandlerRefused) as excinfo:
        list_dir(context)
    assert excinfo.value.kind == TIMED_OUT


def test_the_empty_argv_refusal_does_not_claim_a_route_the_tool_never_takes(
    environment: DispatchEnvironment, workspace: Path, journal: AuditWriter, tmp_path: Path
) -> None:
    """A `proc: none` tool does not "take the spawn route"; the record said so."""
    manifest = manifest_for("fs.read")
    decision = dispatch(
        ToolRequest(call_id="c1", tool="fs.read", args={"path": str(workspace / "a.txt")}),
        manifest=manifest,
        environment=environment,
        path_args=["path"],
    )
    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=str(tmp_path / "cache"),
        task_id="t-1",
        argv=(),
        audit=journal,
        handler=None,
    )
    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert "spawn route" not in outcome.result.error.message_redacted


# ==========================================================================
# L. Second-round review corrections
# ==========================================================================


def test_the_deadline_is_checked_per_ENTRY_not_only_per_directory(
    environment: DispatchEnvironment, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE second-round CRITICAL: one wide directory outran the budget.

    `check_deadline` ran once per directory DEQUEUED, so a single directory —
    the shape `fs.find --mode content` is worst at, reading up to 1 MiB per file
    — was scanned to completion with the clock consulted exactly once, before it
    was even entered. A walk with ONE directory therefore had ONE check.

    The clock is stepped rather than slept: a test that waited for real time
    would be slow and flaky, and this asserts the CHECK's placement, not the
    duration.
    """
    from lsassist.tools.handlers import _common

    root = workspace / "t"
    root.mkdir()
    for i in range(8):
        (root / f"f{i}.txt").write_text("x\n", encoding="utf-8")

    context = context_for(environment, root, tool="fs.list")
    ticks = iter([0.0, 0.0] + [99.0] * 200)
    monkeypatch.setattr(_common.time, "monotonic", lambda: next(ticks))
    object.__setattr__(context, "deadline", 1.0)

    with pytest.raises(HandlerRefused) as excinfo:
        list_dir(context)
    assert excinfo.value.kind == TIMED_OUT


def test_fs_find_checks_the_deadline_per_ENTRY_too(
    environment: DispatchEnvironment, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`fs.find` is the SLOWER tool and had the weaker test.

    A first version of this test set an already-expired deadline before the walk
    began — which the per-DIRECTORY check catches on its own, so deleting the
    per-entry check left it green. The mutation survived, which is the only
    reason this was noticed. The clock is stepped so expiry lands mid-directory,
    where content mode actually spends the budget.
    """
    from lsassist.tools.handlers import _common

    root = workspace / "t"
    root.mkdir()
    for i in range(8):
        (root / f"f{i}.txt").write_text("needle\n", encoding="utf-8")

    context = context_for(
        environment,
        root,
        tool="fs.find",
        args_extra={"mode": "content", "pattern": "needle"},
    )
    ticks = iter([0.0, 0.0] + [99.0] * 200)
    monkeypatch.setattr(_common.time, "monotonic", lambda: next(ticks))
    object.__setattr__(context, "deadline", 1.0)

    with pytest.raises(HandlerRefused) as excinfo:
        find_files(context)
    assert excinfo.value.kind == TIMED_OUT


def test_fs_find_refuses_a_swapped_root_directory(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """`fs.find` shares `open_pinned_dir` but had no §7.5 pin test of its own."""
    root = workspace / "t"
    root.mkdir()
    tree(root)
    context = context_for(
        environment, root, tool="fs.find", args_extra={"mode": "name", "pattern": "x"}
    )
    shutil.rmtree(root)
    root.mkdir()
    (root / "planted.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(HandlerRefused) as excinfo:
        find_files(context)
    assert excinfo.value.kind == TARGET_REPLACED


@pytest.mark.parametrize("tool", ["fs.list", "fs.find"])
def test_a_canary_AT_the_walk_root_trips(
    environment: DispatchEnvironment, workspace: Path, tool: str
) -> None:
    """Every other canary test nests the decoy; the root case was untested."""
    decoy = workspace / "canary_dir"
    decoy.mkdir()
    extra = {"mode": "name", "pattern": "x"} if tool == "fs.find" else None
    context = context_for(
        environment,
        decoy,
        tool=tool,
        args_extra=extra,
        canary_paths=frozenset({str(decoy)}),
    )
    handler = find_files if tool == "fs.find" else list_dir
    with pytest.raises(HandlerRefused) as excinfo:
        handler(context)
    assert excinfo.value.kind == CANARY_TRIPPED


def test_the_truncation_charge_scales_with_the_path_length(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """A flat per-entry charge would give both trees the same entry count.

    Same number of files, same content, only the NAMES differ — so any charge
    that ignores `len(rel)` yields identical results and this test fails.
    """
    def build(name: str, width: int) -> int:
        root = workspace / name
        root.mkdir()
        for n in range(900):
            (root / f"{'z' * width}{n:04d}.txt").write_text("x", encoding="utf-8")
        return len(list_dir(context_for(environment, root, tool="fs.list"))["entries"])

    short_names = build("short", 1)
    long_names = build("long", 120)
    assert long_names < short_names


def test_a_handler_runtime_failure_has_its_own_reason_code(
    environment: DispatchEnvironment, workspace: Path, journal: AuditWriter, tmp_path: Path
) -> None:
    """A wiring fault and a crash are different events; one code hid both.

    `HANDLER_UNAVAILABLE` is documented as "no handler was supplied, or an argv
    was" — both static wiring defects. Reusing it for a data-dependent crash
    makes the §14.1 reason code useless for triage.
    """
    manifest = manifest_for("fs.read")
    decision = dispatch(
        ToolRequest(call_id="c1", tool="fs.read", args={"path": str(workspace / "a.txt")}),
        manifest=manifest,
        environment=environment,
        path_args=["path"],
    )

    def explode(context: HandlerContext) -> dict[str, Any]:
        raise OSError(5, "EIO")

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=str(tmp_path / "cache"),
        task_id="t-1",
        argv=(),
        audit=journal,
        handler=explode,
    )
    assert outcome.result.error is not None
    assert outcome.result.error.kind == HANDLER_FAILED


def test_a_missing_handler_keeps_the_wiring_reason_code(
    environment: DispatchEnvironment, workspace: Path, journal: AuditWriter, tmp_path: Path
) -> None:
    """The discriminating half of the pair above — and of the route conjunct.

    Asserting the KIND is what makes this test discriminate. Asserting only
    "BLOCKED" did not: dropping `and handler is not None` produces a TypeError
    that the broad `except` rewrites into a blocked outcome too.
    """
    manifest = manifest_for("fs.read")
    decision = dispatch(
        ToolRequest(call_id="c1", tool="fs.read", args={"path": str(workspace / "a.txt")}),
        manifest=manifest,
        environment=environment,
        path_args=["path"],
    )
    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=str(tmp_path / "cache"),
        task_id="t-1",
        argv=(),
        audit=journal,
        handler=None,
    )
    assert outcome.result.error is not None
    assert outcome.result.error.kind == HANDLER_UNAVAILABLE


def test_a_refused_in_process_call_still_records_how_long_it_ran(
    environment: DispatchEnvironment, workspace: Path, journal: AuditWriter, tmp_path: Path
) -> None:
    """A timeout that journals `duration_ms=0` discards the only evidence of it.

    Every in-process refusal went through the shared `blocked()` closure, which
    reports `_NOTHING_RAN` — so a call that burned the whole budget and a call
    that failed instantly produced identical records.
    """
    manifest = manifest_for("fs.read")
    decision = dispatch(
        ToolRequest(call_id="c1", tool="fs.read", args={"path": str(workspace / "a.txt")}),
        manifest=manifest,
        environment=environment,
        path_args=["path"],
    )

    def slow_refusal(context: HandlerContext) -> dict[str, Any]:
        time.sleep(0.02)
        raise HandlerRefused(TIMED_OUT, "budget exhausted")

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=str(tmp_path / "cache"),
        task_id="t-1",
        argv=(),
        audit=journal,
        handler=slow_refusal,
    )
    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == TIMED_OUT
    assert outcome.result.duration_ms > 0, "a refusal that ran must report that it ran"


def test_the_entry_overhead_constant_is_derived_not_counted() -> None:
    """The constant was hand-counted twice and wrong twice (44, then 42).

    A number a human has to count is a number that will be wrong again, and this
    one decides truncation. Derive it from the SHAPE the handler actually builds
    so the next payload change fails here instead of silently under-charging.
    """
    from lsassist.tools.handlers import fs_list as module

    widest = {"path": "", "type": "file", "size": 1234}
    rendered = json.dumps(widest)
    fixed = len(rendered) - len(str(widest["size"]))
    assert fixed == module._ENTRY_OVERHEAD_CHARS

    # And it must be the WIDEST: every other entry shape must cost no more.
    for kind in ("dir", "symlink", "other"):
        other = len(json.dumps({"path": "", "type": kind}))
        assert other <= fixed, f"{kind} renders wider than the pinned overhead"
