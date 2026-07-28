"""T3.03 RED (integration): §6.3 steps 5-9 against a REAL bwrap.

Everything in ``tests/unit/tools/test_dispatch_execute.py`` asserts either the
SHAPE of a list of strings or the behaviour of an injected fake. HARDEN-03 is
the standing proof that this is not enough: the §8.1 template composed a
structurally perfect argv that died on every desktop session, and the entire
T2.06 unit suite was green while the exec path was totally down.

So these tests SPAWN. They cover the four claims §8.3 makes about the boundary
that cannot be checked any other way:

* the workspace bind is the ONLY writable path — a write outside it is ``EROFS``
  (§8.3 "Tests (AC-06/AC-09/T-02)");
* the host's own files are ABSENT from the mount view, not merely unreadable;
* the network namespace has no route (``curl``-shaped access fails);
* a tool that outlives its timeout is killed by PROCESS GROUP, and the runner
  returns rather than waiting on a grandchild's pipe.

They skip when the host has no ``bwrap``. CI installs one — an integration test
that always skips is a gate that never runs, which is the exact defect the Wave-1
seam critic found in ``tests/contract/``.
"""

from __future__ import annotations

import datetime
import json
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
from lsassist.contracts.tool_result import ToolResultStatus
from lsassist.policy.stores import PolicyStores
from lsassist.policy.token import TokenService
from lsassist.sandbox.availability import SandboxUnavailable, probe
from lsassist.tools.dispatcher import (
    SANDBOX_UNAVAILABLE,
    ApprovalGrant,
    Decision,
    DispatchEnvironment,
    dispatch,
    run,
)
from lsassist.tools.result import sha256_digest

requires_bwrap = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bwrap is not installed on this host"
)

#: Nothing here may run unbounded: a hung integration test reports nothing.
BUDGET_S = 60


def manifest_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "proc.exec",
        "version": "1.0.0",
        "purpose": "Run an allowlisted program inside the sandbox.",
        "input_schema": {
            "type": "object",
            "required": ["argv"],
            "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
            "additionalProperties": False,
        },
        "output_schema": {
            "type": "object",
            "required": ["stdout", "exit_code"],
            "properties": {"stdout": {"type": "string"}, "exit_code": {"type": "integer"}},
            "additionalProperties": False,
        },
        "permission_class": "AUTO_READ",
        "capabilities": {"fs": "none", "net": "none", "proc": "spawn_argv"},
        "timeout_s": 30,
        "output_limits": {
            "max_stdout_bytes": 51200,
            "max_stderr_bytes": 65536,
            "max_result_chars": 200000,
        },
        "concurrency": "shared_read",
        "idempotent": True,
        "dry_run": False,
        "rollback": "none",
        "redaction": ["paths"],
        "path_scope": "workspace",
        "tests": [],
    }
    base.update(overrides)
    return base


def make_manifest(**overrides: Any) -> ToolManifest:
    return ToolManifest.model_validate(manifest_dict(**overrides))


def write_manifest(**overrides: Any) -> ToolManifest:
    """A ``ws``-profile manifest that DECLARES the path it writes.

    NAMED FINDING, recorded rather than worked around: §6.4's real ``test.run``
    is ``write_scoped`` with an argv and NO path argument — it writes build
    artifacts wherever the runner puts them — and T3.02's guard refuses exactly
    that shape ("declares capabilities.fs=write_scoped but no path_args were
    declared"). So the catalogued ``test.run`` cannot be dispatched as written
    today. That is T3.06's boundary to settle (declare a target, or give the
    guard a "write_scoped with no declared target" carve-out); this fixture
    declares one so the test can measure the SANDBOX rather than that gap.
    """
    base = manifest_dict(
        name="test.run",
        input_schema={
            "type": "object",
            "required": ["argv", "path"],
            "properties": {
                "argv": {"type": "array", "items": {"type": "string"}},
                "path": {"type": "string"},
            },
            "additionalProperties": False,
        },
        permission_class="AUTO_SCOPED_WRITE",
        capabilities={"fs": "write_scoped", "net": "none", "proc": "spawn_argv"},
        rollback="checkpoint",
    )
    base.update(overrides)
    return ToolManifest.model_validate(base)


@pytest.fixture
def workspace() -> Iterator[Path]:
    """Outside ``/tmp``: §8.1's own tmpfs masks it and ``build_argv`` refuses it."""
    ws = Path.home() / ".cache" / "lsassist" / "t303-integration" / uuid.uuid4().hex / "ws"
    ws.mkdir(parents=True)
    (ws / "seed.txt").write_text("seed\n", encoding="utf-8")
    try:
        yield ws
    finally:
        shutil.rmtree(ws.parent, ignore_errors=True)


#: A fixed instant, so a minted token and its verification share one clock.
NOW = datetime.datetime(2026, 7, 28, 12, 0, tzinfo=datetime.UTC)


@pytest.fixture
def environment(tmp_path: Path, workspace: Path) -> DispatchEnvironment:
    home = tmp_path / "home"
    home.mkdir(parents=True)
    return DispatchEnvironment(
        workspace_root=str(workspace),
        cwd=str(workspace),
        stores=PolicyStores(
            home=str(home),
            audit_store=str(home / ".local/state/lsassist/audit"),
            policy_store=str(home / ".config/lsassist"),
            kernel_secret=str(home / ".local/state/lsassist/kernel.secret"),
        ),
        session_id="s-int",
        token_service=TokenService(b"k" * 32),
    )


@pytest.fixture
def cache_dir(tmp_path: Path) -> str:
    return str(tmp_path / "cache" / "lsassist")


def proceeding(
    environment: DispatchEnvironment,
    manifest: ToolManifest,
    argv: list[str],
    path: str | None = None,
) -> Any:
    """Take these argv all the way to PROCEED, approving if §7.2 asks.

    Most argv here contain a shell metacharacter (``|``, ``>``, ``&``) because
    that is how one writes a probe, and §7.2's R4 correctly raises such a request
    to CONFIRM_EXACT. So these tests mint a real token rather than dodging the
    rule with metacharacter-free argv — which also means the §7.4 approval flow
    is exercised end to end on the way to every sandbox assertion below.
    """
    args: dict[str, Any] = {"argv": argv}
    path_args: list[str] = []
    if path is not None:
        args["path"] = path
        path_args = ["path"]
    request = ToolRequest(call_id="c1", tool=manifest.name, args=args)
    decision = dispatch(
        request,
        manifest=manifest,
        environment=environment,
        path_args=path_args,
        # Only ever true for the write fixture: the guard refuses the flag on a
        # manifest that is not `write_scoped`.
        create_if_missing=path is not None,
        now=NOW,
    )
    if decision.decision is Decision.NEEDS_APPROVAL:
        assert decision.approval_record is not None
        service = environment.token_service
        assert service is not None
        decision = dispatch(
            request,
            manifest=manifest,
            environment=environment,
            path_args=path_args,
            create_if_missing=path is not None,
            grant=ApprovalGrant(
                record=decision.approval_record, token=service.mint(decision.approval_record)
            ),
            now=NOW,
        )
    assert decision.decision is Decision.PROCEED, decision
    return decision


def execute(
    environment: DispatchEnvironment,
    cache_dir: str,
    manifest: ToolManifest,
    argv: list[str],
    audit_dir: Path,
    path: str | None = None,
) -> Any:
    """Run §6.3 steps 1-9 for real, journalling to ``audit_dir``."""
    decision = proceeding(environment, manifest, argv, path)
    with AuditWriter(directory=audit_dir, session_id="s-int") as writer:
        return run(
            decision,
            manifest=manifest,
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-int",
            argv=argv,
            probe_fn=probe,
            audit=writer,
            result_of=lambda observation: {
                "stdout": observation.stdout.decode("utf-8", errors="replace"),
                "exit_code": observation.exit_code,
            },
        )


# ==========================================================================
# the §6.5 contract, produced by something that really ran
# ==========================================================================
@requires_bwrap
def test_an_echo_style_tool_yields_the_full_6_5_contract(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    outcome = execute(
        environment, cache_dir, make_manifest(), ["/bin/echo", "lsassist"], tmp_path / "audit"
    )

    assert outcome.decision is Decision.PROCEED
    result = outcome.result
    assert result.tool == "proc.exec"
    assert result.status is ToolResultStatus.OK
    assert result.exit_code == 0
    assert result.duration_ms >= 0
    assert result.stdout_digest == sha256_digest(b"lsassist\n")
    assert result.stderr_digest == sha256_digest(b"")
    assert result.result == {"stdout": "lsassist\n", "exit_code": 0}


@requires_bwrap
def test_a_write_outside_the_workspace_is_EROFS_inside_the_sandbox(
    environment: DispatchEnvironment, cache_dir: str, workspace: Path, tmp_path: Path
) -> None:
    """§8.3 / T-02: the ``ws`` profile binds the workspace rw and NOTHING else.

    The system tree is ``--ro-bind``, so the write fails at the OS boundary
    rather than at a check the tool could talk its way past.
    """
    outcome = execute(
        environment,
        cache_dir,
        write_manifest(),
        ["/bin/sh", "-c", "echo x > /usr/lsassist-probe 2>&1; echo rc=$?"],
        tmp_path / "audit",
        path=str(workspace / "declared.txt"),
    )

    stdout = outcome.result.result["stdout"]
    assert "rc=0" not in stdout, f"a write outside the workspace SUCCEEDED: {stdout!r}"
    assert not Path("/usr/lsassist-probe").exists()

    inside = execute(
        environment,
        cache_dir,
        write_manifest(),
        ["/bin/sh", "-c", f"echo written > {workspace}/made.txt; echo rc=$?"],
        tmp_path / "audit2",
        path=str(workspace / "made.txt"),
    )
    assert "rc=0" in inside.result.result["stdout"]
    assert (workspace / "made.txt").read_text(encoding="utf-8") == "written\n"


@requires_bwrap
def test_the_host_s_own_secrets_are_ABSENT_from_the_mount_view(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    """§8.3 AC-06: ``cat ~/.ssh/id_rsa`` → the path does not exist.

    Absent, not merely unreadable: nothing binds the real home, so there is no
    permission decision to get wrong.
    """
    outcome = execute(
        environment,
        cache_dir,
        make_manifest(),
        ["/bin/sh", "-c", f"ls -d {Path.home()}/.ssh 2>&1 || true"],
        tmp_path / "audit",
    )
    assert "No such file" in outcome.result.result["stdout"]


@requires_bwrap
def test_the_child_environment_carries_no_host_variables(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    """§8.3: "child env = მხოლოდ allowlist … ასარაფერი secrets".

    Measured on bwrap 0.9.0 during T2.05: without ``--clearenv`` the child got 81
    inherited variables including ``LSASSIST_KIMI_API_KEY`` and ``SSH_AUTH_SOCK``.
    """
    outcome = execute(
        environment, cache_dir, make_manifest(), ["/bin/sh", "-c", "env"], tmp_path / "audit"
    )
    names = {line.split("=", 1)[0] for line in outcome.result.result["stdout"].splitlines()}
    assert names <= {"HOME", "LANG", "PATH", "PWD"}, f"leaked into the child: {sorted(names)}"


@requires_bwrap
def test_the_network_namespace_has_no_route(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    """§8.3 AC-09: neither V1 profile passes ``--share-net``.

    Read from ``/proc/net/dev`` rather than by running ``ip``: ``/sbin`` is not
    among the §8.1 binds and ``PATH`` is ``/usr/bin:/bin``, so a missing ``ip``
    would make this test pass for the wrong reason.
    """
    outcome = execute(
        environment,
        cache_dir,
        make_manifest(),
        ["/bin/sh", "-c", "cut -d: -f1 /proc/net/dev | tail -n +3 | tr -d ' '"],
        tmp_path / "audit",
    )
    interfaces = set(outcome.result.result["stdout"].split())
    assert interfaces == {"lo"}, f"the sandbox can see {sorted(interfaces)}"


@requires_bwrap
def test_a_timeout_kills_the_group_and_the_runner_returns(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    """§6.3 step 6 + §8.3: "timeout → SIGKILL process group + verdict evidence
    ``timeout``". The grandchild holds the pipe; killing only the direct child
    leaves the reader blocked past its own deadline."""
    started = time.monotonic()
    outcome = execute(
        environment,
        cache_dir,
        make_manifest(timeout_s=1),
        ["/bin/sh", "-c", "sleep 300 & sleep 300"],
        tmp_path / "audit",
    )
    elapsed = time.monotonic() - started

    assert elapsed < BUDGET_S, "the runner never came back from its own timeout"
    assert outcome.result.status is ToolResultStatus.ERROR
    assert outcome.result.error is not None
    assert outcome.result.error.kind == "timeout"


@requires_bwrap
def test_an_output_flood_is_truncated_with_a_digest_of_the_whole_stream(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    """§6.5: oversized bodies are digest-only. The digest still covers what the
    tool ACTUALLY produced — an I12 downgrade otherwise."""
    manifest = make_manifest(
        output_limits={
            "max_stdout_bytes": 4096,
            "max_stderr_bytes": 4096,
            "max_result_chars": 200000,
        }
    )
    outcome = execute(
        environment,
        cache_dir,
        manifest,
        ["/bin/sh", "-c", "yes lsassist | head -c 200000"],
        tmp_path / "audit",
    )

    assert outcome.result.status is ToolResultStatus.TRUNCATED
    assert outcome.observation is not None
    assert outcome.observation.stdout_bytes == 200000
    assert len(outcome.observation.stdout) == 4096
    # `yes lsassist` emits b"lsassist\n" forever; `head -c` cuts mid-line.
    expected = (b"lsassist\n" * (200000 // 9 + 1))[:200000]
    assert outcome.result.stdout_digest == sha256_digest(expected)


@requires_bwrap
def test_the_journal_records_the_execution_with_every_digest(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    audit_dir = tmp_path / "audit"
    outcome = execute(
        environment, cache_dir, make_manifest(), ["/bin/echo", "hi"], audit_dir
    )
    journal = next(audit_dir.glob("session-s-int*.jsonl"))
    records = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()]

    payload = next(r["payload"] for r in records if r["event"] == "tool_result")
    assert payload["stdout_digest"] == outcome.result.stdout_digest
    assert payload["exit_code"] == 0
    assert payload["profile"] == "ro"


def test_a_host_without_bwrap_BLOCKS_rather_than_running_unsandboxed(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    """§8.3, I11 — and this one deliberately does NOT require ``bwrap``.

    It is the single most important claim in the file, so it must not be a test
    that skips on the very hosts where the mistake would be invisible.
    """
    manifest = make_manifest()
    decision = proceeding(environment, manifest, ["/bin/echo", "hi"])

    def refuse() -> Any:
        raise SandboxUnavailable("bwrap was uninstalled between probe and exec")

    with AuditWriter(directory=tmp_path / "audit", session_id="s-int") as writer:
        outcome = run(
            decision,
            manifest=manifest,
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-int",
            argv=["/bin/echo", "hi"],
            probe_fn=refuse,
            audit=writer,
        )

    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == SANDBOX_UNAVAILABLE
