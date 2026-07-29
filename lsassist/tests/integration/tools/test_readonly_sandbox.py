"""T3.04 integration — the six §6.4 read-only tools against a REAL bwrap.

The unit suite proves each handler and argv builder in isolation with fakes.
This file proves the two things a fake cannot:

1. **The argv builders produce command lines that actually run inside §8.1's
   mount view.** A tool can be correct on paper and ENOENT in the sandbox —
   ``sys.info os_release`` is exactly that case, because §8.1 binds ``/usr`` but
   not ``/etc``, so the obvious ``/etc/os-release`` spelling would fail on every
   host while every unit test passed.
2. **The in-process route and the sandbox route reach the same journal.** They
   are two branches of ``run()``; a record written by only one of them is an
   audit gap that no unit test of either branch alone would show.

``requires_bwrap`` skips this module when bwrap is absent. That skip is a real
risk on this project — two e2e tests silently skipped for weeks on a broken
sandbox and the suite looked clean — so the CI ``integration`` job installs
bubblewrap deliberately, and a skip here means the ENVIRONMENT is wrong, not that
the tests are optional.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from lsassist.audit.writer import AuditWriter
from lsassist.contracts.manifest import ToolManifest
from lsassist.contracts.tool_request import ToolRequest
from lsassist.policy.stores import PolicyStores
from lsassist.tools.dispatcher import Decision, DispatchEnvironment, dispatch, run
from lsassist.tools.handlers.fs_read import read_file
from lsassist.tools.handlers.git_read import build_argv as git_read_argv
from lsassist.tools.handlers.git_read import result_of as git_read_result
from lsassist.tools.handlers.pkg_query import build_argv as pkg_query_argv
from lsassist.tools.handlers.pkg_query import result_of as pkg_query_result
from lsassist.tools.handlers.sys_info import build_argv as sys_info_argv
from lsassist.tools.handlers.sys_info import result_of as sys_info_result
from lsassist.tools.registry import load_registry

requires_bwrap = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bwrap is not installed on this host"
)

#: Nothing here may run unbounded: a hung integration test reports nothing.
BUDGET_S = 60

REGISTRY = load_registry()


def stores_for(home: Path) -> PolicyStores:
    return PolicyStores(
        home=str(home),
        audit_store=str(home / ".local/state/lsassist/audit"),
        policy_store=str(home / ".config/lsassist"),
        kernel_secret=str(home / ".local/state/lsassist/kernel.secret"),
    )


@pytest.fixture
def workspace() -> Iterator[Path]:
    """OUTSIDE ``/tmp`` — §8.1 masks it with a tmpfs and `build_argv` refuses it."""
    ws = Path.home() / ".cache" / "lsassist" / "t304-integration" / uuid.uuid4().hex / "ws"
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
def cache_dir(tmp_path: Path) -> str:
    return str(tmp_path / "cache" / "lsassist")


@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    return tmp_path / "audit"


@pytest.fixture
def journal(audit_dir: Path) -> Iterator[AuditWriter]:
    with AuditWriter(directory=audit_dir, session_id="s-1") as writer:
        yield writer


def records(audit_dir: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in sorted(audit_dir.glob("session-*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


def manifest_for(tool: str) -> ToolManifest:
    return REGISTRY[tool]


def spawn_tool(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
    *,
    tool: str,
    args: dict[str, Any],
    argv: tuple[str, ...],
    result_of: Any,
    path_args: list[str] | None = None,
) -> Any:
    """Dispatch and run one §6.4 spawn tool through the real sandbox.

    ``path_args`` must be declared for any manifest with `capabilities.fs !=
    none` even when the request carries no path: `git.read`'s `path` is optional
    (only `diff` takes one), and T3.02's guard refuses an undeclared path
    argument outright — "an undeclared path argument would skip §7.5 entirely".
    """
    manifest = manifest_for(tool)
    request = ToolRequest(call_id="c1", tool=tool, args=args)
    decision = dispatch(
        request, manifest=manifest, environment=environment, path_args=path_args or []
    )
    assert decision.decision is Decision.PROCEED, decision
    return run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        argv=argv,
        audit=journal,
        result_of=result_of,
    )


# ---------------------------------------------------------------------------
# sys.info — the argv table has to survive contact with the §8.1 mount view
# ---------------------------------------------------------------------------


@requires_bwrap
def test_sys_info_uname_runs_inside_the_sandbox(
    environment: DispatchEnvironment, cache_dir: str, journal: AuditWriter
) -> None:
    args = {"query": "uname"}
    outcome = spawn_tool(
        environment,
        cache_dir,
        journal,
        tool="sys.info",
        args=args,
        argv=sys_info_argv(args),
        result_of=sys_info_result,
    )
    assert outcome.decision is Decision.PROCEED
    assert outcome.result.result["exit_code"] == 0
    assert "Linux" in outcome.result.result["stdout"]


@requires_bwrap
def test_sys_info_os_release_is_actually_reachable_in_the_mount_view(
    environment: DispatchEnvironment, cache_dir: str, journal: AuditWriter
) -> None:
    """The whole reason the builder names `/usr/lib/os-release`.

    §8.1 binds `/usr` but NOT `/etc`. If this tool had used the `/etc` spelling
    the unit tests would still pass and every real call would return exit 1.
    """
    args = {"query": "os_release"}
    outcome = spawn_tool(
        environment,
        cache_dir,
        journal,
        tool="sys.info",
        args=args,
        argv=sys_info_argv(args),
        result_of=sys_info_result,
    )
    assert outcome.result.result["exit_code"] == 0
    assert "ID=" in outcome.result.result["stdout"]


@requires_bwrap
def test_the_sandboxed_tool_sees_none_of_the_host_home(
    environment: DispatchEnvironment, cache_dir: str, journal: AuditWriter, workspace: Path
) -> None:
    """§8.1's mount view is the boundary, and `df -h` enumerates what is mounted."""
    args = {"query": "df"}
    outcome = spawn_tool(
        environment,
        cache_dir,
        journal,
        tool="sys.info",
        args=args,
        argv=sys_info_argv(args),
        result_of=sys_info_result,
    )
    stdout = outcome.result.result["stdout"]
    assert ".ssh" not in stdout
    assert ".gnupg" not in stdout


# ---------------------------------------------------------------------------
# git.read — a real repository, read through the fixed subcommand table
# ---------------------------------------------------------------------------


@requires_bwrap
def test_git_read_status_reports_a_real_repository(
    environment: DispatchEnvironment, cache_dir: str, journal: AuditWriter, workspace: Path
) -> None:
    subprocess.run(["git", "init", "-q", str(workspace)], check=True, timeout=BUDGET_S)
    (workspace / "new.txt").write_text("x\n", encoding="utf-8")

    args = {"subcommand": "status"}
    outcome = spawn_tool(
        environment,
        cache_dir,
        journal,
        tool="git.read",
        args=args,
        argv=git_read_argv(args, workspace_root=str(workspace)),
        result_of=git_read_result,
        path_args=["path"],
    )
    assert outcome.result.result["exit_code"] == 0
    assert "new.txt" in outcome.result.result["stdout"]


@requires_bwrap
def test_git_read_cannot_reach_a_repository_outside_the_workspace(
    environment: DispatchEnvironment, cache_dir: str, journal: AuditWriter, tmp_path: Path
) -> None:
    """`-C` names the workspace; §8.1 does not mount anything else to read."""
    outside = tmp_path / "other-repo"
    outside.mkdir()
    subprocess.run(["git", "init", "-q", str(outside)], check=True, timeout=BUDGET_S)

    args = {"subcommand": "status"}
    argv = git_read_argv(args, workspace_root=str(outside))
    manifest = manifest_for("git.read")
    request = ToolRequest(call_id="c1", tool="git.read", args=args)
    decision = dispatch(
        request, manifest=manifest, environment=environment, path_args=["path"]
    )
    assert decision.decision is Decision.PROCEED
    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        argv=argv,
        audit=journal,
        result_of=git_read_result,
    )
    # The path is simply not in the mount view, so git cannot open it.
    assert outcome.result.result["exit_code"] != 0


# ---------------------------------------------------------------------------
# pkg.query — §6.4's argv list is Debian-specific; the failure must be LOUD
# ---------------------------------------------------------------------------


@requires_bwrap
def test_pkg_query_fails_loudly_where_its_6_4_binary_does_not_exist(
    environment: DispatchEnvironment, cache_dir: str, journal: AuditWriter
) -> None:
    """NAMED RESIDUAL, asserted rather than assumed.

    §6.4 fixes `dpkg-query`/`apt-cache`, which do not exist on an Arch host. The
    requirement this test defends is not that the tool works everywhere — SPEC is
    frozen — but that where it cannot work it says so with a non-zero exit and a
    journalled record, instead of returning an empty result that reads like
    "no packages installed".
    """
    args = {"action": "dpkg_query", "name": "bash"}
    outcome = spawn_tool(
        environment,
        cache_dir,
        journal,
        tool="pkg.query",
        args=args,
        argv=pkg_query_argv(args),
        result_of=pkg_query_result,
    )
    have_dpkg = shutil.which("dpkg-query") is not None
    if have_dpkg:
        assert outcome.result.result["exit_code"] in {0, 1}
    else:
        assert outcome.result.result["exit_code"] != 0
        assert outcome.result.result["stdout"] == ""


# ---------------------------------------------------------------------------
# Both routes, one journal
# ---------------------------------------------------------------------------


@requires_bwrap
def test_the_in_process_and_sandbox_routes_write_the_same_record_shape(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
    audit_dir: Path,
    workspace: Path,
) -> None:
    """One journal, one payload shape — whichever branch of `run()` was taken."""
    read_manifest = manifest_for("fs.read")
    read_request = ToolRequest(
        call_id="c1", tool="fs.read", args={"path": str(workspace / "a.txt")}
    )
    read_decision = dispatch(
        read_request, manifest=read_manifest, environment=environment, path_args=["path"]
    )
    assert read_decision.decision is Decision.PROCEED
    in_process = run(
        read_decision,
        manifest=read_manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        argv=(),
        audit=journal,
        handler=read_file,
    )
    assert in_process.result.result["content"] == "hello\n"

    args = {"query": "uname"}
    sandboxed = spawn_tool(
        environment,
        cache_dir,
        journal,
        tool="sys.info",
        args=args,
        argv=sys_info_argv(args),
        result_of=sys_info_result,
    )
    assert sandboxed.decision is Decision.PROCEED

    journal.close()
    written = records(audit_dir)
    assert [r["event"] for r in written] == ["tool_result", "tool_result"]
    assert {r["payload"]["tool"] for r in written} == {"fs.read", "sys.info"}
    assert set(written[0]["payload"]) == set(written[1]["payload"])
