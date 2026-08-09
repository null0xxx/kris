"""T3.06 real sandbox and local-network boundary tests."""

from __future__ import annotations

import dataclasses
import datetime
import http.server
import shutil
import threading
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from lsassist.audit.writer import AuditWriter
from lsassist.contracts.tool_request import ToolRequest
from lsassist.memory import FETCH_BODY_LIMIT, FetchBodyStore
from lsassist.policy.stores import PolicyStores
from lsassist.policy.token import TokenService
from lsassist.sandbox.availability import probe
from lsassist.tools.dispatcher import (
    ARGV_REBOUND,
    ApprovalGrant,
    Decision,
    DispatchEnvironment,
    NormalizedRequest,
    dispatch,
    run,
)
from lsassist.tools.handlers import (
    BODY_TOO_LARGE,
    CONTENT_TYPE_REFUSED,
    EXECUTABLE_REFUSED,
    REDIRECT_REFUSED,
    HandlerContext,
    HandlerRefused,
)
from lsassist.tools.handlers.net_fetch import make_net_fetch_handler
from lsassist.tools.handlers.proc_exec import make_proc_exec_handler
from lsassist.tools.handlers.test_run import make_test_run_handler
from lsassist.tools.registry import load_registry

REGISTRY = load_registry()
NOW = datetime.datetime(2026, 8, 9, 12, 0, tzinfo=datetime.UTC)
pytestmark = pytest.mark.integration
requires_bwrap = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bwrap is not installed on this host"
)


@pytest.fixture
def workspace() -> Iterator[Path]:
    root = Path.home() / ".cache/lsassist/t306-integration" / uuid.uuid4().hex / "ws"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


@pytest.fixture
def environment(tmp_path: Path, workspace: Path) -> DispatchEnvironment:
    home = tmp_path / "home"
    home.mkdir()
    return DispatchEnvironment(
        workspace_root=str(workspace),
        cwd=str(workspace),
        stores=PolicyStores(
            home=str(home),
            audit_store=str(home / "audit"),
            policy_store=str(home / "policy"),
            kernel_secret=str(home / "secret"),
            exec_allowlist=frozenset({"/usr/bin/python", "/usr/bin/touch", "/usr/bin/true"}),
        ),
        session_id="s-t306",
        token_service=TokenService(b"k" * 32),
    )


@pytest.fixture
def cache_dir(tmp_path: Path) -> str:
    return str(tmp_path / "cache/lsassist")


def approved(
    request: ToolRequest,
    environment: DispatchEnvironment,
    execution_argv: tuple[str, ...] | None = None,
) -> Any:
    manifest = REGISTRY[request.tool]
    decision = dispatch(
        request,
        manifest=manifest,
        environment=environment,
        execution_argv=execution_argv,
        now=NOW,
    )
    assert decision.decision is Decision.NEEDS_APPROVAL
    assert decision.approval_record is not None
    service = environment.token_service
    assert service is not None
    decision = dispatch(
        request,
        manifest=manifest,
        environment=environment,
        execution_argv=execution_argv,
        grant=ApprovalGrant(
            record=decision.approval_record,
            token=service.mint(decision.approval_record),
        ),
        now=NOW,
    )
    assert decision.decision is Decision.PROCEED
    return decision


def execute_spawned(
    request: ToolRequest,
    argv: tuple[str, ...],
    environment: DispatchEnvironment,
    cache_dir: str,
    audit_dir: Path,
    result_of: Any,
) -> Any:
    bound_argv = tuple(request.args["argv"]) if request.tool == "proc.exec" else argv
    with AuditWriter(directory=audit_dir, session_id="s-t306") as audit:
        return run(
            approved(request, environment, bound_argv),
            manifest=REGISTRY[request.tool],
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-t306",
            argv=argv,
            audit=audit,
            probe_fn=probe,
            result_of=result_of,
        )


@requires_bwrap
def test_cargo_pass_and_fail_through_real_dispatch_and_bwrap(
    workspace: Path,
    environment: DispatchEnvironment,
    cache_dir: str,
    tmp_path: Path,
) -> None:
    (workspace / "Cargo.toml").write_text(
        "[package]\nname='t306_probe'\nversion='0.1.0'\nedition='2021'\n",
        encoding="utf-8",
    )
    (workspace / "src").mkdir()
    source = workspace / "src/lib.rs"
    source.write_text("#[test]\nfn boundary() { assert_eq!(2 + 2, 4); }\n", encoding="utf-8")
    builder = make_test_run_handler(str(workspace))
    request = ToolRequest(call_id="cargo-pass", tool="test.run", args={"extra_args": []})
    passed = execute_spawned(
        request,
        builder(request.args),
        environment,
        cache_dir,
        tmp_path / "audit-pass",
        __import__("lsassist.tools.handlers.test_run", fromlist=["result_of"]).result_of,
    )
    assert passed.decision is Decision.PROCEED
    assert passed.result.exit_code == 0
    assert (workspace / "target").is_dir()

    source.write_text("#[test]\nfn boundary() { assert_eq!(2 + 2, 5); }\n", encoding="utf-8")
    request = ToolRequest(call_id="cargo-fail", tool="test.run", args={"extra_args": []})
    failed = execute_spawned(
        request,
        builder(request.args),
        environment,
        cache_dir,
        tmp_path / "audit-fail",
        __import__("lsassist.tools.handlers.test_run", fromlist=["result_of"]).result_of,
    )
    assert failed.decision is Decision.PROCEED
    assert failed.result.exit_code != 0


@requires_bwrap
@pytest.mark.parametrize(
    "argv",
    [
        (
            "/usr/bin/python",
            "-c",
            "import socket; socket.create_connection(('127.0.0.1', 9), .2)",
        ),
        ("/usr/bin/touch", "/var/tmp/lsassist-t306-outside"),
    ],
)
def test_proc_exec_cannot_use_network_or_write_outside_workspace(
    argv: tuple[str, ...],
    environment: DispatchEnvironment,
    cache_dir: str,
    tmp_path: Path,
) -> None:
    builder = make_proc_exec_handler(frozenset({argv[0]}))
    request = ToolRequest(call_id=uuid.uuid4().hex, tool="proc.exec", args={"argv": list(argv)})
    module = __import__("lsassist.tools.handlers.proc_exec", fromlist=["result_of"])
    outcome = execute_spawned(
        request,
        builder(request.args),
        environment,
        cache_dir,
        tmp_path / f"audit-{uuid.uuid4().hex}",
        module.result_of,
    )
    assert outcome.decision is Decision.PROCEED
    assert outcome.result.exit_code != 0
    assert not Path("/var/tmp/lsassist-t306-outside").exists()


@requires_bwrap
def test_proc_exec_rewrite_after_approval_is_blocked_before_spawn(
    environment: DispatchEnvironment,
    cache_dir: str,
    tmp_path: Path,
) -> None:
    request = ToolRequest(call_id="bound-argv", tool="proc.exec", args={"argv": ["/usr/bin/true"]})
    module = __import__("lsassist.tools.handlers.proc_exec", fromlist=["result_of"])
    outcome = execute_spawned(
        request,
        ("/usr/bin/touch", str(environment.workspace_root) + "/rewritten"),
        environment,
        cache_dir,
        tmp_path / "audit-rewrite",
        module.result_of,
    )
    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == ARGV_REBOUND
    assert not (Path(environment.workspace_root) / "rewritten").exists()


@requires_bwrap
def test_proc_exec_public_run_default_empty_allowlist_cannot_touch_workspace(
    environment: DispatchEnvironment,
    cache_dir: str,
    tmp_path: Path,
) -> None:
    denied = dataclasses.replace(
        environment,
        stores=dataclasses.replace(environment.stores, exec_allowlist=frozenset()),
    )
    marker = Path(denied.workspace_root) / "default-empty-bypass"
    argv = ("/usr/bin/touch", str(marker))
    request = ToolRequest(call_id="empty-allowlist", tool="proc.exec", args={"argv": list(argv)})
    module = __import__("lsassist.tools.handlers.proc_exec", fromlist=["result_of"])
    with AuditWriter(directory=tmp_path / "audit-empty", session_id="s-t306") as audit:
        outcome = run(
            approved(request, denied, argv),
            manifest=REGISTRY[request.tool],
            environment=denied,
            cache_dir=cache_dir,
            task_id="t-empty-allowlist",
            argv=argv,
            audit=audit,
            probe_fn=probe,
            result_of=module.result_of,
        )
    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == EXECUTABLE_REFUSED
    assert not marker.exists()


@requires_bwrap
def test_test_run_public_run_cannot_replace_approved_runner_with_touch(
    workspace: Path,
    environment: DispatchEnvironment,
    cache_dir: str,
    tmp_path: Path,
) -> None:
    (workspace / "Cargo.toml").write_text("[package]\nname='probe'\n", encoding="utf-8")
    request = ToolRequest(call_id="test-run-rebind", tool="test.run", args={"extra_args": []})
    approved_argv = make_test_run_handler(str(workspace))(request.args)
    marker = workspace / "runner-rebound"
    rebound_argv = ("/usr/bin/touch", str(marker))
    module = __import__("lsassist.tools.handlers.test_run", fromlist=["result_of"])
    with AuditWriter(directory=tmp_path / "audit-test-run", session_id="s-t306") as audit:
        outcome = run(
            approved(request, environment, approved_argv),
            manifest=REGISTRY[request.tool],
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-test-run-rebind",
            argv=rebound_argv,
            audit=audit,
            probe_fn=probe,
            result_of=module.result_of,
        )
    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == ARGV_REBOUND
    assert not marker.exists()


class LocalHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/text")
            self.end_headers()
            return
        if self.path == "/offlist":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.server.server_port}/text")
            self.end_headers()
            return
        if self.path == "/binary":
            body, content_type = b"\x00\x01", "application/octet-stream"
        elif self.path == "/oversize":
            body, content_type = b"x" * (FETCH_BODY_LIMIT + 1), "text/plain"
        else:
            body, content_type = b"local-body", "text/plain; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@pytest.fixture
def local_http() -> Iterator[int]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def local_context(tmp_path: Path, port: int, method: str, target: str) -> HandlerContext:
    env = DispatchEnvironment(
        workspace_root=str(tmp_path),
        cwd=str(tmp_path),
        stores=PolicyStores(
            home=str(tmp_path),
            audit_store=str(tmp_path / "audit"),
            policy_store=str(tmp_path / "policy"),
            kernel_secret=str(tmp_path / "secret"),
        ),
        session_id="s-local",
    )
    normalized = NormalizedRequest(
        tool="net.fetch",
        args=MappingProxyType(
            {
                "method": method,
                "scheme": "http",
                "domain": "127.0.0.1",
                "port": port,
                "target": target,
            }
        ),
        canonical_paths=(),
        workspace_root=str(tmp_path),
        cwd_real=str(tmp_path),
        env=MappingProxyType({}),
        env_digest="sha256:" + "0" * 64,
        action_hash="sha256:" + "1" * 64,
    )
    return HandlerContext(normalized=normalized, manifest=REGISTRY["net.fetch"], environment=env)


def test_real_local_http_get_head_redirect_and_ram_retrieval(
    tmp_path: Path, local_http: int
) -> None:
    store = FetchBodyStore()
    handler = make_net_fetch_handler(store)
    fetched = handler(local_context(tmp_path, local_http, "GET", "/redirect"))
    assert fetched["redirects"] == 1
    assert store.get(fetched["body_ref"]) == b"local-body"
    headed = handler(local_context(tmp_path, local_http, "HEAD", "/text"))
    assert headed["body_ref"] is None
    assert headed["byte_count"] == 0


@pytest.mark.parametrize(
    ("target", "kind"),
    [
        ("/offlist", REDIRECT_REFUSED),
        ("/binary", CONTENT_TYPE_REFUSED),
        ("/oversize", BODY_TOO_LARGE),
    ],
)
def test_real_local_http_refusals(tmp_path: Path, local_http: int, target: str, kind: str) -> None:
    store = FetchBodyStore()
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(store)(local_context(tmp_path, local_http, "GET", target))
    assert exc.value.kind == kind
