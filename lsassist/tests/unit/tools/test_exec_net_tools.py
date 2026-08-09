"""T3.06 unit contract for exec and network handlers."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import MappingProxyType
from typing import Any

import httpx
import pytest

from lsassist.contracts.enums import PermissionClass
from lsassist.contracts.policy_context import PolicyContext
from lsassist.contracts.tool_request import ToolRequest
from lsassist.memory import FETCH_BODY_LIMIT, FetchBodyStore, FetchBodyStoreError
from lsassist.policy.rules import classify
from lsassist.policy.stores import PolicyStores, PolicyStoresError
from lsassist.tools.dispatcher import (
    DispatchEnvironment,
    DispatchError,
    NormalizedRequest,
    dispatch,
    normalize,
)
from lsassist.tools.handlers import (
    BODY_TOO_LARGE,
    CONTENT_TYPE_REFUSED,
    EXECUTABLE_REFUSED,
    MEMORY_STORE_FAILED,
    REDIRECT_REFUSED,
    RUNNER_AMBIGUOUS,
    RUNNER_MISSING,
    TIMED_OUT,
    URL_REFUSED,
    HandlerContext,
    HandlerRefused,
)
from lsassist.tools.handlers.net_fetch import MAX_REDIRECTS, make_net_fetch_handler
from lsassist.tools.handlers.proc_exec import make_proc_exec_handler
from lsassist.tools.handlers.test_run import make_test_run_handler
from lsassist.tools.registry import load_registry

REGISTRY = load_registry()
EMPTY_SHA256 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def stores(tmp_path: Path, *, domains: frozenset[str] = frozenset()) -> PolicyStores:
    return PolicyStores(
        home=str(tmp_path),
        audit_store=str(tmp_path / "audit"),
        policy_store=str(tmp_path / "policy"),
        kernel_secret=str(tmp_path / "secret"),
        net_allowlist=domains,
    )


def environment(tmp_path: Path, *, domains: frozenset[str] = frozenset()) -> DispatchEnvironment:
    workspace = tmp_path / "ws"
    workspace.mkdir(exist_ok=True)
    return DispatchEnvironment(
        workspace_root=str(workspace),
        cwd=str(workspace),
        stores=stores(tmp_path, domains=domains),
        session_id="s-t306",
    )


def net_context(
    tmp_path: Path, *, domains: frozenset[str] = frozenset(), **overrides: object
) -> HandlerContext:
    args: dict[str, object] = {
        "method": "GET",
        "scheme": "https",
        "domain": "example.test",
        "target": "/resource",
        **overrides,
    }
    env = environment(tmp_path, domains=domains)
    normalized = NormalizedRequest(
        tool="net.fetch",
        args=MappingProxyType(args),
        canonical_paths=(),
        workspace_root=env.workspace_root,
        cwd_real=env.cwd,
        env=MappingProxyType({}),
        env_digest=EMPTY_SHA256,
        action_hash=EMPTY_SHA256,
    )
    return HandlerContext(normalized=normalized, manifest=REGISTRY["net.fetch"], environment=env)


def client_factory(transport: httpx.AsyncBaseTransport, seen: dict[str, Any] | None = None) -> Any:
    def factory(**kwargs: Any) -> httpx.AsyncClient:
        if seen is not None:
            seen.update(kwargs)
        return httpx.AsyncClient(transport=transport, **kwargs)

    return factory


def response_transport(routes: dict[str, httpx.Response]) -> httpx.MockTransport:
    def route(request: httpx.Request) -> httpx.Response:
        response = routes[str(request.url)]
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            content=response.content,
            request=request,
        )

    return httpx.MockTransport(route)


# ---------------------------------------------------------------------------
# Shipped manifests and dispatcher seam
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "permission", "fs", "net", "proc", "timeout", "result_cap"),
    [
        ("test.run", "CONFIRM_ONCE", "write_scoped", "none", "spawn_argv", 600, 200000),
        ("proc.exec", "CONFIRM_ONCE", "write_scoped", "none", "spawn_argv", 120, 50000),
        ("net.fetch", "CONFIRM_ONCE", "none", "fetch_allowlist", "none", 30, 200000),
    ],
)
def test_manifest_contract(
    name: str,
    permission: str,
    fs: str,
    net: str,
    proc: str,
    timeout: int,
    result_cap: int,
) -> None:
    manifest = REGISTRY[name]
    assert manifest.permission_class.value == permission
    assert (manifest.capabilities.fs.value, manifest.capabilities.net.value) == (fs, net)
    assert manifest.capabilities.proc.value == proc
    assert manifest.timeout_s == timeout
    assert manifest.output_limits.max_result_chars == result_cap
    assert manifest.input_schema["additionalProperties"] is False
    assert manifest.tests == [
        "tests/unit/tools/test_exec_net_tools.py",
        "tests/integration/tools/test_exec_net_sandbox.py",
    ]


def test_catalog_now_contains_the_frozen_twelve_tools() -> None:
    assert set(REGISTRY.names) == {
        "fs.read",
        "fs.list",
        "fs.find",
        "sys.info",
        "pkg.query",
        "git.read",
        "fs.write",
        "fs.patch",
        "git.worktree",
        "test.run",
        "proc.exec",
        "net.fetch",
    }


@pytest.mark.parametrize("name", ["test.run", "proc.exec"])
def test_workspace_wide_spawned_tool_needs_no_fake_path_arg(tmp_path: Path, name: str) -> None:
    env = environment(tmp_path)
    args = {"extra_args": []} if name == "test.run" else {"argv": ["/usr/bin/true"]}
    normalized = normalize(
        ToolRequest(call_id="c1", tool=name, args=args),
        manifest=REGISTRY[name],
        environment=env,
        path_args=(),
    )
    assert normalized.canonical_paths == ()


def test_git_worktree_cannot_skip_declared_path_binding(tmp_path: Path) -> None:
    with pytest.raises(DispatchError, match="no path_args"):
        normalize(ToolRequest(call_id="c", tool="git.worktree", args={"path": "new", "branch": "new"}), manifest=REGISTRY["git.worktree"], environment=environment(tmp_path))  # noqa: E501


# ---------------------------------------------------------------------------
# test.run runner detection and token preservation
# ---------------------------------------------------------------------------


def add_pytest_project(root: Path) -> None:
    (root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    runner = root / ".venv/bin/pytest"
    runner.parent.mkdir(parents=True)
    runner.write_text("runner", encoding="utf-8")


def test_test_run_detects_pytest_and_preserves_each_extra_token(tmp_path: Path) -> None:
    add_pytest_project(tmp_path)
    argv = make_test_run_handler(str(tmp_path))({"extra_args": ["-q", "tests/a b.py"]})
    assert argv == (str(tmp_path / ".venv/bin/pytest"), "-q", "tests/a b.py")


def test_test_run_detects_npm_test_with_fixed_head(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"test": "vitest"}}), encoding="utf-8"
    )
    assert make_test_run_handler(str(tmp_path))({"extra_args": ["--run"]}) == (
        "/usr/bin/npm",
        "test",
        "--",
        "--run",
    )


def test_test_run_detects_cargo_with_fixed_head(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("[package]\nname='probe'\n", encoding="utf-8")
    assert make_test_run_handler(str(tmp_path))({"extra_args": ["unit_name"]}) == (
        "/usr/bin/cargo",
        "test",
        "--",
        "unit_name",
    )


def test_test_run_refuses_no_runner(tmp_path: Path) -> None:
    with pytest.raises(HandlerRefused) as exc:
        make_test_run_handler(str(tmp_path))({})
    assert exc.value.kind == RUNNER_MISSING


def test_test_run_refuses_ambiguous_runner(tmp_path: Path) -> None:
    add_pytest_project(tmp_path)
    (tmp_path / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    with pytest.raises(HandlerRefused) as exc:
        make_test_run_handler(str(tmp_path))({})
    assert exc.value.kind == RUNNER_AMBIGUOUS
    assert "pytest" in exc.value.detail and "cargo" in exc.value.detail


@pytest.mark.parametrize("token", [";", "x;y", "&&", "x&&y", "`id`", "a\x00b", ""])
def test_test_run_rejects_every_forbidden_extra_token(tmp_path: Path, token: str) -> None:
    (tmp_path / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    with pytest.raises(HandlerRefused) as exc:
        make_test_run_handler(str(tmp_path))({"extra_args": ["safe", token]})
    assert exc.value.kind == RUNNER_AMBIGUOUS


def test_test_run_checks_all_tokens_not_only_the_first(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    with pytest.raises(HandlerRefused):
        make_test_run_handler(str(tmp_path))({"extra_args": ["safe", "also-safe", "bad;token"]})


# ---------------------------------------------------------------------------
# proc.exec exact immutable allowlist and R4/R5 diagnosis
# ---------------------------------------------------------------------------


def test_proc_exec_returns_exact_argv_without_rewriting() -> None:
    builder = make_proc_exec_handler(frozenset({"/usr/bin/printf"}))
    argv = ["/usr/bin/printf", "%s", "a b", "$(not-a-shell)"]
    assert builder({"argv": argv}) == tuple(argv)
    assert argv == ["/usr/bin/printf", "%s", "a b", "$(not-a-shell)"]


@pytest.mark.parametrize("program", ["printf", "/usr/bin/printf2", "/usr/bin/../bin/printf"])
def test_proc_exec_allowlist_is_exact_absolute_match(program: str) -> None:
    builder = make_proc_exec_handler(frozenset({"/usr/bin/printf"}))
    with pytest.raises(HandlerRefused) as exc:
        builder({"argv": [program]})
    assert exc.value.kind == EXECUTABLE_REFUSED
    assert "exact configured allowlist" in exc.value.detail


def test_proc_exec_default_empty_allowlist_fails_closed() -> None:
    with pytest.raises(HandlerRefused) as exc:
        make_proc_exec_handler(frozenset())({"argv": ["/usr/bin/true"]})
    assert exc.value.kind == EXECUTABLE_REFUSED


def test_proc_exec_requires_immutable_allowlist() -> None:
    with pytest.raises(TypeError, match="immutable frozenset"):
        make_proc_exec_handler({"/usr/bin/true"})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"exec_allowlist": {"/usr/bin/true"}},
        {"exec_allowlist": frozenset({"usr/bin/true"})},
    ],
)
def test_policy_exec_allowlist_is_immutable_and_absolute(
    tmp_path: Path, kwargs: dict[str, object]
) -> None:
    with pytest.raises(PolicyStoresError, match="exec_allowlist"):
        PolicyStores(
            home=str(tmp_path),
            audit_store=str(tmp_path / "audit"),
            policy_store=str(tmp_path / "policy"),
            kernel_secret=str(tmp_path / "secret"),
            **kwargs,
        )


@pytest.mark.parametrize("program", ["/usr/bin/sudo", "/usr/bin/doas", "/usr/bin/su"])
def test_proc_exec_privilege_wrappers_are_deny_always(tmp_path: Path, program: str) -> None:
    manifest = REGISTRY["proc.exec"]
    result = classify(
        ToolRequest(call_id="c", tool="proc.exec", args={"argv": [program, "id"]}),
        PolicyContext(workspace_root="/ws"),
        manifest,
        stores(tmp_path),
    )
    assert result is PermissionClass.DENY_ALWAYS


@pytest.mark.parametrize("argv", [["/usr/bin/rm", "-rf", "x"], ["/usr/bin/git", "reset", "--hard"]])
def test_proc_exec_dangerous_action_is_exact_confirmation(tmp_path: Path, argv: list[str]) -> None:
    result = classify(
        ToolRequest(call_id="c", tool="proc.exec", args={"argv": argv}),
        PolicyContext(workspace_root="/ws"),
        REGISTRY["proc.exec"],
        stores(tmp_path),
    )
    assert result is PermissionClass.CONFIRM_EXACT


def test_proc_exec_metachar_data_is_exact_confirmation(tmp_path: Path) -> None:
    result = classify(
        ToolRequest(
            call_id="c",
            tool="proc.exec",
            args={"argv": ["/usr/bin/printf", "literal;data"]},
        ),
        PolicyContext(workspace_root="/ws"),
        REGISTRY["proc.exec"],
        stores(tmp_path),
    )
    assert result is PermissionClass.CONFIRM_EXACT


# ---------------------------------------------------------------------------
# config-fed R6 authority
# ---------------------------------------------------------------------------


def test_net_allowlist_must_be_immutable(tmp_path: Path) -> None:
    with pytest.raises(PolicyStoresError, match="immutable frozenset"):
        stores(tmp_path, domains={"Example.COM"})  # type: ignore[arg-type]


def test_r6_config_allowlisted_domain_stays_confirm_once(tmp_path: Path) -> None:
    result = classify(
        ToolRequest(
            call_id="c",
            tool="net.fetch",
            args={"method": "GET", "scheme": "https", "domain": "EXAMPLE.COM.", "target": "/"},
        ),
        PolicyContext(workspace_root="/ws"),
        REGISTRY["net.fetch"],
        stores(tmp_path, domains=frozenset({"example.com"})),
    )
    assert result is PermissionClass.CONFIRM_ONCE


def test_r6_off_list_domain_raises_and_action_hash_binds_domain(tmp_path: Path) -> None:
    env = environment(tmp_path, domains=frozenset({"allowed.test"}))
    request = ToolRequest(
        call_id="c",
        tool="net.fetch",
        args={"method": "GET", "scheme": "https", "domain": "off.test", "target": "/"},
    )
    normalized = normalize(request, manifest=REGISTRY["net.fetch"], environment=env)
    assert (
        classify(
            request,
            PolicyContext(workspace_root=env.workspace_root),
            REGISTRY["net.fetch"],
            env.stores,
        )
        is PermissionClass.CONFIRM_EXACT
    )
    changed = normalize(
        request.model_copy(update={"args": {**request.args, "domain": "other.test"}}),
        manifest=REGISTRY["net.fetch"],
        environment=env,
    )
    assert normalized.action_hash != changed.action_hash


# ---------------------------------------------------------------------------
# RAM store lifecycle and net.fetch validation
# ---------------------------------------------------------------------------


def test_fetch_body_store_exact_cap_and_metadata_only() -> None:
    store = FetchBodyStore()
    body = b"x" * FETCH_BODY_LIMIT
    metadata = store.put(body)
    assert metadata.ref.startswith("memory:fetch/")
    assert metadata.byte_count == FETCH_BODY_LIMIT
    assert metadata.digest.startswith("sha256:")
    assert store.get(metadata.ref) == body
    assert not hasattr(metadata, "body")


def test_fetch_body_store_aggregate_cap_and_close() -> None:
    store = FetchBodyStore()
    first = store.put(b"a")
    with pytest.raises(FetchBodyStoreError, match="1 MiB"):
        store.put(b"b" * FETCH_BODY_LIMIT)
    store.close()
    with pytest.raises(FetchBodyStoreError, match="closed"):
        store.get(first.ref)
    with pytest.raises(FetchBodyStoreError, match="closed"):
        store.put(b"x")


def test_net_fetch_constructs_url_and_never_uses_proxy_or_auto_redirect(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}
    store = FetchBodyStore()
    transport = response_transport(
        {
            "https://example.test:8443/a?q=1": httpx.Response(
                200, headers={"Content-Type": "Text/Plain; Charset=UTF-8"}, content=b"secret-body"
            )
        }
    )
    payload = make_net_fetch_handler(
        store,
        client_factory=client_factory(transport, seen),
    )(net_context(tmp_path, port=8443, target="/a?q=1"))
    assert seen["trust_env"] is False
    assert seen["follow_redirects"] is False
    assert payload == {
        "url": "https://example.test:8443/a?q=1",
        "method": "GET",
        "status_code": 200,
        "content_type": "text/plain",
        "body_ref": payload["body_ref"],
        "byte_count": 11,
        "digest": payload["digest"],
        "redirects": 0,
    }
    assert store.get(payload["body_ref"]) == b"secret-body"
    assert "secret-body" not in json.dumps(payload)


def test_net_fetch_head_stores_no_body(tmp_path: Path) -> None:
    class RefusingStore(FetchBodyStore):
        def put(self, body: bytes) -> Any:
            raise AssertionError("HEAD must not call the body store")

    transport = response_transport(
        {
            "https://example.test/resource": httpx.Response(
                200, headers={"content-type": "application/json"}
            )
        }
    )
    payload = make_net_fetch_handler(RefusingStore(), client_factory=client_factory(transport))(
        net_context(tmp_path, method="HEAD")
    )
    assert payload["body_ref"] is None
    assert payload["byte_count"] == 0
    assert payload["digest"] == EMPTY_SHA256


@pytest.mark.parametrize(
    "content_type", ["application/octet-stream", "image/png", "", "textual/plain"]
)
def test_net_fetch_refuses_binary_or_missing_content_type(
    tmp_path: Path, content_type: str
) -> None:
    headers = {"content-type": content_type} if content_type else {}
    transport = response_transport(
        {"https://example.test/resource": httpx.Response(200, headers=headers, content=b"body")}
    )
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(FetchBodyStore(), client_factory=client_factory(transport))(
            net_context(tmp_path)
        )
    assert exc.value.kind == CONTENT_TYPE_REFUSED


@pytest.mark.parametrize(
    "content_type",
    [
        "text/plain",
        "APPLICATION/JSON; charset=utf-8",
        "application/xml",
    ],
)
def test_net_fetch_accepts_allowed_mime_types(tmp_path: Path, content_type: str) -> None:
    transport = response_transport(
        {
            "https://example.test/resource": httpx.Response(
                200, headers={"content-type": content_type}, content=b"x"
            )
        }
    )
    payload = make_net_fetch_handler(FetchBodyStore(), client_factory=client_factory(transport))(
        net_context(tmp_path)
    )
    assert payload["byte_count"] == 1


@pytest.mark.parametrize("content_type", ["application/problem+json", "application/atom+xml"])
def test_net_fetch_refuses_structured_suffix_mime_types(tmp_path: Path, content_type: str) -> None:
    transport = response_transport(
        {
            "https://example.test/resource": httpx.Response(
                200, headers={"content-type": content_type}, content=b"x"
            )
        }
    )
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(FetchBodyStore(), client_factory=client_factory(transport))(
            net_context(tmp_path)
        )
    assert exc.value.kind == CONTENT_TYPE_REFUSED


def test_net_fetch_refuses_an_expired_total_deadline_before_connect(tmp_path: Path) -> None:
    connected = False

    def connect(_: httpx.Request) -> httpx.Response:
        nonlocal connected
        connected = True
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"x")

    context = net_context(tmp_path)
    object.__setattr__(context, "deadline", time.monotonic() - 1)
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(
            FetchBodyStore(), client_factory=client_factory(httpx.MockTransport(connect))
        )(context)
    assert exc.value.kind == TIMED_OUT
    assert connected is False


def test_net_fetch_refuses_when_stream_exhausts_cumulative_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lsassist.tools.handlers import net_fetch as module

    clock = [0.0]

    class AdvancingStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> Any:
            yield b"first"
            clock[0] = 2.0
            yield b"second"

    class SpyStore(FetchBodyStore):
        calls = 0

        def put(self, body: bytes) -> Any:
            self.calls += 1
            return super().put(body)

    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            stream=AdvancingStream(),
            request=request,
        )

    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    context = net_context(tmp_path)
    object.__setattr__(context, "deadline", 1.0)
    store = SpyStore()
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(store, client_factory=client_factory(httpx.MockTransport(route)))(
            context
        )
    assert exc.value.kind == TIMED_OUT
    assert store.calls == 0


def test_net_fetch_recomputes_remaining_timeout_for_each_redirect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lsassist.tools.handlers import net_fetch as module

    clock = [0.0]
    timeouts: list[float] = []

    def route(request: httpx.Request) -> httpx.Response:
        timeouts.append(request.extensions["timeout"]["read"])
        if request.url.path == "/resource":
            clock[0] = 4.0
            return httpx.Response(302, headers={"location": "/next"}, request=request)
        return httpx.Response(
            200, headers={"content-type": "text/plain"}, content=b"ok", request=request
        )

    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    context = net_context(tmp_path)
    object.__setattr__(context, "deadline", 10.0)
    payload = make_net_fetch_handler(
        FetchBodyStore(), client_factory=client_factory(httpx.MockTransport(route))
    )(context)
    assert payload["redirects"] == 1
    assert timeouts == [10.0, 6.0]


def test_net_fetch_rechecks_deadline_before_ram_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lsassist.tools.handlers import net_fetch as module

    clock = [0.0]

    class ExpiringStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> Any:
            yield b"complete"
            clock[0] = 2.0

    class SpyStore(FetchBodyStore):
        calls = 0

        def put(self, body: bytes) -> Any:
            self.calls += 1
            return super().put(body)

    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    context = net_context(tmp_path)
    object.__setattr__(context, "deadline", 1.0)
    store = SpyStore()

    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            stream=ExpiringStream(),
            request=request,
        )

    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(store, client_factory=client_factory(httpx.MockTransport(route)))(
            context
        )
    assert exc.value.kind == TIMED_OUT
    assert store.calls == 0


def test_net_fetch_maps_httpx_timeout_to_typed_total_timeout(tmp_path: Path) -> None:
    def route(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(
            FetchBodyStore(), client_factory=client_factory(httpx.MockTransport(route))
        )(net_context(tmp_path))
    assert exc.value.kind == TIMED_OUT


@pytest.mark.parametrize("blocking", [False, True])
def test_net_fetch_deadline_is_bounded_in_running_loop_and_never_stores_late(
    tmp_path: Path, blocking: bool
) -> None:
    class Drip(httpx.AsyncByteStream):
        async def __aiter__(self) -> Any:
            if blocking:
                time.sleep(0.2)
            else:
                await asyncio.sleep(0.2)
            yield b"late"

    calls: list[bytes] = []
    class SpyStore:
        def put(self, body: bytes) -> Any:
            calls.append(body)
    context = net_context(tmp_path)
    object.__setattr__(context, "deadline", time.monotonic() + 0.05)
    handler = make_net_fetch_handler(
        SpyStore(),  # type: ignore[arg-type]
        client_factory=client_factory(
            httpx.MockTransport(lambda request: httpx.Response(
                200, headers={"content-type": "text/plain"}, stream=Drip(), request=request
            ))
        )
    )
    async def invoke() -> None:
        handler(context)
    started = time.monotonic()
    with pytest.raises(HandlerRefused) as exc:
        asyncio.run(invoke())
    assert exc.value.kind == TIMED_OUT
    assert time.monotonic() - started < 0.15
    time.sleep(0.2)
    assert calls == []


def test_test_run_execution_argv_changes_approval_authority(tmp_path: Path) -> None:
    env = environment(tmp_path)
    request = ToolRequest(call_id="bind-runner", tool="test.run", args={"extra_args": []})
    first = dispatch(
        request,
        manifest=REGISTRY["test.run"],
        environment=env,
        execution_argv=("/usr/bin/cargo", "test", "--"),
    )
    second = dispatch(
        request,
        manifest=REGISTRY["test.run"],
        environment=env,
        execution_argv=("/usr/bin/npm", "test", "--"),
    )
    assert first.approval_record is not None and second.approval_record is not None
    assert first.approval_record.action_hash != second.approval_record.action_hash
    assert first.approval_record.args_normalized["argv"] == [
        "/usr/bin/cargo",
        "test",
        "--",
    ]


def test_proc_exec_request_argv_cannot_conflict_with_execution_argv(tmp_path: Path) -> None:
    request = ToolRequest(
        call_id="conflicting-argv",
        tool="proc.exec",
        args={"argv": ["/usr/bin/true"]},
    )
    with pytest.raises(DispatchError, match="execution_argv differs from request argv"):
        dispatch(
            request,
            manifest=REGISTRY["proc.exec"],
            environment=environment(tmp_path),
            execution_argv=("/usr/bin/touch",),
        )


@pytest.mark.parametrize("size", [FETCH_BODY_LIMIT, FETCH_BODY_LIMIT + 1])
def test_net_fetch_size_boundary_and_store_ordering(tmp_path: Path, size: int) -> None:
    class SpyStore(FetchBodyStore):
        calls = 0

        def put(self, body: bytes) -> Any:
            self.calls += 1
            return super().put(body)

    store = SpyStore()
    transport = response_transport(
        {
            "https://example.test/resource": httpx.Response(
                200, headers={"content-type": "text/plain"}, content=b"x" * size
            )
        }
    )
    handler = make_net_fetch_handler(store, client_factory=client_factory(transport))
    if size == FETCH_BODY_LIMIT:
        assert handler(net_context(tmp_path))["byte_count"] == FETCH_BODY_LIMIT
        assert store.calls == 1
    else:
        with pytest.raises(HandlerRefused) as exc:
            handler(net_context(tmp_path))
        assert exc.value.kind == BODY_TOO_LARGE
        assert store.calls == 0


def test_net_fetch_maps_body_store_failure(tmp_path: Path) -> None:
    store = FetchBodyStore()
    store.close()
    transport = response_transport(
        {
            "https://example.test/resource": httpx.Response(
                200, headers={"content-type": "text/plain"}, content=b"x"
            )
        }
    )
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(store, client_factory=client_factory(transport))(
            net_context(tmp_path)
        )
    assert exc.value.kind == MEMORY_STORE_FAILED


def test_net_fetch_follows_relative_redirect_and_validates_each_hop(tmp_path: Path) -> None:
    transport = response_transport(
        {
            "https://example.test/resource": httpx.Response(302, headers={"location": "/next"}),
            "https://example.test/next": httpx.Response(
                200, headers={"content-type": "text/plain"}, content=b"ok"
            ),
        }
    )
    payload = make_net_fetch_handler(FetchBodyStore(), client_factory=client_factory(transport))(
        net_context(tmp_path)
    )
    assert payload["url"] == "https://example.test/next"
    assert payload["redirects"] == 1


def test_net_fetch_redirect_to_configured_domain_is_allowed(tmp_path: Path) -> None:
    transport = response_transport(
        {
            "https://initial.test/resource": httpx.Response(
                302, headers={"location": "https://allowed.test/final"}
            ),
            "https://allowed.test/final": httpx.Response(
                200, headers={"content-type": "application/json"}, content=b"{}"
            ),
        }
    )
    payload = make_net_fetch_handler(
        FetchBodyStore(),
        client_factory=client_factory(transport),
    )(net_context(tmp_path, domains=frozenset({"allowed.test"}), domain="initial.test"))
    assert payload["redirects"] == 1


@pytest.mark.parametrize(
    "location",
    ["https://evil.test/x", "http://example.test/x", "https://user@example.test/x", "https://example.test:8443/x", "ftp://example.test/x"],  # noqa: E501
)
def test_net_fetch_refuses_offlist_downgrade_or_userinfo_redirect(
    tmp_path: Path, location: str
) -> None:
    transport = response_transport(
        {"https://example.test/resource": httpx.Response(302, headers={"location": location})}
    )
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(FetchBodyStore(), client_factory=client_factory(transport))(
            net_context(tmp_path)
        )
    assert exc.value.kind == REDIRECT_REFUSED


def test_net_fetch_redirect_cap_is_bounded(tmp_path: Path) -> None:
    routes = {
        f"https://example.test/{index}": httpx.Response(302, headers={"location": f"/{index + 1}"})
        for index in range(MAX_REDIRECTS + 1)
    }
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(
            FetchBodyStore(), client_factory=client_factory(response_transport(routes))
        )(net_context(tmp_path, target="/0"))
    assert exc.value.kind == REDIRECT_REFUSED


@pytest.mark.parametrize(
    ("scheme", "domain", "target"),
    [
        ("http", "example.test", "/"),
        ("https", "user@example.test", "/"),
        ("https", "example.test:443", "/"),
        ("https", "example.test", "//evil.test/x"),
        ("https", "example.test", "/x#fragment"),
    ],
)
def test_net_fetch_rejects_authority_smuggling(
    tmp_path: Path, scheme: str, domain: str, target: str
) -> None:
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(FetchBodyStore())(
            net_context(tmp_path, scheme=scheme, domain=domain, target=target)
        )
    assert exc.value.kind == URL_REFUSED


def test_net_fetch_allows_exact_localhost_http_and_normalizes_trailing_dot(tmp_path: Path) -> None:
    transport = response_transport(
        {
            "http://localhost:8080/resource": httpx.Response(
                200, headers={"content-type": "text/plain"}, content=b"ok"
            )
        }
    )
    payload = make_net_fetch_handler(FetchBodyStore(), client_factory=client_factory(transport))(
        net_context(tmp_path, scheme="http", domain="LOCALHOST.", port=8080)
    )
    assert payload["url"] == "http://localhost:8080/resource"


# Coverage-floor branch cases: every refusal is observable, not line painting.


def test_proc_exec_rejects_relative_allowlist_entry() -> None:
    with pytest.raises(ValueError, match="absolute paths"):
        make_proc_exec_handler(frozenset({"true"}))


@pytest.mark.parametrize("argv", [None, [], ["/usr/bin/true", 1], ["/usr/bin/true", "a\x00b"]])
def test_proc_exec_rejects_malformed_argv(argv: object) -> None:
    with pytest.raises(HandlerRefused) as exc:
        make_proc_exec_handler(frozenset({"/usr/bin/true"}))({"argv": argv})
    assert exc.value.kind == EXECUTABLE_REFUSED


def test_test_run_accepts_pytest_ini_signal(tmp_path: Path) -> None:
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    runner = tmp_path / ".venv/bin/pytest"
    runner.parent.mkdir(parents=True)
    runner.write_text("runner", encoding="utf-8")
    assert make_test_run_handler(str(tmp_path))({}) == (str(runner),)


def test_test_run_rejects_detected_pytest_without_sandbox_runner(tmp_path: Path) -> None:
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    with pytest.raises(HandlerRefused) as exc:
        make_test_run_handler(str(tmp_path))({})
    assert exc.value.kind == RUNNER_MISSING
    assert ".venv/bin/pytest" in exc.value.detail


@pytest.mark.parametrize("content", ["not-json", "[]", '{"scripts": {}}'])
def test_invalid_or_testless_package_json_is_not_a_runner(tmp_path: Path, content: str) -> None:
    (tmp_path / "package.json").write_text(content, encoding="utf-8")
    with pytest.raises(HandlerRefused) as exc:
        make_test_run_handler(str(tmp_path))({})
    assert exc.value.kind == RUNNER_MISSING


def test_test_run_rejects_non_list_extra_args(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    with pytest.raises(HandlerRefused) as exc:
        make_test_run_handler(str(tmp_path))({"extra_args": "--all"})
    assert exc.value.kind == RUNNER_AMBIGUOUS


@pytest.mark.parametrize("domain", [None, "", " padded.test", ".", "bad..test", "bad_label.test"])
def test_net_fetch_rejects_invalid_domain_spellings(tmp_path: Path, domain: object) -> None:
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(FetchBodyStore())(net_context(tmp_path, domain=domain))
    assert exc.value.kind == URL_REFUSED


def test_net_fetch_internal_defenses(monkeypatch: pytest.MonkeyPatch) -> None:
    from lsassist.tools.handlers import net_fetch as module
    with pytest.raises(TypeError, match="immutable frozenset"):
        module._normalized_allowlist({"example.test"})  # type: ignore[arg-type]
    monkeypatch.setattr(module.httpx, "URL", lambda _: type("U", (), {"userinfo": b"x"})())
    with pytest.raises(HandlerRefused):
        module._url("https", "example.test", None, "/")
    monkeypatch.setattr(
        module.httpx, "URL", lambda _: (_ for _ in ()).throw(ValueError())
    )
    with pytest.raises(HandlerRefused):
        module._url("https", "example.test", None, "/")


@pytest.mark.parametrize(
    "overrides",
    [
        {"method": "POST"},
        {"scheme": "ftp"},
        {"port": True},
        {"port": 0},
        {"port": 65536},
        {"target": "relative"},
    ],
)
def test_net_fetch_rejects_invalid_authority_inputs(
    tmp_path: Path, overrides: dict[str, object]
) -> None:
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(FetchBodyStore())(net_context(tmp_path, **overrides))
    assert exc.value.kind == URL_REFUSED


def test_net_fetch_refuses_missing_redirect_location(tmp_path: Path) -> None:
    transport = response_transport({"https://example.test/resource": httpx.Response(302)})
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(FetchBodyStore(), client_factory=client_factory(transport))(
            net_context(tmp_path)
        )
    assert exc.value.kind == REDIRECT_REFUSED


def test_net_fetch_refuses_non_success_status(tmp_path: Path) -> None:
    transport = response_transport(
        {
            "https://example.test/resource": httpx.Response(
                503, headers={"content-type": "text/plain"}
            )
        }
    )
    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(FetchBodyStore(), client_factory=client_factory(transport))(
            net_context(tmp_path)
        )
    assert exc.value.kind == "fetch_failed"
    assert "503" in exc.value.detail


def test_net_fetch_maps_transport_error_without_leaking_message(tmp_path: Path) -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("TOP-SECRET", request=request)

    with pytest.raises(HandlerRefused) as exc:
        make_net_fetch_handler(
            FetchBodyStore(), client_factory=client_factory(httpx.MockTransport(broken))
        )(net_context(tmp_path))
    assert exc.value.kind == "fetch_failed"
    assert "ConnectError" in exc.value.detail
    assert "TOP-SECRET" not in exc.value.detail
