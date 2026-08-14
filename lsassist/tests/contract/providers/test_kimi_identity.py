"""T3.09 contract tests for Kimi request identity and credential boundaries."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest

from lsassist.providers.base import (
    ChatMessage,
    ChatRequest,
    ProviderError,
    ProviderErrorKind,
    ProviderProfile,
    StreamEvent,
    ensure_provider_profile,
)


async def _collect(events: AsyncIterator[StreamEvent]) -> list[StreamEvent]:
    return [event async for event in events]


def _client_factory(
    transport: httpx.MockTransport,
    *,
    options: dict[str, Any] | None = None,
) -> Callable[..., httpx.AsyncClient]:
    def factory(**kwargs: Any) -> httpx.AsyncClient:
        if options is not None:
            options.update(kwargs)
        return httpx.AsyncClient(transport=transport, **kwargs)

    return factory


def test_every_request_uses_official_endpoint_auth_and_honest_identity() -> None:
    try:
        from lsassist.providers.kimi_coding import KimiCodingAdapter
    except ModuleNotFoundError:
        pytest.fail("Kimi request behavior is not implemented")

    captured: list[httpx.Request] = []

    def route(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b"data: [DONE]\n\n",
            request=request,
        )

    adapter = KimiCodingAdapter(
        api_key="sk-test-identity-not-real",
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    events = asyncio.run(
        _collect(
            adapter.stream_chat(
                ChatRequest(messages=[ChatMessage(role="user", content="hello")])
            )
        )
    )

    assert events == [StreamEvent(kind="done")]
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "POST"
    assert str(request.url) == "https://api.kimi.com/coding/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer sk-test-identity-not-real"
    assert request.headers["user-agent"] == (
        "lsassist/0.1.0 (+https://github.com/null0xxx/kris)"
    )
    assert request.headers["content-type"] == "application/json"
    assert request.headers["accept"] == "text/event-stream"
    assert json.loads(request.content) == {
        "model": "kimi-for-coding",
        "messages": [{"role": "user", "content": "hello"}],
        "stream": True,
    }


def test_public_surface_is_frozen_and_uses_the_t3_08_profile_identity() -> None:
    from lsassist.providers import kimi_coding

    assert kimi_coding.__all__ == (
        "DEFAULT_KIMI_MODEL",
        "KIMI_CHAT_COMPLETIONS_URL",
        "KIMI_CODING_BASE_URL",
        "KIMI_MODEL_IDS",
        "KIMI_PROVIDER_ID",
        "KIMI_REPOSITORY_URL",
        "KimiCodingAdapter",
        "KimiRequestFailed",
    )
    adapter = kimi_coding.KimiCodingAdapter(api_key="sk-public-surface-not-real")
    assert isinstance(adapter, ProviderProfile)
    assert ensure_provider_profile(adapter) is adapter

    with pytest.raises(AttributeError):
        adapter.model = "k3"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        adapter.available_model_ids = ("k3",)  # type: ignore[misc]


def test_injected_secret_beats_environment_and_client_disables_proxy_and_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from lsassist.providers.kimi_coding import KimiCodingAdapter

    monkeypatch.setenv("LSASSIST_KIMI_API_KEY", "sk-environment-must-not-win")
    injected = "sk-injected-boundary-not-real"
    captured: list[httpx.Request] = []
    options: dict[str, Any] = {}

    def route(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            307,
            headers={"location": "https://credential-sink.invalid/redirect"},
            content=b"redirect body",
            request=request,
        )

    adapter = KimiCodingAdapter(
        api_key=injected,
        client_factory=_client_factory(httpx.MockTransport(route), options=options),
    )
    events = asyncio.run(
        _collect(
            adapter.stream_chat(
                ChatRequest(messages=[ChatMessage(role="user", content="do not redirect")])
            )
        )
    )

    assert options["trust_env"] is False
    assert options["follow_redirects"] is False
    assert len(captured) == 1
    assert str(captured[0].url) == "https://api.kimi.com/coding/v1/chat/completions"
    assert captured[0].headers["authorization"] == f"Bearer {injected}"
    assert b"sk-environment-must-not-win" not in captured[0].content
    assert injected.encode() not in captured[0].content
    assert len(events) == 1
    assert events[0].error is not None
    assert events[0].error.kind is ProviderErrorKind.TRANSIENT


def test_client_options_disable_environment_proxy_and_redirect_following() -> None:
    from lsassist.providers.kimi_coding import KimiCodingAdapter

    options: dict[str, Any] = {}
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b"data: [DONE]\n\n",
            request=request,
        )
    )
    adapter = KimiCodingAdapter(
        api_key="sk-client-options-not-real",
        client_factory=_client_factory(transport, options=options),
    )

    events = asyncio.run(
        _collect(
            adapter.stream_chat(
                ChatRequest(messages=[ChatMessage(role="user", content="options")])
            )
        )
    )

    assert events == [StreamEvent(kind="done")]
    assert options["trust_env"] is False
    assert options["follow_redirects"] is False


def test_honest_user_agent_is_rebuilt_on_success_error_and_later_request() -> None:
    from lsassist.providers.kimi_coding import KimiCodingAdapter

    captured: list[httpx.Request] = []
    responses = [200, 401, 200]

    def route(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        status = responses[len(captured) - 1]
        if status == 200:
            return httpx.Response(
                status,
                headers={"content-type": "text/event-stream"},
                content=b"data: [DONE]\n\n",
                request=request,
            )
        return httpx.Response(
            status,
            content=b"Invalid API key for this request",
            request=request,
        )

    adapter = KimiCodingAdapter(
        api_key="sk-three-requests-not-real",
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    request = ChatRequest(messages=[ChatMessage(role="user", content="identity")])

    first = asyncio.run(_collect(adapter.stream_chat(request)))
    second = asyncio.run(_collect(adapter.stream_chat(request)))
    third = asyncio.run(_collect(adapter.stream_chat(request)))

    assert first == [StreamEvent(kind="done")]
    assert second[0].error is not None
    assert second[0].error.kind is ProviderErrorKind.AUTH
    assert third == [StreamEvent(kind="done")]
    assert [item.headers["user-agent"] for item in captured] == [
        "lsassist/0.1.0 (+https://github.com/null0xxx/kris)",
        "lsassist/0.1.0 (+https://github.com/null0xxx/kris)",
        "lsassist/0.1.0 (+https://github.com/null0xxx/kris)",
    ]


def test_response_and_transport_credentials_never_escape_diagnostics(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from lsassist.providers.kimi_coding import KimiCodingAdapter, KimiRequestFailed

    secret = "sk-diagnostic-sentinel-not-real"
    requests: list[httpx.Request] = []

    def mapped_error(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            400,
            headers={"x-secret": secret},
            content=f"missing reasoning_content {secret}".encode(),
            request=request,
        )

    adapter = KimiCodingAdapter(
        api_key=secret,
        client_factory=_client_factory(httpx.MockTransport(mapped_error)),
    )
    events = asyncio.run(
        _collect(
            adapter.stream_chat(
                ChatRequest(messages=[ChatMessage(role="user", content="mapped error")])
            )
        )
    )

    assert len(events) == 1
    assert events[0].error is not None
    assert events[0].error.kind is ProviderErrorKind.CLIENT
    assert secret not in events[0].model_dump_json()
    assert secret not in repr(adapter)
    assert secret.encode() not in requests[0].content
    assert caplog.records == []

    transport_calls = 0

    def transport_error(request: httpx.Request) -> httpx.Response:
        nonlocal transport_calls
        transport_calls += 1
        raise httpx.ConnectError(f"transport included {secret}", request=request)

    failed_adapter = KimiCodingAdapter(
        api_key=secret,
        client_factory=_client_factory(httpx.MockTransport(transport_error)),
    )

    async def invoke() -> None:
        await failed_adapter.complete_tool_request(
            [ChatMessage(role="user", content="transport")],
            [],
        )

    with pytest.raises(KimiRequestFailed) as caught:
        asyncio.run(invoke())
    assert caught.value.error.kind is ProviderErrorKind.TRANSIENT
    assert secret not in caught.value.error.message
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)
    assert caplog.records == []
    assert transport_calls == 1


def test_safe_failure_wrapper_names_only_the_existing_error_kind() -> None:
    from lsassist.providers.kimi_coding import KimiRequestFailed

    error = ProviderError(
        kind=ProviderErrorKind.AUTH,
        retryable=False,
        terminal=True,
        message="body with sk-wrapper-sentinel-not-real",
    )
    wrapped = KimiRequestFailed(error)

    assert wrapped.error is error
    assert str(wrapped) == "Kimi request failed (auth)"
    assert repr(wrapped) == "KimiRequestFailed(kind='auth')"
    assert "sk-wrapper-sentinel-not-real" not in str(wrapped)
    assert "sk-wrapper-sentinel-not-real" not in repr(wrapped)
