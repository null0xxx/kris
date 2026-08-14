"""T3.09 table-driven tests for the frozen Kimi §5.2 error taxonomy."""

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
    ProviderErrorKind,
    StreamEvent,
    unhealthy,
)
from lsassist.providers.kimi_coding import KimiCodingAdapter

SENTINEL_KEY = "sk-error-sentinel-not-real"


async def _collect(events: AsyncIterator[StreamEvent]) -> list[StreamEvent]:
    return [event async for event in events]


def _run(adapter: KimiCodingAdapter) -> list[StreamEvent]:
    return asyncio.run(
        _collect(
            adapter.stream_chat(
                ChatRequest(messages=[ChatMessage(role="user", content="classify")])
            )
        )
    )


def _client_factory(transport: httpx.MockTransport) -> Callable[..., httpx.AsyncClient]:
    def factory(**kwargs: Any) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=transport, **kwargs)

    return factory


@pytest.mark.parametrize(
    ("status", "condition", "kind", "retryable", "terminal", "message"),
    [
        (
            401,
            f"Invalid or expired API key {SENTINEL_KEY}",
            ProviderErrorKind.AUTH,
            False,
            True,
            "Kimi authentication failed",
        ),
        (
            401,
            "Current subscription tier does not allow the requested model",
            ProviderErrorKind.AUTH,
            False,
            True,
            "Kimi authentication failed",
        ),
        (
            402,
            f"Membership verification unavailable {SENTINEL_KEY}",
            ProviderErrorKind.TRANSIENT,
            True,
            False,
            "Kimi membership verification failed",
        ),
        (
            403,
            f"Weekly billing-cycle quota exhausted {SENTINEL_KEY}",
            ProviderErrorKind.QUOTA,
            False,
            True,
            "Kimi membership quota exhausted",
        ),
        (
            403,
            f"Access terminated due to policy {SENTINEL_KEY}",
            ProviderErrorKind.TERMINATED,
            False,
            True,
            "Kimi access terminated",
        ),
        (
            429,
            f"Five-hour usage limit for this period reached {SENTINEL_KEY}",
            ProviderErrorKind.QUOTA,
            False,
            False,
            "Kimi usage quota reached",
        ),
        (
            429,
            f"Monthly usage limit reached {SENTINEL_KEY}",
            ProviderErrorKind.QUOTA,
            False,
            False,
            "Kimi usage quota reached",
        ),
        (
            429,
            f"Engine overloaded; try later {SENTINEL_KEY}",
            ProviderErrorKind.OVERLOAD,
            True,
            False,
            "Kimi service overloaded",
        ),
        (
            429,
            f"Too many requests {SENTINEL_KEY}",
            ProviderErrorKind.RATE_LIMIT,
            True,
            False,
            "Kimi rate limit reached",
        ),
        (
            500,
            f"Internal server failure {SENTINEL_KEY}",
            ProviderErrorKind.TRANSIENT,
            True,
            False,
            "Kimi service temporarily unavailable",
        ),
        (
            499,
            f"Client disconnected {SENTINEL_KEY}",
            ProviderErrorKind.CLIENT,
            False,
            False,
            "Kimi request cancelled",
        ),
        (
            400,
            f"Missing reasoning_content in assistant tool call {SENTINEL_KEY}",
            ProviderErrorKind.CLIENT,
            False,
            False,
            "Kimi request rejected; provider output is blocked",
        ),
        (
            403,
            f"Unrecognized forbidden condition {SENTINEL_KEY}",
            ProviderErrorKind.QUOTA,
            False,
            True,
            "Kimi membership quota exhausted",
        ),
        (
            429,
            f"Unrecognized throttling condition {SENTINEL_KEY}",
            ProviderErrorKind.TRANSIENT,
            True,
            False,
            "HTTP 429 unclassified",
        ),
    ],
    ids=[
        "401-invalid-key",
        "401-tier",
        "402-membership",
        "403-weekly-quota",
        "403-access-terminated",
        "429-window",
        "429-monthly",
        "429-engine-overloaded",
        "429-too-many",
        "500-transient",
        "499-client",
        "400-reasoning-schema",
        "403-fallback",
        "429-unclassified",
    ],
)
def test_frozen_error_table_maps_each_condition_to_fixed_safe_error(
    status: int,
    condition: str,
    kind: ProviderErrorKind,
    retryable: bool,
    terminal: bool,
    message: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = httpx.Request("POST", "https://api.kimi.com/coding/v1/chat/completions")
    response = httpx.Response(
        status,
        headers={"content-type": "application/json", "x-secret": SENTINEL_KEY},
        content=json.dumps({"message": condition, "secret": SENTINEL_KEY}).encode(),
        request=request,
    )
    adapter = KimiCodingAdapter(api_key=SENTINEL_KEY)

    error = adapter.normalize_error(response)

    assert error.kind is kind
    assert error.retryable is retryable
    assert error.retry_after_s is None
    assert error.terminal is terminal
    assert error.message == message
    assert SENTINEL_KEY not in error.message
    assert caplog.records == []


def test_normalize_error_is_side_effect_free_for_tier_gating_response() -> None:
    request = httpx.Request("POST", "https://api.kimi.com/coding/v1/chat/completions")
    response = httpx.Response(
        401,
        content=b"Current subscription tier does not allow the requested model",
        request=request,
    )
    adapter = KimiCodingAdapter(api_key=SENTINEL_KEY, model="k3")

    assert adapter.normalize_error(response).kind is ProviderErrorKind.AUTH
    assert adapter.available_model_ids == (
        "kimi-for-coding",
        "k3",
        "kimi-for-coding-highspeed",
    )


def test_tier_gating_removes_only_requested_model_and_next_call_stays_local() -> None:
    calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            401,
            headers={"content-type": "application/json"},
            content=b"Current subscription tier does not allow the requested model",
            request=request,
        )

    adapter = KimiCodingAdapter(
        api_key=SENTINEL_KEY,
        model="k3",
        client_factory=_client_factory(httpx.MockTransport(route)),
    )

    first = _run(adapter)
    second = _run(adapter)

    assert first[0].error is not None
    assert first[0].error.kind is ProviderErrorKind.AUTH
    assert second[0].error is not None
    assert second[0].error.kind is ProviderErrorKind.AUTH
    assert adapter.available_model_ids == ("kimi-for-coding", "kimi-for-coding-highspeed")
    assert adapter.model == "k3"
    assert calls == 1


def test_invalid_key_401_does_not_change_model_catalog_or_retry() -> None:
    calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            401,
            content=f"Invalid API key {SENTINEL_KEY}".encode(),
            request=request,
        )

    adapter = KimiCodingAdapter(
        api_key=SENTINEL_KEY,
        model="k3",
        client_factory=_client_factory(httpx.MockTransport(route)),
    )

    events = _run(adapter)

    assert events[0].error is not None
    assert events[0].error.kind is ProviderErrorKind.AUTH
    assert adapter.available_model_ids == (
        "kimi-for-coding",
        "k3",
        "kimi-for-coding-highspeed",
    )
    assert calls == 1


def test_401_with_incidental_tier_and_model_words_does_not_downgrade_catalog() -> None:
    calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            401,
            content=b"Invalid key for model access on this tier",
            request=request,
        )

    adapter = KimiCodingAdapter(
        api_key=SENTINEL_KEY,
        model="k3",
        client_factory=_client_factory(httpx.MockTransport(route)),
    )

    events = _run(adapter)

    assert events[0].error is not None
    assert events[0].error.kind is ProviderErrorKind.AUTH
    assert adapter.available_model_ids == (
        "kimi-for-coding",
        "k3",
        "kimi-for-coding-highspeed",
    )
    assert calls == 1


def test_unmapped_object_uses_type_label_without_stringifying_raw_value() -> None:
    class HostileRaw:
        def __str__(self) -> str:
            raise AssertionError("normalize_error must not stringify raw objects")

    adapter = KimiCodingAdapter(api_key=SENTINEL_KEY)

    error = adapter.normalize_error(HostileRaw())

    assert error.kind is ProviderErrorKind.TRANSIENT
    assert error.retryable is True
    assert error.retry_after_s is None
    assert error.terminal is False
    assert error.message == "Kimi unmapped error (HostileRaw)"


def test_unmapped_http_status_uses_sanitized_status_only() -> None:
    request = httpx.Request("POST", "https://api.kimi.com/coding/v1/chat/completions")
    response = httpx.Response(
        418,
        content=f"raw body {SENTINEL_KEY}".encode(),
        request=request,
    )
    adapter = KimiCodingAdapter(api_key=SENTINEL_KEY)

    error = adapter.normalize_error(response)

    assert error.kind is ProviderErrorKind.TRANSIENT
    assert error.retryable is True
    assert error.message == "HTTP 418 unclassified"
    assert SENTINEL_KEY not in error.message


def test_transport_failure_is_one_sanitized_event_with_no_retry_or_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError(f"cannot connect with {SENTINEL_KEY}", request=request)

    adapter = KimiCodingAdapter(
        api_key=SENTINEL_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )

    events = _run(adapter)

    assert len(events) == 1
    assert events[0].kind == "error"
    assert events[0].error is not None
    assert events[0].error.kind is ProviderErrorKind.TRANSIENT
    assert events[0].error.retryable is True
    assert events[0].error.message == "Kimi unmapped error (ConnectError)"
    assert SENTINEL_KEY not in events[0].model_dump_json()
    assert adapter.healthcheck() == unhealthy("last request failed: transient")
    assert caplog.records == []
    assert calls == 1
