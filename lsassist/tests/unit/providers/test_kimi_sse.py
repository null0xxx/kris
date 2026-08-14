"""T3.09 unit tests for Kimi request construction and streamed events."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest

from lsassist.providers.base import (
    AssistantTurn,
    ChatMessage,
    ChatRequest,
    Health,
    ModelCapabilities,
    ProviderError,
    ProviderErrorKind,
    ProviderProfile,
    StreamEvent,
    ToolSpec,
    UsageAccounting,
    ensure_provider_profile,
    healthy,
    unhealthy,
)
from lsassist.providers.kimi_coding import KimiCodingAdapter, KimiRequestFailed

TEST_API_KEY = "sk-test-request-not-real"


async def _collect(events: AsyncIterator[StreamEvent]) -> list[StreamEvent]:
    return [event async for event in events]


def _run(adapter: KimiCodingAdapter, request: ChatRequest) -> list[StreamEvent]:
    return asyncio.run(_collect(adapter.stream_chat(request)))


def _complete(
    adapter: KimiCodingAdapter,
    messages: list[ChatMessage],
    tools: list[ToolSpec],
    *,
    cancel_token: asyncio.Event | None = None,
) -> AssistantTurn:
    async def invoke() -> AssistantTurn:
        method = getattr(adapter, "complete_tool_request", None)
        assert callable(method), "complete_tool_request behavior is not implemented"
        return await method(messages, tools, cancel_token=cancel_token)

    return asyncio.run(invoke())


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


def _done_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        content=b"data: [DONE]\n\n",
        request=request,
    )


def _error_event(kind: ProviderErrorKind, *, terminal: bool = False) -> StreamEvent:
    return StreamEvent(
        kind="error",
        error=ProviderError(
            kind=kind,
            retryable=False,
            terminal=terminal,
            message=(
                "Kimi authentication failed"
                if kind is ProviderErrorKind.AUTH
                else "Kimi request validation failed"
            ),
        ),
    )


def _protocol_error_event() -> StreamEvent:
    return StreamEvent(
        kind="error",
        error=ProviderError(
            kind=ProviderErrorKind.TRANSIENT,
            retryable=True,
            terminal=False,
            message="Kimi stream protocol failed",
        ),
    )


class ByteChunks(httpx.AsyncByteStream):
    """Real HTTPX byte-stream seam with caller-controlled hostile boundaries."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


def _stream_adapter(
    chunks: list[bytes],
    *,
    content_type: str = "text/event-stream",
) -> KimiCodingAdapter:
    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": content_type},
            stream=ByteChunks(chunks),
            request=request,
        )

    return KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )


def _cleanup_failure(kind: str, request: httpx.Request) -> Exception:
    message = f"cleanup failed for {TEST_API_KEY}"
    if kind == "read-error":
        return httpx.ReadError(message, request=request)
    if kind == "runtime-error":
        return RuntimeError(message)
    raise AssertionError(f"unknown test cleanup kind: {kind}")


async def _capture_complete_outcome(
    adapter: KimiCodingAdapter,
    message: str,
    *,
    cancel_token: asyncio.Event | None = None,
) -> tuple[AssistantTurn | None, KimiRequestFailed | None, Exception | None]:
    try:
        turn = await adapter.complete_tool_request(
            [ChatMessage(role="user", content=message)],
            [],
            cancel_token=cancel_token,
        )
    except KimiRequestFailed as exc:
        return None, exc, None
    except Exception as exc:
        return None, None, exc
    return turn, None, None


async def _live_child_task_count_after_quiescence() -> int:
    empty_turns = 0
    live_children: list[asyncio.Task[Any]] = []
    for _ in range(20):
        await asyncio.sleep(0)
        live_children = [
            task for task in asyncio.all_tasks() if task is not asyncio.current_task()
        ]
        empty_turns = empty_turns + 1 if not live_children else 0
        if empty_turns == 3:
            return 0
    return len(live_children)


FULL_TOOL_STREAM = (
    b'data: {"choices":[{"delta":{"reasoning_content":"think ","content":"an",'
    b'"tool_calls":[{"index":0,"id":"call_0","type":"function","function":'
    b'{"name":"read_file","arguments":"{\\"path\\":"}},{"index":1,"id":'
    b'"call_1","type":"function","function":{"name":"list_dir","arguments":""}}]}}]}\n\n'
    b'data: {"choices":[{"delta":{"reasoning_content":"more","content":"swer",'
    b'"tool_calls":[{"index":0,"function":{"arguments":"\\"a\\"}"}},{"index":1,'
    b'"function":{"arguments":"{}"}}]}}],"usage":{"prompt_tokens":11,'
    b'"completion_tokens":7,"total_tokens":18}}\n\n'
    b"data: [DONE]\n\n"
)
RETAINED_TOOL_STREAM = (
    b'data: {"choices":[{"delta":{"reasoning_content":"private","content":"call",'
    b'"tool_calls":[{"index":0,"id":"retained_0","type":"function","function":'
    b'{"name":"read_file","arguments":"{}"}}]}}],"usage":{"prompt_tokens":2,'
    b'"completion_tokens":3}}\n\ndata: [DONE]\n\n'
)
SECOND_RETAINED_TOOL_STREAM = RETAINED_TOOL_STREAM.replace(b"retained_0", b"retained_1")
FINAL_TEXT_STREAM = b'data: {"choices":[{"delta":{"content":"final"}}]}\n\ndata: [DONE]\n\n'


TOOLS = [
    ToolSpec(name="read_file", description="Read one file", parameters={"type": "object"}),
    ToolSpec(name="list_dir", description="List one directory", parameters={"type": "object"}),
]


@pytest.mark.parametrize(
    "model",
    ["kimi-for-coding", "k3", "kimi-for-coding-highspeed"],
)
def test_model_request_sends_each_frozen_id_without_substitution(model: str) -> None:
    bodies: list[dict[str, Any]] = []

    def route(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return _done_response(request)

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        model=model,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    assert adapter.model == model
    assert adapter.available_model_ids == (
        "kimi-for-coding",
        "k3",
        "kimi-for-coding-highspeed",
    )

    assert _run(
        adapter,
        ChatRequest(messages=[ChatMessage(role="user", content="model request")]),
    ) == [StreamEvent(kind="done")]
    assert bodies == [
        {
            "model": model,
            "messages": [{"role": "user", "content": "model request"}],
            "stream": True,
        }
    ]


def test_unknown_model_request_fails_before_transport_without_default_substitution() -> None:
    transport_calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal transport_calls
        transport_calls += 1
        return _done_response(request)

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        model="typo-model",
        client_factory=_client_factory(httpx.MockTransport(route)),
    )

    assert _run(
        adapter,
        ChatRequest(messages=[ChatMessage(role="user", content="never sent")]),
    ) == [_error_event(ProviderErrorKind.CLIENT)]
    assert adapter.model == "typo-model"
    assert transport_calls == 0


def test_unavailable_model_request_is_cached_and_never_substituted() -> None:
    requests: list[httpx.Request] = []

    def route(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            401,
            headers={"content-type": "application/json"},
            content=(
                b'{"message":"Current subscription tier does not allow the requested model"}'
            ),
            request=request,
        )

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        model="k3",
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    request = ChatRequest(messages=[ChatMessage(role="user", content="tier check")])

    assert _run(adapter, request) == [_error_event(ProviderErrorKind.AUTH, terminal=True)]
    assert adapter.available_model_ids == ("kimi-for-coding", "kimi-for-coding-highspeed")
    assert _run(adapter, request) == [_error_event(ProviderErrorKind.AUTH, terminal=True)]
    assert adapter.model == "k3"
    assert len(requests) == 1


def test_tool_request_serializes_strict_openai_shape_and_optional_limits() -> None:
    bodies: list[dict[str, Any]] = []

    def route(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return _done_response(request)

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    tool = ToolSpec(
        name="read_file",
        description="Read one file",
        parameters={"type": "object", "properties": {}},
    )

    assert _run(
        adapter,
        ChatRequest(
            messages=[ChatMessage(role="user", content="read")],
            tools=[tool],
            effort="high",
            max_output_tokens=262_144,
            timeout_s=2.5,
        ),
    ) == [StreamEvent(kind="done")]
    assert bodies == [
        {
            "model": "kimi-for-coding",
            "messages": [{"role": "user", "content": "read"}],
            "stream": True,
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "read_file",
                        "description": "Read one file",
                        "parameters": {"type": "object", "properties": {}},
                        "strict": True,
                    },
                }
            ],
            "reasoning_effort": "high",
            "max_tokens": 262_144,
        }
    ]


@pytest.mark.parametrize("name", ["abc", "a" * 64])
def test_tool_request_accepts_exact_name_boundaries(name: str) -> None:
    calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _done_response(request)

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    events = _run(
        adapter,
        ChatRequest(
            messages=[ChatMessage(role="user", content="tool")],
            tools=[ToolSpec(name=name)],
        ),
    )

    assert events == [StreamEvent(kind="done")]
    assert calls == 1


@pytest.mark.parametrize(
    "name",
    ["ab", "a" * 65, "1ab", "a b", "a/b", "a.b"],
)
def test_tool_request_rejects_invalid_name_before_transport(name: str) -> None:
    calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _done_response(request)

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    events = _run(
        adapter,
        ChatRequest(
            messages=[ChatMessage(role="user", content="tool")],
            tools=[ToolSpec(name=name)],
        ),
    )

    assert events == [_error_event(ProviderErrorKind.CLIENT)]
    assert calls == 0


def test_request_omits_absent_optional_fields_and_api_key_from_json() -> None:
    bodies: list[dict[str, Any]] = []

    def route(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        assert TEST_API_KEY.encode() not in request.content
        return _done_response(request)

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )

    assert _run(
        adapter,
        ChatRequest(messages=[ChatMessage(role="user", content="small λ")]),
    ) == [StreamEvent(kind="done")]
    assert bodies == [
        {
            "model": "kimi-for-coding",
            "messages": [{"role": "user", "content": "small λ"}],
            "stream": True,
        }
    ]


def test_request_rejects_token_limit_above_frozen_cap_before_transport() -> None:
    calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _done_response(request)

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    events = _run(
        adapter,
        ChatRequest(
            messages=[ChatMessage(role="user", content="too many tokens")],
            max_output_tokens=262_145,
        ),
    )

    assert events == [_error_event(ProviderErrorKind.CLIENT)]
    assert calls == 0


def test_body_request_rejects_exactly_one_byte_over_frozen_cap_before_transport() -> None:
    calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _done_response(request)

    empty_payload = {
        "model": "kimi-for-coding",
        "messages": [{"role": "user", "content": ""}],
        "stream": True,
    }
    empty_size = len(
        json.dumps(empty_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )
    content = "x" * (2_097_153 - empty_size)
    expected_payload = {
        "model": "kimi-for-coding",
        "messages": [{"role": "user", "content": content}],
        "stream": True,
    }
    expected_bytes = json.dumps(
        expected_payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert len(expected_bytes) == 2_097_153

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    events = _run(
        adapter,
        ChatRequest(messages=[ChatMessage(role="user", content=content)]),
    )

    assert events == [_error_event(ProviderErrorKind.CLIENT)]
    assert calls == 0


@pytest.mark.parametrize("api_key", ["", "   ", " padded", "padded "])
def test_request_constructor_rejects_empty_or_padded_api_key_before_client(
    api_key: str,
) -> None:
    factory_calls = 0

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        nonlocal factory_calls
        factory_calls += 1
        return httpx.AsyncClient(**kwargs)

    with pytest.raises(ValueError, match="Kimi API key must be non-empty and unpadded"):
        KimiCodingAdapter(api_key=api_key, client_factory=factory)
    assert factory_calls == 0


def test_sse_chunk_boundaries_preserve_utf8_and_dispatch_multiple_records() -> None:
    wire = (
        'data: {"choices":[{"delta":{"content":"café"}}]}\n\n'
        'data: {"choices":[{"delta":{"content":"!"}}]}\n\n'
        "data: [DONE]\n\n"
    ).encode()
    utf8_start = wire.index("é".encode())
    chunks = [
        wire[:2],
        wire[2:4],
        wire[4:5],
        wire[5:utf8_start],
        wire[utf8_start : utf8_start + 1],
        wire[utf8_start + 1 :],
    ]

    events = _run(
        _stream_adapter(chunks),
        ChatRequest(messages=[ChatMessage(role="user", content="stream")]),
    )

    assert events == [
        StreamEvent(kind="text_delta", text="café"),
        StreamEvent(kind="text_delta", text="!"),
        StreamEvent(kind="done"),
    ]


def test_sse_valid_replacement_character_is_preserved_across_byte_chunks() -> None:
    wire = (
        'data: {"choices":[{"delta":{"content":"\ufffd"}}]}\n\n'
        "data: [DONE]\n\n"
    ).encode()
    replacement_start = wire.index("\ufffd".encode())
    chunks = [
        wire[: replacement_start + 1],
        wire[replacement_start + 1 : replacement_start + 2],
        wire[replacement_start + 2 :],
    ]

    events = _run(
        _stream_adapter(chunks),
        ChatRequest(messages=[ChatMessage(role="user", content="replacement")]),
    )

    assert events == [
        StreamEvent(kind="text_delta", text="\ufffd"),
        StreamEvent(kind="done"),
    ]


def test_sse_crlf_comments_ignored_fields_and_data_free_records() -> None:
    wire = (
        b": keepalive\r\n"
        b"event: message\r\n"
        b"id: 7\r\n"
        b"retry: 20\r\n"
        b"unknown: ignored\r\n"
        b"data: {\"choices\":[{\"delta\":{\"content\":\"ordered\"}}]}\r\n"
        b"\r\n"
        b"event: data-free\r\n\r\n"
        b"\r\n"
        b"data:[DONE]\r\n\r\n"
    )

    events = _run(
        _stream_adapter([wire]),
        ChatRequest(messages=[ChatMessage(role="user", content="crlf")]),
    )

    assert events == [
        StreamEvent(kind="text_delta", text="ordered"),
        StreamEvent(kind="done"),
    ]


def test_sse_multiline_data_joins_with_one_newline_before_json_decode() -> None:
    wire = (
        b'data: {"choices":[\n'
        b'data: {"delta":{"content":"joined"}}]}\n\n'
        b"data: [DONE]\n\n"
    )

    events = _run(
        _stream_adapter([wire]),
        ChatRequest(messages=[ChatMessage(role="user", content="multiline")]),
    )

    assert events == [
        StreamEvent(kind="text_delta", text="joined"),
        StreamEvent(kind="done"),
    ]


def test_sse_multiline_numeric_token_is_not_accidentally_concatenated() -> None:
    wire = (
        b'data: {"choices":[],"ignored":-\n'
        b"data: 1}\n\n"
        b"data: [DONE]\n\n"
    )

    events = _run(
        _stream_adapter([wire]),
        ChatRequest(messages=[ChatMessage(role="user", content="bad multiline")]),
    )

    assert events == [_protocol_error_event()]


def test_done_sentinel_emits_once_and_stops_before_trailing_bytes() -> None:
    wire = (
        b"data: [DONE]\n\n"
        b'data: {"choices":[{"delta":{"content":"must not appear"}}]}\n\n'
        b"data: [DONE]\n\n"
    )

    events = _run(
        _stream_adapter([wire]),
        ChatRequest(messages=[ChatMessage(role="user", content="stop")]),
    )

    assert events == [StreamEvent(kind="done")]


def test_done_sentinel_at_eof_needs_no_final_blank_record() -> None:
    events = _run(
        _stream_adapter([b"data: [DONE]"]),
        ChatRequest(messages=[ChatMessage(role="user", content="eof")]),
    )

    assert events == [StreamEvent(kind="done")]


def test_finish_reason_without_done_ends_with_incomplete_stream_error() -> None:
    wire = b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'

    events = _run(
        _stream_adapter([wire]),
        ChatRequest(messages=[ChatMessage(role="user", content="unfinished")]),
    )

    assert events == [_protocol_error_event()]


def test_sse_role_only_and_empty_delta_do_not_emit_model_events() -> None:
    wire = (
        b'data: {"choices":[{"delta":{"role":"assistant"}}]}\n\n'
        b'data: {"choices":[{"delta":{}}]}\n\n'
        b"data: [DONE]\n\n"
    )

    events = _run(
        _stream_adapter([wire]),
        ChatRequest(messages=[ChatMessage(role="user", content="empty")]),
    )

    assert events == [StreamEvent(kind="done")]


@pytest.mark.parametrize(
    "wire",
    [
        b'data: {"choices":[{"delta":{"content":"\xff"}}]}\n\n',
        b"data: {not-json}\n\n",
        b"data: []\n\n",
        b'data: {"choices":"wrong"}\n\n',
        b'data: {"choices":[7]}\n\n',
        b'data: {"choices":[{"delta":"wrong"}]}\n\n',
        b'data: {"choices":[{"delta":{"reasoning_content":7}}]}\n\n',
        b'data: {"choices":[{"delta":{"content":7}}]}\n\n',
        b'data: {"choices":[{"delta":{"tool_calls":{}}}]}\n\n',
        b'data: {"choices":[{"delta":{"tool_calls":[7]}}]}\n\n',
        b'data: {"choices":[],"usage":[]}\n\n',
        b'data: {"choices":[],"usage":{"prompt_tokens":true,"completion_tokens":1}}\n\n',
    ],
    ids=[
        "utf8",
        "json",
        "non-object",
        "choices",
        "choice-item",
        "delta",
        "reasoning-type",
        "content-type",
        "tool-calls-type",
        "tool-call-item",
        "usage-type",
        "usage-token-type",
    ],
)
def test_malformed_sse_payload_emits_one_sanitized_transient_error(wire: bytes) -> None:
    events = _run(
        _stream_adapter([wire]),
        ChatRequest(messages=[ChatMessage(role="user", content="malformed")]),
    )

    assert events == [_protocol_error_event()]
    assert b"not-json" not in events[0].model_dump_json().encode()


def test_content_type_must_be_event_stream_before_body_is_parsed() -> None:
    events = _run(
        _stream_adapter(
            [b'data: {"choices":[{"delta":{"content":"not parsed"}}]}\n\n'],
            content_type="application/json",
        ),
        ChatRequest(messages=[ChatMessage(role="user", content="wrong type")]),
    )

    assert events == [_protocol_error_event()]


def test_reasoning_text_tool_call_and_usage_events_have_fixed_order() -> None:
    adapter = _stream_adapter([FULL_TOOL_STREAM[:37], FULL_TOOL_STREAM[37:]])

    events = _run(
        adapter,
        ChatRequest(
            messages=[ChatMessage(role="user", content="use tools")],
            tools=TOOLS,
            effort="high",
        ),
    )

    assert events == [
        StreamEvent(kind="reasoning_delta", text="think "),
        StreamEvent(kind="text_delta", text="an"),
        StreamEvent(
            kind="tool_call_delta",
            tool_call={
                "index": 0,
                "id": "call_0",
                "type": "function",
                "function": {
                    "name": "read_file",
                    "arguments": '{"path":',
                },
            },
        ),
        StreamEvent(
            kind="tool_call_delta",
            tool_call={
                "index": 1,
                "id": "call_1",
                "type": "function",
                "function": {"name": "list_dir", "arguments": ""},
            },
        ),
        StreamEvent(kind="reasoning_delta", text="more"),
        StreamEvent(kind="text_delta", text="swer"),
        StreamEvent(
            kind="tool_call_delta",
            tool_call={
                "index": 0,
                "function": {"arguments": '"a"}'},
            },
        ),
        StreamEvent(
            kind="tool_call_delta",
            tool_call={
                "index": 1,
                "function": {"arguments": "{}"},
            },
        ),
        StreamEvent(
            kind="usage",
            usage=UsageAccounting(requests_made=1, tokens_in=11, tokens_out=7),
        ),
        StreamEvent(kind="done"),
    ]


def test_choice_level_usage_is_translated_and_recorded_once() -> None:
    wire = (
        b'data: {"choices":[{"delta":{},"usage":{"prompt_tokens":2,'
        b'"completion_tokens":3,"total_tokens":5}}]}\n\n'
        b"data: [DONE]\n\n"
    )
    adapter = _stream_adapter([wire])

    events = _run(
        adapter,
        ChatRequest(messages=[ChatMessage(role="user", content="usage")]),
    )

    assert events == [
        StreamEvent(
            kind="usage",
            usage=UsageAccounting(requests_made=1, tokens_in=2, tokens_out=3),
        ),
        StreamEvent(kind="done"),
    ]
    usage = getattr(adapter, "usage", None)
    assert callable(usage), "usage accounting behavior is not implemented"
    assert usage() == UsageAccounting(requests_made=1, tokens_in=2, tokens_out=3)


def test_complete_tool_request_assembles_reasoning_parallel_calls_and_usage() -> None:
    adapter = _stream_adapter([FULL_TOOL_STREAM])

    try:
        turn = _complete(
            adapter,
            [ChatMessage(role="user", content="use tools")],
            TOOLS,
        )
    except Exception as exc:
        raise AssertionError("a valid fragmented tool call must complete") from exc

    assert turn.text == "answer"
    assert turn.tool_requests == [
        {
            "id": "call_0",
            "type": "function",
            "function": {"name": "read_file", "arguments": '{"path":"a"}'},
        },
        {
            "id": "call_1",
            "type": "function",
            "function": {"name": "list_dir", "arguments": "{}"},
        },
    ]
    assert turn.reasoning_opaque == "think more"
    assert "think more" not in turn.model_dump_json()
    assert "think more" not in repr(turn)
    assert turn.usage == UsageAccounting(requests_made=1, tokens_in=11, tokens_out=7)


def test_continuation_resends_private_reasoning_and_call_ids_without_mutating_messages(
    caplog: pytest.LogCaptureFixture,
) -> None:
    bodies: list[dict[str, Any]] = []
    response_bodies = [
        FULL_TOOL_STREAM,
        (
            b'data: {"choices":[{"delta":{"content":"final"}}]}\n\n'
            b"data: [DONE]\n\n"
        ),
    ]

    def route(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=ByteChunks([response_bodies[len(bodies) - 1]]),
            request=request,
        )

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    first_turn = _complete(
        adapter,
        [ChatMessage(role="user", content="use tools")],
        TOOLS,
    )
    continuation = [
        ChatMessage(role="assistant", content="answer"),
        ChatMessage(role="tool", content='{"content":"file"}'),
        ChatMessage(role="tool", content='{"entries":[]}'),
    ]
    before = [message.model_dump() for message in continuation]

    second_turn = _complete(adapter, continuation, TOOLS)

    assert second_turn.text == "final"
    assert bodies[1]["messages"] == [
        {
            "role": "assistant",
            "content": "answer",
            "reasoning_content": "think more",
            "tool_calls": [
                {
                    "id": "call_0",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": '{"path":"a"}'},
                },
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "list_dir", "arguments": "{}"},
                },
            ],
        },
        {
            "role": "tool",
            "content": '{"content":"file"}',
            "tool_call_id": "call_0",
        },
        {
            "role": "tool",
            "content": '{"entries":[]}',
            "tool_call_id": "call_1",
        },
    ]
    assert [message.model_dump() for message in continuation] == before
    assert "think more" not in first_turn.model_dump_json()
    assert "think more" not in repr(first_turn)
    assert caplog.records == []


def test_full_retained_history_survives_repeated_tool_loops_and_final_turn() -> None:
    responses = [
        RETAINED_TOOL_STREAM,
        SECOND_RETAINED_TOOL_STREAM,
        FINAL_TEXT_STREAM,
        b"data: [DONE]\n\n",
    ]
    bodies: list[dict[str, Any]] = []
    def route(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=ByteChunks([responses[len(bodies) - 1]]),
            request=request,
        )
    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    history = [ChatMessage(role="user", content="seed")]
    def complete() -> AssistantTurn:
        before = [message.model_dump() for message in history]
        try:
            turn = _complete(adapter, history, TOOLS)
        except KimiRequestFailed as exc:
            pytest.fail(f"retained history was rejected: {exc.error.kind.value}")
        assert [message.model_dump() for message in history] == before
        return turn
    for result in ("file", "file-2"):
        turn = complete()
        history += [
            ChatMessage(role="assistant", content=turn.text),
            ChatMessage(role="tool", content=result),
        ]
    final = complete()
    history += [
        ChatMessage(role="assistant", content=final.text),
        ChatMessage(role="user", content="later"),
    ]
    complete()
    wire = bodies[2]["messages"]
    assert [message["role"] for message in wire] == [
        "user", "assistant", "tool", "assistant", "tool"
    ]
    assert [message["content"] for message in wire] == [
        "seed", "call", "file", "call", "file-2"
    ]
    for assistant_index, call_id in ((1, "retained_0"), (3, "retained_1")):
        assistant = wire[assistant_index]
        assert assistant.get("reasoning_content") == "private"
        assert [call["id"] for call in assistant["tool_calls"]] == [call_id]
        assert wire[assistant_index + 1]["tool_call_id"] == call_id
    assert bodies[3]["messages"] == [
        *wire,
        {"role": "assistant", "content": "final"},
        {"role": "user", "content": "later"},
    ]
    assert len(bodies) == 4
    assert adapter.usage() == UsageAccounting(requests_made=4, tokens_in=4, tokens_out=6)


@pytest.mark.parametrize(
    "continuation",
    [
        [
            ChatMessage(role="assistant", content="wrong"),
            ChatMessage(role="tool", content="first"),
            ChatMessage(role="tool", content="second"),
        ],
        [
            ChatMessage(role="assistant", content="answer"),
            ChatMessage(role="tool", content="only one"),
        ],
        [
            ChatMessage(role="assistant", content="answer"),
            ChatMessage(role="tool", content="first"),
            ChatMessage(role="user", content="out of order"),
        ],
        [
            ChatMessage(role="assistant", content="answer"),
            ChatMessage(role="tool", content="first"),
            ChatMessage(role="tool", content="second"),
            ChatMessage(role="tool", content="extra"),
        ],
    ],
    ids=["assistant", "count", "order", "extra"],
)
def test_continuation_mismatch_fails_before_second_transport(
    continuation: list[ChatMessage],
) -> None:
    calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=ByteChunks([FULL_TOOL_STREAM]),
            request=request,
        )

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    _complete(adapter, [ChatMessage(role="user", content="seed")], TOOLS)

    with pytest.raises(Exception) as caught:
        _complete(adapter, continuation, TOOLS)
    assert type(caught.value).__name__ == "KimiRequestFailed"
    assert caught.value.error.kind is ProviderErrorKind.CLIENT
    assert caught.value.error.retryable is False
    assert calls == 1


def test_tool_message_without_pending_state_fails_before_transport() -> None:
    calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _done_response(request)

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )

    with pytest.raises(Exception) as caught:
        _complete(adapter, [ChatMessage(role="tool", content="orphan")], TOOLS)
    assert type(caught.value).__name__ == "KimiRequestFailed"
    assert caught.value.error.kind is ProviderErrorKind.CLIENT
    assert calls == 0


@pytest.mark.parametrize(
    "second_fragment",
    [
        {"index": 0, "id": "other"},
        {"index": 0, "function": {"name": "other"}},
    ],
    ids=["id", "name"],
)
def test_complete_rejects_conflicting_tool_call_identity(
    second_fragment: dict[str, Any],
) -> None:
    first = {
        "choices": [
            {
                "delta": {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call_0",
                            "type": "function",
                            "function": {"name": "read_file", "arguments": "{}"},
                        }
                    ]
                }
            }
        ]
    }
    second = {"choices": [{"delta": {"tool_calls": [second_fragment]}}]}
    wire = (
        f"data: {json.dumps(first, separators=(',', ':'))}\n\n"
        f"data: {json.dumps(second, separators=(',', ':'))}\n\n"
        "data: [DONE]\n\n"
    ).encode()
    adapter = _stream_adapter([wire])

    with pytest.raises(Exception) as caught:
        _complete(adapter, [ChatMessage(role="user", content="conflict")], TOOLS)
    assert type(caught.value).__name__ == "KimiRequestFailed"
    assert caught.value.error.kind is ProviderErrorKind.CLIENT
    assert caught.value.error.retryable is False


@pytest.mark.parametrize(
    "tool_delta",
    [
        {"id": "call_0", "function": {"name": "read_file", "arguments": "{}"}},
        {
            "index": 0,
            "id": "call_0",
            "type": "function",
            "function": {"name": "read_file", "arguments": 7},
        },
        {
            "index": 0,
            "id": "call_0",
            "type": "function",
            "function": {"name": "read_file", "arguments": "{"},
        },
    ],
    ids=["missing-index", "non-string-arguments", "incomplete-json"],
)
def test_complete_rejects_malformed_tool_call_before_done(
    tool_delta: dict[str, Any],
) -> None:
    chunk = {"choices": [{"delta": {"tool_calls": [tool_delta]}}]}
    wire = (
        f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n"
        "data: [DONE]\n\n"
    ).encode()
    adapter = _stream_adapter([wire])

    with pytest.raises(Exception) as caught:
        _complete(adapter, [ChatMessage(role="user", content="malformed call")], TOOLS)
    assert type(caught.value).__name__ == "KimiRequestFailed"
    assert caught.value.error.kind is ProviderErrorKind.CLIENT


def test_profile_usage_and_health_snapshots_are_structural_and_network_free() -> None:
    calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _done_response(request)

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    assert adapter.id == "kimi-coding"
    assert adapter.capabilities == ModelCapabilities(
        tool_calling=True,
        parallel_tools=True,
        streaming=True,
        thinking=True,
    )
    assert isinstance(adapter, ProviderProfile)
    assert ensure_provider_profile(adapter) is adapter
    assert adapter.usage() == UsageAccounting()
    assert adapter.healthcheck() == healthy(detail="configured, not yet contacted")
    assert calls == 0

    assert _run(
        adapter,
        ChatRequest(messages=[ChatMessage(role="user", content="healthy")]),
    ) == [StreamEvent(kind="done")]
    assert adapter.usage() == UsageAccounting(requests_made=1)
    assert adapter.healthcheck() == healthy(detail="last request completed")
    assert calls == 1

    adapter_with_failure = _stream_adapter([b"not-sse"], content_type="application/json")
    assert _run(
        adapter_with_failure,
        ChatRequest(messages=[ChatMessage(role="user", content="unhealthy")]),
    ) == [_protocol_error_event()]
    assert adapter_with_failure.healthcheck() == unhealthy(
        "last request failed: transient"
    )


def test_cancelled_complete_request_raises_safe_client_error_before_transport() -> None:
    calls = 0

    def route(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _done_response(request)

    adapter = KimiCodingAdapter(
        api_key=TEST_API_KEY,
        client_factory=_client_factory(httpx.MockTransport(route)),
    )
    cancel_token = asyncio.Event()
    cancel_token.set()

    with pytest.raises(Exception) as caught:
        _complete(
            adapter,
            [ChatMessage(role="user", content="cancel")],
            TOOLS,
            cancel_token=cancel_token,
        )
    assert type(caught.value).__name__ == "KimiRequestFailed"
    assert caught.value.error.kind is ProviderErrorKind.CLIENT
    assert caught.value.error.retryable is False
    assert caught.value.error.message == "Kimi request cancelled"
    assert TEST_API_KEY not in str(caught.value)
    assert TEST_API_KEY not in repr(caught.value)
    assert calls == 0


def test_complete_timeout_is_non_retryable_client_and_adapter_stays_reusable() -> None:
    async def scenario() -> None:
        calls = 0

        def route(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise httpx.ReadTimeout(
                    f"deadline exceeded for {TEST_API_KEY}",
                    request=request,
                )
            return _done_response(request)

        adapter = KimiCodingAdapter(
            api_key=TEST_API_KEY,
            client_factory=_client_factory(httpx.MockTransport(route)),
        )
        with pytest.raises(KimiRequestFailed) as caught:
            await adapter.complete_tool_request(
                [ChatMessage(role="user", content="timeout")],
                [],
                timeout_s=0.01,
            )

        assert caught.value.error == ProviderError(
            kind=ProviderErrorKind.CLIENT,
            retryable=False,
            terminal=False,
            message="Kimi request cancelled",
        )
        assert TEST_API_KEY not in caught.value.error.message
        assert TEST_API_KEY not in str(caught.value)
        assert TEST_API_KEY not in repr(caught.value)

        second_turn = await adapter.complete_tool_request(
            [ChatMessage(role="user", content="after timeout")],
            [],
        )
        assert second_turn == AssistantTurn(
            text="",
            tool_requests=[],
            reasoning_opaque="",
            usage=UsageAccounting(requests_made=1),
        )
        assert calls == 2

    asyncio.run(scenario())


def test_complete_cancel_token_stops_inflight_stream_and_releases_adapter() -> None:
    async def scenario() -> None:
        started = asyncio.Event()
        release = asyncio.Event()
        closed = asyncio.Event()
        cancel_token = asyncio.Event()
        calls = 0

        class BlockingStream(httpx.AsyncByteStream):
            async def __aiter__(self) -> AsyncIterator[bytes]:
                started.set()
                await release.wait()
                yield b"data: [DONE]\n\n"

            async def aclose(self) -> None:
                closed.set()

        def route(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=BlockingStream(),
                    request=request,
                )
            return _done_response(request)

        adapter = KimiCodingAdapter(
            api_key=TEST_API_KEY,
            client_factory=_client_factory(httpx.MockTransport(route)),
        )
        first_task = asyncio.create_task(
            adapter.complete_tool_request(
                [ChatMessage(role="user", content="cancel in flight")],
                [],
                cancel_token=cancel_token,
            )
        )
        await asyncio.wait_for(started.wait(), timeout=1.0)
        cancel_token.set()
        done, _ = await asyncio.wait({first_task}, timeout=0.5)
        stopped_promptly = first_task in done
        if not stopped_promptly:
            release.set()

        first_turn: AssistantTurn | None = None
        first_error: KimiRequestFailed | None = None
        try:
            first_turn = await first_task
        except KimiRequestFailed as exc:
            first_error = exc

        assert stopped_promptly is True
        assert first_turn is None
        assert first_error is not None
        assert first_error.error == ProviderError(
            kind=ProviderErrorKind.CLIENT,
            retryable=False,
            terminal=False,
            message="Kimi request cancelled",
        )
        assert TEST_API_KEY not in str(first_error)
        assert TEST_API_KEY not in repr(first_error)
        assert closed.is_set()

        second_turn = await adapter.complete_tool_request(
            [ChatMessage(role="user", content="after cancellation")],
            [],
        )
        assert second_turn == AssistantTurn(
            text="",
            tool_requests=[],
            reasoning_opaque="",
            usage=UsageAccounting(requests_made=1),
        )
        assert calls == 2

    asyncio.run(scenario())


@pytest.mark.parametrize("cleanup_kind", ["read-error", "runtime-error"])
def test_mapped_client_error_survives_cleanup_failure_and_adapter_reuses(
    cleanup_kind: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> tuple[
        KimiRequestFailed | None,
        Exception | None,
        AssistantTurn | None,
        Exception | None,
        int,
        int,
        int,
    ]:
        calls = 0
        close_attempts = 0

        class FailingCloseStream(httpx.AsyncByteStream):
            def __init__(self, request: httpx.Request) -> None:
                self._request = request

            async def __aiter__(self) -> AsyncIterator[bytes]:
                yield b'{"error":"schema failure"}'

            async def aclose(self) -> None:
                nonlocal close_attempts
                close_attempts += 1
                raise _cleanup_failure(cleanup_kind, self._request)

        def route(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    400,
                    stream=FailingCloseStream(request),
                    request=request,
                )
            return _done_response(request)

        adapter = KimiCodingAdapter(
            api_key=TEST_API_KEY,
            client_factory=_client_factory(httpx.MockTransport(route)),
        )
        _, first_error, first_raw = await _capture_complete_outcome(
            adapter,
            "mapped cleanup",
        )
        second_turn, _, second_raw = await _capture_complete_outcome(
            adapter,
            "reuse after mapped cleanup",
        )
        live_children = await _live_child_task_count_after_quiescence()
        return (
            first_error,
            first_raw,
            second_turn,
            second_raw,
            calls,
            close_attempts,
            live_children,
        )

    (
        first_error,
        first_raw,
        second_turn,
        second_raw,
        calls,
        close_attempts,
        live_children,
    ) = asyncio.run(scenario())

    raw_surface = "" if first_raw is None else f"{first_raw!s} {first_raw!r}"
    assert TEST_API_KEY not in raw_surface
    assert first_raw is None
    assert first_error is not None
    assert first_error.error == ProviderError(
        kind=ProviderErrorKind.CLIENT,
        retryable=False,
        terminal=False,
        message="Kimi request rejected; provider output is blocked",
    )
    event = StreamEvent(kind="error", error=first_error.error)
    assert TEST_API_KEY not in first_error.error.model_dump_json()
    assert TEST_API_KEY not in str(first_error)
    assert TEST_API_KEY not in repr(first_error)
    assert TEST_API_KEY not in event.model_dump_json()
    assert second_raw is None
    assert second_turn == AssistantTurn(
        text="",
        tool_requests=[],
        reasoning_opaque="",
        usage=UsageAccounting(requests_made=1),
    )
    assert calls == 2
    assert close_attempts >= 1
    assert live_children == 0
    assert caplog.records == []


@pytest.mark.parametrize("cleanup_kind", ["read-error", "runtime-error"])
def test_cancellation_survives_cleanup_failure_and_adapter_reuses(
    cleanup_kind: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> tuple[
        KimiRequestFailed | None,
        Exception | None,
        AssistantTurn | None,
        Exception | None,
        int,
        int,
        int,
    ]:
        started = asyncio.Event()
        never_release = asyncio.Event()
        cancel_token = asyncio.Event()
        calls = 0
        close_attempts = 0

        class BlockingFailingCloseStream(httpx.AsyncByteStream):
            def __init__(self, request: httpx.Request) -> None:
                self._request = request

            async def __aiter__(self) -> AsyncIterator[bytes]:
                started.set()
                await never_release.wait()
                yield b"data: [DONE]\n\n"

            async def aclose(self) -> None:
                nonlocal close_attempts
                close_attempts += 1
                raise _cleanup_failure(cleanup_kind, self._request)

        def route(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=BlockingFailingCloseStream(request),
                    request=request,
                )
            return _done_response(request)

        adapter = KimiCodingAdapter(
            api_key=TEST_API_KEY,
            client_factory=_client_factory(httpx.MockTransport(route)),
        )
        first_task = asyncio.create_task(
            adapter.complete_tool_request(
                [ChatMessage(role="user", content="cancel with cleanup failure")],
                [],
                cancel_token=cancel_token,
            )
        )
        await asyncio.wait_for(started.wait(), timeout=1.0)
        cancel_token.set()
        try:
            first_turn = await asyncio.wait_for(first_task, timeout=1.0)
        except KimiRequestFailed as exc:
            first_turn, first_error, first_raw = None, exc, None
        except Exception as exc:
            first_turn, first_error, first_raw = None, None, exc
        else:
            first_error, first_raw = None, None
        second_turn, _, second_raw = await _capture_complete_outcome(
            adapter,
            "reuse after cancel cleanup",
        )
        live_children = await _live_child_task_count_after_quiescence()
        assert first_turn is None
        return (
            first_error,
            first_raw,
            second_turn,
            second_raw,
            calls,
            close_attempts,
            live_children,
        )

    (
        first_error,
        first_raw,
        second_turn,
        second_raw,
        calls,
        close_attempts,
        live_children,
    ) = asyncio.run(scenario())

    raw_surface = "" if first_raw is None else f"{first_raw!s} {first_raw!r}"
    assert TEST_API_KEY not in raw_surface
    assert first_raw is None
    assert first_error is not None
    assert first_error.error == ProviderError(
        kind=ProviderErrorKind.CLIENT,
        retryable=False,
        terminal=False,
        message="Kimi request cancelled",
    )
    event = StreamEvent(kind="error", error=first_error.error)
    assert TEST_API_KEY not in first_error.error.model_dump_json()
    assert TEST_API_KEY not in str(first_error)
    assert TEST_API_KEY not in repr(first_error)
    assert TEST_API_KEY not in event.model_dump_json()
    assert second_raw is None
    assert second_turn == AssistantTurn(
        text="",
        tool_requests=[],
        reasoning_opaque="",
        usage=UsageAccounting(requests_made=1),
    )
    assert calls == 2
    assert close_attempts >= 1
    assert live_children == 0
    assert caplog.records == []


def test_cleanup_only_runtime_failure_is_sanitized_and_adapter_reuses(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> tuple[
        KimiRequestFailed | None,
        Exception | None,
        AssistantTurn | None,
        Exception | None,
        int,
        int,
    ]:
        calls = 0

        class ValidFailingCloseStream(httpx.AsyncByteStream):
            def __init__(self, request: httpx.Request) -> None:
                self._request = request

            async def __aiter__(self) -> AsyncIterator[bytes]:
                yield b"data: [DONE]\n\n"

            async def aclose(self) -> None:
                raise _cleanup_failure("runtime-error", self._request)

        def route(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=ValidFailingCloseStream(request),
                    request=request,
                )
            return _done_response(request)

        adapter = KimiCodingAdapter(
            api_key=TEST_API_KEY,
            client_factory=_client_factory(httpx.MockTransport(route)),
        )
        _, first_error, first_raw = await _capture_complete_outcome(
            adapter,
            "cleanup only",
        )
        second_turn, _, second_raw = await _capture_complete_outcome(
            adapter,
            "reuse after cleanup only",
        )
        live_children = await _live_child_task_count_after_quiescence()
        return first_error, first_raw, second_turn, second_raw, calls, live_children

    first_error, first_raw, second_turn, second_raw, calls, live_children = asyncio.run(
        scenario()
    )

    raw_surface = "" if first_raw is None else f"{first_raw!s} {first_raw!r}"
    assert TEST_API_KEY not in raw_surface
    assert first_raw is None
    assert first_error is not None
    assert first_error.error == ProviderError(
        kind=ProviderErrorKind.TRANSIENT,
        retryable=True,
        terminal=False,
        message="Kimi unmapped error (RuntimeError)",
    )
    event = StreamEvent(kind="error", error=first_error.error)
    assert TEST_API_KEY not in first_error.error.model_dump_json()
    assert TEST_API_KEY not in str(first_error)
    assert TEST_API_KEY not in repr(first_error)
    assert TEST_API_KEY not in event.model_dump_json()
    assert second_raw is None
    assert second_turn == AssistantTurn(
        text="",
        tool_requests=[],
        reasoning_opaque="",
        usage=UsageAccounting(requests_made=1),
    )
    assert calls == 2
    assert live_children == 0
    assert caplog.records == []


def test_completed_tool_turn_cleanup_failure_commits_no_hidden_state(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> tuple[
        AssistantTurn | None,
        KimiRequestFailed | None,
        Exception | None,
        UsageAccounting,
        Health,
        UsageAccounting,
        Health,
        AssistantTurn | None,
        KimiRequestFailed | None,
        Exception | None,
        UsageAccounting,
        Health,
        list[dict[str, Any]],
        int,
    ]:
        bodies: list[dict[str, Any]] = []
        close_attempts = 0

        class CompletedFailingCloseStream(httpx.AsyncByteStream):
            def __init__(self, request: httpx.Request) -> None:
                self._request = request

            async def __aiter__(self) -> AsyncIterator[bytes]:
                yield FULL_TOOL_STREAM

            async def aclose(self) -> None:
                nonlocal close_attempts
                close_attempts += 1
                raise _cleanup_failure("runtime-error", self._request)

        def route(request: httpx.Request) -> httpx.Response:
            bodies.append(json.loads(request.content))
            if len(bodies) == 1:
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=CompletedFailingCloseStream(request),
                    request=request,
                )
            return _done_response(request)

        adapter = KimiCodingAdapter(
            api_key=TEST_API_KEY,
            client_factory=_client_factory(httpx.MockTransport(route)),
        )
        usage_before = adapter.usage()
        health_before = adapter.healthcheck()

        try:
            first_turn = await adapter.complete_tool_request(
                [ChatMessage(role="user", content="tool turn with failed cleanup")],
                TOOLS,
            )
        except KimiRequestFailed as exc:
            first_turn, first_error, first_raw = None, exc, None
        except Exception as exc:
            first_turn, first_error, first_raw = None, None, exc
        else:
            first_error, first_raw = None, None

        usage_after_first = adapter.usage()
        health_after_first = adapter.healthcheck()
        second_turn, second_error, second_raw = await _capture_complete_outcome(
            adapter,
            "unrelated after failed cleanup",
        )
        return (
            first_turn,
            first_error,
            first_raw,
            usage_before,
            health_before,
            usage_after_first,
            health_after_first,
            second_turn,
            second_error,
            second_raw,
            adapter.usage(),
            adapter.healthcheck(),
            bodies,
            close_attempts,
        )

    (
        first_turn,
        first_error,
        first_raw,
        usage_before,
        health_before,
        usage_after_first,
        health_after_first,
        second_turn,
        second_error,
        second_raw,
        usage_after_second,
        health_after_second,
        bodies,
        close_attempts,
    ) = asyncio.run(scenario())

    assert first_turn is None
    assert first_raw is None
    assert first_error is not None
    assert first_error.error == ProviderError(
        kind=ProviderErrorKind.TRANSIENT,
        retryable=True,
        terminal=False,
        message="Kimi unmapped error (RuntimeError)",
    )
    error_event = StreamEvent(kind="error", error=first_error.error)
    assert TEST_API_KEY not in first_error.error.model_dump_json()
    assert TEST_API_KEY not in str(first_error)
    assert TEST_API_KEY not in repr(first_error)
    assert TEST_API_KEY not in error_event.model_dump_json()
    assert usage_before == UsageAccounting()
    assert health_before == healthy(detail="configured, not yet contacted")
    assert usage_after_first == usage_before
    assert health_after_first == health_before

    assert second_error is None
    assert second_raw is None
    assert second_turn == AssistantTurn(
        text="",
        tool_requests=[],
        reasoning_opaque="",
        usage=UsageAccounting(requests_made=1),
    )
    assert usage_after_second == UsageAccounting(requests_made=1)
    assert health_after_second == healthy(detail="last request completed")
    assert len(bodies) == 2
    assert bodies[1]["messages"] == [
        {"role": "user", "content": "unrelated after failed cleanup"}
    ]
    assert close_attempts >= 1
    assert caplog.records == []


def test_completed_tool_turn_wins_when_cancellation_is_ready_during_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> tuple[
        AssistantTurn | None,
        KimiRequestFailed | None,
        AssistantTurn | None,
        KimiRequestFailed | None,
        list[dict[str, Any]],
        bool,
        UsageAccounting,
        asyncio.Task[Any],
    ]:
        cancel_token = asyncio.Event()
        response_closed = asyncio.Event()
        bodies: list[dict[str, Any]] = []
        created_tasks: list[asyncio.Task[Any]] = []

        class CompletingStream(httpx.AsyncByteStream):
            async def __aiter__(self) -> AsyncIterator[bytes]:
                yield FULL_TOOL_STREAM

            async def aclose(self) -> None:
                cancel_token.set()
                await cancel_watcher_ready.wait()
                response_closed.set()

        def route(request: httpx.Request) -> httpx.Response:
            bodies.append(json.loads(request.content))
            if len(bodies) == 1:
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=CompletingStream(),
                    request=request,
                )
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=ByteChunks(
                    [
                        b'data: {"choices":[{"delta":{"content":"final"}}]}\n\n'
                        b"data: [DONE]\n\n"
                    ]
                ),
                request=request,
            )

        adapter = KimiCodingAdapter(
            api_key=TEST_API_KEY,
            client_factory=_client_factory(httpx.MockTransport(route)),
        )
        first_error: KimiRequestFailed | None
        second_error: KimiRequestFailed | None
        wait_done_set: frozenset[asyncio.Task[Any]] = frozenset()
        real_create_task = asyncio.create_task
        real_wait = asyncio.wait

        def tracked_create_task(coro: Any) -> asyncio.Task[Any]:
            task = real_create_task(coro)
            created_tasks.append(task)
            return task

        monkeypatch.setattr(asyncio, "create_task", tracked_create_task)

        async def observed_wait(*args: Any, **kwargs: Any) -> tuple[set[Any], set[Any]]:
            nonlocal wait_done_set
            done, pending = await real_wait(*args, **kwargs)
            wait_done_set = frozenset(done)
            return done, pending

        monkeypatch.setattr(asyncio, "wait", observed_wait)
        cancel_watcher_ready = asyncio.Event()
        original_wait = cancel_token.wait

        async def observed_cancel_wait() -> bool:
            await original_wait()
            cancel_watcher_ready.set()
            return True

        monkeypatch.setattr(cancel_token, "wait", observed_cancel_wait)
        try:
            first_turn = await adapter.complete_tool_request(
                [ChatMessage(role="user", content="complete while cancelling")],
                TOOLS,
                cancel_token=cancel_token,
            )
        except KimiRequestFailed as exc:
            first_turn, first_error = None, exc
        else:
            first_error = None
        assert len(created_tasks) == 2
        assert all(task.done() for task in created_tasks)
        assert wait_done_set == frozenset(created_tasks)
        observed_stream_task = created_tasks[0]

        if first_turn is None:
            next_messages = [ChatMessage(role="user", content="retry unseen turn")]
        else:
            next_messages = [
                ChatMessage(role="assistant", content=first_turn.text),
                ChatMessage(role="tool", content='{"content":"file"}'),
                ChatMessage(role="tool", content='{"entries":[]}'),
            ]
        try:
            second_turn = await adapter.complete_tool_request(next_messages, TOOLS)
        except KimiRequestFailed as exc:
            second_turn, second_error = None, exc
        else:
            second_error = None

        return (
            first_turn,
            first_error,
            second_turn,
            second_error,
            bodies,
            response_closed.is_set(),
            adapter.usage(),
            observed_stream_task,
        )

    (
        first_turn,
        first_error,
        second_turn,
        second_error,
        bodies,
        response_closed,
        usage,
        observed_stream_task,
    ) = asyncio.run(scenario())

    assert response_closed is True
    assert observed_stream_task.cancelled() is False
    assert first_error is None
    assert first_turn == AssistantTurn(
        text="answer",
        tool_requests=[
            {
                "id": "call_0",
                "type": "function",
                "function": {"name": "read_file", "arguments": '{"path":"a"}'},
            },
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "list_dir", "arguments": "{}"},
            },
        ],
        reasoning_opaque="think more",
        usage=UsageAccounting(requests_made=1, tokens_in=11, tokens_out=7),
    )
    assert second_error is None
    assert second_turn == AssistantTurn(
        text="final",
        tool_requests=[],
        reasoning_opaque="",
        usage=UsageAccounting(requests_made=1),
    )
    assert len(bodies) == 2
    assert bodies[1]["messages"][0]["reasoning_content"] == "think more"
    assert usage == UsageAccounting(requests_made=2, tokens_in=11, tokens_out=7)


def test_complete_error_closes_stream_before_next_request_in_same_loop() -> None:
    async def scenario() -> tuple[
        KimiRequestFailed | None,
        AssistantTurn | None,
        KimiRequestFailed | None,
        int,
    ]:
        calls = 0

        def route(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(500, content=b"internal failure", request=request)
            return _done_response(request)

        adapter = KimiCodingAdapter(
            api_key=TEST_API_KEY,
            client_factory=_client_factory(httpx.MockTransport(route)),
        )
        first_error: KimiRequestFailed | None = None
        second_turn: AssistantTurn | None = None
        second_error: KimiRequestFailed | None = None
        try:
            await adapter.complete_tool_request(
                [ChatMessage(role="user", content="first")],
                [],
            )
        except KimiRequestFailed as exc:
            first_error = exc
        try:
            second_turn = await adapter.complete_tool_request(
                [ChatMessage(role="user", content="second")],
                [],
            )
        except KimiRequestFailed as exc:
            second_error = exc
        return first_error, second_turn, second_error, calls

    first_error, second_turn, second_error, calls = asyncio.run(scenario())

    assert first_error is not None
    assert first_error.error.kind is ProviderErrorKind.TRANSIENT
    assert first_error.error.retryable is True
    assert second_error is None
    assert second_turn == AssistantTurn(
        text="",
        tool_requests=[],
        reasoning_opaque="",
        usage=UsageAccounting(requests_made=1),
    )
    assert calls == 2


@pytest.mark.parametrize(
    ("content_type", "body", "terminal_kind"),
    [
        ("text/event-stream", b"data: [DONE]\n\n", "done"),
        ("application/json", b'{"error":"not SSE"}', "error"),
    ],
    ids=["done", "error"],
)
def test_terminal_event_releases_response_and_adapter_before_consumer_stops(
    content_type: str,
    body: bytes,
    terminal_kind: str,
) -> None:
    async def scenario() -> tuple[StreamEvent, bool, list[StreamEvent], int]:
        closed = asyncio.Event()
        calls = 0
        class TrackedStream(httpx.AsyncByteStream):
            async def __aiter__(self) -> AsyncIterator[bytes]:
                yield body
            async def aclose(self) -> None:
                closed.set()
        def route(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls > 1:
                return _done_response(request)
            return httpx.Response(
                200,
                headers={"content-type": content_type},
                stream=TrackedStream(),
                request=request,
            )
        adapter = KimiCodingAdapter(
            api_key=TEST_API_KEY,
            client_factory=_client_factory(httpx.MockTransport(route)),
        )
        request = ChatRequest(messages=[ChatMessage(role="user", content="request")])
        first = adapter.stream_chat(request)
        terminal = await anext(first)
        return (
            terminal,
            closed.is_set(),
            await _collect(adapter.stream_chat(request)),
            calls,
        )

    terminal, closed, second, calls = asyncio.run(scenario())
    assert terminal.kind == terminal_kind
    assert closed is True
    assert second == [StreamEvent(kind="done")]
    assert calls == 2


def test_concurrent_second_request_fails_before_a_second_transport() -> None:
    async def scenario() -> tuple[list[StreamEvent], list[StreamEvent], int]:
        started = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        class BlockingStream(httpx.AsyncByteStream):
            async def __aiter__(self) -> AsyncIterator[bytes]:
                started.set()
                await release.wait()
                yield b"data: [DONE]\n\n"

        def route(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=BlockingStream(),
                request=request,
            )

        adapter = KimiCodingAdapter(
            api_key=TEST_API_KEY,
            client_factory=_client_factory(httpx.MockTransport(route)),
        )
        request = ChatRequest(messages=[ChatMessage(role="user", content="parallel")])
        first_task = asyncio.create_task(_collect(adapter.stream_chat(request)))
        await started.wait()
        second = await _collect(adapter.stream_chat(request))
        release.set()
        first = await first_task
        return first, second, calls

    first, second, calls = asyncio.run(scenario())

    assert first == [StreamEvent(kind="done")]
    assert second == [_error_event(ProviderErrorKind.CLIENT)]
    assert calls == 1
