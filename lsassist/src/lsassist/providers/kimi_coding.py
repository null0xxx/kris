"""Kimi Code provider adapter (SPEC §5.2, ADR-003, AC-03)."""

from __future__ import annotations

import asyncio
import codecs
import json
import re
from collections.abc import AsyncGenerator, AsyncIterator, Callable
from contextlib import aclosing, suppress
from dataclasses import dataclass, field
from typing import Any, Final, TypeGuard, cast

import httpx

from lsassist import __version__
from lsassist.providers.base import (
    AssistantTurn,
    ChatMessage,
    ChatRequest,
    Health,
    ModelCapabilities,
    ProviderError,
    ProviderErrorKind,
    StreamEvent,
    ToolSpec,
    UsageAccounting,
    UsageCounter,
    healthy,
    unhealthy,
)

KIMI_PROVIDER_ID: Final[str] = "kimi-coding"
KIMI_CODING_BASE_URL: Final[str] = "https://api.kimi.com/coding/v1"
KIMI_CHAT_COMPLETIONS_URL: Final[str] = (
    "https://api.kimi.com/coding/v1/chat/completions"
)
KIMI_REPOSITORY_URL: Final[str] = "https://github.com/null0xxx/kris"
KIMI_MODEL_IDS: Final[tuple[str, ...]] = (
    "kimi-for-coding",
    "k3",
    "kimi-for-coding-highspeed",
)
DEFAULT_KIMI_MODEL: Final[str] = "kimi-for-coding"

__all__: Final[tuple[str, ...]] = (
    "DEFAULT_KIMI_MODEL",
    "KIMI_CHAT_COMPLETIONS_URL",
    "KIMI_CODING_BASE_URL",
    "KIMI_MODEL_IDS",
    "KIMI_PROVIDER_ID",
    "KIMI_REPOSITORY_URL",
    "KimiCodingAdapter",
    "KimiRequestFailed",
)

_TOOL_NAME: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z_][a-zA-Z0-9-_]{2,63}$")
_MAX_OUTPUT_TOKENS: Final[int] = 262_144
_MAX_BODY_BYTES: Final[int] = 2_097_152
_ACCESS_TERMINATED_PHRASES: Final[tuple[str, ...]] = ("access terminated",)
_WINDOW_QUOTA_PHRASES: Final[tuple[str, ...]] = (
    "five-hour",
    "5-hour",
    "usage limit for this period",
    "period usage limit",
)
_MONTHLY_QUOTA_PHRASES: Final[tuple[str, ...]] = ("monthly usage limit",)
_OVERLOAD_PHRASES: Final[tuple[str, ...]] = ("engine overloaded", "engine is overloaded")
_RATE_LIMIT_PHRASES: Final[tuple[str, ...]] = ("too many requests",)


class KimiRequestFailed(Exception):
    """Credential-safe control flow around the frozen ProviderError model."""

    __slots__ = ("error",)

    error: ProviderError

    def __init__(self, error: ProviderError) -> None:
        self.error = error
        super().__init__(error.kind.value)

    def __str__(self) -> str:
        return f"Kimi request failed ({self.error.kind.value})"

    def __repr__(self) -> str:
        return f"KimiRequestFailed(kind={self.error.kind.value!r})"


class _StreamProtocolFailure(Exception):
    """Credential-free marker for malformed or incomplete SSE."""


class _ToolOutputFailure(Exception):
    """Credential-free marker for an unusable streamed tool call."""


@dataclass(frozen=True, slots=True)
class _CompletedToolCall:
    identifier: str
    call_type: str
    name: str
    arguments: str

    def as_wire(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "type": self.call_type,
            "function": {"name": self.name, "arguments": self.arguments},
        }


@dataclass(slots=True)
class _ToolCallParts:
    index: int
    identifier: str | None = None
    call_type: str | None = None
    name: str | None = None
    arguments: str = ""

    def merge(self, fragment: dict[str, Any]) -> None:
        self.identifier = _merge_non_empty(self.identifier, fragment.get("id"))
        self.call_type = _merge_non_empty(self.call_type, fragment.get("type"))
        function = fragment.get("function")
        if function is None:
            return
        if not isinstance(function, dict):
            raise _ToolOutputFailure
        self.name = _merge_non_empty(self.name, function.get("name"))
        if "arguments" in function:
            argument_fragment = function["arguments"]
            if not isinstance(argument_fragment, str):
                raise _ToolOutputFailure
            self.arguments += argument_fragment

    def finish(self) -> _CompletedToolCall:
        if self.identifier is None or self.call_type != "function" or self.name is None:
            raise _ToolOutputFailure
        try:
            parsed_arguments = json.loads(self.arguments)
        except json.JSONDecodeError as exc:
            raise _ToolOutputFailure from exc
        if not isinstance(parsed_arguments, dict):
            raise _ToolOutputFailure
        return _CompletedToolCall(
            identifier=self.identifier,
            call_type=self.call_type,
            name=self.name,
            arguments=self.arguments,
        )


@dataclass(frozen=True, slots=True)
class _CompletedTurn:
    text: str
    reasoning: str
    tool_calls: tuple[_CompletedToolCall, ...]
    usage: UsageAccounting


@dataclass(frozen=True, slots=True)
class _PendingToolTurn:
    assistant_text: str
    reasoning: str
    tool_calls: tuple[_CompletedToolCall, ...]


@dataclass(frozen=True, slots=True)
class _RetainedConversation:
    messages: tuple[ChatMessage, ...]
    wire_messages: tuple[dict[str, Any], ...]


@dataclass(slots=True)
class _TurnAccumulator:
    text_parts: list[str] = field(default_factory=list)
    reasoning_parts: list[str] = field(default_factory=list)
    tool_parts: dict[int, _ToolCallParts] = field(default_factory=dict)
    final_usage: UsageAccounting | None = None

    def observe(self, event: StreamEvent) -> None:
        if event.kind == "text_delta":
            if event.text is None:
                raise _StreamProtocolFailure
            self.text_parts.append(event.text)
        elif event.kind == "reasoning_delta":
            if event.text is None:
                raise _StreamProtocolFailure
            self.reasoning_parts.append(event.text)
        elif event.kind == "tool_call_delta":
            if event.tool_call is None:
                raise _ToolOutputFailure
            index = event.tool_call.get("index")
            if isinstance(index, bool) or not isinstance(index, int) or index < 0:
                raise _ToolOutputFailure
            parts = self.tool_parts.setdefault(index, _ToolCallParts(index=index))
            parts.merge(event.tool_call)
        elif event.kind == "usage":
            if event.usage is None:
                raise _StreamProtocolFailure
            self.final_usage = event.usage

    def finish(self) -> _CompletedTurn:
        tool_calls = tuple(self.tool_parts[index].finish() for index in sorted(self.tool_parts))
        usage = self.final_usage or UsageAccounting(requests_made=1)
        return _CompletedTurn(
            text="".join(self.text_parts),
            reasoning="".join(self.reasoning_parts),
            tool_calls=tool_calls,
            usage=usage,
        )


def _merge_non_empty(current: str | None, incoming: object) -> str | None:
    if incoming is None or incoming == "":
        return current
    if not isinstance(incoming, str):
        raise _ToolOutputFailure
    if current is not None and current != incoming:
        raise _ToolOutputFailure
    return incoming


def _client_error(message: str = "Kimi request validation failed") -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.CLIENT,
        retryable=False,
        terminal=False,
        message=message,
    )


def _auth_error() -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.AUTH,
        retryable=False,
        terminal=True,
        message="Kimi authentication failed",
    )


def _membership_error() -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.TRANSIENT,
        retryable=True,
        terminal=False,
        message="Kimi membership verification failed",
    )


def _membership_quota_error() -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.QUOTA,
        retryable=False,
        terminal=True,
        message="Kimi membership quota exhausted",
    )


def _terminated_error() -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.TERMINATED,
        retryable=False,
        terminal=True,
        message="Kimi access terminated",
    )


def _window_quota_error() -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.QUOTA,
        retryable=False,
        terminal=False,
        message="Kimi usage quota reached",
    )


def _monthly_quota_error() -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.QUOTA,
        retryable=False,
        terminal=False,
        message="Kimi usage quota reached",
    )


def _overload_error() -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.OVERLOAD,
        retryable=True,
        terminal=False,
        message="Kimi service overloaded",
    )


def _rate_limit_error() -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.RATE_LIMIT,
        retryable=True,
        terminal=False,
        message="Kimi rate limit reached",
    )


def _server_error() -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.TRANSIENT,
        retryable=True,
        terminal=False,
        message="Kimi service temporarily unavailable",
    )


def _cancel_error() -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.CLIENT,
        retryable=False,
        terminal=False,
        message="Kimi request cancelled",
    )


def _schema_error() -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.CLIENT,
        retryable=False,
        terminal=False,
        message="Kimi request rejected; provider output is blocked",
    )


def _stream_error() -> ProviderError:
    return ProviderError(
        kind=ProviderErrorKind.TRANSIENT,
        retryable=True,
        terminal=False,
        message="Kimi stream protocol failed",
    )


def _as_error_event(error: ProviderError) -> StreamEvent:
    return StreamEvent(kind="error", error=error)


def _request_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": f"lsassist/{__version__} (+{KIMI_REPOSITORY_URL})",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }


def _serialize_tool(tool: ToolSpec) -> dict[str, object]:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters,
            "strict": True,
        },
    }


def _request_payload(
    model: str,
    request: ChatRequest,
    wire_messages: list[dict[str, Any]],
) -> dict[str, object]:
    payload: dict[str, object] = {
        "model": model,
        "messages": wire_messages,
        "stream": True,
    }
    if request.tools:
        payload["tools"] = [_serialize_tool(tool) for tool in request.tools]
    if request.effort is not None:
        payload["reasoning_effort"] = request.effort
    if request.max_output_tokens is not None:
        payload["max_tokens"] = request.max_output_tokens
    return payload


def _compact_json(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _token_limit_is_valid(request: ChatRequest) -> bool:
    return (
        request.max_output_tokens is None
        or request.max_output_tokens <= _MAX_OUTPUT_TOKENS
    )


def _tool_names_are_valid(tools: list[ToolSpec]) -> bool:
    return all(_TOOL_NAME.fullmatch(tool.name) is not None for tool in tools)


def _body_size_is_valid(body: bytes) -> bool:
    return len(body) <= _MAX_BODY_BYTES


def _request_is_valid(request: ChatRequest, body: bytes) -> bool:
    return (
        _token_limit_is_valid(request)
        and _tool_names_are_valid(request.tools)
        and _body_size_is_valid(body)
    )


def _is_tier_gating(body: str) -> bool:
    lowered = body.casefold()
    return (
        "requested model" in lowered
        and "does not allow" in lowered
        and ("current subscription" in lowered or "current tier" in lowered)
    )


def _contains_any(condition: str, phrases: tuple[str, ...]) -> bool:
    return any(phrase in condition for phrase in phrases)


def _normalize_http_error(status: int, condition: str) -> ProviderError:
    lowered = condition.casefold()
    if status == 401:
        return _auth_error()
    if status == 402:
        return _membership_error()
    if status == 403:
        if _contains_any(lowered, _ACCESS_TERMINATED_PHRASES):
            return _terminated_error()
        return _membership_quota_error()
    if status == 429:
        if _contains_any(lowered, _WINDOW_QUOTA_PHRASES):
            return _window_quota_error()
        if _contains_any(lowered, _MONTHLY_QUOTA_PHRASES):
            return _monthly_quota_error()
        if _contains_any(lowered, _OVERLOAD_PHRASES):
            return _overload_error()
        if _contains_any(lowered, _RATE_LIMIT_PHRASES):
            return _rate_limit_error()
        return ProviderError.normalize_unmapped("HTTP 429 unclassified")
    if status == 500:
        return _server_error()
    if status == 499:
        return _cancel_error()
    if status == 400:
        return _schema_error()
    return ProviderError.normalize_unmapped(f"HTTP {status} unclassified")


def _normalize_unmapped_error(raw: object) -> ProviderError:
    safe_type_label = type(raw).__name__
    return ProviderError.normalize_unmapped(f"Kimi unmapped error ({safe_type_label})")


def _complete_lines(text: str, *, final: bool) -> tuple[list[str], str]:
    lines: list[str] = []
    start = 0
    index = 0
    while index < len(text):
        character = text[index]
        if character not in "\r\n":
            index += 1
            continue
        if character == "\r" and index + 1 == len(text) and not final:
            break
        lines.append(text[start:index])
        index += 1
        if character == "\r" and index < len(text) and text[index] == "\n":
            index += 1
        start = index
    return lines, text[start:]


async def _strict_utf8_lines(response: httpx.Response) -> AsyncIterator[str]:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    buffered = ""
    byte_stream = cast(AsyncGenerator[bytes, None], response.aiter_bytes())
    async with aclosing(byte_stream) as chunks:
        async for chunk in chunks:
            buffered += decoder.decode(chunk, final=False)
            lines, buffered = _complete_lines(buffered, final=False)
            for line in lines:
                yield line
    buffered += decoder.decode(b"", final=True)
    lines, buffered = _complete_lines(buffered, final=True)
    for line in lines:
        yield line
    if buffered:
        yield buffered


async def _sse_records(response: httpx.Response) -> AsyncIterator[str]:
    data_lines: list[str] = []
    line_stream = cast(AsyncGenerator[str, None], _strict_utf8_lines(response))
    async with aclosing(line_stream) as lines:
        async for line in lines:
            if line == "":
                if data_lines:
                    yield "\n".join(data_lines)
                    data_lines.clear()
                continue
            if line.startswith(":"):
                continue
            if line.startswith("data:"):
                value = line[len("data:") :]
                if value.startswith(" "):
                    value = value[1:]
                data_lines.append(value)
    if data_lines:
        yield "\n".join(data_lines)


def _plain_non_negative_int(value: object) -> TypeGuard[int]:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _usage_from(raw: object) -> UsageAccounting:
    if not isinstance(raw, dict):
        raise _StreamProtocolFailure
    prompt_tokens = raw.get("prompt_tokens")
    completion_tokens = raw.get("completion_tokens")
    if not _plain_non_negative_int(prompt_tokens) or not _plain_non_negative_int(
        completion_tokens
    ):
        raise _StreamProtocolFailure
    return UsageAccounting(
        requests_made=1,
        tokens_in=prompt_tokens,
        tokens_out=completion_tokens,
    )


def _translated_events(payload: object) -> list[StreamEvent]:
    if not isinstance(payload, dict):
        raise _StreamProtocolFailure
    choices = payload.get("choices")
    if not isinstance(choices, list):
        raise _StreamProtocolFailure

    choice: dict[str, Any] | None = None
    delta: dict[str, Any] = {}
    if choices:
        first_choice = choices[0]
        if not isinstance(first_choice, dict):
            raise _StreamProtocolFailure
        choice = first_choice
        raw_delta = choice.get("delta", {})
        if not isinstance(raw_delta, dict):
            raise _StreamProtocolFailure
        delta = raw_delta

    reasoning = delta.get("reasoning_content")
    content = delta.get("content")
    tool_calls = delta.get("tool_calls")
    if reasoning is not None and not isinstance(reasoning, str):
        raise _StreamProtocolFailure
    if content is not None and not isinstance(content, str):
        raise _StreamProtocolFailure
    if tool_calls is not None and not isinstance(tool_calls, list):
        raise _StreamProtocolFailure

    events: list[StreamEvent] = []
    if reasoning:
        events.append(StreamEvent(kind="reasoning_delta", text=reasoning))
    if content:
        events.append(StreamEvent(kind="text_delta", text=content))
    if tool_calls is not None:
        for tool_call in tool_calls:
            if not isinstance(tool_call, dict):
                raise _StreamProtocolFailure
            events.append(StreamEvent(kind="tool_call_delta", tool_call=tool_call))

    raw_usage = payload.get("usage")
    if raw_usage is None and choice is not None:
        raw_usage = choice.get("usage")
    if raw_usage is not None:
        events.append(StreamEvent(kind="usage", usage=_usage_from(raw_usage)))
    return events


def _is_event_stream(response: httpx.Response) -> bool:
    content_type = cast(str, response.headers.get("content-type", ""))
    media_type = content_type.split(";", 1)[0]
    return media_type.strip().casefold() == "text/event-stream"


def _continuation_parts(
    messages: list[ChatMessage],
    pending: _PendingToolTurn,
) -> tuple[list[ChatMessage], ChatMessage, list[ChatMessage]] | None:
    tool_count = len(pending.tool_calls)
    assistant_index = len(messages) - tool_count - 1
    if assistant_index < 0:
        return None
    prefix = messages[:assistant_index]
    assistant = messages[assistant_index]
    tool_results = messages[assistant_index + 1 :]
    if (
        any(message.role == "tool" for message in prefix)
        or assistant.role != "assistant"
        or assistant.content != pending.assistant_text
        or len(tool_results) != tool_count
        or any(message.role != "tool" for message in tool_results)
    ):
        return None
    return prefix, assistant, tool_results


class KimiCodingAdapter:
    """Thin OpenAI-compatible adapter for the official Kimi Code endpoint."""

    id: str = KIMI_PROVIDER_ID
    capabilities: ModelCapabilities = ModelCapabilities(
        tool_calling=True,
        parallel_tools=True,
        streaming=True,
        thinking=True,
    )

    def __init__(
        self,
        *,
        api_key: str,
        model: str = DEFAULT_KIMI_MODEL,
        client_factory: Callable[..., httpx.AsyncClient] = httpx.AsyncClient,
    ) -> None:
        if api_key == "" or api_key != api_key.strip():
            raise ValueError("Kimi API key must be non-empty and unpadded")
        self._api_key = api_key
        self._model = model
        self._available_model_ids = list(KIMI_MODEL_IDS)
        self._client_factory = client_factory
        self._usage = UsageCounter()
        self._health = healthy(detail="configured, not yet contacted")
        self._pending: _PendingToolTurn | None = None
        self._history: _RetainedConversation | None = None
        self._request_active = False

    @property
    def model(self) -> str:
        return self._model

    @property
    def available_model_ids(self) -> tuple[str, ...]:
        return tuple(self._available_model_ids)

    async def stream_chat(self, request: ChatRequest) -> AsyncIterator[StreamEvent]:
        if self._request_active:
            error = _client_error()
            self._record_failure(error)
            yield _as_error_event(error)
            return
        self._request_active = True
        terminal: StreamEvent | None = None
        try:
            event_stream = cast(
                AsyncGenerator[StreamEvent, None],
                self._stream_chat_once(request),
            )
            async with aclosing(event_stream) as events:
                async for event in events:
                    if event.kind in ("done", "error"):
                        terminal = event
                    else:
                        yield event
        finally:
            self._request_active = False
        if terminal is not None:
            yield terminal

    async def _stream_chat_once(self, request: ChatRequest) -> AsyncIterator[StreamEvent]:
        if self._model not in KIMI_MODEL_IDS:
            error = _client_error()
            self._record_failure(error)
            yield _as_error_event(error)
            return
        if self._model not in self._available_model_ids:
            error = _auth_error()
            self._record_failure(error)
            yield _as_error_event(error)
            return

        wire_messages = self._wire_messages(request.messages)
        if wire_messages is None:
            error = _client_error()
            self._record_failure(error)
            yield _as_error_event(error)
            return
        payload = _request_payload(self._model, request, wire_messages)
        body = _compact_json(payload)
        if not _request_is_valid(request, body):
            error = _client_error()
            self._record_failure(error)
            yield _as_error_event(error)
            return

        completed: _CompletedTurn | None = None
        error_emitted = False
        try:
            async with self._client_factory(
                trust_env=False,
                follow_redirects=False,
            ) as client, client.stream(
                "POST",
                KIMI_CHAT_COMPLETIONS_URL,
                content=body,
                headers=_request_headers(self._api_key),
                timeout=request.timeout_s,
            ) as response:
                response_accumulator = _TurnAccumulator()
                event_stream = cast(
                    AsyncGenerator[StreamEvent, None],
                    self._response_events(response, response_accumulator),
                )
                async with aclosing(event_stream) as events:
                    async for event in events:
                        if event.kind == "error":
                            error_emitted = True
                        elif event.kind == "done":
                            completed = response_accumulator.finish()
                            continue
                        yield event
            if completed is not None:
                self._record_success(completed, request.messages, wire_messages)
                yield StreamEvent(kind="done")
        except Exception as raw:
            if error_emitted:
                return
            error = self.normalize_error(raw)
            if completed is None:
                self._record_failure(error)
            yield _as_error_event(error)

    async def _response_events(
        self,
        response: httpx.Response,
        accumulator: _TurnAccumulator,
    ) -> AsyncIterator[StreamEvent]:
        if response.status_code < 200 or response.status_code >= 300:
            try:
                response_body = (await response.aread()).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                response_body = ""
            if response.status_code == 401 and _is_tier_gating(response_body):
                self._available_model_ids = [
                    candidate
                    for candidate in self._available_model_ids
                    if candidate != self._model
                ]
            error = _normalize_http_error(response.status_code, response_body)
            self._record_failure(error)
            yield _as_error_event(error)
            return
        if not _is_event_stream(response):
            error = _stream_error()
            self._record_failure(error)
            yield _as_error_event(error)
            return

        record_stream = cast(AsyncGenerator[str, None], _sse_records(response))
        try:
            async with aclosing(record_stream) as records:
                async for record in records:
                    if record == "[DONE]":
                        try:
                            accumulator.finish()
                        except _ToolOutputFailure:
                            error = _client_error()
                            self._record_failure(error)
                            yield _as_error_event(error)
                            return
                        yield StreamEvent(kind="done")
                        return
                    payload_object = json.loads(record)
                    for event in _translated_events(payload_object):
                        try:
                            accumulator.observe(event)
                        except _ToolOutputFailure:
                            error = _client_error()
                            self._record_failure(error)
                            yield _as_error_event(error)
                            return
                        yield event
        except (json.JSONDecodeError, _StreamProtocolFailure, UnicodeError):
            error = _stream_error()
            self._record_failure(error)
            yield _as_error_event(error)
            return
        error = _stream_error()
        self._record_failure(error)
        yield _as_error_event(error)

    async def complete_tool_request(
        self,
        messages: list[ChatMessage],
        tools: list[ToolSpec],
        effort: str | None = None,
        timeout_s: float | None = None,
        cancel_token: asyncio.Event | None = None,
    ) -> AssistantTurn:
        if cancel_token is not None and cancel_token.is_set():
            error = _cancel_error()
            self._record_failure(error)
            raise KimiRequestFailed(error)
        request = ChatRequest(
            messages=messages,
            tools=tools,
            effort=effort,
            timeout_s=timeout_s,
        )
        accumulator = _TurnAccumulator()

        async def consume_stream() -> bool:
            saw_done = False
            stream = cast(AsyncGenerator[StreamEvent, None], self.stream_chat(request))
            primary: BaseException | None = None
            try:
                async for event in stream:
                    if event.kind == "error":
                        raise KimiRequestFailed(event.error or _client_error())
                    accumulator.observe(event)
                    if event.kind == "done":
                        saw_done = True
            except KimiRequestFailed as exc:
                primary = exc
                raise
            except asyncio.CancelledError as exc:
                primary = exc
                raise
            except Exception as raw:
                error = self.normalize_error(raw)
                self._record_failure(error)
                primary = KimiRequestFailed(error)
                raise primary from None
            except BaseException as exc:
                primary = exc
                raise
            finally:
                try:
                    await stream.aclose()
                except Exception as raw:
                    if primary is None:
                        error = self.normalize_error(raw)
                        self._record_failure(error)
                        raise KimiRequestFailed(error) from None
            return saw_done

        if cancel_token is None:
            saw_done = await consume_stream()
        else:
            stream_task = asyncio.create_task(consume_stream())
            cancel_task = asyncio.create_task(cancel_token.wait())
            try:
                done, _ = await asyncio.wait(
                    (stream_task, cancel_task),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if stream_task in done:
                    saw_done = await stream_task
                else:
                    stream_task.cancel()
                    with suppress(asyncio.CancelledError, Exception):
                        await stream_task
                    error = _cancel_error()
                    self._record_failure(error)
                    raise KimiRequestFailed(error)
            finally:
                cancel_task.cancel()
                with suppress(asyncio.CancelledError):
                    await cancel_task
                if not stream_task.done():
                    stream_task.cancel()
                    with suppress(asyncio.CancelledError, Exception):
                        await stream_task
        if not saw_done:
            raise KimiRequestFailed(_stream_error())
        completed = accumulator.finish()
        return AssistantTurn(
            text=completed.text,
            tool_requests=[call.as_wire() for call in completed.tool_calls],
            reasoning_opaque=completed.reasoning,
            usage=completed.usage,
        )

    def normalize_error(self, raw: object) -> ProviderError:
        if isinstance(raw, httpx.TimeoutException):
            return _cancel_error()
        if isinstance(raw, httpx.Response):
            return _normalize_http_error(raw.status_code, raw.text)
        return _normalize_unmapped_error(raw)

    def usage(self) -> UsageAccounting:
        return self._usage.snapshot()

    def healthcheck(self) -> Health:
        return self._health

    def _record_failure(self, error: ProviderError) -> None:
        self._health = unhealthy(f"last request failed: {error.kind.value}")

    def _record_success(
        self,
        completed: _CompletedTurn,
        messages: list[ChatMessage],
        wire_messages: list[dict[str, Any]],
    ) -> None:
        self._usage.record_request(
            tokens_in=completed.usage.tokens_in,
            tokens_out=completed.usage.tokens_out,
        )
        self._health = healthy(detail="last request completed")
        assistant = ChatMessage(role="assistant", content=completed.text)
        assistant_wire = assistant.model_dump()
        if completed.tool_calls:
            assistant_wire["reasoning_content"] = completed.reasoning
            assistant_wire["tool_calls"] = [
                call.as_wire() for call in completed.tool_calls
            ]
            self._pending = _PendingToolTurn(
                assistant_text=completed.text,
                reasoning=completed.reasoning,
                tool_calls=completed.tool_calls,
            )
        else:
            self._pending = None
        self._history = _RetainedConversation(
            messages=(*messages, assistant),
            wire_messages=(*wire_messages, assistant_wire),
        )

    def _wire_messages(self, messages: list[ChatMessage]) -> list[dict[str, Any]] | None:
        pending = self._pending
        history = self._history
        if history is not None:
            split = len(history.messages)
            if tuple(messages[:split]) == history.messages:
                suffix = messages[split:]
                wire_messages = list(history.wire_messages)
                if pending is None:
                    if any(message.role == "tool" for message in suffix):
                        return None
                    return wire_messages + [message.model_dump() for message in suffix]
                if len(suffix) != len(pending.tool_calls) or any(
                    message.role != "tool" for message in suffix
                ):
                    return None
                for message, call in zip(suffix, pending.tool_calls, strict=True):
                    wire_messages.append(
                        {"role": "tool", "content": message.content,
                         "tool_call_id": call.identifier}
                    )
                return wire_messages
        if pending is None:
            if any(message.role == "tool" for message in messages):
                return None
            return [message.model_dump() for message in messages]

        parts = _continuation_parts(messages, pending)
        if parts is None:
            return None
        prefix, assistant, tool_results = parts

        wire_messages = [message.model_dump() for message in prefix]
        wire_messages.append(
            {
                "role": "assistant",
                "content": assistant.content,
                "reasoning_content": pending.reasoning,
                "tool_calls": [call.as_wire() for call in pending.tool_calls],
            }
        )
        for index, message in enumerate(tool_results):
            wire_messages.append(
                {
                    "role": "tool",
                    "content": message.content,
                    "tool_call_id": pending.tool_calls[index].identifier,
                }
            )
        return wire_messages
