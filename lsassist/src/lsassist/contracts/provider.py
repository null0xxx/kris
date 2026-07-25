"""Provider-neutral contract models and the ProviderProfile Protocol (SPEC §5.1).

Type-level foundation for the §5.1 adapter prohibitions: every provider
adapter implements :class:`ProviderProfile`; the kernel only ever sees these
models. I16: ``AssistantTurn.reasoning_opaque`` is RAM-only — it is excluded
from ``model_dump()``/``model_dump_json()``/``repr()`` by default so it can
never reach the audit log through serialization.

I1 (adapter-side prelude): this module — like the adapters built on it — must
never spawn child processes or touch the filesystem.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from enum import StrEnum
from typing import Any, Literal, Protocol, Self, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

# §5.1 stream_chat event kinds.
StreamEventKind = Literal[
    "text_delta",
    "tool_call_delta",
    "reasoning_delta",
    "usage",
    "error",
    "done",
]


class ProviderErrorKind(StrEnum):
    """§5.1 normalize_error taxonomy."""

    AUTH = "auth"
    QUOTA = "quota"
    RATE_LIMIT = "rate_limit"
    OVERLOAD = "overload"
    TRANSIENT = "transient"
    CLIENT = "client"
    TERMINATED = "terminated"


class ModelCapabilities(BaseModel):
    """§5.1 capabilities row.

    Conservative defaults: every boolean capability defaults to ``False`` and
    unknown fields are ignored, so a capability a provider does not declare
    (or a future key the kernel does not know yet) can never silently turn on.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    tool_calling: bool = False
    parallel_tools: bool = False
    streaming: bool = False
    thinking: bool = False
    vision: bool = False
    max_context: int = Field(default=0, ge=0)
    max_output: int = Field(default=0, ge=0)
    structured_output: bool = False


class UsageAccounting(BaseModel):
    """§5.1 usage() row — client-side counters per rolling window."""

    model_config = ConfigDict(frozen=True)

    requests_made: int = Field(default=0, ge=0)
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    session_cost_estimate: float | None = Field(default=None, ge=0)


class Health(BaseModel):
    """§5.1 healthcheck() row — read-only probe; errors feed the circuit breaker."""

    model_config = ConfigDict(frozen=True)

    ok: bool
    detail: str = ""
    latency_ms: float | None = Field(default=None, ge=0)


class ProviderError(BaseModel):
    """§5.1 typed transport/normalized error.

    ``terminal=True`` combined with ``retryable=True`` is forbidden: the
    §5.2 retry policy only retries ``retryable=True`` classes, and a terminal
    error must never enter a retry loop.
    """

    model_config = ConfigDict(frozen=True)

    kind: ProviderErrorKind
    retryable: bool
    retry_after_s: float | None = Field(default=None, ge=0)
    terminal: bool = False
    message: str = ""

    @model_validator(mode="after")
    def _terminal_never_retryable(self) -> Self:
        if self.terminal and self.retryable:
            raise ValueError("terminal=True forbids retryable=True (SPEC §5.1)")
        return self

    @classmethod
    def normalize_unmapped(cls, raw: object) -> ProviderError:
        """§5.1 failure behavior: unmapped error -> transient, retryable=True.

        Safe side: limited retries are permitted, but the error is never
        classified as terminal without an explicit adapter mapping.
        """
        return cls(
            kind=ProviderErrorKind.TRANSIENT,
            retryable=True,
            terminal=False,
            message=str(raw),
        )


class StreamEvent(BaseModel):
    """One ``stream_chat`` event; ``kind`` is the §5.1 discriminator."""

    model_config = ConfigDict(frozen=True)

    kind: StreamEventKind
    text: str | None = None
    tool_call: dict[str, Any] | None = None
    usage: UsageAccounting | None = None
    error: ProviderError | None = None


class ChatMessage(BaseModel):
    """One message in a provider request (OpenAI-compatible roles)."""

    model_config = ConfigDict(frozen=True)

    role: Literal["system", "user", "assistant", "tool"]
    content: str


class ToolSpec(BaseModel):
    """Provider-neutral tool declaration handed to the model."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)


class ChatRequest(BaseModel):
    """Input to ``ProviderProfile.stream_chat``."""

    model_config = ConfigDict(frozen=True)

    messages: list[ChatMessage]
    tools: list[ToolSpec] = Field(default_factory=list)
    effort: str | None = None
    timeout_s: float | None = Field(default=None, gt=0)
    max_output_tokens: int | None = Field(default=None, gt=0)


class AssistantTurn(BaseModel):
    """§5.1 complete_tool_request return value.

    ``reasoning_opaque`` holds the provider's opaque reasoning blob (e.g.
    Kimi ``reasoning_content``) solely for same-turn RAM round-tripping. Per
    I16 it is excluded from every serialization form (``Field(exclude=True)``)
    and from ``repr`` (``repr=False``), so it cannot be written to the audit
    log or leak into prompt text.
    """

    model_config = ConfigDict(frozen=True)

    text: str = ""
    tool_requests: list[dict[str, Any]] = Field(default_factory=list)
    reasoning_opaque: str | None = Field(default=None, exclude=True, repr=False)
    usage: UsageAccounting = Field(default_factory=UsageAccounting)


@runtime_checkable
class ProviderProfile(Protocol):
    """§5.1 provider-neutral interface every adapter must implement.

    Structural typing foundation for the §5.1 adapter prohibitions
    (no child processes, no fs writes, no tool execution, no credential logging):
    the kernel depends only on this Protocol, so an adapter missing any
    member fails the runtime structural check.
    """

    id: str
    capabilities: ModelCapabilities

    def stream_chat(self, request: ChatRequest) -> AsyncIterator[StreamEvent]:
        """Stream one turn; transport errors surface as typed ProviderError."""
        ...

    async def complete_tool_request(
        self,
        messages: list[ChatMessage],
        tools: list[ToolSpec],
        effort: str | None = None,
        timeout_s: float | None = None,
        cancel_token: asyncio.Event | None = None,
    ) -> AssistantTurn:
        """One full non-streaming turn; timeout/cancel -> ProviderError(retryable=False)."""
        ...

    def normalize_error(self, raw: object) -> ProviderError:
        """Map a raw provider error; unmapped -> transient/retryable (safe side)."""
        ...

    def usage(self) -> UsageAccounting:
        """Client-side usage counters for the rolling window."""
        ...

    def healthcheck(self) -> Health:
        """Read-only probe; errors feed the §5.2 circuit breaker."""
        ...
