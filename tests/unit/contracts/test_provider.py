"""T1.06 RED: provider-neutral contracts (SPEC §5.1, I16, I1).

Covers: ModelCapabilities conservative defaults, StreamEvent discriminator,
ProviderError taxonomy + terminal/retryable ban, AssistantTurn.reasoning_opaque
serialization exclusion (I16), and the ProviderProfile runtime-checkable
Protocol.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from lsassist.contracts.provider import (
    AssistantTurn,
    Health,
    ModelCapabilities,
    ProviderError,
    ProviderErrorKind,
    ProviderProfile,
    StreamEvent,
    UsageAccounting,
)

# --- ModelCapabilities (§5.1 row: unknown field -> conservative false) --------


def test_capabilities_all_spec_fields_present() -> None:
    caps = ModelCapabilities(
        tool_calling=True,
        parallel_tools=True,
        streaming=True,
        thinking=True,
        vision=True,
        max_context=131_072,
        max_output=8_192,
        structured_output=True,
    )
    assert caps.tool_calling and caps.parallel_tools and caps.streaming
    assert caps.thinking and caps.vision and caps.structured_output
    assert caps.max_context == 131_072
    assert caps.max_output == 8_192


def test_capabilities_defaults_are_conservative_false() -> None:
    caps = ModelCapabilities()
    for field in (
        "tool_calling",
        "parallel_tools",
        "streaming",
        "thinking",
        "vision",
        "structured_output",
    ):
        assert getattr(caps, field) is False, field


def test_capabilities_unknown_field_ignored_defaults_false() -> None:
    # §5.1: a future/unknown capability key must NOT silently turn the
    # capability on — extra fields are ignored, defaults stay false.
    caps = ModelCapabilities.model_validate({"some_future_capability": True})
    assert caps.tool_calling is False
    assert caps.structured_output is False
    assert not hasattr(caps, "some_future_capability")


def test_capabilities_frozen() -> None:
    caps = ModelCapabilities()
    with pytest.raises(ValidationError):
        caps.streaming = True  # type: ignore[misc]


# --- StreamEvent discriminator (§5.1 stream_chat event kinds) -----------------

_STREAM_KINDS = (
    "text_delta",
    "tool_call_delta",
    "reasoning_delta",
    "usage",
    "error",
    "done",
)


@pytest.mark.parametrize("kind", _STREAM_KINDS)
def test_stream_event_accepts_every_spec_kind(kind: str) -> None:
    event = StreamEvent(kind=kind)  # type: ignore[arg-type]
    assert event.kind == kind


def test_stream_event_invalid_kind_rejected() -> None:
    with pytest.raises(ValidationError):
        StreamEvent(kind="chunk")  # type: ignore[arg-type]


def test_stream_event_text_delta_payload() -> None:
    event = StreamEvent(kind="text_delta", text="hello")
    assert event.text == "hello"


def test_stream_event_error_payload_is_typed() -> None:
    err = ProviderError(kind=ProviderErrorKind.OVERLOAD, retryable=True)
    event = StreamEvent(kind="error", error=err)
    assert event.error is not None
    assert event.error.kind is ProviderErrorKind.OVERLOAD


# --- ProviderError taxonomy (§5.1 normalize_error row) -------------------------


def test_provider_error_kind_enum_values() -> None:
    assert {k.value for k in ProviderErrorKind} == {
        "auth",
        "quota",
        "rate_limit",
        "overload",
        "transient",
        "client",
        "terminated",
    }


def test_normalize_unmapped_defaults_to_transient_retryable() -> None:
    # §5.1: unmapped error -> transient, retryable=True (safe side).
    err = ProviderError.normalize_unmapped(RuntimeError("weird provider response"))
    assert err.kind is ProviderErrorKind.TRANSIENT
    assert err.retryable is True
    assert err.terminal is False
    assert err.retry_after_s is None


def test_normalize_unmapped_keeps_message_without_secrets() -> None:
    err = ProviderError.normalize_unmapped("boom")
    assert "boom" in err.message


def test_terminal_and_retryable_combination_forbidden() -> None:
    # §5.1: a terminal error must never be retried by the retry policy.
    with pytest.raises(ValidationError):
        ProviderError(kind=ProviderErrorKind.TERMINATED, retryable=True, terminal=True)


def test_terminal_non_retryable_ok() -> None:
    err = ProviderError(kind=ProviderErrorKind.AUTH, retryable=False, terminal=True)
    assert err.terminal is True


def test_provider_error_frozen() -> None:
    err = ProviderError(kind=ProviderErrorKind.CLIENT, retryable=False)
    with pytest.raises(ValidationError):
        err.retryable = True  # type: ignore[misc]


# --- AssistantTurn.reasoning_opaque (I16: never serialized / audited) ----------


def _turn() -> AssistantTurn:
    return AssistantTurn(
        text="answer",
        tool_requests=[],
        reasoning_opaque="raw-reasoning-content-blob",
        usage=UsageAccounting(requests_made=1, tokens_in=10, tokens_out=5),
    )


def test_assistant_turn_reasoning_opaque_field_exists_in_ram() -> None:
    turn = _turn()
    assert turn.reasoning_opaque == "raw-reasoning-content-blob"


def test_assistant_turn_model_dump_excludes_reasoning_opaque() -> None:
    dumped = _turn().model_dump()
    assert "reasoning_opaque" not in dumped
    assert "raw-reasoning-content-blob" not in str(dumped)


def test_assistant_turn_model_dump_json_excludes_reasoning_opaque() -> None:
    payload = _turn().model_dump_json()
    assert "reasoning_opaque" not in payload
    assert "raw-reasoning-content-blob" not in payload


def test_assistant_turn_repr_excludes_reasoning_opaque() -> None:
    text = repr(_turn())
    assert "reasoning_opaque" not in text
    assert "raw-reasoning-content-blob" not in text


def test_assistant_turn_roundtrip_loses_reasoning_opaque() -> None:
    # I16 foundation: an audit/persist roundtrip cannot carry the blob.
    restored = AssistantTurn.model_validate(_turn().model_dump())
    assert restored.reasoning_opaque is None


# --- ProviderProfile Protocol (structural, runtime-checkable) -------------------


class _FullProvider:
    """Positive control: satisfies every §5.1 member."""

    id = "dummy"
    capabilities = ModelCapabilities()

    async def stream_chat(self, request: Any) -> Any:
        yield StreamEvent(kind="done")

    async def complete_tool_request(
        self,
        messages: Any,
        tools: Any,
        effort: Any = None,
        timeout: Any = None,
        cancel_token: Any = None,
    ) -> AssistantTurn:
        return AssistantTurn(text="", usage=UsageAccounting())

    def normalize_error(self, raw: Any) -> ProviderError:
        return ProviderError.normalize_unmapped(raw)

    def usage(self) -> UsageAccounting:
        return UsageAccounting()

    def healthcheck(self) -> Health:
        return Health(ok=True)


class _MissingStreamChat:
    """Negative control: every member except stream_chat."""

    id = "broken"
    capabilities = ModelCapabilities()

    async def complete_tool_request(self, *args: Any, **kwargs: Any) -> Any:
        return None

    def normalize_error(self, raw: Any) -> ProviderError:
        return ProviderError.normalize_unmapped(raw)

    def usage(self) -> UsageAccounting:
        return UsageAccounting()

    def healthcheck(self) -> Health:
        return Health(ok=True)


def test_provider_profile_positive_structural_check() -> None:
    assert isinstance(_FullProvider(), ProviderProfile)


def test_provider_profile_missing_stream_chat_fails_check() -> None:
    assert not isinstance(_MissingStreamChat(), ProviderProfile)


def test_provider_profile_plain_object_fails_check() -> None:
    assert not isinstance(object(), ProviderProfile)
