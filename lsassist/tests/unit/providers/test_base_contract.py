"""T3.08 RED: provider base plumbing over the T1.06 contracts (SPEC §5.1, I1, I16).

``providers/base.py`` is plumbing, not contract definition. T1.06 already owns
every provider-neutral type in ``contracts/provider.py``; this module re-exports
them and adds the two things an adapter needs and a frozen pydantic model
cannot give it — a mutable usage accumulator and ``Health`` constructors — plus
the fail-closed structural check the kernel uses before trusting an adapter.

The first section is therefore the load-bearing one: every re-exported name must
be the SAME OBJECT as the contract's. Equality is not enough. A parallel class
that merely looks alike would give the codebase two ``ProviderError`` types, and
``except ProviderError`` in the kernel would stop catching the adapter's.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from lsassist.contracts import provider as contracts_provider
from lsassist.providers import base
from lsassist.providers.base import (
    ADAPTER_PROHIBITED_CALLS,
    ADAPTER_PROHIBITED_MODULES,
    ADAPTER_PROHIBITED_PACKAGES,
    AssistantTurn,
    ChatMessage,
    ChatRequest,
    Health,
    ModelCapabilities,
    ProviderContractError,
    ProviderError,
    ProviderErrorKind,
    ProviderProfile,
    StreamEvent,
    ToolSpec,
    UsageAccounting,
    UsageCounter,
    healthy,
    unhealthy,
)

# --- a conforming adapter double ---------------------------------------------


class FakeAdapter:
    """The smallest object that satisfies the §5.1 Protocol structurally."""

    id = "fake-provider"
    capabilities = ModelCapabilities(streaming=True)

    def stream_chat(self, request: ChatRequest) -> object:  # never called: shape only
        raise NotImplementedError

    async def complete_tool_request(
        self,
        messages: list[ChatMessage],
        tools: list[ToolSpec],
        effort: str | None = None,
        timeout_s: float | None = None,
        cancel_token: object | None = None,
    ) -> AssistantTurn:  # never called: shape only
        raise NotImplementedError

    def normalize_error(self, raw: object) -> ProviderError:
        return ProviderError.normalize_unmapped(raw)

    def usage(self) -> UsageAccounting:
        return UsageAccounting()

    def healthcheck(self) -> Health:
        return healthy()


# ==========================================================================
# 1. re-export identity — base.py defines NO contract type
# ==========================================================================
RE_EXPORTED = [
    "AssistantTurn",
    "ChatMessage",
    "ChatRequest",
    "Health",
    "ModelCapabilities",
    "ProviderError",
    "ProviderErrorKind",
    "ProviderProfile",
    "StreamEvent",
    "StreamEventKind",
    "ToolSpec",
    "UsageAccounting",
]


@pytest.mark.parametrize("name", RE_EXPORTED)
def test_every_contract_type_is_the_same_object(name: str) -> None:
    """Identity, not equality: two ``ProviderError`` classes break ``except``."""
    assert getattr(base, name) is getattr(contracts_provider, name), (
        f"providers.base.{name} is not contracts.provider.{name} — T1.06 owns this type"
    )


def test_base_declares_no_pydantic_model_of_its_own() -> None:
    """Contract types live in ``contracts/`` (§2.2); plumbing lives here."""
    from pydantic import BaseModel

    locally_defined = [
        name
        for name, value in vars(base).items()
        if isinstance(value, type)
        and issubclass(value, BaseModel)
        and value.__module__ == base.__name__
    ]
    assert locally_defined == [], f"base.py defines contract models: {locally_defined}"


def test_everything_exported_is_importable() -> None:
    for name in base.__all__:
        assert hasattr(base, name), f"__all__ lists a missing name: {name}"


# ==========================================================================
# 2. UsageAccounting plumbing (§5.1 usage())
# ==========================================================================
def test_counter_starts_at_zero() -> None:
    snapshot = UsageCounter().snapshot()
    assert snapshot == UsageAccounting()
    assert snapshot.requests_made == 0
    assert snapshot.session_cost_estimate is None


def test_counter_accumulates_across_requests() -> None:
    counter = UsageCounter()
    counter.record_request(tokens_in=100, tokens_out=20)
    counter.record_request(tokens_in=5, tokens_out=1)

    snapshot = counter.snapshot()
    assert snapshot.requests_made == 2
    assert snapshot.tokens_in == 105
    assert snapshot.tokens_out == 21


def test_counter_snapshot_is_a_frozen_contract_model() -> None:
    snapshot = UsageCounter().snapshot()
    assert isinstance(snapshot, UsageAccounting)
    with pytest.raises(ValidationError):
        snapshot.requests_made = 99  # type: ignore[misc]


def test_snapshot_does_not_alias_the_counter() -> None:
    counter = UsageCounter()
    counter.record_request(tokens_in=10, tokens_out=1)
    before = counter.snapshot()
    counter.record_request(tokens_in=10, tokens_out=1)

    assert before.requests_made == 1, "an earlier snapshot must not move"
    assert counter.snapshot().requests_made == 2


def test_cost_stays_none_until_an_estimate_is_supplied() -> None:
    counter = UsageCounter()
    counter.record_request(tokens_in=1, tokens_out=1)
    assert counter.snapshot().session_cost_estimate is None

    counter.record_request(tokens_in=1, tokens_out=1, cost_estimate=0.25)
    counter.record_request(tokens_in=1, tokens_out=1, cost_estimate=0.25)
    assert counter.snapshot().session_cost_estimate == pytest.approx(0.5)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"tokens_in": -1},
        {"tokens_out": -1},
        {"tokens_in": -5, "tokens_out": 5},
        {"cost_estimate": -0.01},
    ],
)
def test_counter_refuses_negative_deltas(kwargs: dict[str, float]) -> None:
    """§4.3 budgets are enforced on these counters.

    A negative delta would let a hostile or buggy provider response REDUCE the
    tally and buy back budget it had already spent, so the counter is
    monotonic by construction.
    """
    counter = UsageCounter()
    with pytest.raises(ProviderContractError):
        counter.record_request(**kwargs)  # type: ignore[arg-type]
    assert counter.snapshot() == UsageAccounting(), "a refused delta must not partially apply"


@pytest.mark.parametrize("kwargs", [{"tokens_in": 1.5}, {"tokens_out": "3"}, {"tokens_in": True}])
def test_counter_refuses_non_integer_token_counts(kwargs: dict[str, object]) -> None:
    """No lax coercion in the budget path: a token count is an int or an error."""
    with pytest.raises(ProviderContractError):
        UsageCounter().record_request(**kwargs)  # type: ignore[arg-type]


def test_counter_reset_starts_a_new_rolling_window() -> None:
    """§5.1: "client-side counters per rolling window"."""
    counter = UsageCounter()
    counter.record_request(tokens_in=10, tokens_out=2, cost_estimate=1.0)
    counter.reset()
    assert counter.snapshot() == UsageAccounting()


# ==========================================================================
# 3. Health plumbing (§5.1 healthcheck())
# ==========================================================================
def test_healthy_builds_an_ok_probe() -> None:
    health = healthy(latency_ms=12.5)
    assert isinstance(health, Health)
    assert health.ok is True
    assert health.latency_ms == pytest.approx(12.5)
    assert health.detail == ""


def test_unhealthy_requires_a_reason() -> None:
    """An unexplained failure is a circuit-breaker input nobody can act on."""
    health = unhealthy("connect timeout after 5s")
    assert health.ok is False
    assert "timeout" in health.detail

    with pytest.raises(ProviderContractError):
        unhealthy("")


def test_unhealthy_never_yields_ok() -> None:
    assert unhealthy("down", latency_ms=None).ok is False


def test_health_rejects_a_negative_latency() -> None:
    """The contract's own ``ge=0`` still applies through the helper."""
    with pytest.raises(ValidationError):
        healthy(latency_ms=-1.0)


# ==========================================================================
# 4. error normalization (§5.1 normalize_error)
# ==========================================================================
def test_unmapped_error_is_transient_and_retryable() -> None:
    """§5.1 failure behavior: the SAFE side is limited retries, never terminal."""
    error = ProviderError.normalize_unmapped(RuntimeError("who knows"))
    assert error.kind is ProviderErrorKind.TRANSIENT
    assert error.retryable is True
    assert error.terminal is False


def test_terminal_and_retryable_remain_mutually_exclusive_through_the_re_export() -> None:
    with pytest.raises(ValidationError):
        ProviderError(kind=ProviderErrorKind.AUTH, retryable=True, terminal=True)


# ==========================================================================
# 5. the structural adapter gate (§5.1 Protocol)
# ==========================================================================
def test_conforming_adapter_is_accepted() -> None:
    adapter = FakeAdapter()
    assert base.ensure_provider_profile(adapter) is adapter
    assert isinstance(adapter, ProviderProfile)


@pytest.mark.parametrize(
    "missing",
    ["stream_chat", "complete_tool_request", "normalize_error", "usage", "healthcheck"],
)
def test_adapter_missing_a_member_is_refused(missing: str) -> None:
    """Fail-closed: the kernel must not hold a half-implemented adapter."""
    incomplete = type("Incomplete", (FakeAdapter,), {missing: None})()
    with pytest.raises(ProviderContractError) as excinfo:
        base.ensure_provider_profile(incomplete)
    assert missing in str(excinfo.value)


@pytest.mark.parametrize("absent", ["id", "capabilities"])
def test_adapter_missing_a_data_member_is_refused(absent: str) -> None:
    """``id`` and ``capabilities`` are §5.1 rows too, not just the five methods."""
    members = {
        name: getattr(FakeAdapter, name)
        for name in base.PROVIDER_PROFILE_MEMBERS
        if name != absent
    }
    incomplete = type("Incomplete", (), members)()
    with pytest.raises(ProviderContractError) as excinfo:
        base.ensure_provider_profile(incomplete)
    assert absent in str(excinfo.value)


def test_a_plain_object_is_refused() -> None:
    with pytest.raises(ProviderContractError):
        base.ensure_provider_profile(object())


# ==========================================================================
# 6. I16 — reasoning_opaque is RAM-only
# ==========================================================================
REASONING = "CHAIN-OF-THOUGHT-THAT-MUST-NEVER-BE-AUDITED"


def test_reasoning_opaque_round_trips_in_memory() -> None:
    turn = AssistantTurn(text="hello", reasoning_opaque=REASONING)
    assert turn.reasoning_opaque == REASONING


@pytest.mark.parametrize("mode", ["python", "json"])
def test_reasoning_opaque_is_absent_from_every_dump(mode: str) -> None:
    turn = AssistantTurn(text="hello", reasoning_opaque=REASONING)
    dumped = turn.model_dump(mode=mode)
    assert "reasoning_opaque" not in dumped
    assert REASONING not in str(dumped)


def test_reasoning_opaque_is_absent_from_json_and_repr() -> None:
    turn = AssistantTurn(text="hello", reasoning_opaque=REASONING)
    assert REASONING not in turn.model_dump_json()
    assert REASONING not in repr(turn)
    assert REASONING not in str(turn)


def test_a_stream_event_carrying_a_turn_still_hides_the_reasoning() -> None:
    """The event stream is an audit-facing sink too (§14.1)."""
    turn = AssistantTurn(text="hi", reasoning_opaque=REASONING)
    event = StreamEvent(kind="done", text=turn.text, usage=turn.usage)
    assert REASONING not in event.model_dump_json()


# ==========================================================================
# 7. the prohibition list is DATA that lives with the code
# ==========================================================================
def test_prohibitions_name_every_spec_22_forbidden_item() -> None:
    """§2.2 providers row: forbidden = subprocess, fs writes, tools, kernel."""
    assert "subprocess" in ADAPTER_PROHIBITED_MODULES
    assert "lsassist.tools" in ADAPTER_PROHIBITED_PACKAGES
    assert "lsassist.kernel" in ADAPTER_PROHIBITED_PACKAGES
    assert "open" in ADAPTER_PROHIBITED_CALLS


def test_prohibitions_cover_credential_logging() -> None:
    """§5.1 also forbids credential logging; an adapter reaches no log sink."""
    assert "logging" in ADAPTER_PROHIBITED_MODULES
    assert "print" in ADAPTER_PROHIBITED_CALLS


def test_prohibition_lists_are_immutable() -> None:
    for prohibited in (
        ADAPTER_PROHIBITED_MODULES,
        ADAPTER_PROHIBITED_CALLS,
        ADAPTER_PROHIBITED_PACKAGES,
    ):
        assert isinstance(prohibited, frozenset)
