"""Provider adapter plumbing over the T1.06 contracts (SPEC §5.1, I1, I16).

**THIS MODULE DEFINES NO CONTRACT TYPE.** ``contracts/provider.py`` (T1.06)
owns every provider-neutral model and the :class:`ProviderProfile` Protocol;
this module re-exports them so an adapter has one import site, and adds only the
plumbing a frozen pydantic model cannot provide:

* :class:`UsageCounter` — a mutable accumulator that snapshots into the frozen
  :class:`~lsassist.contracts.provider.UsageAccounting` of §5.1's ``usage()``.
* :func:`healthy` / :func:`unhealthy` — the two shapes of §5.1's
  ``healthcheck()`` probe, so an adapter never has to remember that a failure
  needs a reason attached.
* :func:`ensure_provider_profile` — the fail-closed structural gate the kernel
  applies before it will talk to an adapter at all.
* the §2.2/§5.1 prohibition lists as DATA, consumed by
  ``tests/contract/providers/test_provider_prohibitions.py``.

Re-export is by IDENTITY: ``base.ProviderError is contracts.provider.ProviderError``.
A parallel definition would give the codebase two error types, and the kernel's
``except ProviderError`` would quietly stop catching the adapter's.

**§2.2 dependency direction.** ``providers/`` may import ``contracts`` (and
``httpx``); ``subprocess``, filesystem writes, ``tools`` and ``kernel`` are
forbidden. §5.1 adds credential logging. This module therefore also carries the
rule list — modules, symbols, bare calls, methods and inward packages — because
a rule kept only in a test drifts from the code it governs. The checker parses
the AST rather than grepping, which is what lets the list live here at all: the
strings below are data, not imports.

The five lists exist because a capability has more than one spelling, and an
adversarial critic round demonstrated that on the first draft: ``from os import
system``, ``Path(p).write_text(t)``, ``p.write_text(t)``, ``from ..kernel import
decide``, ``importlib.import_module("subprocess")`` and ``sys.stderr.write(m)``
ALL passed a gate that checked module names, bare-call names and
``receiver.attr`` pairs. A prohibition list that only knows the obvious spelling
of a rule is worse than none, because it reads as enforcement.

**I16.** ``AssistantTurn.reasoning_opaque`` is ``Field(exclude=True, repr=False)``
in the contract, so it is absent from ``model_dump()``, ``model_dump_json()``
and ``repr()``. Nothing here undoes that, and no module in this package may read
the attribute — reading it is how the blob escapes into a serializable
structure.

**I1.** No child processes, no filesystem access, no tool execution. The
plumbing below is pure computation over the contract models.
"""

from __future__ import annotations

from typing import Final, final

from lsassist.contracts.provider import (
    AssistantTurn,
    ChatMessage,
    ChatRequest,
    Health,
    ModelCapabilities,
    ProviderError,
    ProviderErrorKind,
    ProviderProfile,
    StreamEvent,
    StreamEventKind,
    ToolSpec,
    UsageAccounting,
)

__all__ = [
    "ADAPTER_PROHIBITED_CALLS",
    "ADAPTER_PROHIBITED_METHODS",
    "ADAPTER_PROHIBITED_MODULES",
    "ADAPTER_PROHIBITED_PACKAGES",
    "ADAPTER_PROHIBITED_SYMBOLS",
    "PROVIDER_PROFILE_MEMBERS",
    "AssistantTurn",
    "ChatMessage",
    "ChatRequest",
    "Health",
    "ModelCapabilities",
    "ProviderContractError",
    "ProviderError",
    "ProviderErrorKind",
    "ProviderProfile",
    "StreamEvent",
    "StreamEventKind",
    "ToolSpec",
    "UsageAccounting",
    "UsageCounter",
    "ensure_provider_profile",
    "healthy",
    "unhealthy",
]

#: Modules an adapter may never import. ``subprocess`` is §2.2's own word;
#: ``logging`` implements §5.1's "credential-ების logging" prohibition
#: structurally — an adapter that cannot reach a log sink cannot log a
#: credential to one. Adapters surface events through the kernel and the §14.1
#: audit journal, which is where redaction (§12.4) is applied.
ADAPTER_PROHIBITED_MODULES: Final[frozenset[str]] = frozenset(
    {
        "subprocess",
        "multiprocessing",
        "logging",
        "shutil",
        "tempfile",
        "pty",
        "ctypes",
    }
)

#: Bare calls an adapter may never make. ``open`` is the filesystem-write vector
#: §2.2 forbids (and a read vector §5.1 has no use for); ``print`` is an
#: unaudited output sink; ``eval``/``exec``/``compile`` are code execution.
ADAPTER_PROHIBITED_CALLS: Final[frozenset[str]] = frozenset(
    {
        "open",
        "print",
        "eval",
        "exec",
        "compile",
        "__import__",
        # Reachable without importing a prohibited MODULE, because the symbol
        # can be imported on its own: `from os import system` names neither
        # `subprocess` nor `open`. See ADAPTER_PROHIBITED_SYMBOLS.
        "system",
        "popen",
        "fork",
        "import_module",
    }
)

#: Symbols an adapter may never import, from ANY module. The module allowlist
#: alone is not enough: ``from os import system`` imports ``os`` — which is not
#: prohibited, since reading ``os.environ`` is legitimate — and then calls a
#: bare name. Measured against the first draft of the guard, this exact two-word
#: line bypassed both the module list and the call list.
ADAPTER_PROHIBITED_SYMBOLS: Final[frozenset[str]] = frozenset(
    {
        "system",
        "popen",
        "fork",
        "forkpty",
        "execv",
        "execve",
        "execvp",
        "spawnv",
        "spawnve",
        "Popen",
        "check_output",
        "check_call",
        "getLogger",
        "basicConfig",
        "import_module",
        "NamedTemporaryFile",
        "mkstemp",
        "mkdtemp",
    }
)

#: Method names an adapter may never CALL, on any receiver. Matching the
#: receiver's spelling instead — ``os.open``, ``Path.write_text`` — is what the
#: first draft did, and it caught only the unbound form nobody writes:
#: ``Path(p).write_text(t)`` has a ``Call`` as its receiver and ``p.write_text(t)``
#: has a local variable, so both walked straight through. The METHOD name is the
#: capability; the receiver is just how you spell reaching it.
ADAPTER_PROHIBITED_METHODS: Final[frozenset[str]] = frozenset(
    {
        "write",
        "writelines",
        "write_text",
        "write_bytes",
        "touch",
        "mkdir",
        "makedirs",
        "unlink",
        "rmdir",
        "rename",
        "replace",
        "chmod",
        "system",
        "popen",
        "fork",
        "spawnv",
        "execv",
        "communicate",
        "import_module",
    }
)

#: Inward packages §2.2 places off-limits: an adapter must not reach the
#: decision core or the tool runtime. Communication is by data contract only.
ADAPTER_PROHIBITED_PACKAGES: Final[frozenset[str]] = frozenset(
    {
        "lsassist.tools",
        "lsassist.kernel",
        "lsassist.policy",
        "lsassist.sandbox",
        "lsassist.audit",
        "lsassist.recovery",
    }
)

#: The §5.1 interface, member by member. Named explicitly rather than derived
#: from the Protocol so that deleting a method from ``ProviderProfile`` shows up
#: as a failing test instead of a silently smaller gate.
PROVIDER_PROFILE_MEMBERS: Final[tuple[str, ...]] = (
    "id",
    "capabilities",
    "stream_chat",
    "complete_tool_request",
    "normalize_error",
    "usage",
    "healthcheck",
)


class ProviderContractError(Exception):
    """An adapter, or a value handed to this plumbing, violates §5.1.

    Distinct from :class:`~lsassist.contracts.provider.ProviderError`, which
    describes a *remote* failure the retry policy may act on. This one means the
    LOCAL contract is broken — a non-conforming adapter, a negative usage
    delta — and is never retryable.
    """


@final
class UsageCounter:
    """Mutable §5.1 usage accumulator; :meth:`snapshot` freezes it.

    ``UsageAccounting`` is a frozen contract model, which is right for something
    the kernel reads but useless for something an adapter increments. This is
    the increment side.

    **Monotonic by construction.** Every delta must be a non-negative ``int``
    (``float`` and ``bool`` included), and a rejected delta applies nothing.
    §4.3's budgets are enforced on these numbers, so a negative delta would let
    a hostile or buggy provider response hand back budget it had already spent —
    the counter refuses instead of clamping, because a clamp would hide the bug.
    """

    __slots__ = ("_cost_estimate", "_requests_made", "_tokens_in", "_tokens_out")

    def __init__(self) -> None:
        self._requests_made: int = 0
        self._tokens_in: int = 0
        self._tokens_out: int = 0
        self._cost_estimate: float | None = None

    def record_request(
        self,
        *,
        tokens_in: int = 0,
        tokens_out: int = 0,
        cost_estimate: float | None = None,
    ) -> None:
        """Add one completed request to the window.

        :param cost_estimate: added to the running total. Left as ``None``
            until an estimate is supplied at least once, so "no estimate
            available" stays distinguishable from "an estimate of zero".
        :raises ProviderContractError: any delta is negative or not the right
            type. Validation happens BEFORE any field is touched.
        """
        _check_non_negative_int("tokens_in", tokens_in)
        _check_non_negative_int("tokens_out", tokens_out)
        if cost_estimate is not None:
            _check_non_negative_number("cost_estimate", cost_estimate)

        self._requests_made += 1
        self._tokens_in += tokens_in
        self._tokens_out += tokens_out
        if cost_estimate is not None:
            self._cost_estimate = (self._cost_estimate or 0.0) + float(cost_estimate)

    def snapshot(self) -> UsageAccounting:
        """A frozen §5.1 ``usage()`` value — a copy, never a live view."""
        return UsageAccounting(
            requests_made=self._requests_made,
            tokens_in=self._tokens_in,
            tokens_out=self._tokens_out,
            session_cost_estimate=self._cost_estimate,
        )

    def reset(self) -> None:
        """Start a new rolling window (§5.1)."""
        self._requests_made = 0
        self._tokens_in = 0
        self._tokens_out = 0
        self._cost_estimate = None


def _check_non_negative_int(label: str, value: object) -> None:
    """Reject anything that is not a plain, non-negative ``int``.

    ``bool`` is excluded explicitly: it is an ``int`` subclass, so ``True``
    would otherwise be accepted as the token count ``1``.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProviderContractError(
            f"{label} must be an int, got {type(value).__name__} — the §4.3 budget "
            "path does not coerce"
        )
    if value < 0:
        raise ProviderContractError(f"{label}={value} is negative; usage counters are monotonic")


def _check_non_negative_number(label: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ProviderContractError(f"{label} must be a number, got {type(value).__name__}")
    if value < 0:
        raise ProviderContractError(f"{label}={value} is negative; usage counters are monotonic")


def healthy(*, detail: str = "", latency_ms: float | None = None) -> Health:
    """A passing §5.1 ``healthcheck()`` probe."""
    return Health(ok=True, detail=detail, latency_ms=latency_ms)


def unhealthy(detail: str, *, latency_ms: float | None = None) -> Health:
    """A failing §5.1 probe — the circuit-breaker input.

    :param detail: REQUIRED and non-empty. The breaker's job is to decide
        whether to fall back (§5.4, "never silent"), and an unexplained failure
        is a decision nobody downstream can render or act on.
    :raises ProviderContractError: ``detail`` is blank.
    """
    if not detail.strip():
        raise ProviderContractError(
            "unhealthy() requires a reason; §5.4 forbids a silent fallback, and a "
            "blank detail is what makes one silent"
        )
    return Health(ok=False, detail=detail, latency_ms=latency_ms)


def ensure_provider_profile(candidate: object) -> ProviderProfile:
    """Structurally verify an adapter against §5.1, or raise (fail-closed).

    :returns: ``candidate`` unchanged, typed as :class:`ProviderProfile`.
    :raises ProviderContractError: a §5.1 member is missing, or one that should
        be callable is not. The message names the member so the failure is
        actionable.

    This checks SHAPE, not behaviour — ``isinstance`` against a
    ``runtime_checkable`` Protocol cannot inspect signatures, and neither can
    this. It exists so the kernel never holds a half-implemented adapter, not so
    it can stop auditing what one returns: §2.3 places ``providers/`` outside
    the TCB precisely because adapter OUTPUT must be validated at every use.
    """
    missing = [name for name in PROVIDER_PROFILE_MEMBERS if not hasattr(candidate, name)]
    if missing:
        raise ProviderContractError(
            f"{type(candidate).__name__} is not a ProviderProfile: missing {missing} (SPEC §5.1)"
        )
    not_callable = [
        name
        for name in PROVIDER_PROFILE_MEMBERS[2:]
        if not callable(getattr(candidate, name, None))
    ]
    if not_callable:
        raise ProviderContractError(
            f"{type(candidate).__name__} is not a ProviderProfile: {not_callable} "
            "are not callable (SPEC §5.1)"
        )
    return candidate  # type: ignore[return-value]
