"""§4.7 idempotency keys + replay protection (T2.10).

Every tool request gets ``idempotency_key = HMAC(session_id, task_id,
action_hash, seq)``. On §14.5 resume the journal's last ``seq`` is known, and an
already-executed ``seq`` is NEVER re-executed: the state machine either restores
from the captured ``OBSERVE`` result or re-forms the action from ``PLAN``. A
crash mid-exec leaves a STARTED-but-not-COMPLETED ``seq``, which §4.7 routes to
the human review prompt ("unknown side effects, inspect checkpoint diff") — so
it must be reported as its OWN outcome, never silently re-executed and never
silently skipped.

CRITICAL — the HMAC input is INJECTIVE (:meth:`ActionRef.canonical_bytes`).
A naive ``f"{session_id}:{task_id}:{action_hash}:{seq}"`` join is FORBIDDEN
here: ids are free-form strings, so ``("a:b", "c")`` and ``("a", "b:c")`` would
join to the same string and derive the SAME key — request A could then present
request B's key and slip past the guard. This project already shipped a HIGH
defect of exactly this shape (a non-injective ``k=v\\n`` join in
``policy.canonical.env_digest``). We therefore serialize with the SAME canonical
JSON as the rest of the TCB (``sort_keys=True``, ``separators=(",", ":")``,
``ensure_ascii=False``): field names delimit values, and ``json.dumps`` escapes
``"``/``\\``/control characters inside them, so the encoding is unambiguous and
each field's bytes cannot bleed into its neighbour. The payload also carries a
``kind`` domain tag: the SAME kernel secret mints §7.4 approval tokens, and the
tag makes an idempotency key and a token HMAC structurally unable to collide.

PURE (§2.2): the kernel secret is INJECTED as ``bytes`` (like
:class:`~lsassist.policy.token.TokenService`) — no filesystem, env, clock, or
randomness in this module. The ledger is kernel-side in-memory state keyed by
``seq`` (V1); :meth:`IdempotencyLedger.restore` rebuilds it from the journal on
``lsassist resume``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

# The §4.7 domain tag. Included in the HMAC payload so an idempotency key can
# never be confused with (or spliced from) another HMAC minted under the same
# kernel secret — notably the §7.4 approval token over ApprovalRecord.
_KIND = "lsassist/idempotency/v1"


class IdempotencyError(Exception):
    """Base for every fail-closed §4.7 refusal. The guard NEVER answers a
    replay/forgery signal with a silent allow or a silent skip."""


class SeqConflictError(IdempotencyError):
    """A ``seq`` already in the ledger was presented with DIFFERENT identity
    fields (``session_id``/``task_id``/``action_hash``), i.e. a different
    idempotency key. That is a replay/forgery signal, not a retry: a genuine
    retry of ``seq`` replays the IDENTICAL tuple."""


class SeqRegressionError(IdempotencyError):
    """A NEW ``seq`` arrived at or below the ledger's high-water mark. ``seq`` is
    monotonic within a task, so an out-of-order new seq is a replay signal."""


class UnknownSeqError(IdempotencyError):
    """:meth:`IdempotencyLedger.complete` named a ``seq`` that was never begun —
    completing an action the guard never authorized."""


class DuplicateCompletionError(IdempotencyError):
    """:meth:`IdempotencyLedger.complete` named an already-COMPLETED ``seq``.
    The recorded result reference is kept; the second completion is refused."""


class ExecutionState(StrEnum):
    """The recorded lifecycle of a ``seq`` in the ledger."""

    #: begin() authorized execution; no completion recorded (crash mid-exec
    #: leaves the entry here — §4.7 partial execution).
    STARTED = "STARTED"
    #: The action ran to completion and its result was captured (OBSERVE).
    COMPLETED = "COMPLETED"


class ReplayVerdict(StrEnum):
    """The fail-closed outcome of :meth:`IdempotencyLedger.begin`. Exactly one
    is returned; only :data:`ALLOWED` authorizes execution."""

    #: Fresh, monotonic seq — execute it (now recorded STARTED).
    ALLOWED = "ALLOWED"
    #: This seq already ran to completion. Never re-execute; restore the state
    #: machine from the captured OBSERVE result (``result_ref``).
    ALREADY_EXECUTED = "ALREADY_EXECUTED"
    #: STARTED but never COMPLETED (crash mid-exec). Neither re-execute nor
    #: skip: §4.7 escalates to the human review prompt.
    PARTIAL_EXECUTION = "PARTIAL_EXECUTION"


@dataclass(frozen=True, slots=True)
class ActionRef:
    """The four §4.7 key fields identifying one tool request. Frozen — a request
    identity is a value, not mutable state.

    Preconditions are enforced at construction (fail closed): the three id
    fields must be non-empty and ``seq`` a non-negative ``int``. ``bool`` is
    rejected explicitly even though it is an ``int`` subclass — ``seq=True``
    would silently alias ``seq=1``.
    """

    session_id: str
    task_id: str
    action_hash: str
    seq: int

    def __post_init__(self) -> None:
        for name in ("session_id", "task_id", "action_hash"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty str, got {value!r}")
        if isinstance(self.seq, bool) or not isinstance(self.seq, int) or self.seq < 0:
            raise ValueError(f"seq must be a non-negative int, got {self.seq!r}")

    def canonical_json(self) -> str:
        """The ONE canonical form of this request (see the module docstring for
        why it is canonical JSON and not a separator join). Keep it STABLE: a
        resumed session recomputes keys from the journal and compares them."""
        payload: dict[str, Any] = {
            "kind": _KIND,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "action_hash": self.action_hash,
            "seq": self.seq,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def canonical_bytes(self) -> bytes:
        """UTF-8 bytes of :meth:`canonical_json` (the direct HMAC input)."""
        return self.canonical_json().encode("utf-8")


@dataclass(frozen=True, slots=True)
class ReplayDecision:
    """What :meth:`IdempotencyLedger.begin` decided, plus this request's key.

    ``result_ref`` is set ONLY for :data:`ReplayVerdict.ALREADY_EXECUTED` — it is
    the reference to the previously captured result the state machine restores
    from instead of re-executing.
    """

    verdict: ReplayVerdict
    key: str
    result_ref: str | None


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """One recorded ``seq``: the request that claimed it, its idempotency key,
    its execution state, and (once COMPLETED) its result reference."""

    ref: ActionRef
    key: str
    state: ExecutionState
    result_ref: str | None


class IdempotencyLedger:
    """Derives §4.7 idempotency keys and enforces the replay rules.

    The kernel calls :meth:`begin` before EXECUTE and :meth:`complete` after the
    result is captured. On ``lsassist resume`` the journal is replayed into
    :meth:`restore` first, so the in-memory (V1) ledger reflects what the
    previous run already did.
    """

    def __init__(self, kernel_secret: bytes) -> None:
        # 32-byte install-time random secret, resolved+ownership-checked by the
        # T1.09 resolver and injected here as bytes (no fs/env access, §2.2).
        self._secret = kernel_secret
        # Kernel-side ledger, keyed by seq (V1: in-memory dict).
        self._entries: dict[int, LedgerEntry] = {}
        self._highest_seq: int | None = None

    # -- key derivation ---------------------------------------------------

    def derive_key(self, ref: ActionRef) -> str:
        """Return ``HMAC-SHA256(secret, ref.canonical_bytes())`` as hex.

        The ONLY HMAC input is the request's single canonical form, VERBATIM —
        this method never re-serializes the fields itself (a second
        serialization path IS the collision/forgery vulnerability).
        """
        return hmac.new(self._secret, ref.canonical_bytes(), hashlib.sha256).hexdigest()

    def verify_key(self, key: str, ref: ActionRef) -> bool:
        """Timing-safely test whether ``key`` is ``ref``'s idempotency key.

        Compared with :func:`hmac.compare_digest` over UTF-8 BYTES, never ``==``.
        Bytes matter for more than timing: ``key`` comes off the journal (or an
        attacker) and may be non-ASCII, on which a *str* ``compare_digest``
        RAISES (the token service already hit this). Encoding both operands
        keeps the answer a fail-closed ``False``.
        """
        return hmac.compare_digest(
            self.derive_key(ref).encode("ascii"), key.encode("utf-8")
        )

    # -- ledger introspection ---------------------------------------------

    @property
    def highest_seq(self) -> int | None:
        """The high-water mark, or ``None`` while the ledger is empty."""
        return self._highest_seq

    def entry(self, seq: int) -> LedgerEntry | None:
        """The recorded entry for ``seq``, or ``None`` if it is unknown."""
        return self._entries.get(seq)

    # -- replay guard ------------------------------------------------------

    def begin(self, ref: ActionRef) -> ReplayDecision:
        """Decide whether ``ref`` may execute, recording STARTED if it may.

        Fail-closed and ordered:

        1. unknown ``seq`` at/below the high-water mark → :class:`SeqRegressionError`;
        2. unknown, monotonic ``seq`` → recorded STARTED, :data:`ReplayVerdict.ALLOWED`;
        3. known ``seq`` whose key does NOT match → :class:`SeqConflictError`;
        4. known ``seq``, COMPLETED → :data:`ReplayVerdict.ALREADY_EXECUTED`
           carrying the prior ``result_ref`` (NEVER re-executed);
        5. known ``seq``, STARTED → :data:`ReplayVerdict.PARTIAL_EXECUTION`
           (never re-executed, never skipped — human review per §4.7).

        Re-calling :meth:`begin` on a STARTED or COMPLETED ``seq`` is stable: it
        keeps returning the same non-ALLOWED verdict, so a retry loop can never
        wear the guard down into authorizing a second execution.
        """
        key = self.derive_key(ref)
        recorded = self._entries.get(ref.seq)

        if recorded is None:
            if self._highest_seq is not None and ref.seq <= self._highest_seq:
                raise SeqRegressionError(
                    f"out-of-order seq {ref.seq}: high-water mark is {self._highest_seq}"
                )
            self._put(LedgerEntry(ref=ref, key=key, state=ExecutionState.STARTED, result_ref=None))
            return ReplayDecision(verdict=ReplayVerdict.ALLOWED, key=key, result_ref=None)

        self._assert_same_request(recorded, key, ref.seq)

        if recorded.state is ExecutionState.COMPLETED:
            return ReplayDecision(
                verdict=ReplayVerdict.ALREADY_EXECUTED,
                key=key,
                result_ref=recorded.result_ref,
            )
        return ReplayDecision(
            verdict=ReplayVerdict.PARTIAL_EXECUTION, key=key, result_ref=None
        )

    def complete(self, ref: ActionRef, result_ref: str) -> None:
        """Record that ``ref``'s action finished and its result was captured.

        ``result_ref`` names the captured OBSERVE result a later replay restores
        from, so it must be non-empty. Refuses fail-closed if ``seq`` was never
        begun (:class:`UnknownSeqError`), if the presented fields do not match
        the entry (:class:`SeqConflictError`), or if it already completed
        (:class:`DuplicateCompletionError` — the first result is kept).
        """
        if not result_ref:
            raise ValueError("result_ref must be a non-empty reference to the captured result")

        recorded = self._entries.get(ref.seq)
        if recorded is None:
            raise UnknownSeqError(f"cannot complete seq {ref.seq}: never begun")

        self._assert_same_request(recorded, self.derive_key(ref), ref.seq)

        if recorded.state is ExecutionState.COMPLETED:
            raise DuplicateCompletionError(f"seq {ref.seq} is already COMPLETED")

        self._entries[ref.seq] = LedgerEntry(
            ref=recorded.ref,
            key=recorded.key,
            state=ExecutionState.COMPLETED,
            result_ref=result_ref,
        )

    def restore(
        self, ref: ActionRef, state: ExecutionState, result_ref: str | None
    ) -> None:
        """Rebuild one journal entry into the ledger (§14.5 ``lsassist resume``).

        Entries are replayed in journal order, so ``seq`` must be strictly above
        the high-water mark (:class:`SeqRegressionError`) and not already
        present (:class:`SeqConflictError`). A COMPLETED entry MUST carry its
        ``result_ref`` (otherwise the replay could not restore from OBSERVE) and
        a STARTED one must NOT — a half-recorded entry is refused rather than
        being resumed on a guess.
        """
        if state is ExecutionState.COMPLETED and not result_ref:
            raise ValueError(f"restored COMPLETED seq {ref.seq} requires a result_ref")
        if state is ExecutionState.STARTED and result_ref is not None:
            raise ValueError(f"restored STARTED seq {ref.seq} must not carry a result_ref")
        if ref.seq in self._entries:
            raise SeqConflictError(f"seq {ref.seq} is already recorded")
        if self._highest_seq is not None and ref.seq <= self._highest_seq:
            raise SeqRegressionError(
                f"out-of-order restored seq {ref.seq}: high-water mark is {self._highest_seq}"
            )
        self._put(
            LedgerEntry(
                ref=ref, key=self.derive_key(ref), state=state, result_ref=result_ref
            )
        )

    # -- internals ---------------------------------------------------------

    def _put(self, entry: LedgerEntry) -> None:
        self._entries[entry.ref.seq] = entry
        if self._highest_seq is None or entry.ref.seq > self._highest_seq:
            self._highest_seq = entry.ref.seq

    def _assert_same_request(self, recorded: LedgerEntry, key: str, seq: int) -> None:
        """A known seq must be the SAME request. Identity is the idempotency key
        itself (it covers all four fields), compared timing-safely — both
        operands are locally derived ASCII hex."""
        if not hmac.compare_digest(recorded.key.encode("ascii"), key.encode("ascii")):
            raise SeqConflictError(
                f"seq {seq} was recorded for a different request "
                "(session_id/task_id/action_hash mismatch)"
            )
