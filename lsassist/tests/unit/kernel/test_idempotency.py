"""T2.10: §4.7 idempotency keys + replay protection (kernel state-machine guard).

These tests pin the two halves of §4.7:

**Key derivation** — ``idempotency_key = HMAC(session_id, task_id, action_hash,
seq)`` under an INJECTED kernel secret. Deterministic, sensitive to every one of
the four fields, and INJECTIVE: the serialization fed to the HMAC is canonical
JSON, so the field pair ``("a:b", "c")`` and ``("a", "b:c")`` — which a naive
``f"{a}:{b}:..."`` join would collide into one string — derive DIFFERENT keys.
(This project already shipped a HIGH defect from a non-injective ``k=v\\n`` join
in ``env_digest``; the same class of bug here is a replay-guard bypass.)
Presented keys are compared with :func:`hmac.compare_digest` over UTF-8 bytes,
so an attacker-supplied non-ASCII key returns ``False`` instead of raising.

**Replay guard** — a seq-keyed ledger with three fail-closed outcomes:
``ALLOWED`` (never seen), ``ALREADY_EXECUTED`` (COMPLETED — never re-executed,
carries the prior ``result_ref`` so §14.5 resume can restore from OBSERVE), and
``PARTIAL_EXECUTION`` (STARTED but never completed — crash mid-exec; §4.7 routes
it to the human review prompt, so it is never silently re-executed and never
silently skipped). A duplicate seq whose fields differ (a forgery/replay signal,
not a retry) and an out-of-order seq are TYPED errors, never silent drops.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from lsassist.kernel.idempotency import (
    ActionRef,
    DuplicateCompletionError,
    ExecutionState,
    IdempotencyError,
    IdempotencyLedger,
    LedgerEntry,
    ReplayVerdict,
    SeqConflictError,
    SeqRegressionError,
    UnknownSeqError,
)

# A fixed 32-byte "kernel secret": install-time random in production, resolved
# by the T1.09 resolver and INJECTED here as bytes (this module never touches
# the filesystem/env for it).
SECRET = bytes(range(32))
OTHER_SECRET = bytes(range(1, 33))

AHASH = "sha256:" + "ab" * 32
AHASH2 = "sha256:" + "cd" * 32


def _ref(
    *,
    session_id: str = "sess-abc",
    task_id: str = "task-001",
    action_hash: str = AHASH,
    seq: int = 1,
) -> ActionRef:
    return ActionRef(
        session_id=session_id, task_id=task_id, action_hash=action_hash, seq=seq
    )


# --------------------------------------------------------------------------
# Key derivation
# --------------------------------------------------------------------------


def test_key_is_deterministic_across_calls() -> None:
    """The same four fields under the same secret always derive the same key."""
    ledger = IdempotencyLedger(SECRET)
    ref = _ref()
    assert ledger.derive_key(ref) == ledger.derive_key(ref)
    # And across ledger instances — the key is a pure function of secret+fields.
    assert IdempotencyLedger(SECRET).derive_key(ref) == ledger.derive_key(ref)


@pytest.mark.parametrize(
    "mutation",
    [
        {"session_id": "sess-xyz"},
        {"task_id": "task-002"},
        {"action_hash": AHASH2},
        {"seq": 2},
    ],
)
def test_key_is_sensitive_to_every_field(mutation: dict[str, object]) -> None:
    """Changing ANY of session_id/task_id/action_hash/seq changes the key."""
    ledger = IdempotencyLedger(SECRET)
    base = ledger.derive_key(_ref())
    assert ledger.derive_key(_ref(**mutation)) != base  # type: ignore[arg-type]


def test_key_is_secret_bound() -> None:
    """A different kernel secret derives a different key for identical fields."""
    ref = _ref()
    assert IdempotencyLedger(SECRET).derive_key(ref) != IdempotencyLedger(
        OTHER_SECRET
    ).derive_key(ref)


def test_serialization_is_injective_where_a_naive_join_collides() -> None:
    """The §4.7 anti-collision property (the ``env_digest`` defect class).

    A naive ``f"{session}:{task}:{hash}:{seq}"`` join maps BOTH of these field
    tuples onto the identical string — so under it, request A could replay
    request B's key. Canonical JSON keeps them distinct.
    """
    left = _ref(session_id="a:b", task_id="c")
    right = _ref(session_id="a", task_id="b:c")

    naive_left = f"{left.session_id}:{left.task_id}:{left.action_hash}:{left.seq}"
    naive_right = f"{right.session_id}:{right.task_id}:{right.action_hash}:{right.seq}"
    assert naive_left == naive_right, "control: the naive join really does collide"

    ledger = IdempotencyLedger(SECRET)
    assert ledger.derive_key(left) != ledger.derive_key(right)
    assert left.canonical_bytes() != right.canonical_bytes()


def test_serialization_resists_json_structure_injection() -> None:
    """A field carrying JSON metacharacters cannot forge another field's value.

    ``json.dumps`` escapes ``"`` and ``\\`` inside the string, so a session_id
    that *looks* like ``"…","task_id":"…`` stays one value.
    """
    ledger = IdempotencyLedger(SECRET)
    sneaky = _ref(session_id='a","task_id":"b', task_id="c")
    honest = _ref(session_id="a", task_id="b")
    assert ledger.derive_key(sneaky) != ledger.derive_key(honest)


def test_key_matches_independent_hmac_recomputation() -> None:
    """Pin the EXACT HMAC input: domain-tagged canonical JSON, HMAC-SHA256."""
    ledger = IdempotencyLedger(SECRET)
    ref = _ref()
    payload = {
        "kind": "lsassist/idempotency/v1",
        "session_id": ref.session_id,
        "task_id": ref.task_id,
        "action_hash": ref.action_hash,
        "seq": ref.seq,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert ref.canonical_bytes() == blob.encode("utf-8")
    expected = hmac.new(SECRET, blob.encode("utf-8"), hashlib.sha256).hexdigest()
    assert ledger.derive_key(ref) == expected


def test_key_handles_non_ascii_fields() -> None:
    """Non-ASCII ids serialize (ensure_ascii=False) + hash without raising, and
    remain distinguishable."""
    ledger = IdempotencyLedger(SECRET)
    key_a = ledger.derive_key(_ref(session_id="სესია-ა"))
    key_b = ledger.derive_key(_ref(session_id="სესია-ბ"))
    assert key_a != key_b
    assert all(c in "0123456789abcdef" for c in key_a)


# --------------------------------------------------------------------------
# Timing-safe key verification
# --------------------------------------------------------------------------


def test_verify_key_accepts_the_derived_key() -> None:
    ledger = IdempotencyLedger(SECRET)
    ref = _ref()
    assert ledger.verify_key(ledger.derive_key(ref), ref) is True


def test_verify_key_rejects_a_key_for_different_fields() -> None:
    ledger = IdempotencyLedger(SECRET)
    assert ledger.verify_key(ledger.derive_key(_ref(seq=2)), _ref(seq=1)) is False


def test_verify_key_does_not_raise_on_non_ascii_presented_key() -> None:
    """A journal/attacker-supplied non-ASCII key must fail-close, not raise.

    ``hmac.compare_digest`` raises ``TypeError`` on non-ASCII *str* operands —
    the token service already hit this; the comparison happens over UTF-8 bytes.
    """
    ledger = IdempotencyLedger(SECRET)
    assert ledger.verify_key("გასაღები-არა-ascii", _ref()) is False
    assert ledger.verify_key("", _ref()) is False


def test_verify_key_uses_compare_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    """The comparison is the timing-safe primitive over bytes, not ``==``."""
    ledger = IdempotencyLedger(SECRET)
    ref = _ref()
    calls: list[tuple[object, object]] = []
    real = hmac.compare_digest

    def _spy(a: object, b: object) -> bool:
        calls.append((a, b))
        return real(a, b)  # type: ignore[arg-type]

    monkeypatch.setattr(hmac, "compare_digest", _spy)
    assert ledger.verify_key(ledger.derive_key(ref), ref) is True
    assert calls, "verify_key must route through hmac.compare_digest"
    assert all(isinstance(a, bytes) and isinstance(b, bytes) for a, b in calls)


# --------------------------------------------------------------------------
# ActionRef preconditions (fail closed at construction)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"session_id": ""},
        {"task_id": ""},
        {"action_hash": ""},
        {"seq": -1},
    ],
)
def test_action_ref_rejects_malformed_fields(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _ref(**kwargs)  # type: ignore[arg-type]


def test_action_ref_rejects_bool_seq() -> None:
    """``bool`` is an ``int`` subclass — ``seq=True`` would alias seq 1."""
    with pytest.raises(ValueError):
        ActionRef(session_id="s", task_id="t", action_hash=AHASH, seq=True)


# --------------------------------------------------------------------------
# Replay guard
# --------------------------------------------------------------------------


def test_first_begin_is_allowed_and_records_started() -> None:
    ledger = IdempotencyLedger(SECRET)
    ref = _ref(seq=1)
    decision = ledger.begin(ref)
    assert decision.verdict is ReplayVerdict.ALLOWED
    assert decision.result_ref is None
    assert decision.key == ledger.derive_key(ref)

    entry = ledger.entry(1)
    assert entry is not None
    assert entry.state is ExecutionState.STARTED
    assert entry.result_ref is None


def test_unknown_seq_is_allowed() -> None:
    """A fresh, strictly-higher seq is never blocked by the guard."""
    ledger = IdempotencyLedger(SECRET)
    ledger.begin(_ref(seq=1))
    ledger.complete(_ref(seq=1), "obs:1")
    assert ledger.begin(_ref(seq=2, action_hash=AHASH2)).verdict is ReplayVerdict.ALLOWED


def test_completed_seq_is_never_re_executed() -> None:
    """§14.5: an already-executed seq replays as ALREADY_EXECUTED, carrying the
    prior result reference so the state machine restores from OBSERVE."""
    ledger = IdempotencyLedger(SECRET)
    ref = _ref(seq=1)
    assert ledger.begin(ref).verdict is ReplayVerdict.ALLOWED
    ledger.complete(ref, "obs:result-1")

    replay = ledger.begin(ref)
    assert replay.verdict is ReplayVerdict.ALREADY_EXECUTED
    assert replay.result_ref == "obs:result-1"
    assert replay.key == ledger.derive_key(ref)
    # ...and it stays that way however many times resume retries it.
    assert ledger.begin(ref).verdict is ReplayVerdict.ALREADY_EXECUTED


def test_started_but_not_completed_is_a_distinct_outcome() -> None:
    """Crash mid-exec: STARTED-not-COMPLETED is neither re-executed nor
    skipped — it surfaces as its own verdict for the §4.7 human review prompt."""
    ledger = IdempotencyLedger(SECRET)
    ref = _ref(seq=1)
    ledger.begin(ref)

    partial = ledger.begin(ref)
    assert partial.verdict is ReplayVerdict.PARTIAL_EXECUTION
    assert partial.result_ref is None
    # Repeating never degrades into ALLOWED.
    assert ledger.begin(ref).verdict is ReplayVerdict.PARTIAL_EXECUTION


def test_same_seq_with_different_action_hash_is_a_typed_error() -> None:
    """Replay/forgery signal, not a retry — never a silent allow or skip."""
    ledger = IdempotencyLedger(SECRET)
    ledger.begin(_ref(seq=1, action_hash=AHASH))
    with pytest.raises(SeqConflictError):
        ledger.begin(_ref(seq=1, action_hash=AHASH2))


@pytest.mark.parametrize("mutation", [{"session_id": "other"}, {"task_id": "other"}])
def test_same_seq_with_different_identity_is_a_typed_error(
    mutation: dict[str, str],
) -> None:
    ledger = IdempotencyLedger(SECRET)
    ledger.begin(_ref(seq=1))
    with pytest.raises(SeqConflictError):
        ledger.begin(_ref(seq=1, **mutation))  # type: ignore[arg-type]


def test_conflict_is_raised_even_after_completion() -> None:
    ledger = IdempotencyLedger(SECRET)
    ledger.begin(_ref(seq=1))
    ledger.complete(_ref(seq=1), "obs:1")
    with pytest.raises(SeqConflictError):
        ledger.begin(_ref(seq=1, action_hash=AHASH2))


def test_out_of_order_new_seq_is_a_typed_error() -> None:
    """seq is monotonic: a NEW seq at/below the high-water mark is a replay
    signal (a genuine retry of an old seq is a duplicate, handled above)."""
    ledger = IdempotencyLedger(SECRET)
    ledger.begin(_ref(seq=5))
    with pytest.raises(SeqRegressionError):
        ledger.begin(_ref(seq=4))
    assert ledger.highest_seq == 5


def test_typed_errors_share_a_base() -> None:
    assert issubclass(SeqConflictError, IdempotencyError)
    assert issubclass(SeqRegressionError, IdempotencyError)
    assert issubclass(UnknownSeqError, IdempotencyError)
    assert issubclass(DuplicateCompletionError, IdempotencyError)


# --------------------------------------------------------------------------
# complete()
# --------------------------------------------------------------------------


def test_complete_of_unknown_seq_is_a_typed_error() -> None:
    ledger = IdempotencyLedger(SECRET)
    with pytest.raises(UnknownSeqError):
        ledger.complete(_ref(seq=7), "obs:7")


def test_double_complete_is_a_typed_error() -> None:
    ledger = IdempotencyLedger(SECRET)
    ref = _ref(seq=1)
    ledger.begin(ref)
    ledger.complete(ref, "obs:1")
    with pytest.raises(DuplicateCompletionError):
        ledger.complete(ref, "obs:1-again")
    entry = ledger.entry(1)
    assert entry is not None and entry.result_ref == "obs:1"


def test_complete_with_mismatched_fields_is_a_conflict() -> None:
    ledger = IdempotencyLedger(SECRET)
    ledger.begin(_ref(seq=1, action_hash=AHASH))
    with pytest.raises(SeqConflictError):
        ledger.complete(_ref(seq=1, action_hash=AHASH2), "obs:1")
    entry = ledger.entry(1)
    assert entry is not None and entry.state is ExecutionState.STARTED


def test_complete_requires_a_result_ref() -> None:
    ledger = IdempotencyLedger(SECRET)
    ref = _ref(seq=1)
    ledger.begin(ref)
    with pytest.raises(ValueError):
        ledger.complete(ref, "")


# --------------------------------------------------------------------------
# restore() — §14.5 `lsassist resume` rebuilds the ledger from the journal
# --------------------------------------------------------------------------


def test_restore_completed_then_begin_reports_already_executed() -> None:
    ledger = IdempotencyLedger(SECRET)
    ledger.restore(_ref(seq=1), ExecutionState.COMPLETED, "obs:from-journal")
    decision = ledger.begin(_ref(seq=1))
    assert decision.verdict is ReplayVerdict.ALREADY_EXECUTED
    assert decision.result_ref == "obs:from-journal"


def test_restore_started_then_begin_reports_partial() -> None:
    ledger = IdempotencyLedger(SECRET)
    ledger.restore(_ref(seq=1), ExecutionState.STARTED, None)
    assert ledger.begin(_ref(seq=1)).verdict is ReplayVerdict.PARTIAL_EXECUTION


def test_restore_rejects_a_started_entry_with_a_result_ref() -> None:
    ledger = IdempotencyLedger(SECRET)
    with pytest.raises(ValueError):
        ledger.restore(_ref(seq=1), ExecutionState.STARTED, "obs:1")


def test_restore_rejects_a_completed_entry_without_a_result_ref() -> None:
    ledger = IdempotencyLedger(SECRET)
    with pytest.raises(ValueError):
        ledger.restore(_ref(seq=1), ExecutionState.COMPLETED, None)


def test_restore_rejects_duplicate_and_out_of_order_seqs() -> None:
    ledger = IdempotencyLedger(SECRET)
    ledger.restore(_ref(seq=3), ExecutionState.COMPLETED, "obs:3")
    with pytest.raises(SeqConflictError):
        ledger.restore(_ref(seq=3), ExecutionState.COMPLETED, "obs:3")
    with pytest.raises(SeqRegressionError):
        ledger.restore(_ref(seq=2), ExecutionState.COMPLETED, "obs:2")
    assert ledger.highest_seq == 3


def test_highest_seq_is_none_on_an_empty_ledger() -> None:
    assert IdempotencyLedger(SECRET).highest_seq is None
    assert IdempotencyLedger(SECRET).entry(0) is None


# --------------------------------------------------------------------------
# The high-water mark's monotonic guard — a DEFENSIVE invariant, tested at the
# private helper on purpose (see the docstrings).
# --------------------------------------------------------------------------


def test_no_public_entry_point_reaches_put_with_a_regressing_seq() -> None:
    """The CONSTRUCTION claim, stated as a test: both callers of ``_put``
    (:meth:`begin` and :meth:`restore`) reject a seq at/below the high-water mark
    with :class:`SeqRegressionError` BEFORE the write happens — so the ledger is
    left untouched and ``_put`` never sees a regressing seq in production. This
    is why the guard inside ``_put`` is unreachable through the public API, and
    it is the premise the direct test below depends on."""
    ledger = IdempotencyLedger(SECRET)
    assert ledger.begin(_ref(seq=5)).verdict is ReplayVerdict.ALLOWED

    for regressing in (0, 1, 4):  # UNKNOWN seqs at/below the mark
        with pytest.raises(SeqRegressionError):
            ledger.begin(_ref(seq=regressing))
        with pytest.raises(SeqRegressionError):
            ledger.restore(_ref(seq=regressing), ExecutionState.STARTED, None)
        # ...and nothing was written on the way to either refusal.
        assert ledger.entry(regressing) is None
        assert ledger.highest_seq == 5


def test_put_never_lowers_the_high_water_mark() -> None:
    """DEFENSIVE INVARIANT of ``_put``, driven DIRECTLY at the private helper.

    ``_put``'s ``self._highest_seq is None or entry.ref.seq > self._highest_seq``
    guard has a FALSE arm that is unreachable through the public API BY
    CONSTRUCTION (see the test above). It is still load-bearing: ``_put`` is the
    single write path into the ledger, and without the guard a regressing write
    would DROP the high-water mark and re-open every seq below it to replay —
    turning the §4.7 replay guard into a no-op for that range.

    So the arm is pinned by calling ``_put`` directly rather than by deleting the
    guard to make a coverage number go green; deleting it is exactly the Goodhart
    failure the §23.1 floor exists to prevent.
    """
    ledger = IdempotencyLedger(SECRET)
    assert ledger.begin(_ref(seq=5)).verdict is ReplayVerdict.ALLOWED
    assert ledger.highest_seq == 5

    for regressing in (0, 2, 5):
        ref = _ref(seq=regressing, task_id="direct")
        ledger._put(
            LedgerEntry(
                ref=ref,
                key=ledger.derive_key(ref),
                state=ExecutionState.STARTED,
                result_ref=None,
            )
        )
        # The entry IS written (that is _put's job) but the mark does NOT move.
        assert ledger.entry(regressing) is not None
        assert ledger.highest_seq == 5

    # A strictly-higher seq still advances it — the guard gates, it does not freeze.
    higher = _ref(seq=9, task_id="direct")
    ledger._put(
        LedgerEntry(
            ref=higher,
            key=ledger.derive_key(higher),
            state=ExecutionState.STARTED,
            result_ref=None,
        )
    )
    assert ledger.highest_seq == 9

    # And the surviving mark still refuses a replay below it through the public API.
    with pytest.raises(SeqRegressionError):
        ledger.begin(_ref(seq=6, task_id="after"))
