"""§23.1 PT: §4.7 replay protection holds over ARBITRARY execution attempts.

Two properties, both run at >=200 examples via ``--hypothesis-profile=ci``
(profile registered in ``tests/property/conftest.py``):

1. **No double execution.** Driving the ledger with an arbitrary interleaving of
   ``(seq, action_hash, complete?)`` attempts — duplicates, out-of-order seqs,
   forged hashes on a known seq, crash-mid-exec (begin without complete) — every
   seq is ALLOWED to execute AT MOST ONCE, and once a seq is COMPLETED it only
   ever replays as ``ALREADY_EXECUTED`` carrying its recorded result reference.
   Anything the guard refuses is refused as a TYPED :class:`IdempotencyError`,
   never as a silent allow or a silent skip.

2. **Key injectivity.** No two DISTINCT ``(session_id, task_id, action_hash,
   seq)`` tuples ever derive the same idempotency key — including tuples built
   from separator/JSON metacharacters that a naive ``"{a}:{b}:{c}:{d}"`` join
   would collide. A collision here is a replay-guard bypass (request A presents
   request B's key), the same defect class as the ``env_digest`` ``k=v\\n`` join.

A positive control keeps property 1 non-vacuous: a strictly increasing run of
fresh seqs is ALWAYS ALLOWED, so the guard is not trivially refusing everything.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from lsassist.kernel.idempotency import (
    ActionRef,
    ExecutionState,
    IdempotencyError,
    IdempotencyLedger,
    ReplayVerdict,
)

SECRET = bytes(range(32, 64))

# A deliberately nasty id alphabet: the separators and JSON metacharacters that
# break non-injective serializations.
_NASTY = st.text(alphabet=':"\\{},\n\tabé', min_size=1, max_size=6)
_HASHES = st.sampled_from([f"sha256:{c * 64}" for c in "0123"])
_ATTEMPTS = st.lists(
    st.tuples(st.integers(min_value=0, max_value=5), _HASHES, st.booleans()),
    min_size=1,
    max_size=12,
)


@st.composite
def _refs(draw: st.DrawFn) -> ActionRef:
    return ActionRef(
        session_id=draw(_NASTY),
        task_id=draw(_NASTY),
        action_hash=draw(st.one_of(_NASTY, _HASHES)),
        seq=draw(st.integers(min_value=0, max_value=9)),
    )


def _fields(ref: ActionRef) -> tuple[str, str, str, int]:
    return (ref.session_id, ref.task_id, ref.action_hash, ref.seq)


# --------------------------------------------------------------------------
# Property 1 — a completed seq is never executed twice
# --------------------------------------------------------------------------


@given(attempts=_ATTEMPTS)
def test_no_seq_is_ever_executed_twice(
    attempts: list[tuple[int, str, bool]],
) -> None:
    ledger = IdempotencyLedger(SECRET)
    executions: dict[int, int] = {}
    completed: set[int] = set()
    started: set[int] = set()

    for seq, action_hash, do_complete in attempts:
        ref = ActionRef(
            session_id="sess-p", task_id="task-p", action_hash=action_hash, seq=seq
        )
        try:
            decision = ledger.begin(ref)
        except IdempotencyError:
            # Typed refusal (forged hash on a known seq, or an out-of-order
            # seq). Nothing executed, nothing silently dropped.
            continue

        # The decision always carries THIS request's key.
        assert decision.key == ledger.derive_key(ref)

        if decision.verdict is ReplayVerdict.ALLOWED:
            # Never allowed for something already run to completion...
            assert seq not in completed
            # ...nor for something already in flight.
            assert seq not in started
            executions[seq] = executions.get(seq, 0) + 1
            started.add(seq)
            if do_complete:
                ledger.complete(ref, f"obs:{seq}")
                started.discard(seq)
                completed.add(seq)
        elif decision.verdict is ReplayVerdict.ALREADY_EXECUTED:
            assert seq in completed
            assert decision.result_ref == f"obs:{seq}"
        else:
            assert decision.verdict is ReplayVerdict.PARTIAL_EXECUTION
            assert seq in started
            assert decision.result_ref is None

    # THE property: at most one execution per seq, ever.
    assert all(count == 1 for count in executions.values())
    # And the ledger's own view agrees with the driver's.
    for seq in completed:
        entry = ledger.entry(seq)
        assert entry is not None and entry.state is ExecutionState.COMPLETED
    for seq in started:
        entry = ledger.entry(seq)
        assert entry is not None and entry.state is ExecutionState.STARTED


@given(
    seqs=st.lists(st.integers(min_value=0, max_value=50), min_size=1, max_size=10),
    action_hash=_HASHES,
)
def test_positive_control_fresh_increasing_seqs_are_always_allowed(
    seqs: list[int], action_hash: str
) -> None:
    """Non-vacuity: the guard does not simply refuse everything."""
    ledger = IdempotencyLedger(SECRET)
    for seq in sorted(set(seqs)):
        ref = ActionRef(
            session_id="sess-p", task_id="task-p", action_hash=action_hash, seq=seq
        )
        assert ledger.begin(ref).verdict is ReplayVerdict.ALLOWED
        ledger.complete(ref, f"obs:{seq}")
        assert ledger.begin(ref).verdict is ReplayVerdict.ALREADY_EXECUTED


# --------------------------------------------------------------------------
# Property 2 — key injectivity
# --------------------------------------------------------------------------


@given(left=_refs(), right=_refs())
def test_distinct_field_tuples_never_share_a_key(
    left: ActionRef, right: ActionRef
) -> None:
    ledger = IdempotencyLedger(SECRET)
    if _fields(left) == _fields(right):
        assert ledger.derive_key(left) == ledger.derive_key(right)
        return
    assert ledger.derive_key(left) != ledger.derive_key(right)
    assert left.canonical_bytes() != right.canonical_bytes()


@given(left=_refs(), right=_refs())
def test_verify_key_accepts_exactly_the_matching_tuple(
    left: ActionRef, right: ActionRef
) -> None:
    """The timing-safe check agrees with injectivity: a key verifies against a
    tuple iff it is that tuple's own key (never raises, whatever the bytes)."""
    ledger = IdempotencyLedger(SECRET)
    expected = _fields(left) == _fields(right)
    assert ledger.verify_key(ledger.derive_key(left), right) is expected


@st.composite
def _naive_join_collisions(draw: st.DrawFn) -> tuple[ActionRef, ActionRef]:
    """Build a pair of DISTINCT tuples whose naive ``a:b:c:d`` join is IDENTICAL.

    Splitting ``a:b:c`` at either colon gives ``("a:b", "c")`` and
    ``("a", "b:c")`` — different requests, one naive string.
    """
    head, mid, tail = draw(_NASTY), draw(_NASTY), draw(_NASTY)
    action_hash, seq = draw(_HASHES), draw(st.integers(min_value=0, max_value=9))
    left = ActionRef(
        session_id=f"{head}:{mid}", task_id=tail, action_hash=action_hash, seq=seq
    )
    right = ActionRef(
        session_id=head, task_id=f"{mid}:{tail}", action_hash=action_hash, seq=seq
    )
    return left, right


@given(pair=_naive_join_collisions())
def test_naive_join_collisions_do_not_survive_canonicalization(
    pair: tuple[ActionRef, ActionRef],
) -> None:
    """Focus the injectivity property on exactly the defect class."""
    left, right = pair
    naive_l = f"{left.session_id}:{left.task_id}:{left.action_hash}:{left.seq}"
    naive_r = f"{right.session_id}:{right.task_id}:{right.action_hash}:{right.seq}"
    assert naive_l == naive_r, "control: these tuples DO collide under a naive join"
    assert _fields(left) != _fields(right)

    ledger = IdempotencyLedger(SECRET)
    assert ledger.derive_key(left) != ledger.derive_key(right)
