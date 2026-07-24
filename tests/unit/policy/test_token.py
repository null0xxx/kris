"""T2.03: the §7.4 HMAC approval-token service (mint / verify).

These tests pin the I5/I6 token-forgery-resistance core:

- mint→verify roundtrip is VALID and the HMAC input is EXACTLY
  ``record.canonical_bytes()`` (proven by an independent recomputation);
- ANY material change to the re-canonicalized record (args, class, ttl_s,
  max_uses, cwd, paths, env, session, token_id) flips the canonical bytes and
  yields ``HMAC_MISMATCH`` (I6 material-change check);
- a valid-HMAC token that was never minted (or whose struct ``token_id`` was
  spliced) is ``UNKNOWN_TOKEN``;
- TTL expiry → ``EXPIRED``; exceeding ``max_uses`` → ``EXHAUSTED``; the use
  counter increments ONLY on an otherwise-valid verify (never on an invalid
  one);
- a naive (tz-unaware) ``now`` is rejected fail-closed.

The service takes the 32-byte kernel secret as INJECTED bytes and does no
fs/env access (§2.2 purity).
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from lsassist.contracts.approval import ApprovalClass, ApprovalRecord
from lsassist.policy.canonical import action_hash, env_digest
from lsassist.policy.token import ApprovalToken, TokenService, TokenVerdict

# A fixed 32-byte "kernel secret" (install-time random in production, injected
# here as bytes — the module never touches the fs/env for it).
SECRET = bytes(range(32))
FIXED_ISSUED = datetime(2026, 7, 24, 19, 0, 0, tzinfo=UTC)


def _make_record(
    *,
    session_id: str = "sess-abc",
    tool: str = "proc.exec",
    args_normalized: dict[str, Any] | None = None,
    canonical_paths: list[str] | None = None,
    cwd_real: str = "/home/null/Desktop/LinuxSec",
    env: dict[str, str] | None = None,
    max_uses: int = 1,
    ttl_s: int = 300,
    issued_at: datetime = FIXED_ISSUED,
    policy_class: ApprovalClass = ApprovalClass.CONFIRM_ONCE,
    token_id: str | None = None,
) -> ApprovalRecord:
    """Build a realistic §7.4 record; ``env_digest``/``action_hash`` are the
    single-sourced primitives from ``canonical.py`` (never re-derived here)."""
    args = {"argv": ["pytest", "-q", "tests/"]} if args_normalized is None else args_normalized
    paths = ["/home/null/Desktop/LinuxSec"] if canonical_paths is None else canonical_paths
    envmap = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"} if env is None else env
    edigest = env_digest(envmap)
    ahash = action_hash(tool, args, paths, cwd_real, edigest)
    kwargs: dict[str, Any] = {
        "session_id": session_id,
        "tool": tool,
        "args_normalized": args,
        "canonical_paths": paths,
        "cwd_real": cwd_real,
        "env_digest": edigest,
        "action_hash": ahash,
        "max_uses": max_uses,
        "ttl_s": ttl_s,
        "issued_at": issued_at,
        "policy_class": policy_class,
    }
    if token_id is not None:
        kwargs["token_id"] = token_id
    return ApprovalRecord(**kwargs)


def _expected_value(record: ApprovalRecord) -> str:
    """Independent reference HMAC over ``record.canonical_bytes()`` (the ONLY
    canonical form) — the test's ground truth for the token value."""
    return hmac.new(SECRET, record.canonical_bytes(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# roundtrip + HMAC-input proof
# ---------------------------------------------------------------------------


def test_mint_verify_roundtrip_valid() -> None:
    service = TokenService(SECRET)
    record = _make_record()
    token = service.mint(record)
    assert service.verify(token, record, now=FIXED_ISSUED) is TokenVerdict.VALID


def test_hmac_input_is_exactly_canonical_bytes() -> None:
    """The MANDATE: HMAC input is verbatim ``record.canonical_bytes()``."""
    service = TokenService(SECRET)
    record = _make_record()
    token = service.mint(record)
    assert token.value == _expected_value(record)
    # And the value is a 64-char lowercase hex sha256 digest.
    assert len(token.value) == 64
    assert all(c in "0123456789abcdef" for c in token.value)


def test_token_carries_record_token_id() -> None:
    service = TokenService(SECRET)
    record = _make_record(token_id="fixed-tid-001")
    token = service.mint(record)
    assert token.token_id == "fixed-tid-001"
    assert token.token_id == record.token_id


def test_mint_does_not_regenerate_token_id_or_issued_at() -> None:
    """Mint is over the record AS GIVEN (no re-stamping of id/issued_at)."""
    service = TokenService(SECRET)
    record = _make_record(token_id="tid-keep", issued_at=FIXED_ISSUED)
    token = service.mint(record)
    assert token.token_id == "tid-keep"
    assert record.issued_at == FIXED_ISSUED


# ---------------------------------------------------------------------------
# TTL
# ---------------------------------------------------------------------------


def test_ttl_expiry_returns_expired() -> None:
    service = TokenService(SECRET)
    record = _make_record(ttl_s=300)
    token = service.mint(record)
    now = FIXED_ISSUED + timedelta(seconds=301)
    assert service.verify(token, record, now=now) is TokenVerdict.EXPIRED


def test_ttl_exact_boundary_is_valid() -> None:
    """Expiry is strictly ``> ttl`` — exactly at the boundary is still VALID."""
    service = TokenService(SECRET)
    record = _make_record(ttl_s=300)
    token = service.mint(record)
    now = FIXED_ISSUED + timedelta(seconds=300)
    assert service.verify(token, record, now=now) is TokenVerdict.VALID


def test_expired_token_does_not_consume_a_use() -> None:
    service = TokenService(SECRET)
    record = _make_record(ttl_s=10, max_uses=1)
    token = service.mint(record)
    expired = FIXED_ISSUED + timedelta(seconds=11)
    assert service.verify(token, record, now=expired) is TokenVerdict.EXPIRED
    # Still within its single use at a valid time.
    assert service.verify(token, record, now=FIXED_ISSUED) is TokenVerdict.VALID


# ---------------------------------------------------------------------------
# uses / exhaustion — counter increments only on VALID
# ---------------------------------------------------------------------------


def test_exhausted_after_max_uses() -> None:
    service = TokenService(SECRET)
    record = _make_record(max_uses=1)
    token = service.mint(record)
    assert service.verify(token, record, now=FIXED_ISSUED) is TokenVerdict.VALID
    assert service.verify(token, record, now=FIXED_ISSUED) is TokenVerdict.EXHAUSTED


def test_counter_increments_only_on_valid() -> None:
    service = TokenService(SECRET)
    record = _make_record(max_uses=2)
    token = service.mint(record)

    # 1st valid use.
    assert service.verify(token, record, now=FIXED_ISSUED) is TokenVerdict.VALID

    # An HMAC_MISMATCH attempt (bumped ttl_s) must NOT consume a use.
    tampered = record.model_copy(update={"ttl_s": record.ttl_s + 1000})
    assert service.verify(token, tampered, now=FIXED_ISSUED) is TokenVerdict.HMAC_MISMATCH

    # 2nd valid use still available, then exhausted.
    assert service.verify(token, record, now=FIXED_ISSUED) is TokenVerdict.VALID
    assert service.verify(token, record, now=FIXED_ISSUED) is TokenVerdict.EXHAUSTED


def test_multi_use_token_honours_max_uses() -> None:
    service = TokenService(SECRET)
    record = _make_record(max_uses=3)
    token = service.mint(record)
    verdicts = [service.verify(token, record, now=FIXED_ISSUED) for _ in range(4)]
    assert verdicts == [
        TokenVerdict.VALID,
        TokenVerdict.VALID,
        TokenVerdict.VALID,
        TokenVerdict.EXHAUSTED,
    ]


# ---------------------------------------------------------------------------
# I6 material-change → HMAC_MISMATCH
# ---------------------------------------------------------------------------


def test_one_byte_change_in_args_is_hmac_mismatch() -> None:
    service = TokenService(SECRET)
    record = _make_record(args_normalized={"argv": ["pytest", "-q", "tests/"]})
    token = service.mint(record)

    # A one-byte change in args → different action_hash AND canonical_bytes.
    mutated = _make_record(
        args_normalized={"argv": ["pytest", "-q", "tests/x"]},
        token_id=record.token_id,
    )
    assert mutated.canonical_bytes() != record.canonical_bytes()
    assert mutated.action_hash != record.action_hash
    assert service.verify(token, mutated, now=FIXED_ISSUED) is TokenVerdict.HMAC_MISMATCH


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("policy_class", ApprovalClass.CONFIRM_EXACT),
        ("ttl_s", 999),
        ("max_uses", 42),
        ("session_id", "other-session"),
        ("cwd_real", "/evil"),
        ("canonical_paths", ["/somewhere/else"]),
        ("action_hash", "sha256:" + "0" * 64),
        ("env_digest", "sha256:" + "f" * 64),
        ("policy_note", "tampered note"),
        ("rollback_hint", "tampered hint"),
    ],
)
def test_mutating_any_field_is_hmac_mismatch(field: str, value: Any) -> None:
    service = TokenService(SECRET)
    record = _make_record()
    token = service.mint(record)

    mutated = record.model_copy(update={field: value})
    assert mutated.canonical_bytes() != record.canonical_bytes()
    assert service.verify(token, mutated, now=FIXED_ISSUED) is TokenVerdict.HMAC_MISMATCH


def test_corrupted_token_value_is_hmac_mismatch() -> None:
    service = TokenService(SECRET)
    record = _make_record()
    token = service.mint(record)
    # Flip the first hex nibble.
    flipped = ("f" if token.value[0] != "f" else "0") + token.value[1:]
    corrupted = ApprovalToken(token_id=token.token_id, value=flipped)
    assert service.verify(corrupted, record, now=FIXED_ISSUED) is TokenVerdict.HMAC_MISMATCH


def test_non_ascii_token_value_is_hmac_mismatch_not_crash() -> None:
    """A non-ASCII ``token.value`` must return HMAC_MISMATCH, not raise.

    ``hmac.compare_digest`` raises ``TypeError`` on a non-ASCII ``str``; the
    value compare is done over bytes so an attacker-controlled value fails
    CLOSED (verdict) instead of crashing verify() (fail-closed-contract, S1)."""
    service = TokenService(SECRET)
    record = _make_record()
    service.mint(record)  # register the token_id so we can only fail at the HMAC
    forged = ApprovalToken(token_id=record.token_id, value="ñoño-" + "λ" * 60)
    verdict = service.verify(forged, record, now=FIXED_ISSUED)
    assert verdict is TokenVerdict.HMAC_MISMATCH


def test_wrong_secret_is_hmac_mismatch() -> None:
    minter = TokenService(SECRET)
    record = _make_record()
    token = minter.mint(record)
    # A verifier with a different kernel secret must reject the token.
    other = TokenService(bytes(range(1, 33)))
    other.mint(record)  # register the token_id in the other store
    assert other.verify(token, record, now=FIXED_ISSUED) is TokenVerdict.HMAC_MISMATCH


# ---------------------------------------------------------------------------
# UNKNOWN_TOKEN — valid HMAC but not a known minted token / spliced id
# ---------------------------------------------------------------------------


def test_never_minted_valid_hmac_is_unknown_token() -> None:
    service = TokenService(SECRET)
    record = _make_record(token_id="never-minted")
    # A structurally valid token (correct HMAC) that was never minted.
    token = ApprovalToken(token_id=record.token_id, value=_expected_value(record))
    assert service.verify(token, record, now=FIXED_ISSUED) is TokenVerdict.UNKNOWN_TOKEN


def test_token_id_splice_is_unknown_token() -> None:
    """A valid token for record B, presented with B but claiming A's id."""
    service = TokenService(SECRET)
    record_a = _make_record(session_id="A", token_id="tid-A")
    record_b = _make_record(session_id="B", token_id="tid-B")
    service.mint(record_a)
    token_b = service.mint(record_b)

    # HMAC matches record_b, but the struct id (A) != record_b.token_id (B).
    spliced = ApprovalToken(token_id=record_a.token_id, value=token_b.value)
    assert service.verify(spliced, record_b, now=FIXED_ISSUED) is TokenVerdict.UNKNOWN_TOKEN


# ---------------------------------------------------------------------------
# naive `now` rejected fail-closed
# ---------------------------------------------------------------------------


def test_naive_now_is_rejected() -> None:
    service = TokenService(SECRET)
    record = _make_record()
    token = service.mint(record)
    naive = datetime(2026, 7, 24, 19, 0, 0)  # intentionally tz-naive
    with pytest.raises(ValueError, match=r"tz-aware|timezone"):
        service.verify(token, record, now=naive)


# ---------------------------------------------------------------------------
# shapes
# ---------------------------------------------------------------------------


def test_token_verdict_members_exact() -> None:
    assert {v.name for v in TokenVerdict} == {
        "VALID",
        "HMAC_MISMATCH",
        "UNKNOWN_TOKEN",
        "EXPIRED",
        "EXHAUSTED",
    }


def test_approval_token_is_frozen() -> None:
    token = ApprovalToken(token_id="t", value="v")
    with pytest.raises((AttributeError, TypeError)):
        token.value = "mutated"  # type: ignore[misc]


def test_ordering_hmac_checked_before_expiry_and_uses() -> None:
    """A tampered record that is ALSO expired and exhausted still reports the
    HMAC mismatch first (fail-closed, material-change dominates)."""
    service = TokenService(SECRET)
    record = _make_record(ttl_s=10, max_uses=1)
    token = service.mint(record)
    service.verify(token, record, now=FIXED_ISSUED)  # exhaust the single use

    tampered = record.model_copy(update={"cwd_real": "/evil"})
    late = FIXED_ISSUED + timedelta(seconds=999)
    assert service.verify(token, tampered, now=late) is TokenVerdict.HMAC_MISMATCH
