"""T1.11 RED: IntentRecord contract model (SPEC §16.2).

§16.2 pipeline step 1 is "capture immutable intent": an ``IntentRecord`` is
``{text, digest, ts}`` — immutable, with ``digest`` the ``sha256:``-prefixed
hash of the canonical intent text and ``ts`` a UTC ISO-8601 timestamp. Every
plan references the digest, so the helper :func:`make_intent` must be
deterministic: the same text yields the same digest on every run.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from lsassist.contracts.intent import IntentRecord, make_intent

# --- (1) record shape: {text, digest, ts} -------------------------------------------


def test_make_intent_produces_sha256_prefixed_digest() -> None:
    record = make_intent("add a --dry-run flag to fs.write")
    expected = "sha256:" + hashlib.sha256(b"add a --dry-run flag to fs.write").hexdigest()
    assert record.text == "add a --dry-run flag to fs.write"
    assert record.digest == expected
    assert record.digest.startswith("sha256:")


def test_ts_is_utc_iso8601_aware() -> None:
    record = make_intent("x")
    assert isinstance(record.ts, datetime)
    assert record.ts.tzinfo is not None
    assert record.ts.utcoffset() == UTC.utcoffset(None)


def test_explicit_record_parses() -> None:
    digest = "sha256:" + hashlib.sha256(b"x").hexdigest()
    record = IntentRecord.model_validate(
        {"text": "x", "digest": digest, "ts": "2026-07-24T00:00:00Z"}
    )
    assert record.text == "x"


def test_digest_must_be_sha256_prefixed_hex() -> None:
    with pytest.raises(ValidationError):
        IntentRecord(text="x", digest="md5:" + "a" * 32, ts=datetime.now(UTC))


# --- (2) frozen model: mutation rejected (§16.2 immutable) ---------------------------


def test_intent_record_is_frozen() -> None:
    record = make_intent("original")
    with pytest.raises(ValidationError):
        record.text = "tampered"  # type: ignore[misc]


def test_intent_record_digest_field_frozen() -> None:
    record = make_intent("original")
    with pytest.raises(ValidationError):
        record.digest = "sha256:" + "0" * 64  # type: ignore[misc]


# --- (3) digest helper is deterministic ----------------------------------------------


def test_make_intent_digest_deterministic_across_calls() -> None:
    first = make_intent("same text")
    second = make_intent("same text")
    assert first.digest == second.digest


def test_make_intent_digest_matches_manual_sha256() -> None:
    text = "canonical intent — ünicode ✓"
    record = make_intent(text)
    assert record.digest == "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
