"""T4.02 RED: the §14.1 audit record schema and its canonical serialization.

§14.1 gives the record shape verbatim::

    {"seq": 41, "ts": "2026-07-23T19:05:11.512Z", "session_id": "…",
     "task_id": "…", "event": "tool_result", "payload": { },
     "payload_digest": "sha256:…", "prev_hash": "sha256:…",
     "model": "kimi-for-coding", "provider": "kimi-coding"}

and the event vocabulary as a closed list plus one PATTERN (``lab_*``). Both are
pinned here: a record whose ``event`` is not in the list and does not match the
pattern is a record nobody downstream can dispatch on, and §14.1's own
"tamper-evident" promise rests on the serialization being byte-stable.
"""

from __future__ import annotations

import datetime
import json
from typing import Any

import pytest
from pydantic import ValidationError

from lsassist.audit.schema import (
    GENESIS_HASH,
    LAB_EVENT_PATTERN,
    AuditEvent,
    AuditRecord,
    canonical_bytes,
    record_hash,
    stable_serialization,
)

NOW = datetime.datetime(2026, 7, 23, 19, 5, 11, 512000, tzinfo=datetime.UTC)


def record(**overrides: Any) -> AuditRecord:
    base: dict[str, Any] = {
        "seq": 41,
        "ts": NOW,
        "session_id": "s-1",
        "task_id": "t-1",
        "event": "tool_result",
        "payload": {"tool": "fs.read"},
        "payload_digest": "sha256:" + "a" * 64,
        "prev_hash": GENESIS_HASH,
        "model": "kimi-for-coding",
        "provider": "kimi-coding",
    }
    base.update(overrides)
    return AuditRecord.model_validate(base)


# ==========================================================================
# 1. the §14.1 record shape
# ==========================================================================
def test_a_well_formed_record_validates() -> None:
    assert record().seq == 41


@pytest.mark.parametrize(
    "field",
    [
        "seq",
        "ts",
        "session_id",
        "task_id",
        "event",
        "payload",
        "payload_digest",
        "prev_hash",
        "model",
        "provider",
    ],
)
def test_every_section_141_field_is_required(field: str) -> None:
    payload = {
        "seq": 1,
        "ts": NOW,
        "session_id": "s",
        "task_id": "t",
        "event": "intent",
        "payload": {},
        "payload_digest": "sha256:" + "a" * 64,
        "prev_hash": GENESIS_HASH,
        "model": "m",
        "provider": "kimi-coding",
    }
    del payload[field]
    with pytest.raises(ValidationError):
        AuditRecord.model_validate(payload)


def test_unknown_fields_are_refused() -> None:
    """An audit record with room for an undeclared field is a record whose
    meaning is not fixed by §14.1."""
    with pytest.raises(ValidationError):
        record(surprise="x")


def test_the_record_is_frozen() -> None:
    with pytest.raises(ValidationError):
        record().seq = 99  # type: ignore[misc]


@pytest.mark.parametrize("bad", [-1, "1", 1.5])
def test_seq_is_a_non_negative_integer(bad: Any) -> None:
    with pytest.raises(ValidationError):
        record(seq=bad)


@pytest.mark.parametrize(
    "field", ["payload_digest", "prev_hash"]
)
@pytest.mark.parametrize(
    "bad", ["", "deadbeef", "sha256:" + "A" * 64, "sha256:" + "a" * 63, "md5:" + "a" * 32]
)
def test_digest_fields_carry_the_sha256_prefix(field: str, bad: str) -> None:
    with pytest.raises(ValidationError):
        record(**{field: bad})


def test_timestamps_must_be_timezone_aware() -> None:
    """A naive timestamp in a tamper-evident journal is an ambiguous one."""
    with pytest.raises(ValidationError):
        record(ts=datetime.datetime(2026, 7, 23, 19, 5, 11))


# ==========================================================================
# 2. the §14.1 event vocabulary
# ==========================================================================
SPEC_EVENTS = (
    "intent",
    "ground",
    "plan_revision",
    "policy_decision",
    "approval",
    "tool_request",
    "tool_result",
    "verify",
    "verdict",
    "budget",
    "provider_down",
    "provider_fallback",
    "provider_restored",
    "memory_write",
    "skill_lifecycle",
    "recovery",
    "config_change",
)


def test_the_event_enum_is_exactly_the_section_141_list() -> None:
    assert {member.value for member in AuditEvent} == set(SPEC_EVENTS)


@pytest.mark.parametrize("event", SPEC_EVENTS)
def test_every_spec_event_is_accepted(event: str) -> None:
    assert record(event=event).event == event


@pytest.mark.parametrize("event", ["lab_proposed", "lab_halted", "lab_eval_run"])
def test_lab_events_are_accepted_by_pattern(event: str) -> None:
    """§14.1 writes ``lab_*``: a family, not an enumeration — §11's pipeline
    names its own stages and this schema must not have to know them."""
    assert record(event=event).event == event


@pytest.mark.parametrize(
    "event",
    [
        "",
        "Intent",
        "tool-result",
        "lab",
        "lab_",
        "labX",
        "lab_UPPER",
        "unknown_event",
        "lab_" + "x" * 40,
    ],
)
def test_an_event_outside_the_vocabulary_is_refused(event: str) -> None:
    with pytest.raises(ValidationError):
        record(event=event)


def test_the_lab_pattern_is_anchored() -> None:
    """An unanchored pattern would accept ``not_a_lab_event``."""
    assert LAB_EVENT_PATTERN.startswith("^")
    assert LAB_EVENT_PATTERN.endswith("$")
    with pytest.raises(ValidationError):
        record(event="not_a_lab_event")


# ==========================================================================
# 3. canonical serialization — the basis of the hash chain
# ==========================================================================
def test_canonical_bytes_is_byte_stable() -> None:
    assert canonical_bytes(record()) == canonical_bytes(record())


def test_canonical_bytes_is_independent_of_key_insertion_order() -> None:
    """The chain compares digests; a serializer that depended on dict order
    would make an identical record hash differently on a different run."""
    first = record(payload={"a": 1, "b": 2})
    second = record(payload={"b": 2, "a": 1})
    assert canonical_bytes(first) == canonical_bytes(second)


def test_canonical_bytes_carries_no_trailing_whitespace_or_newline() -> None:
    blob = canonical_bytes(record())
    assert blob == blob.strip()
    assert b'": ' not in blob, "separators must be compact so the bytes are fixed"


def test_canonical_bytes_is_utf8_and_not_ascii_escaped() -> None:
    blob = canonical_bytes(record(payload={"note": "ქართული"}))
    assert "ქართული".encode() in blob


@pytest.mark.parametrize(
    "field",
    ["seq", "session_id", "task_id", "event", "payload", "payload_digest", "prev_hash",
     "model", "provider"],
)
def test_every_field_is_covered_by_the_hash(field: str) -> None:
    """Tamper-evidence means EVERY field is bound; a field outside the digest is
    a field an attacker may rewrite freely."""
    changed = {
        "seq": 42,
        "session_id": "other",
        "task_id": "other",
        "event": "verdict",
        "payload": {"tool": "fs.write"},
        "payload_digest": "sha256:" + "b" * 64,
        "prev_hash": "sha256:" + "c" * 64,
        "model": "k3",
        "provider": "ollama-local",
    }[field]
    assert record_hash(record()) != record_hash(record(**{field: changed}))


def test_the_timestamp_is_covered_by_the_hash() -> None:
    later = NOW + datetime.timedelta(milliseconds=1)
    assert record_hash(record()) != record_hash(record(ts=later))


def test_record_hash_has_the_sha256_prefix() -> None:
    digest = record_hash(record())
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64


def test_canonical_bytes_round_trips_as_json() -> None:
    """The journal is JSONL: each line must be a parseable object."""
    parsed = json.loads(canonical_bytes(record()))
    assert parsed["event"] == "tool_result"
    assert parsed["ts"].endswith("Z") or "+00:00" in parsed["ts"]


def test_genesis_hash_is_a_well_formed_digest() -> None:
    """The first record in a chain has no predecessor; §14.1 still requires a
    ``prev_hash``, so the chain starts from a fixed, recognizable value."""
    assert GENESIS_HASH == "sha256:" + "0" * 64
    assert record(prev_hash=GENESIS_HASH).prev_hash == GENESIS_HASH


# ==========================================================================
# 4. JSONL framing — one record is one line, whatever the payload contains
# ==========================================================================
@pytest.mark.parametrize(
    ("char", "name"),
    [
        ("\x85", "U+0085 NEL"),
        ("\u2028", "U+2028 LINE SEPARATOR"),
        ("\u2029", "U+2029 PARAGRAPH SEPARATOR"),
    ],
)
def test_a_unicode_line_boundary_cannot_split_a_record(char: str, name: str) -> None:
    """Found by the T4.02 fuzz. ``str.splitlines()`` breaks on more than ``\n``,
    and ``ensure_ascii=False`` leaves exactly these three raw — so one record
    containing U+2028 became TWO journal lines and the chain read as malformed.
    U+2028 is the realistic vector: it is common in JavaScript-derived text, and
    tool output is attacker-influenced."""
    blob = canonical_bytes(record(payload={"note": f"a{char}b"}))
    assert len(blob.decode("utf-8").splitlines()) == 1, f"{name} split the record"


@pytest.mark.parametrize("char", ["\x85", "\u2028", "\u2029"])
def test_a_line_boundary_in_a_KEY_cannot_split_a_record(char: str) -> None:
    """The fuzz's own counterexample was a KEY, not a value."""
    blob = canonical_bytes(record(payload={f"k{char}": None}))
    assert len(blob.decode("utf-8").splitlines()) == 1


@pytest.mark.parametrize("char", ["\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e"])
def test_ascii_control_characters_were_already_safe(char: str) -> None:
    """The counterweight, measured rather than assumed: ``json.dumps`` escapes
    every ASCII control character, so the extra translation is needed for
    exactly three characters and no more."""
    blob = canonical_bytes(record(payload={"note": f"a{char}b"}))
    assert len(blob.decode("utf-8").splitlines()) == 1


def test_escaping_keeps_the_line_and_the_hash_input_identical() -> None:
    """The escape happens in the serializer, so the bytes that are hashed are
    the bytes that are written. Doing it on the way out instead would make an
    affected record hash differently from the line carrying it."""
    subject = record(payload={"note": "a\u2028b"})
    line = canonical_bytes(subject)
    assert json.loads(line)["payload"]["note"] == "a\u2028b"
    assert record_hash(json.loads(line)) == record_hash(subject)


def test_the_import_time_stability_check_actually_holds() -> None:
    """The check runs at import; this is what proves it FIRES rather than
    merely existing."""
    assert stable_serialization() is True


def test_the_stability_guard_raises_when_the_premise_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Watch the import-time guard actually fire.

    §14.1's tamper-evidence rests on a stable serialization; if that ever
    stopped holding, the chain would report tampering on files nobody touched.
    The guard is exercised rather than trusted.
    """
    from lsassist.audit import schema as module

    calls = {"n": 0}

    def unstable(_record: object) -> bytes:
        calls["n"] += 1
        return str(calls["n"]).encode()

    monkeypatch.setattr(module, "canonical_bytes", unstable)
    assert module.stable_serialization() is False
    with pytest.raises(RuntimeError, match="order-dependent"):
        module.assert_stable_serialization()
