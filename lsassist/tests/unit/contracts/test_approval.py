"""T1.05 RED: ApprovalRecord + canonical_json (SPEC §7.4; invariants I5/I6).

I5 (§1.2): approval binds to the exact action — the HMAC token (Phase 2 token
service) is computed over ``canonical_json(record)``. I6: any material change
to the record must change the canonical bytes (pre-exec re-canonicalization
mismatch → re-approval). The mutation vectors below are the AC-09
precondition: args, paths, cwd, ttl, max_uses, tool, and the §7.1 display
annotations (``policy_note``/``rollback_hint``, part of the record because
display = record, §7.4).
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from pydantic import ValidationError

from lsassist.contracts.approval import ApprovalRecord

# SPEC §7.4 example record, verbatim except that the SPEC's "uuid4" and
# "sha256:…" placeholders are made concrete.
SPEC_74_RECORD: dict[str, Any] = {
    "token_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "session_id": "sess-2026-07-23-01",
    "tool": "proc.exec",
    "args_normalized": {"argv": ["pytest", "-q", "tests/"]},
    "canonical_paths": ["/home/null/Desktop/LinuxSec"],
    "cwd_real": "/home/null/Desktop/LinuxSec",
    "env_digest": "sha256:" + "a" * 64,
    "action_hash": "sha256:" + "b" * 64,
    "max_uses": 1,
    "ttl_s": 300,
    "issued_at": "2026-07-23T19:00:00Z",
    "class": "CONFIRM_ONCE",
}


def _record(**overrides: Any) -> ApprovalRecord:
    data = dict(SPEC_74_RECORD)
    data.update(overrides)
    return ApprovalRecord.model_validate(data)


# --- (1) §7.4 example record parses ------------------------------------------


def test_spec_74_example_record_parses() -> None:
    rec = _record()
    uuid.UUID(rec.token_id)  # well-formed uuid4
    assert rec.session_id == "sess-2026-07-23-01"
    assert rec.tool == "proc.exec"
    assert rec.args_normalized == {"argv": ["pytest", "-q", "tests/"]}
    assert rec.canonical_paths == ["/home/null/Desktop/LinuxSec"]
    assert rec.cwd_real == "/home/null/Desktop/LinuxSec"
    assert rec.max_uses == 1
    assert rec.ttl_s == 300
    assert rec.policy_class == "CONFIRM_ONCE"


def test_canonical_json_uses_spec_74_key_names() -> None:
    payload = json.loads(_record().canonical_json())
    # "class" is a Python keyword; the wire form must still carry the §7.4 key.
    for key in (
        "token_id", "session_id", "tool", "args_normalized", "canonical_paths",
        "cwd_real", "env_digest", "action_hash", "max_uses", "ttl_s",
        "issued_at", "class",
    ):
        assert key in payload
    assert payload["class"] == "CONFIRM_ONCE"
    assert payload["issued_at"] == "2026-07-23T19:00:00Z"


# --- (2) canonical_json determinism ------------------------------------------


def test_canonical_json_byte_identical_for_same_record() -> None:
    rec = _record()
    assert rec.canonical_bytes() == rec.canonical_bytes()
    reparsed = ApprovalRecord.model_validate(SPEC_74_RECORD)
    assert reparsed.canonical_bytes() == rec.canonical_bytes()


def test_canonical_json_sorted_keys_and_no_whitespace() -> None:
    canonical = _record().canonical_json()
    payload = json.loads(canonical)
    assert list(payload) == sorted(payload)
    # Round-trip with the mandated encoder settings must reproduce the bytes:
    # any deviation (whitespace, key order, unicode) breaks HMAC stability.
    assert canonical == json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def test_canonical_json_escapes_unicode() -> None:
    rec = _record(policy_note="სარისკო ხაზი")  # Georgian policy annotation
    canonical = rec.canonical_json()
    assert canonical.isascii()
    assert "\\u" in canonical
    assert json.loads(canonical)["policy_note"] == "სარისკო ხაზი"


# --- (3) mutation vectors change canonical bytes (I5/I6, AC-09 precondition) --

MUTATION_VECTORS: list[dict[str, Any]] = [
    {"args_normalized": {"argv": ["pytest", "-q", "tests/unit"]}},
    {"canonical_paths": ["/home/null/Desktop/LinuxSec/lsassist"]},
    {"cwd_real": "/home/null/Desktop"},
    {"ttl_s": 301},
    {"max_uses": 2},
    {"tool": "fs.write"},
]


@pytest.mark.parametrize(
    "mutation",
    MUTATION_VECTORS,
    ids=[next(iter(m)) for m in MUTATION_VECTORS],
)
def test_any_bound_field_mutation_changes_canonical_bytes(
    mutation: dict[str, Any],
) -> None:
    baseline = _record().canonical_bytes()
    assert _record(**mutation).canonical_bytes() != baseline


# --- (4) max_uses / ttl_s bounds ----------------------------------------------


@pytest.mark.parametrize("bad_max_uses", [0, -1])
def test_max_uses_below_one_rejected(bad_max_uses: int) -> None:
    with pytest.raises(ValidationError):
        _record(max_uses=bad_max_uses)


@pytest.mark.parametrize("bad_ttl", [0, -5])
def test_ttl_s_must_be_positive(bad_ttl: int) -> None:
    with pytest.raises(ValidationError):
        _record(ttl_s=bad_ttl)


# --- (5) tokens are never minted for AUTO classes ----------------------------


@pytest.mark.parametrize("bad_class", ["AUTO_READ", "AUTO_SCOPED_WRITE", "DENY_ALWAYS"])
def test_non_confirm_class_rejected(bad_class: str) -> None:
    with pytest.raises(ValidationError):
        _record(**{"class": bad_class})


@pytest.mark.parametrize("ok_class", ["CONFIRM_ONCE", "CONFIRM_EXACT"])
def test_confirm_classes_accepted(ok_class: str) -> None:
    assert _record(**{"class": ok_class}).policy_class == ok_class


# --- (6) policy_note / rollback_hint display fields (§7.1, display = record) ---


def test_display_fields_default_empty() -> None:
    rec = _record()
    assert rec.policy_note == ""
    assert rec.rollback_hint == ""


def test_display_fields_present_in_canonical_json() -> None:
    payload = json.loads(_record().canonical_json())
    assert payload["policy_note"] == ""
    assert payload["rollback_hint"] == ""


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("policy_note", "R5: argv[0]=rm is destructive"),
        ("rollback_hint", "shadow-git checkpoint cp-1"),
    ],
)
def test_display_field_mutation_changes_canonical_bytes(field: str, value: str) -> None:
    assert _record(**{field: value}).canonical_bytes() != _record().canonical_bytes()
