"""The §14.1 audit record and its canonical serialization (SPEC §14.1).

§14.1 fixes the record shape verbatim::

    {"seq": 41, "ts": "2026-07-23T19:05:11.512Z", "session_id": "…",
     "task_id": "…", "event": "tool_result", "payload": { },
     "payload_digest": "sha256:…", "prev_hash": "sha256:…",
     "model": "kimi-for-coding", "provider": "kimi-coding"}

and the event vocabulary as a closed list PLUS one family: ``lab_*``. The family
is a pattern rather than an enumeration because §11's LAB pipeline names its own
stages, and a schema that had to know them would have to change every time the
pipeline did — which is precisely how an audit schema stops being a contract.

**THE SERIALIZATION IS THE HASH INPUT, so it is pinned, not incidental.**
``sort_keys=True`` makes the bytes independent of dict insertion order;
``separators=(",", ":")`` removes the whitespace a pretty-printer would add;
``ensure_ascii=False`` keeps UTF-8 text as UTF-8 (the §0.3 language rule puts
Georgian prose in payloads, and escaping it would make the journal unreadable
for the audience it is written for). The same bytes are what the writer appends
to the journal, so a reader never has to guess how to re-derive what was hashed:
the LINE IS the canonical form.

Every field is inside the digest. A field outside it is a field an attacker may
rewrite without breaking the chain, which would make the §14.1 tamper-evidence
claim true only of the fields nobody cared to exclude.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
from enum import StrEnum
from typing import Annotated, Any, Final

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

__all__ = [
    "GENESIS_HASH",
    "LAB_EVENT_PATTERN",
    "AuditEvent",
    "AuditRecord",
    "assert_stable_serialization",
    "canonical_bytes",
    "record_hash",
    "stable_serialization",
]

#: The §14.1 event list, verbatim. ``provider_down|provider_fallback|
#: provider_restored`` is written as one alternation in the SPEC; it is three
#: distinct events, so it is three members here.
class AuditEvent(StrEnum):
    """The closed part of §14.1's event vocabulary."""

    INTENT = "intent"
    GROUND = "ground"
    PLAN_REVISION = "plan_revision"
    POLICY_DECISION = "policy_decision"
    APPROVAL = "approval"
    TOOL_REQUEST = "tool_request"
    TOOL_RESULT = "tool_result"
    VERIFY = "verify"
    VERDICT = "verdict"
    BUDGET = "budget"
    PROVIDER_DOWN = "provider_down"
    PROVIDER_FALLBACK = "provider_fallback"
    PROVIDER_RESTORED = "provider_restored"
    MEMORY_WRITE = "memory_write"
    SKILL_LIFECYCLE = "skill_lifecycle"
    RECOVERY = "recovery"
    CONFIG_CHANGE = "config_change"


#: §14.1's ``lab_*`` family. ANCHORED at both ends: an unanchored pattern would
#: accept ``not_a_lab_event``, and an audit event nobody can dispatch on is an
#: event that will be silently ignored by whatever reads the journal.
LAB_EVENT_PATTERN: Final = r"^lab_[a-z][a-z0-9_]{0,31}$"

_LAB_EVENT_RE: Final = re.compile(LAB_EVENT_PATTERN)
_ALLOWED_EVENTS: Final[frozenset[str]] = frozenset(member.value for member in AuditEvent)

#: The ``prev_hash`` of the first record in a chain. §14.1 requires the field on
#: every record, and the first one has no predecessor, so the chain starts from
#: a fixed, obviously-recognizable value rather than a null the reader would
#: have to special-case.
GENESIS_HASH: Final = "sha256:" + "0" * 64

Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]


class AuditRecord(BaseModel):
    """One §14.1 journal line.

    Frozen and ``extra="forbid"``: a record with room for an undeclared field is
    a record whose meaning is not fixed by the SPEC, and a mutable one is a
    record whose hash can go stale between computing and writing it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int = Field(ge=0, strict=True)
    ts: datetime.datetime
    session_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    event: str
    payload: dict[str, Any]
    payload_digest: Sha256Digest
    prev_hash: Sha256Digest
    model: str = Field(min_length=1)
    provider: str = Field(min_length=1)

    @field_validator("event")
    @classmethod
    def _known_event(cls, value: str) -> str:
        """§14.1's list, or the ``lab_*`` family. Nothing else."""
        if value in _ALLOWED_EVENTS or _LAB_EVENT_RE.match(value):
            return value
        raise ValueError(f"{value!r} is not a §14.1 event type")

    @field_validator("ts")
    @classmethod
    def _aware(cls, value: datetime.datetime) -> datetime.datetime:
        """A naive timestamp in a tamper-evident journal is an ambiguous one."""
        if value.tzinfo is None:
            raise ValueError("audit timestamps must be timezone-aware (§14.1)")
        return value

    def as_canonical_dict(self) -> dict[str, Any]:
        """The exact mapping :func:`canonical_bytes` serializes."""
        data: dict[str, Any] = self.model_dump(mode="json")
        return data


#: Characters that survive ``ensure_ascii=False`` and that ``str.splitlines()``
#: nevertheless treats as line boundaries. Measured, not assumed: ``json.dumps``
#: already escapes every ASCII control character (so ``\n``, ``\r``, ``\v``,
#: ``\f`` and ``\x1c``-``\x1e`` are safe), and exactly these three come
#: through raw.
#:
#: They break the JOURNAL'S FRAMING, which is the whole point of JSONL: one
#: record containing U+2028 becomes two lines, so the chain reads as malformed
#: and one payload has silently become two. Hypothesis found this with the key
#: ``"\x85"``; U+2028 is the realistic one, because it is common in
#: JavaScript-derived text and tool output is attacker-influenced.
#: The replacements are the JSON ESCAPE SEQUENCES (a literal backslash, then
#: ``uXXXX``), not the characters themselves - writing the character would make
#: this table a no-op that still reads like a fix.
_LINE_BREAKERS: Final[dict[int, str]] = {
    0x85: "\\u0085",
    0x2028: "\\u2028",
    0x2029: "\\u2029",
}


def canonical_bytes(record: AuditRecord | dict[str, Any]) -> bytes:
    """The byte-stable serialization that is BOTH hashed and written.

    Accepts a parsed record or the raw mapping a reader loaded from a line, so
    verification never has to round-trip through the model to re-derive the
    bytes it is checking.

    ``ensure_ascii=False`` keeps UTF-8 readable (§14.1's journal is meant to be
    read), and :data:`_LINE_BREAKERS` then escapes the three characters that
    would otherwise split one record across two lines. Applied HERE rather than
    at the writer so the hashed bytes and the written bytes stay identical —
    escaping only on the way out would make every affected record hash
    differently from the line that carries it.
    """
    data = record.as_canonical_dict() if isinstance(record, AuditRecord) else record
    text = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.translate(_LINE_BREAKERS).encode("utf-8")


def record_hash(record: AuditRecord | dict[str, Any]) -> str:
    """``sha256:<hex>`` over :func:`canonical_bytes` — the chain's link value."""
    return "sha256:" + hashlib.sha256(canonical_bytes(record)).hexdigest()


def stable_serialization() -> bool:
    """Is :func:`canonical_bytes` independent of dict insertion order?

    §14.1's tamper-evidence rests on it: a serializer that depended on ordering
    would make an identical record hash differently on a different run, and the
    chain would report tampering on a file nobody touched. Checked at import
    (below) so a bad build fails loudly rather than at the first verification,
    and exposed as a function so the check itself is testable — an import-time
    ``if`` that nothing can reach is a check nobody has verified fires.
    """
    probe: dict[str, Any] = {"b": 1, "a": [2, {"d": 3, "c": 4}]}
    reversed_probe: dict[str, Any] = {"a": [2, {"c": 4, "d": 3}], "b": 1}
    return canonical_bytes(probe) == canonical_bytes(reversed_probe)


def assert_stable_serialization() -> None:
    """Raise if :func:`stable_serialization` does not hold. Called at import.

    Kept as a FUNCTION rather than a bare module-level ``if`` so the raising arm
    is reachable from a test. An import-time guard nobody can exercise is a
    guard nobody has watched fire, which is the same category of assurance §23.1
    exists to refuse.
    """
    if not stable_serialization():
        raise RuntimeError("canonical serialization is order-dependent (§14.1)")


assert_stable_serialization()
