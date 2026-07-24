"""IntentRecord contract model — immutable captured intent (SPEC §16.2).

§16.2 pipeline step 1 is "capture immutable intent": ``{text, digest, ts}``
where ``digest`` is the ``sha256:``-prefixed SHA-256 of the canonical intent
text (UTF-8 bytes of ``text`` verbatim) and ``ts`` a UTC ISO-8601 timestamp.
Every plan references the digest, so :func:`make_intent` is deterministic:
the same text always yields the same digest. The model is frozen — a mutation
attempt raises ``ValidationError``.

§2.2: stdlib + pydantic only; no I/O, no child processes, no network.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, field_validator

from lsassist.contracts.tool_result import Sha256Digest


def _utc_now() -> datetime:
    return datetime.now(UTC)


def intent_digest(text: str) -> str:
    """Canonical intent digest: ``sha256:`` + SHA-256 of the UTF-8 text."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class IntentRecord(BaseModel):
    """§16.2 immutable intent record: ``{text, digest, ts}``."""

    model_config = ConfigDict(frozen=True)

    text: str
    digest: Sha256Digest
    ts: datetime

    @field_validator("ts")
    @classmethod
    def _ts_must_be_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("ts must be timezone-aware (UTC ISO-8601)")
        return value


def make_intent(text: str) -> IntentRecord:
    """Capture an immutable intent record for ``text`` (§16.2 step 1).

    Deterministic digest: the same text produces the same digest on every
    run; ``ts`` is the capture time in UTC.
    """
    return IntentRecord(text=text, digest=intent_digest(text), ts=_utc_now())
