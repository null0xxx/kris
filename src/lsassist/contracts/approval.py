"""ApprovalRecord contract model + canonical form (SPEC §7.4, invariants I5/I6).

I5 (§1.2): approval binds to the exact action — the Phase 2 token service
computes ``HMAC_SHA256(kernel_secret, canonical_json(record))``. I6: any
material change to the record changes the canonical bytes, so pre-exec
re-canonicalization mismatch forces re-approval.

``canonical_json()`` is the ONLY canonical form in the codebase: a thin
wrapper over ``json.dumps(..., sort_keys=True, separators=(",", ":"),
ensure_ascii=True)``. Nothing else may serialize an approval record for HMAC
input.

``policy_note`` / ``rollback_hint`` are §7.1 classification annotations
(risk line = policy rule reference, rollback hint), populated at
classify/dispatch time (T3.02) and rendered in the T5.03 approval box. They
are part of the canonical record because display = record (§7.4): the user
must see exactly what is approved.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from lsassist.contracts.manifest import TOOL_NAME_PATTERN
from lsassist.contracts.tool_result import Sha256Digest


class ApprovalClass(StrEnum):
    """Classes for which an approval token may be minted (SPEC §7.1).

    Tokens never exist for AUTO_READ / AUTO_SCOPED_WRITE (no prompt, no token)
    or DENY_ALWAYS (no approval possible).
    """

    CONFIRM_ONCE = "CONFIRM_ONCE"
    CONFIRM_EXACT = "CONFIRM_EXACT"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ApprovalRecord(BaseModel):
    """§7.4 approval token record — canonical, rendered to the user verbatim."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    token_id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str = Field(min_length=1)
    tool: str = Field(pattern=TOOL_NAME_PATTERN)
    args_normalized: dict[str, Any]
    canonical_paths: list[str]
    cwd_real: str = Field(min_length=1)
    env_digest: Sha256Digest
    action_hash: Sha256Digest
    max_uses: int = Field(ge=1)
    ttl_s: int = Field(gt=0)
    issued_at: datetime = Field(default_factory=_utc_now)
    # §7.4 wire key is "class" (a Python keyword), hence the alias.
    policy_class: ApprovalClass = Field(alias="class")
    policy_note: str = ""
    rollback_hint: str = ""

    @field_validator("issued_at")
    @classmethod
    def _issued_at_must_be_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("issued_at must be timezone-aware (UTC ISO-8601)")
        return value

    def canonical_json(self) -> str:
        """The single canonical serialization of the record (HMAC input).

        Deterministic: sorted keys, no whitespace, unicode escaped. Same
        record → byte-identical output across runs and processes.
        """
        return json.dumps(
            self._canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )

    def canonical_bytes(self) -> bytes:
        """UTF-8 bytes of :meth:`canonical_json` (direct HMAC input)."""
        return self.canonical_json().encode("utf-8")

    def _canonical_dict(self) -> dict[str, Any]:
        issued_utc = self.issued_at.astimezone(UTC)
        return {
            "token_id": self.token_id,
            "session_id": self.session_id,
            "tool": self.tool,
            "args_normalized": self.args_normalized,
            "canonical_paths": self.canonical_paths,
            "cwd_real": self.cwd_real,
            "env_digest": self.env_digest,
            "action_hash": self.action_hash,
            "max_uses": self.max_uses,
            "ttl_s": self.ttl_s,
            "issued_at": issued_utc.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "class": self.policy_class.value,
            "policy_note": self.policy_note,
            "rollback_hint": self.rollback_hint,
        }
