"""§7.4 HMAC approval-token service — mint / verify (I5/I6, threat class T-12).

The kernel mints a token binding an :class:`~lsassist.contracts.approval.ApprovalRecord`
to a timing-safe HMAC and, at exec time, re-canonicalizes the CURRENT action into
a fresh record and asks :meth:`TokenService.verify` whether it still matches. Any
material change to the record (args, paths, ``cwd``, env, ``class``, ``ttl_s``,
``max_uses``, ``token_id``, ...) changes ``canonical_bytes`` and therefore the
HMAC, forcing re-approval (I6).

CRITICAL (T-12): the HMAC input is ALWAYS
:meth:`ApprovalRecord.canonical_bytes` used VERBATIM — the ONLY canonical form
in the codebase. This module NEVER serializes an approval record itself (no
hand-rolled JSON, no mapping-building, no field re-ordering): a second
serialization path IS the token-forgery vulnerability.

PURE (§2.2): the 32-byte kernel secret is INJECTED as ``bytes`` (resolved by the
T1.09 secret resolver); this module does no fs/env access. The in-memory
use-counter store is kernel-side state, keyed by ``token_id`` (V1).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from lsassist.contracts.approval import ApprovalRecord


class TokenVerdict(StrEnum):
    """The fail-closed outcome of :meth:`TokenService.verify`.

    Exactly one of these is returned; only :data:`VALID` authorizes execution
    (and only :data:`VALID` consumes a use).
    """

    VALID = "VALID"
    HMAC_MISMATCH = "HMAC_MISMATCH"
    UNKNOWN_TOKEN = "UNKNOWN_TOKEN"
    EXPIRED = "EXPIRED"
    EXHAUSTED = "EXHAUSTED"


@dataclass(frozen=True, slots=True)
class ApprovalToken:
    """The minted token handed back to the kernel: the record's ``token_id`` and
    the hex HMAC ``value`` over its canonical bytes. Frozen — a token is a value,
    not mutable state."""

    token_id: str
    value: str


class TokenService:
    """Mints and verifies §7.4 approval tokens under an injected kernel secret."""

    def __init__(self, kernel_secret: bytes) -> None:
        # 32-byte install-time random secret, resolved+ownership-checked by the
        # T1.09 resolver and injected here as bytes (no fs/env access in policy).
        self._secret = kernel_secret
        # Kernel-side use-counter store, keyed by token_id (V1: in-memory dict).
        self._uses: dict[str, int] = {}

    def _hmac(self, record: ApprovalRecord) -> str:
        # The ONLY HMAC input: the record's single canonical form, VERBATIM.
        # No serialization happens here — canonical_bytes() is authoritative.
        return hmac.new(self._secret, record.canonical_bytes(), hashlib.sha256).hexdigest()

    def mint(self, record: ApprovalRecord) -> ApprovalToken:
        """Bind ``record`` (AS GIVEN — its ``token_id``/``issued_at`` are not
        regenerated) to an HMAC and register its use counter at 0."""
        value = self._hmac(record)
        self._uses[record.token_id] = 0
        return ApprovalToken(token_id=record.token_id, value=value)

    def verify(
        self, token: ApprovalToken, recomputed_record: ApprovalRecord, now: datetime
    ) -> TokenVerdict:
        """Verify ``token`` against the freshly re-canonicalized ``recomputed_record``.

        Ordered, ALL fail-closed. The HMAC/identity checks run BEFORE the use
        counter is touched, so an invalid token never consumes a use.
        """
        # Precondition: TTL math needs a tz-aware `now`; a naive one is refused
        # fail-closed (subtracting tz-aware issued_at from it would be undefined).
        if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
            raise ValueError("now must be timezone-aware (UTC)")

        # 1. I6 material-change check: recompute the HMAC over the CURRENT record
        #    and compare timing-safely. ANY changed field flips canonical_bytes.
        #    Compare as bytes: `expected` is ASCII hex, but `token.value` is
        #    attacker-controllable and may be non-ASCII — a str compare_digest
        #    would RAISE on that (DoS), so encode both (unequal → False →
        #    HMAC_MISMATCH, never raises; still constant-ish-time / fail-closed).
        expected = self._hmac(recomputed_record)
        if not hmac.compare_digest(expected.encode("ascii"), token.value.encode("utf-8")):
            return TokenVerdict.HMAC_MISMATCH

        # 2. The struct id must match the record's id AND name a KNOWN minted
        #    token (catches token_id splicing and never-minted valid HMACs).
        #    Compare as UTF-8 bytes: token_id is attacker-controllable and may be
        #    non-ASCII, which would make str compare_digest raise (not fail-close).
        if not hmac.compare_digest(
            token.token_id.encode("utf-8"), recomputed_record.token_id.encode("utf-8")
        ):
            return TokenVerdict.UNKNOWN_TOKEN
        if token.token_id not in self._uses:
            return TokenVerdict.UNKNOWN_TOKEN

        # 3. TTL: strictly past issued_at + ttl_s → expired.
        if now - recomputed_record.issued_at > timedelta(seconds=recomputed_record.ttl_s):
            return TokenVerdict.EXPIRED

        # 4. Uses: at/over the cap → exhausted; otherwise consume one use and OK.
        if self._uses[token.token_id] >= recomputed_record.max_uses:
            return TokenVerdict.EXHAUSTED
        self._uses[token.token_id] += 1
        return TokenVerdict.VALID
