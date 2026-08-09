"""Bounded, session-only storage for ``net.fetch`` response bodies."""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass
from typing import Final, final

__all__ = [
    "FETCH_BODY_LIMIT",
    "FetchBody",
    "FetchBodyStore",
    "FetchBodyStoreError",
]

FETCH_BODY_LIMIT: Final = 1024 * 1024
_REF_PREFIX: Final = "memory:fetch/"


class FetchBodyStoreError(RuntimeError):
    """The session store is closed, full, or does not contain a reference."""


@final
@dataclass(frozen=True, slots=True)
class FetchBody:
    """Non-secret metadata for a body held only in RAM."""

    ref: str
    byte_count: int
    digest: str


@final
class FetchBodyStore:
    """A 1 MiB aggregate RAM store whose lifetime is one session.

    No filesystem or SQLite handle exists in this type. ``close`` zeroes the
    owned bytearrays before dropping them, then permanently refuses access.
    """

    __slots__ = ("_bodies", "_closed", "_lock", "_used")

    def __init__(self) -> None:
        self._bodies: dict[str, bytearray] = {}
        self._closed = False
        self._lock = threading.Lock()
        self._used = 0

    def put(self, body: bytes) -> FetchBody:
        """Copy ``body`` into RAM after enforcing the aggregate cap."""
        if not isinstance(body, bytes):
            raise FetchBodyStoreError("fetch body must be bytes")
        with self._lock:
            if self._closed:
                raise FetchBodyStoreError("fetch body store is closed")
            if self._used + len(body) > FETCH_BODY_LIMIT:
                raise FetchBodyStoreError("fetch body store exceeds the 1 MiB session cap")
            ref = _REF_PREFIX + secrets.token_urlsafe(24)
            while ref in self._bodies:
                ref = _REF_PREFIX + secrets.token_urlsafe(24)
            self._bodies[ref] = bytearray(body)
            self._used += len(body)
        return FetchBody(
            ref=ref,
            byte_count=len(body),
            digest="sha256:" + hashlib.sha256(body).hexdigest(),
        )

    def get(self, ref: str) -> bytes:
        """Return an immutable copy for an opaque reference."""
        with self._lock:
            if self._closed:
                raise FetchBodyStoreError("fetch body store is closed")
            try:
                return bytes(self._bodies[ref])
            except KeyError as exc:
                raise FetchBodyStoreError("unknown fetch body reference") from exc

    def close(self) -> None:
        """Destroy every body and make the store unusable."""
        with self._lock:
            for body in self._bodies.values():
                body[:] = b"\x00" * len(body)
            self._bodies.clear()
            self._used = 0
            self._closed = True

    def __enter__(self) -> FetchBodyStore:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
