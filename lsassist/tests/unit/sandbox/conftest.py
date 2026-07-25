"""Shared purity trip-wire for the sandbox unit tests (SPEC §2.2).

``sandbox/`` must never read the process environment. The fixture below swaps it
for a mapping that raises on ANY access, so a future ``environ`` read inside a
"pure" function fails loudly instead of quietly working on the dev machine.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Callable, Iterator, Mapping

import pytest


class _TripWire(Mapping[str, str]):
    """Any read of the process environment fails the test."""

    def __getitem__(self, key: str) -> str:
        raise AssertionError(f"environment read in a PURE module: {key!r}")

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("environment iterated in a PURE module")

    def __len__(self) -> int:
        raise AssertionError("environment sized in a PURE module")


@contextlib.contextmanager
def _tripwired_environ() -> Iterator[None]:
    """Install the trip-wire for the narrowest possible window.

    Restored in ``finally``, and deliberately tight: pytest's own reporting
    reads the environment (``COLUMNS``, ``PY_COLORS``), so assertions belong
    OUTSIDE the block — a failure raised inside it crashes the test session
    instead of being reported.
    """
    saved = os.environ
    os.environ = _TripWire()  # type: ignore[assignment]  # noqa: B003
    try:
        yield
    finally:
        os.environ = saved  # type: ignore[assignment]  # noqa: B003


@pytest.fixture
def tripwired_environ() -> Callable[[], contextlib.AbstractContextManager[None]]:
    """Return the trip-wire context-manager factory (used as ``with f():``)."""
    return _tripwired_environ
