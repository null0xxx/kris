"""Sandbox Profile enum (SPEC §8).

V1 ships exactly two bwrap profiles: ``ro`` (read-only workspace bind, §8.1)
and ``ws`` (scoped write workspace bind, §8.2). The network-enabled variant
``ws-net`` is explicitly NOT in V1 (§8.2: test runners must work offline;
documented as a §20 V2 candidate). Values are lowercase strings so they
travel as plain data (argv building, audit events, JSON).

§2.2: stdlib + pydantic only; no I/O, no child processes, no network.
"""

from __future__ import annotations

from enum import StrEnum


class Profile(StrEnum):
    """§8 sandbox profiles available in V1."""

    RO = "ro"
    WS = "ws"
