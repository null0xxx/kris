"""T1.11 RED: sandbox Profile enum (SPEC §8).

V1 ships exactly two bwrap profiles: ``ro`` (read-only, §8.1) and ``ws``
(scoped write, §8.2). The network-enabled variant ``ws-net`` is explicitly NOT
in V1 (§8.2: "Network-enabled variant (`ws-net`) V1-ში არ არსებობს"; §20 V2
candidate). Values are lowercase strings so they can travel as argv/JSON data.
"""

from __future__ import annotations

from lsassist.contracts.sandbox_profile import Profile

# --- (1) exactly the two V1 members ----------------------------------------------------


def test_profile_members_exactly_ro_and_ws() -> None:
    assert {member.value for member in Profile} == {"ro", "ws"}


def test_profile_member_names() -> None:
    assert set(Profile.__members__) == {"RO", "WS"}


def test_ws_net_does_not_exist_in_v1() -> None:
    assert "WS_NET" not in Profile.__members__
    assert "ws-net" not in {member.value for member in Profile}


# --- (2) lowercase string values --------------------------------------------------------


def test_values_are_lowercase_strings() -> None:
    for member in Profile:
        assert isinstance(member, str)
        assert member.value == member.value.lower()


def test_str_round_trip() -> None:
    assert Profile("ro") is Profile.RO
    assert Profile("ws") is Profile.WS
