"""T2.08: §4.3 loop detection — identical ``action_hash`` 3x CONSECUTIVE halts.

RED-first tests for :mod:`lsassist.kernel.loopdetect`. The SPEC sentence is
short and every word of it is load-bearing:

    ``action_hash`` (tool+normalized args+cwd) 3x consecutive identical → halt
    → REPORT with ``loop_detected`` evidence.

So the tests pin: **3** (not 2), **consecutive** (an interleaved different
action resets the streak), the halt is **sticky** (a caller cannot un-halt a
tripped tracker by feeding it something new), and the halt reason is
``ExitReason.LOOP_DETECTED`` rendering to the §4.4 wire form ``loop_detected``.

The keys are REAL :func:`lsassist.policy.canonical.action_hash` values, so this
also pins the T2.02 hash as the loop-detection key (§4.3) rather than some
parallel notion of "same action".
"""

from __future__ import annotations

import dataclasses

import pytest

from lsassist.contracts.enums import ExitReason
from lsassist.kernel.loopdetect import (
    LOOP_THRESHOLD,
    LoopDetectionError,
    LoopTracker,
)
from lsassist.policy.canonical import action_hash

_ENV = "sha256:" + "0" * 64


def _hash(tool: str, path: str = "/home/u/ws/a.txt") -> str:
    return action_hash(tool, {"path": path}, [path], "/home/u/ws", _ENV)


A = _hash("fs.read")
B = _hash("fs.read", "/home/u/ws/b.txt")
C = _hash("shell.exec")


def _feed(*hashes: str, threshold: int = LOOP_THRESHOLD) -> LoopTracker:
    tracker = LoopTracker(threshold=threshold)
    for value in hashes:
        tracker = tracker.observe(value)
    return tracker


# ---------------------------------------------------------------------------
# The §4.3 threshold
# ---------------------------------------------------------------------------


def test_spec_threshold_is_three() -> None:
    assert LOOP_THRESHOLD == 3


def test_fresh_tracker_is_not_halted() -> None:
    tracker = LoopTracker()
    assert tracker.halted is False
    assert tracker.streak == 0
    assert tracker.last_hash is None


def test_three_identical_consecutive_halts() -> None:
    tracker = _feed(A, A, A)
    assert tracker.halted is True
    assert tracker.streak == 3
    assert tracker.last_hash == A


def test_two_identical_consecutive_do_not_halt() -> None:
    tracker = _feed(A, A)
    assert tracker.halted is False
    assert tracker.streak == 2


def test_two_identical_then_a_different_one_does_not_halt() -> None:
    tracker = _feed(A, A, B)
    assert tracker.halted is False
    assert tracker.streak == 1
    assert tracker.last_hash == B


def test_identical_but_non_consecutive_does_not_halt() -> None:
    tracker = _feed(A, B, A, C, A)
    assert tracker.halted is False
    assert tracker.streak == 1


def test_a_reset_restarts_the_count_from_one() -> None:
    tracker = _feed(A, A, B, A, A)
    assert tracker.halted is False
    assert tracker.streak == 2


def test_three_identical_after_an_unrelated_prefix_halts() -> None:
    tracker = _feed(B, C, A, A, A)
    assert tracker.halted is True
    assert tracker.last_hash == A


def test_a_different_tool_with_the_same_args_is_a_different_action() -> None:
    assert _hash("fs.read") != _hash("fs.write")
    assert _feed(_hash("fs.read"), _hash("fs.write"), _hash("fs.read")).halted is False


# ---------------------------------------------------------------------------
# Purity and stickiness
# ---------------------------------------------------------------------------


def test_observe_returns_a_new_tracker_and_leaves_the_old_one_alone() -> None:
    first = LoopTracker()
    second = first.observe(A)
    assert second is not first
    assert first.streak == 0
    assert second.streak == 1


def test_tracker_is_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        LoopTracker().streak = 2  # type: ignore[misc]


def test_halt_is_sticky_a_new_action_cannot_un_halt_it() -> None:
    tracker = _feed(A, A, A)
    after = tracker.observe(B)
    assert after.halted is True
    assert after.last_hash == A
    assert after.streak == 3


def test_halt_is_sticky_across_many_further_observations() -> None:
    tracker = _feed(A, A, A)
    for value in (B, C, B, C):
        tracker = tracker.observe(value)
    assert tracker.halted is True


# ---------------------------------------------------------------------------
# §4.4 exit reason
# ---------------------------------------------------------------------------


def test_halt_reason_is_the_spec_4_4_loop_detected_reason() -> None:
    tracker = _feed(A, A, A)
    assert tracker.exit_reason() is ExitReason.LOOP_DETECTED
    assert tracker.exit_reason().render() == "loop_detected"


def test_exit_reason_on_a_non_halted_tracker_raises() -> None:
    with pytest.raises(LoopDetectionError):
        _feed(A, A).exit_reason()


def test_evidence_exposes_the_repeated_action_hash() -> None:
    tracker = _feed(A, A, A)
    assert tracker.last_hash == A
    assert tracker.streak >= LOOP_THRESHOLD


# ---------------------------------------------------------------------------
# Fail-closed input validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "fs.read",
        "sha256:" + "0" * 63,
        "sha256:" + "0" * 65,
        "sha256:" + "Z" * 64,
        "SHA256:" + "0" * 64,
        "0" * 64,
    ],
)
def test_observe_rejects_a_non_action_hash_key(bad: str) -> None:
    with pytest.raises(LoopDetectionError):
        LoopTracker().observe(bad)


def test_observe_rejects_an_uppercase_hex_digest() -> None:
    with pytest.raises(LoopDetectionError):
        LoopTracker().observe("sha256:" + "AB" * 32)


@pytest.mark.parametrize("threshold", [1, 0, -1])
def test_threshold_below_two_is_rejected(threshold: int) -> None:
    with pytest.raises(LoopDetectionError):
        LoopTracker(threshold=threshold)


def test_threshold_override_halts_at_the_configured_count() -> None:
    tracker = _feed(A, A, threshold=2)
    assert tracker.halted is True
