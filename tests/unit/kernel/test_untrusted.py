"""T2.11: §4.6 step-2 untrusted-turn flag propagation (the FLAG's source, I7).

This module owns where ``PolicyContext.untrusted_turn`` comes FROM. The policy
side of R3 (untrusted turn → any non-AUTO_READ raises to CONFIRM_EXACT) already
lives in T2.01's ``policy.rules.classify`` and is NOT re-implemented here; the
last test below only proves the two halves meet.

Central property under test: the flag is STICKY within a turn — trusted content
ingested after untrusted content can never restore trust. A fresh turn (a new
:class:`TurnTrust`) starts trusted again.
"""

from __future__ import annotations

import dataclasses

import pytest

from lsassist.contracts.enums import PermissionClass
from lsassist.contracts.manifest import (
    Capabilities,
    Concurrency,
    FsCapability,
    NetCapability,
    OutputLimits,
    ProcCapability,
    Rollback,
    ToolManifest,
)
from lsassist.contracts.tool_request import ToolRequest
from lsassist.kernel.untrusted import (
    START_MARKER_PATTERN,
    TurnTrust,
    compute_turn_trust,
    ingest_untrusted_block,
    new_turn,
)
from lsassist.policy.classes import rank
from lsassist.policy.rules import classify
from lsassist.policy.stores import PolicyStores

WS = "/ws/project"
HOME = "/home/u"
ID = "0123456789abcdef"

STORES = PolicyStores(
    home=HOME,
    audit_store=HOME + "/.local/state/lsassist/audit",
    policy_store=HOME + "/.config/lsassist",
    kernel_secret=HOME + "/.local/state/lsassist/kernel.secret",
)


def _manifest(permission_class: PermissionClass) -> ToolManifest:
    return ToolManifest(
        name="fs.write",
        version="1.0.0",
        purpose="test manifest",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        permission_class=permission_class,
        capabilities=Capabilities(
            fs=FsCapability.NONE, net=NetCapability.NONE, proc=ProcCapability.NONE
        ),
        timeout_s=10,
        output_limits=OutputLimits(
            max_stdout_bytes=1024, max_stderr_bytes=1024, max_result_chars=1024
        ),
        concurrency=Concurrency.EXCLUSIVE,
        idempotent=True,
        dry_run=False,
        rollback=Rollback.NONE,
        redaction=[],
        tests=["t"],
    )


# ============================================================================
# Turn trust — initial state
# ============================================================================


def test_new_turn_starts_trusted() -> None:
    trust = new_turn()
    assert trust.untrusted is False
    assert trust.untrusted_sources == ()


def test_new_turn_policy_context_is_not_untrusted() -> None:
    ctx = new_turn().to_policy_context(WS)
    assert ctx.untrusted_turn is False
    assert ctx.workspace_root == WS


# ============================================================================
# Flag source: any untrusted ingestion flips the flag
# ============================================================================


def test_untrusted_ingestion_sets_the_flag_and_records_the_source() -> None:
    trust = new_turn().ingest_untrusted("tool:fs.read:/etc/hosts")
    assert trust.untrusted is True
    assert trust.untrusted_sources == ("tool:fs.read:/etc/hosts",)


def test_untrusted_ingestions_accumulate_sources_in_order() -> None:
    trust = new_turn().ingest_untrusted("a").ingest_untrusted("b")
    assert trust.untrusted_sources == ("a", "b")


def test_trusted_ingestion_alone_never_sets_the_flag() -> None:
    trust = new_turn().ingest_trusted("user:direct-instruction")
    assert trust.untrusted is False
    assert trust.untrusted_sources == ()


def test_propagated_policy_context_carries_untrusted_turn() -> None:
    ctx = new_turn().ingest_untrusted("web:https://example.invalid").to_policy_context(WS)
    assert ctx.untrusted_turn is True


def test_to_policy_context_passes_skill_ceiling_through() -> None:
    ctx = new_turn().to_policy_context(WS, skill_ceiling=PermissionClass.AUTO_READ)
    assert ctx.skill_ceiling is PermissionClass.AUTO_READ


# ============================================================================
# STICKY: untrusted → untrusted, never back (monotonicity, I7)
# ============================================================================


def test_flag_is_sticky_across_a_later_trusted_ingestion() -> None:
    trust = new_turn().ingest_untrusted("tool:web.fetch").ingest_trusted("user:direct")
    assert trust.untrusted is True
    assert trust.to_policy_context(WS).untrusted_turn is True


def test_flag_is_sticky_across_many_alternating_ingestions() -> None:
    trust = new_turn()
    for i in range(5):
        trust = trust.ingest_untrusted(f"u{i}").ingest_trusted(f"t{i}")
        assert trust.untrusted is True


def test_trust_is_immutable_frozen_dataclass() -> None:
    trust = new_turn()
    with pytest.raises(dataclasses.FrozenInstanceError):
        trust.untrusted = True  # type: ignore[misc]


def test_ingestion_returns_a_new_value_leaving_the_original_trusted() -> None:
    original = new_turn()
    derived = original.ingest_untrusted("s")
    assert original.untrusted is False
    assert derived is not original


def test_next_turn_resets_the_flag() -> None:
    dirty = new_turn().ingest_untrusted("tool:fs.read")
    assert dirty.untrusted is True
    assert new_turn().untrusted is False


# ============================================================================
# compute_turn_trust fold + the wrap⇄flag single call site
# ============================================================================


def test_compute_turn_trust_over_an_empty_sequence_is_trusted() -> None:
    assert compute_turn_trust(()) == TurnTrust()


def test_compute_turn_trust_folds_mixed_ingestions_monotonically() -> None:
    trust = compute_turn_trust(
        [("user:direct", True), ("tool:fs.read", False), ("user:direct2", True)]
    )
    assert trust.untrusted is True
    assert trust.untrusted_sources == ("tool:fs.read",)


def test_ingest_untrusted_block_wraps_and_flags_in_one_step() -> None:
    trust, block = ingest_untrusted_block(
        new_turn(), "file body", "tool:fs.read", "model", marker_id=ID
    )
    assert trust.untrusted is True
    assert trust.untrusted_sources == ("tool:fs.read",)
    start = START_MARKER_PATTERN.search(block)
    assert start is not None
    assert start["source"] == "tool:fs.read"
    assert start["id"] == ID


def test_ingest_untrusted_block_generates_an_id_when_none_given() -> None:
    _, block = ingest_untrusted_block(new_turn(), "b", "skill:git", "tier2")
    start = START_MARKER_PATTERN.search(block)
    assert start is not None
    assert len(start["id"]) == 16


# ============================================================================
# Meeting point with T2.01's R3 (NOT re-implemented here — only wired)
# ============================================================================


def test_propagated_flag_drives_t2_01_r3_raise() -> None:
    ctx = new_turn().ingest_untrusted("tool:fs.read").to_policy_context(WS)
    request = ToolRequest(call_id="c1", tool="fs.write", args={"path": WS + "/a.txt"})
    result = classify(request, ctx, _manifest(PermissionClass.AUTO_SCOPED_WRITE), STORES)
    assert rank(result) >= rank(PermissionClass.CONFIRM_EXACT)
