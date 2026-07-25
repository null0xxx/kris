"""T2.11 property: untrusted-turn flag monotonicity + capability reduction (I7).

Hypothesis over arbitrary ingestion sequences ``[(source, trusted), ...]``:

1. the flag is MONOTONE — once set it never clears at any prefix of the fold;
2. the produced :class:`~lsassist.contracts.policy_context.PolicyContext`
   always carries the flag;
3. §4.6 step 2 end-to-end (T2.01's R3, consumed not re-implemented): on an
   untrusted turn the classifier NEVER returns an AUTO class for a request
   whose manifest floor is not AUTO_READ.

Run with ``--hypothesis-profile=ci`` for the ≥200-example budget (§23.1 PT).
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

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
from lsassist.kernel.untrusted import TurnTrust, compute_turn_trust, new_turn
from lsassist.policy.classes import rank
from lsassist.policy.rules import classify
from lsassist.policy.stores import PolicyStores

WS = "/ws/project"
HOME = "/home/u"
AUTO_CLASSES = (PermissionClass.AUTO_READ, PermissionClass.AUTO_SCOPED_WRITE)

STORES = PolicyStores(
    home=HOME,
    audit_store=HOME + "/.local/state/lsassist/audit",
    policy_store=HOME + "/.config/lsassist",
    kernel_secret=HOME + "/.local/state/lsassist/kernel.secret",
)

ingestions = st.lists(
    st.tuples(st.text(min_size=1, max_size=12), st.booleans()),
    max_size=12,
)


def _manifest(permission_class: PermissionClass) -> ToolManifest:
    return ToolManifest(
        name="fs.write",
        version="1.0.0",
        purpose="property manifest",
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


@given(ingestions)
def test_flag_is_monotone_over_arbitrary_ingestion_sequences(
    events: list[tuple[str, bool]],
) -> None:
    trust = new_turn()
    seen_untrusted = False
    for source, trusted in events:
        previous = trust.untrusted
        trust = trust.ingest_trusted(source) if trusted else trust.ingest_untrusted(source)
        seen_untrusted = seen_untrusted or not trusted
        assert trust.untrusted >= previous  # never clears
        assert trust.untrusted is seen_untrusted


@given(ingestions)
def test_fold_equals_step_by_step_and_records_only_untrusted_sources(
    events: list[tuple[str, bool]],
) -> None:
    folded = compute_turn_trust(events)
    stepwise = new_turn()
    for source, trusted in events:
        stepwise = (
            stepwise.ingest_trusted(source) if trusted else stepwise.ingest_untrusted(source)
        )
    assert folded == stepwise
    assert folded.untrusted_sources == tuple(s for s, trusted in events if not trusted)
    assert folded.untrusted is any(not trusted for _, trusted in events)


@given(ingestions)
def test_policy_context_always_carries_the_flag(events: list[tuple[str, bool]]) -> None:
    trust = compute_turn_trust(events)
    ctx = trust.to_policy_context(WS)
    assert ctx.untrusted_turn is trust.untrusted
    assert ctx.workspace_root == WS


@given(ingestions, st.sampled_from(list(PermissionClass)))
def test_untrusted_turn_never_yields_auto_for_non_read(
    events: list[tuple[str, bool]], floor: PermissionClass
) -> None:
    trust = compute_turn_trust([*events, ("tool:fs.read:hostile", False)])
    assert trust.untrusted is True
    ctx = trust.to_policy_context(WS)
    request = ToolRequest(call_id="c1", tool="fs.write", args={"path": WS + "/a.txt"})
    result = classify(request, ctx, _manifest(floor), STORES)
    if floor is PermissionClass.AUTO_READ:
        # A pure read stays AUTO_READ (§4.6 step 2 restricts the turn TO reads).
        assert result is PermissionClass.AUTO_READ
    else:
        assert result not in AUTO_CLASSES
        assert rank(result) >= rank(PermissionClass.CONFIRM_EXACT)


@given(st.text(max_size=20))
def test_trusted_only_turns_stay_trusted(source: str) -> None:
    trust = TurnTrust().ingest_trusted(source).ingest_trusted(source)
    assert trust.untrusted is False
    assert trust.to_policy_context(WS).untrusted_turn is False
