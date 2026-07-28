"""T3.02 RED: dispatch steps 3-4 — classify, approve (SPEC §6.3, SPEC 7.1-7.5, I5).

§6.3 step 3: "Policy classify — deterministic rules (§7.2) → permission class for
*this exact request* (manifest class is the ceiling; rules can only raise)."
§6.3 step 4: "Approval — AUTO → proceed; CONFIRM → token verify ან prompt
(canonical record render); DENY → BLOCKED."

**THE DISPATCHER NEVER DECIDES THE CLASS ITSELF.** ``policy.rules.classify`` is
the single authority; the dispatcher calls it and routes on the answer. It does
separately ask which rules FIRED, but only to fill the human-facing
``policy_note`` — a second class computation would be a second decision path, and
this codebase already learned what that costs (the T-12 single-canonicalization
rule behind I5/I6). A test below pins that the note can never contradict the class.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

import pytest

from lsassist.contracts.approval import ApprovalClass, ApprovalRecord
from lsassist.contracts.enums import PermissionClass
from lsassist.contracts.manifest import ToolManifest
from lsassist.contracts.tool_request import ToolRequest
from lsassist.policy.stores import PolicyStores
from lsassist.policy.token import ApprovalToken, TokenService, TokenVerdict
from lsassist.tools.dispatcher import (
    CLASS_APPROVAL_TERMS,
    ApprovalGrant,
    Decision,
    DispatchEnvironment,
    denying_rule_id,
    dispatch,
    matched_rule_ids,
    rollback_hint,
)

NOW = datetime.datetime(2026, 7, 27, 12, 0, 0, tzinfo=datetime.UTC)
SECRET = b"k" * 32


def manifest_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "fs.read",
        "version": "1.0.0",
        "purpose": "Read a UTF-8 text file inside the workspace.",
        "input_schema": {
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}},
            "additionalProperties": False,
        },
        "output_schema": {"type": "object"},
        "permission_class": "AUTO_READ",
        "capabilities": {"fs": "read_scoped", "net": "none", "proc": "none"},
        "timeout_s": 10,
        "output_limits": {
            "max_stdout_bytes": 204800,
            "max_stderr_bytes": 65536,
            "max_result_chars": 200000,
        },
        "concurrency": "shared_read",
        "idempotent": True,
        "dry_run": False,
        "rollback": "none",
        "redaction": ["paths"],
        "path_scope": "workspace",
        "tests": [],
    }
    base.update(overrides)
    return base


def make_manifest(**overrides: Any) -> ToolManifest:
    return ToolManifest.model_validate(manifest_dict(**overrides))


def exec_manifest(**overrides: Any) -> ToolManifest:
    return make_manifest(
        name="proc.exec",
        permission_class="CONFIRM_ONCE",
        capabilities={"fs": "none", "net": "none", "proc": "spawn_argv"},
        input_schema={
            "type": "object",
            "required": ["argv"],
            "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
            "additionalProperties": False,
        },
        **overrides,
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir(parents=True)
    (ws / "a.txt").write_text("hello\n", encoding="utf-8")
    return ws


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    (h / ".ssh").mkdir(parents=True)
    (h / ".ssh" / "id_rsa").write_text("SYNTHETIC CANARY DECOY\n", encoding="utf-8")
    return h


def env_for(workspace: Path, home: Path, **overrides: Any) -> DispatchEnvironment:
    return DispatchEnvironment(
        workspace_root=str(workspace),
        cwd=str(workspace),
        stores=PolicyStores(
            home=str(home),
            audit_store=str(home / ".local/state/lsassist/audit"),
            policy_store=str(home / ".config/lsassist"),
            kernel_secret=str(home / ".local/state/lsassist/kernel.secret"),
        ),
        session_id="s-1",
        **overrides,
    )


def read_request(path: Path) -> ToolRequest:
    return ToolRequest(call_id="c1", tool="fs.read", args={"path": str(path)})


# ==========================================================================
# 1. step 3 — the class comes from policy.rules.classify, never from here
# ==========================================================================
def test_an_in_scope_read_is_auto(workspace: Path, home: Path) -> None:
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.permission_class is PermissionClass.AUTO_READ
    assert decision.decision is Decision.PROCEED
    assert decision.normalized is not None


def test_a_deny_path_read_is_blocked(workspace: Path, home: Path) -> None:
    """§7.3: ~/.ssh/** is DENY_ALWAYS for READ too (the I8 read-exposure harden)."""
    decision = dispatch(
        read_request(home / ".ssh" / "id_rsa"),
        manifest=make_manifest(),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.permission_class is PermissionClass.DENY_ALWAYS
    assert decision.decision is Decision.BLOCKED
    assert decision.normalized is None, "a BLOCKED request must not hand a handler anything"
    assert decision.approval_record is None, "DENY_ALWAYS is not approvable (§7.1)"


def test_an_untrusted_turn_raises_a_write_to_confirm_exact(
    workspace: Path, home: Path
) -> None:
    """R3 (§4.6): on an untrusted turn any non-AUTO_READ becomes CONFIRM_EXACT."""
    decision = dispatch(
        ToolRequest(call_id="c1", tool="fs.write", args={"path": str(workspace / "a.txt")}),
        manifest=make_manifest(
            name="fs.write",
            permission_class="AUTO_SCOPED_WRITE",
            capabilities={"fs": "write_scoped", "net": "none", "proc": "none"},
            rollback="checkpoint",
        ),
        environment=env_for(workspace, home, untrusted_turn=True),
        path_args=("path",),
    )
    assert decision.permission_class is PermissionClass.CONFIRM_EXACT
    assert decision.decision is Decision.NEEDS_APPROVAL


def test_an_untrusted_turn_leaves_a_pure_read_alone(workspace: Path, home: Path) -> None:
    """R3's carve-out: AUTO_READ survives, which is what makes §4.6 usable."""
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(),
        environment=env_for(workspace, home, untrusted_turn=True),
        path_args=("path",),
    )
    assert decision.permission_class is PermissionClass.AUTO_READ


def test_sudo_is_denied(workspace: Path, home: Path) -> None:
    """R5: argv[0] ∈ {sudo, doas, su} → DENY_ALWAYS in V1."""
    decision = dispatch(
        ToolRequest(call_id="c1", tool="proc.exec", args={"argv": ["sudo", "rm", "-rf", "/"]}),
        manifest=exec_manifest(),
        environment=env_for(workspace, home),
        path_args=(),
    )
    assert decision.permission_class is PermissionClass.DENY_ALWAYS
    assert decision.decision is Decision.BLOCKED


def test_a_dangerous_argv0_is_raised_to_confirm_exact(workspace: Path, home: Path) -> None:
    """R5: rm is CONFIRM_EXACT — above the manifest's CONFIRM_ONCE floor."""
    decision = dispatch(
        ToolRequest(call_id="c1", tool="proc.exec", args={"argv": ["rm", "-rf", "build"]}),
        manifest=exec_manifest(),
        environment=env_for(workspace, home),
        path_args=(),
    )
    assert decision.permission_class is PermissionClass.CONFIRM_EXACT


def test_the_dispatcher_does_not_recompute_the_class(
    workspace: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """policy.rules.classify is the SINGLE authority (I5/I6's discipline).

    Stubbing it must change the dispatcher's answer completely; if the module
    kept its own fold, this would keep returning AUTO_READ.
    """
    from lsassist.tools import dispatcher as module

    monkeypatch.setattr(module, "classify", lambda *a, **k: PermissionClass.CONFIRM_EXACT)
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.permission_class is PermissionClass.CONFIRM_EXACT


# ==========================================================================
# 2. step 3 — policy_note and rollback_hint (for T5.03's renderer)
# ==========================================================================
def test_matched_rule_ids_name_the_rules_that_fired(workspace: Path, home: Path) -> None:
    from lsassist.contracts.policy_context import PolicyContext

    context = PolicyContext(workspace_root=str(workspace.resolve()), untrusted_turn=False)
    stores = env_for(workspace, home).stores
    fired = matched_rule_ids(
        ToolRequest(call_id="c1", tool="proc.exec", args={"argv": ["rm", "-rf", "x"]}),
        context,
        stores,
    )
    assert "R5" in fired


def test_the_note_names_the_class_and_every_matched_rule(workspace: Path, home: Path) -> None:
    decision = dispatch(
        ToolRequest(call_id="c1", tool="proc.exec", args={"argv": ["rm", "-rf", "build"]}),
        manifest=exec_manifest(),
        environment=env_for(workspace, home),
        path_args=(),
    )
    assert decision.approval_record is not None
    note = decision.approval_record.policy_note
    assert "CONFIRM_EXACT" in note
    assert "R5" in note


def test_the_note_can_never_contradict_the_class(workspace: Path, home: Path) -> None:
    """The note is DIAGNOSTIC; the class is AUTHORITATIVE. It is built FROM the
    class, so the two cannot disagree even if the rule probe were wrong."""
    decision = dispatch(
        ToolRequest(
            call_id="c1", tool="fs.write", args={"path": str(workspace / "a.txt")}
        ),
        manifest=make_manifest(
            name="fs.write",
            permission_class="AUTO_SCOPED_WRITE",
            capabilities={"fs": "write_scoped", "net": "none", "proc": "none"},
            rollback="checkpoint",
        ),
        environment=env_for(workspace, home, untrusted_turn=True),
        path_args=("path",),
    )
    assert decision.approval_record is not None
    assert decision.approval_record.policy_note.startswith(decision.permission_class.value)


def test_the_note_is_populated_even_when_no_rule_fired(workspace: Path, home: Path) -> None:
    """A manifest-floor CONFIRM still needs a risk line for the renderer."""
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class="CONFIRM_ONCE"),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.approval_record is not None
    note = decision.approval_record.policy_note
    assert "CONFIRM_ONCE" in note
    assert "manifest" in note.lower()


@pytest.mark.parametrize(
    ("rollback", "expected"),
    [("checkpoint", "checkpoint"), ("manual_steps", "manual"), ("none", "no rollback")],
)
def test_rollback_hint_comes_from_the_manifest(rollback: str, expected: str) -> None:
    """§6.2 already declares each tool's rollback path — the hint reads it rather
    than inventing a class-to-hint mapping the manifest could contradict."""
    manifest = make_manifest(rollback=rollback, permission_class="CONFIRM_EXACT")
    assert expected in rollback_hint(manifest, PermissionClass.CONFIRM_EXACT).lower()


def test_the_record_carries_the_hint(workspace: Path, home: Path) -> None:
    decision = dispatch(
        ToolRequest(call_id="c1", tool="fs.write", args={"path": str(workspace / "a.txt")}),
        manifest=make_manifest(
            name="fs.write",
            permission_class="CONFIRM_EXACT",
            capabilities={"fs": "write_scoped", "net": "none", "proc": "none"},
            rollback="checkpoint",
        ),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.approval_record is not None
    assert "checkpoint" in decision.approval_record.rollback_hint.lower()


# ==========================================================================
# 3. step 4 — AUTO proceeds, DENY blocks, CONFIRM asks
# ==========================================================================
def test_auto_proceeds_without_a_record(workspace: Path, home: Path) -> None:
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.decision is Decision.PROCEED
    assert decision.approval_record is None, "AUTO never prompts (§7.1)"


def test_confirm_without_a_token_requests_approval(workspace: Path, home: Path) -> None:
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class="CONFIRM_ONCE"),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.decision is Decision.NEEDS_APPROVAL
    assert decision.normalized is None, "nothing executes before consent"
    record = decision.approval_record
    assert record is not None
    assert record.policy_class is ApprovalClass.CONFIRM_ONCE
    assert record.tool == "fs.read"
    assert record.canonical_paths == [str((workspace / "a.txt").resolve())]


@pytest.mark.parametrize(
    ("permission_class", "ttl_s", "max_uses"),
    [(PermissionClass.CONFIRM_ONCE, 300, 1), (PermissionClass.CONFIRM_EXACT, 120, 1)],
)
def test_the_record_carries_the_71_terms(
    workspace: Path, home: Path, permission_class: PermissionClass, ttl_s: int, max_uses: int
) -> None:
    """§7.1: CONFIRM_ONCE = 1 use / 300 s; CONFIRM_EXACT = 1 use / 120 s."""
    assert CLASS_APPROVAL_TERMS[permission_class] == (ttl_s, max_uses)
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class=permission_class.value),
        environment=env_for(workspace, home),
        path_args=("path",),
        now=NOW,
    )
    record = decision.approval_record
    assert record is not None
    assert record.ttl_s == ttl_s
    assert record.max_uses == max_uses
    assert record.issued_at == NOW


def test_the_record_binds_the_same_action_hash_the_dispatcher_computed(
    workspace: Path, home: Path
) -> None:
    """§7.4: what the user approves and what would run must be one action."""
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class="CONFIRM_ONCE"),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    record = decision.approval_record
    assert record is not None
    proceed = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert proceed.normalized is not None
    assert record.action_hash == proceed.normalized.action_hash


def test_the_record_is_serializable_for_the_renderer(workspace: Path, home: Path) -> None:
    """§7.4: "Display = renderer input არის ეს record (არა მოდელის ტექსტი)"."""
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class="CONFIRM_EXACT"),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.approval_record is not None
    assert isinstance(decision.approval_record.canonical_json(), str)


# ==========================================================================
# 4. step 4 — token verification (I5/I6)
# ==========================================================================
def minted(
    workspace: Path, home: Path, permission_class: str
) -> tuple[ApprovalGrant, TokenService]:
    """Mint a grant for the record the dispatcher would build for this request.

    The MINTED record travels with the token: ``canonical_bytes()`` covers
    ``issued_at`` and ``token_id``, so verifying against a rebuilt record would
    only ever succeed in the exact second of minting.
    """
    service = TokenService(SECRET)
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class=permission_class),
        environment=env_for(workspace, home),
        path_args=("path",),
        now=NOW,
    )
    assert decision.approval_record is not None
    record = decision.approval_record
    return ApprovalGrant(record=record, token=service.mint(record)), service


def test_a_valid_token_proceeds(workspace: Path, home: Path) -> None:
    grant, service = minted(workspace, home, "CONFIRM_ONCE")
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class="CONFIRM_ONCE"),
        environment=env_for(workspace, home, token_service=service),
        path_args=("path",),
        grant=grant,
        now=NOW,
    )
    assert decision.decision is Decision.PROCEED
    assert decision.normalized is not None


def test_a_token_for_a_different_action_is_refused(workspace: Path, home: Path) -> None:
    """I6: the token binds THIS action; a different path is a different action."""
    grant, service = minted(workspace, home, "CONFIRM_ONCE")
    (workspace / "other.txt").write_text("x\n", encoding="utf-8")
    decision = dispatch(
        read_request(workspace / "other.txt"),
        manifest=make_manifest(permission_class="CONFIRM_ONCE"),
        environment=env_for(workspace, home, token_service=service),
        path_args=("path",),
        grant=grant,
        now=NOW,
    )
    assert decision.decision is Decision.NEEDS_APPROVAL, "a mismatched token re-prompts"
    assert decision.normalized is None


def test_an_expired_token_is_refused(workspace: Path, home: Path) -> None:
    grant, service = minted(workspace, home, "CONFIRM_EXACT")
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class="CONFIRM_EXACT"),
        environment=env_for(workspace, home, token_service=service),
        path_args=("path",),
        grant=grant,
        now=NOW + datetime.timedelta(seconds=121),
    )
    assert decision.decision is Decision.NEEDS_APPROVAL


def test_a_forged_token_is_refused(workspace: Path, home: Path) -> None:
    grant, service = minted(workspace, home, "CONFIRM_ONCE")
    forged = ApprovalGrant(
        record=grant.record,
        token=ApprovalToken(token_id=grant.record.token_id, value="00" * 32),
    )
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class="CONFIRM_ONCE"),
        environment=env_for(workspace, home, token_service=service),
        path_args=("path",),
        grant=forged,
        now=NOW,
    )
    assert decision.decision is Decision.NEEDS_APPROVAL


def test_a_token_cannot_unblock_a_denied_action(workspace: Path, home: Path) -> None:
    """DENY_ALWAYS is terminal: no token, valid or not, opens it (§7.1, §7.3)."""
    grant, service = minted(workspace, home, "CONFIRM_ONCE")
    forged = ApprovalGrant(record=grant.record, token=grant.token)
    decision = dispatch(
        read_request(home / ".ssh" / "id_rsa"),
        manifest=make_manifest(),
        environment=env_for(workspace, home, token_service=service),
        path_args=("path",),
        grant=forged,
        now=NOW,
    )
    assert decision.decision is Decision.BLOCKED


def test_a_token_on_an_auto_request_is_ignored_not_honoured(
    workspace: Path, home: Path
) -> None:
    """AUTO needs no token; presenting one must not change the routing."""
    grant, service = minted(workspace, home, "CONFIRM_ONCE")
    forged = ApprovalGrant(record=grant.record, token=grant.token)
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(),
        environment=env_for(workspace, home, token_service=service),
        path_args=("path",),
        grant=forged,
        now=NOW,
    )
    assert decision.decision is Decision.PROCEED


def test_a_token_without_a_service_cannot_proceed(workspace: Path, home: Path) -> None:
    """Fail-closed: no verifier means no verification, so no execution."""
    grant, _ = minted(workspace, home, "CONFIRM_ONCE")
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class="CONFIRM_ONCE"),
        environment=env_for(workspace, home),
        path_args=("path",),
        grant=grant,
        now=NOW,
    )
    assert decision.decision is Decision.NEEDS_APPROVAL


# ==========================================================================
# 5. structural properties of the decision itself
# ==========================================================================
@pytest.mark.parametrize(
    "permission_class",
    ["AUTO_READ", "AUTO_SCOPED_WRITE", "CONFIRM_ONCE", "CONFIRM_EXACT", "DENY_ALWAYS"],
)
def test_every_class_routes_somewhere(
    workspace: Path, home: Path, permission_class: str
) -> None:
    """Totality: no class may fall through to an undefined outcome."""
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class=permission_class),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.decision in set(Decision)


def test_only_proceed_carries_a_normalized_request(workspace: Path, home: Path) -> None:
    """The structural form of "nothing executes without a decision to execute"."""
    for permission_class in ("AUTO_READ", "CONFIRM_ONCE", "CONFIRM_EXACT", "DENY_ALWAYS"):
        decision = dispatch(
            read_request(workspace / "a.txt"),
            manifest=make_manifest(permission_class=permission_class),
            environment=env_for(workspace, home),
            path_args=("path",),
        )
        assert (decision.normalized is not None) == (decision.decision is Decision.PROCEED)


def test_a_blocked_decision_names_the_rule_for_section_44(
    workspace: Path, home: Path
) -> None:
    """§4.4 renders ``policy_blocked:<rule_id>``; the id has to come from here."""
    decision = dispatch(
        read_request(home / ".ssh" / "id_rsa"),
        manifest=make_manifest(),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.decision is Decision.BLOCKED
    assert decision.policy_rule_id
    from lsassist.contracts.enums import ExitReason

    assert ExitReason.POLICY_BLOCKED.render(decision.policy_rule_id).startswith("policy_blocked:")


def test_the_decision_is_immutable(workspace: Path, home: Path) -> None:
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    with pytest.raises((AttributeError, TypeError)):
        decision.decision = Decision.BLOCKED  # type: ignore[misc]


def test_an_approval_record_is_a_contracts_model_not_a_dict(
    workspace: Path, home: Path
) -> None:
    """I5: the HMAC binds ApprovalRecord.canonical_bytes(); anything else forks
    the serialization and reopens T-12."""
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class="CONFIRM_ONCE"),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert isinstance(decision.approval_record, ApprovalRecord)


def test_a_denied_action_has_no_rollback_hint() -> None:
    """Nothing was done, so there is nothing to undo — and offering a recovery
    path for a refused action would misdescribe what happened."""
    manifest = make_manifest(rollback="checkpoint")
    assert "not applicable" in rollback_hint(manifest, PermissionClass.DENY_ALWAYS)


# ==========================================================================
# 6. REGRESSION PINS — every defect the adversarial critic round reproduced
# ==========================================================================
def test_a_symlink_cannot_launder_a_deny_path(workspace: Path, home: Path) -> None:
    """CRITICAL, reproduced by four independent lenses.

    §6.3 orders step 2 (realpath, symlink-chain resolution) BEFORE step 3 so
    that policy judges the path that will actually be opened. The first draft
    classified the RAW request while handing the handler the RESOLVED path, so
    a symlink inside the workspace pointing at ``~/.ssh/id_rsa`` classified
    AUTO_READ and PROCEEDed — a complete bypass of a §7.3 refusal specified as
    absolute ("no approval can grant it").
    """
    (workspace / "notes.txt").symlink_to(home / ".ssh" / "id_rsa")
    decision = dispatch(
        read_request(workspace / "notes.txt"),
        manifest=make_manifest(),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.permission_class is PermissionClass.DENY_ALWAYS
    assert decision.decision is Decision.BLOCKED
    assert decision.normalized is None


def test_a_symlink_to_an_in_workspace_deny_path_is_also_caught(
    workspace: Path, home: Path
) -> None:
    """The stronger form: nothing outside the workspace is needed.

    ``<ws>/readme.md -> <ws>/.env`` is a symlink that can already exist in a
    cloned repository, so the attack needs no model action at all.
    """
    (workspace / ".env").write_text("SYNTHETIC=CANARY\n", encoding="utf-8")
    (workspace / "readme.md").symlink_to(workspace / ".env")
    decision = dispatch(
        read_request(workspace / "readme.md"),
        manifest=make_manifest(),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.permission_class is PermissionClass.DENY_ALWAYS


def test_a_symlinked_parent_cannot_launder_a_write_outside_the_workspace(
    workspace: Path, home: Path, tmp_path: Path
) -> None:
    """R2 clause B, defeated the same way: the symlink is on the PARENT."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "sub").symlink_to(outside, target_is_directory=True)
    decision = dispatch(
        ToolRequest(
            call_id="c1", tool="fs.write", args={"path": str(workspace / "sub" / "t.txt")}
        ),
        manifest=make_manifest(
            name="fs.write",
            permission_class="AUTO_SCOPED_WRITE",
            capabilities={"fs": "write_scoped", "net": "none", "proc": "none"},
            rollback="checkpoint",
        ),
        environment=env_for(workspace, home),
        path_args=("path",),
        create_if_missing=True,
    )
    assert decision.permission_class is PermissionClass.CONFIRM_EXACT
    assert decision.decision is Decision.NEEDS_APPROVAL


@pytest.mark.parametrize("elapsed_s", [0, 1, 60, 299])
def test_a_grant_verifies_at_every_instant_inside_its_ttl(
    workspace: Path, home: Path, elapsed_s: int
) -> None:
    """HIGH, reproduced: the first draft re-stamped ``issued_at`` on a REBUILT
    record, so the HMAC matched only in the exact second of minting — VALID at
    T0 and HMAC_MISMATCH at T0+1s. The §7.1 CONFIRM flow ("1 use, TTL 300 s")
    was unusable in production, and ``TokenVerdict.EXPIRED`` was unreachable
    because ``now - issued_at`` was always zero.
    """
    grant, service = minted(workspace, home, "CONFIRM_ONCE")
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class="CONFIRM_ONCE"),
        environment=env_for(workspace, home, token_service=service),
        path_args=("path",),
        grant=grant,
        now=NOW + datetime.timedelta(seconds=elapsed_s),
    )
    assert decision.decision is Decision.PROCEED, f"a live grant failed at +{elapsed_s}s"


def test_expiry_is_reached_by_time_not_by_hmac_mismatch(
    workspace: Path, home: Path
) -> None:
    """The counterweight to the test above: refusal past the TTL must come from
    the TTL. With a rebuilt record every late verification failed on the HMAC,
    so an "expired token is refused" test passed without the TTL ever running.
    """
    grant, service = minted(workspace, home, "CONFIRM_ONCE")
    late = NOW + datetime.timedelta(seconds=301)
    assert service.verify(grant.token, grant.record, late) is TokenVerdict.EXPIRED


def test_a_grant_minted_at_a_weaker_class_cannot_satisfy_a_raised_one(
    workspace: Path, home: Path
) -> None:
    """``machine._g_valid_token`` condition 3, mirrored: an untrusted turn that
    raises the class to CONFIRM_EXACT must not be satisfied by a CONFIRM_ONCE
    grant minted before the turn became untrusted."""
    grant, service = minted(workspace, home, "CONFIRM_ONCE")
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class="CONFIRM_ONCE"),
        environment=env_for(workspace, home, token_service=service, untrusted_turn=True),
        path_args=("path",),
        grant=grant,
        now=NOW,
    )
    assert decision.permission_class is PermissionClass.CONFIRM_EXACT
    assert decision.decision is Decision.NEEDS_APPROVAL


def test_the_denying_rule_is_named_not_merely_the_first_to_fire(
    workspace: Path, home: Path
) -> None:
    """MEDIUM, reproduced: ``proc.exec argv=["sudo","sh","-c","a && b"]`` fires
    R4 (metacharacters -> CONFIRM_EXACT) before R5 (sudo -> DENY_ALWAYS), so
    ``policy_blocked:R4`` named a rule that merely raised while the rule that
    REFUSED went unnamed."""
    decision = dispatch(
        ToolRequest(
            call_id="c1", tool="proc.exec", args={"argv": ["sudo", "sh", "-c", "a && b"]}
        ),
        manifest=exec_manifest(),
        environment=env_for(workspace, home),
        path_args=(),
    )
    assert decision.decision is Decision.BLOCKED
    assert decision.policy_rule_id == "R5"


def test_a_rule_that_raised_nothing_is_not_reported_as_having_raised(
    workspace: Path, home: Path
) -> None:
    """MEDIUM, reproduced: a rule proposing a class no stricter than the one
    already reached changes no outcome, so naming it in the record told the user
    "raised by R<n>" about a rule that did nothing."""
    from lsassist.contracts.policy_context import PolicyContext

    context = PolicyContext(workspace_root=str(workspace.resolve()), untrusted_turn=False)
    stores = env_for(workspace, home).stores
    request = ToolRequest(call_id="c1", tool="proc.exec", args={"argv": ["rm", "-rf", "x"]})
    fired = matched_rule_ids(
        request,
        context,
        stores,
        floor=PermissionClass.CONFIRM_EXACT,  # already at the class R5 proposes
        final_class=PermissionClass.CONFIRM_EXACT,
    )
    assert "R5" not in fired, "R5 proposes CONFIRM_EXACT, which is where the floor already is"


def test_r3_is_reported_only_when_it_actually_elevated(workspace: Path, home: Path) -> None:
    """MEDIUM, reproduced: R3 was appended on EVERY untrusted turn, including
    turns where the fold had already reached CONFIRM_EXACT and R3 changed
    nothing."""
    decision = dispatch(
        ToolRequest(call_id="c1", tool="proc.exec", args={"argv": ["rm", "-rf", "x"]}),
        manifest=exec_manifest(),
        environment=env_for(workspace, home, untrusted_turn=True),
        path_args=(),
    )
    assert decision.permission_class is PermissionClass.CONFIRM_EXACT
    assert "R3" not in decision.matched_rules, "R5 had already reached CONFIRM_EXACT"


def test_the_denying_rule_helper_falls_back_to_the_manifest_floor(
    workspace: Path, home: Path
) -> None:
    """A DENY that came straight from the manifest is R1, not a numbered rule."""
    from lsassist.contracts.policy_context import PolicyContext

    context = PolicyContext(workspace_root=str(workspace.resolve()), untrusted_turn=False)
    stores = env_for(workspace, home).stores
    request = read_request(workspace / "a.txt")
    assert denying_rule_id(request, context, stores) == "R1"


def test_a_manifest_floor_deny_is_attributed_to_r1(workspace: Path, home: Path) -> None:
    decision = dispatch(
        read_request(workspace / "a.txt"),
        manifest=make_manifest(permission_class="DENY_ALWAYS"),
        environment=env_for(workspace, home),
        path_args=("path",),
    )
    assert decision.decision is Decision.BLOCKED
    assert decision.policy_rule_id == "R1"


def test_an_unroutable_class_fails_closed(
    workspace: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unreachable while PermissionClass has exactly five members, all handled.

    Exercised directly by emptying the CONFIRM set, because the alternative to
    this guard is a fall-through that hands an unknown class to
    ``CLASS_APPROVAL_TERMS[...]`` and raises a ``KeyError`` out of a function
    documented not to. Kept and tested rather than deleted (T2.13: never close a
    branch by removing defensive code); never silenced with a pragma. If a sixth
    class is ever added, dispatch fails CLOSED and says which class it cannot
    route.
    """
    from lsassist.tools import dispatcher as module

    monkeypatch.setattr(module, "_CONFIRM_CLASSES", frozenset())
    with pytest.raises(module.DispatchError) as excinfo:
        dispatch(
            read_request(workspace / "a.txt"),
            manifest=make_manifest(permission_class="CONFIRM_ONCE"),
            environment=env_for(workspace, home),
            path_args=("path",),
        )
    assert "step-4 route" in str(excinfo.value)
