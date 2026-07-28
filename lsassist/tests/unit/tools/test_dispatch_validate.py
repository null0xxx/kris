"""T3.02 RED: dispatch steps 1-2 — schema validate, normalize (SPEC §6.3, I2).

§6.3 step 1: "Schema validate — ``jsonschema`` args vs ``input_schema``,
``additionalProperties:false`` ყველა tool-ზე. Fail → ``malformed_tool_request``
(model error, budget refund)."

§6.3 step 2: "Normalize/canonicalize — paths: ``realpath`` fail-closed (symlink
chain resolution, missing target → error unless ``create_if_missing`` tool and
parent canonicalizes in-scope); argv: list[str] verbatim, no interpolation;
env: allowlist projection."

**A WIRING BUG IS NOT A POLICY DECISION.** The kernel's N4 discipline (see
``machine.missing_measurements``) applies here too: a misconfigured dispatcher
raises :class:`DispatchError`, while a request the policy engine refuses returns
a BLOCKED decision. Collapsing the two would make "the operator wired this
wrong" indistinguishable from "the model asked for something forbidden", and the
runner would blame the model for an install error.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from lsassist.contracts.enums import PermissionClass
from lsassist.contracts.manifest import ToolManifest
from lsassist.contracts.tool_request import ToolRequest
from lsassist.policy.stores import PolicyStores
from lsassist.tools.dispatcher import (
    MALFORMED_TOOL_REQUEST,
    Decision,
    DispatchEnvironment,
    DispatchError,
    MalformedToolRequest,
    NormalizedRequest,
    dispatch,
    normalize,
    validate_args,
)

# --- fixtures ----------------------------------------------------------------


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


def stores_for(home: Path) -> PolicyStores:
    return PolicyStores(
        home=str(home),
        audit_store=str(home / ".local/state/lsassist/audit"),
        policy_store=str(home / ".config/lsassist"),
        kernel_secret=str(home / ".local/state/lsassist/kernel.secret"),
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "sub").mkdir(parents=True)
    (ws / "a.txt").write_text("hello\n", encoding="utf-8")
    (ws / "sub" / "b.txt").write_text("nested\n", encoding="utf-8")
    return ws


@pytest.fixture
def environment(tmp_path: Path, workspace: Path) -> DispatchEnvironment:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_rsa").write_text("SYNTHETIC CANARY DECOY\n", encoding="utf-8")
    return DispatchEnvironment(
        workspace_root=str(workspace),
        cwd=str(workspace),
        stores=stores_for(home),
        session_id="s-1",
    )


def request_for(path: str, tool: str = "fs.read") -> ToolRequest:
    return ToolRequest(call_id="c1", tool=tool, args={"path": path})


# ==========================================================================
# 1. step 1 — args validated against input_schema (I2)
# ==========================================================================
def test_valid_args_pass_through_unchanged() -> None:
    manifest = make_manifest()
    args = validate_args(manifest, ToolRequest(call_id="c1", tool="fs.read", args={"path": "/x"}))
    assert args == {"path": "/x"}


@pytest.mark.parametrize(
    ("args", "why"),
    [
        ({}, "required property missing"),
        ({"path": 42}, "wrong type"),
        ({"path": "/x", "extra": 1}, "additionalProperties: false"),
        ({"path": None}, "null is not a string"),
    ],
)
def test_invalid_args_are_rejected(args: dict[str, Any], why: str) -> None:
    manifest = make_manifest()
    with pytest.raises(DispatchError) as excinfo:
        validate_args(manifest, ToolRequest(call_id="c1", tool="fs.read", args=args))
    assert MALFORMED_TOOL_REQUEST in str(excinfo.value), why


def test_a_tool_schema_without_additional_properties_false_is_a_wiring_bug() -> None:
    """§6.3 step 1 says additionalProperties:false on EVERY tool.

    A schema that omits it accepts unknown keys, and an unknown key is an
    un-validated channel straight into a handler. Refused at dispatch rather
    than silently honoured — the registry cannot catch this, because §6.2 types
    ``input_schema`` as a free-form object.
    """
    manifest = make_manifest(
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}}
    )
    with pytest.raises(DispatchError) as excinfo:
        validate_args(manifest, request_for("/x"))
    assert "additionalProperties" in str(excinfo.value)


def test_a_non_object_input_schema_is_a_wiring_bug() -> None:
    manifest = make_manifest(input_schema={"type": "string"})
    with pytest.raises(DispatchError):
        validate_args(manifest, request_for("/x"))


def test_the_request_tool_must_match_the_manifest() -> None:
    """Dispatching one tool's args against another tool's schema is a wiring bug."""
    with pytest.raises(DispatchError) as excinfo:
        validate_args(make_manifest(), request_for("/x", tool="fs.write"))
    assert "fs.write" in str(excinfo.value)


def test_malformed_args_return_a_budget_refund_decision(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§6.3 step 1: the model produced garbage, so the tool-call budget is refunded."""
    decision = dispatch(
        ToolRequest(call_id="c1", tool="fs.read", args={"nope": 1}),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert decision.decision is Decision.BLOCKED
    assert decision.error is not None
    assert decision.error.kind == MALFORMED_TOOL_REQUEST
    assert decision.budget_refund is True


def test_a_policy_block_does_not_refund_budget(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """The refund marker is for MODEL error only; a policy refusal was a real call."""
    decision = dispatch(
        request_for(str(Path(environment.stores.home) / ".ssh" / "id_rsa")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert decision.decision is Decision.BLOCKED
    assert decision.budget_refund is False


# ==========================================================================
# 2. step 2 — path canonicalization, fail-closed (§7.5)
# ==========================================================================
def test_paths_are_canonicalized(environment: DispatchEnvironment, workspace: Path) -> None:
    normalized = normalize(
        request_for(str(workspace / "sub" / ".." / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert normalized.canonical_paths == (str(workspace.resolve() / "a.txt"),)


def test_a_symlinked_path_resolves_to_its_target(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§7.5 step 1: the symlink chain is RESOLVED, so policy sees the real path."""
    (workspace / "link.txt").symlink_to(workspace / "a.txt")
    normalized = normalize(
        request_for(str(workspace / "link.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert normalized.canonical_paths == (str(workspace.resolve() / "a.txt"),)


def test_a_dangling_target_is_refused(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§7.5 step 1: dangling → fail, unless the tool creates the target."""
    with pytest.raises(DispatchError):
        normalize(
            request_for(str(workspace / "nope.txt")),
            manifest=make_manifest(),
            environment=environment,
            path_args=("path",),
        )


def test_a_missing_target_is_allowed_for_a_creating_tool(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§6.3 step 2's ``create_if_missing`` carve-out, keyed off the manifest."""
    normalized = normalize(
        request_for(str(workspace / "new.txt"), tool="fs.write"),
        manifest=make_manifest(
            name="fs.write",
            permission_class="AUTO_SCOPED_WRITE",
            capabilities={"fs": "write_scoped", "net": "none", "proc": "none"},
            rollback="checkpoint",
        ),
        environment=environment,
        path_args=("path",),
        create_if_missing=True,
    )
    assert normalized.canonical_paths == (str(workspace.resolve() / "new.txt"),)


def test_the_workspace_root_is_canonicalized_before_policy_sees_it(
    tmp_path: Path, workspace: Path
) -> None:
    """HARDEN-02's recorded obligation.

    ``PolicyContext``'s validator was made PURE, so it no longer resolves the
    path — the dispatcher owns that I/O now. A caller handing over an
    un-resolved workspace_root must not be able to make §7.3's home-anchored
    DENY subtrees miss.
    """
    home = tmp_path / "home"
    home.mkdir()
    aliased = tmp_path / "alias"
    aliased.symlink_to(workspace, target_is_directory=True)

    environment = DispatchEnvironment(
        workspace_root=str(aliased),
        cwd=str(aliased),
        stores=stores_for(home),
        session_id="s-1",
    )
    normalized = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert normalized.workspace_root == str(workspace.resolve())
    assert normalized.cwd_real == str(workspace.resolve())


def test_a_leading_double_slash_is_collapsed(tmp_path: Path, workspace: Path) -> None:
    """HARDEN-02's second recorded obligation, pinned on the OBSERVABLE result.

    POSIX ``normpath`` preserves a leading ``//`` and §7.3's matcher splits on
    ``/``, so the two spellings of one directory must not classify differently.
    Measured: ``canonicalize`` resolves through ``realpath``, which collapses it
    (``normpath("//tmp") == "//tmp"`` but ``realpath("//tmp") == "/tmp"``), so
    the dispatcher needs no collapse of its own. This test pins the RESULT, not
    the mechanism — if canonicalization ever stops resolving, it goes red.
    """
    home = tmp_path / "home"
    home.mkdir()
    environment = DispatchEnvironment(
        workspace_root="/" + str(workspace.resolve()),
        cwd=str(workspace),
        stores=stores_for(home),
        session_id="s-1",
    )
    normalized = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert not normalized.workspace_root.startswith("//")
    assert normalized.workspace_root == str(workspace.resolve())


def test_a_tool_with_fs_capability_but_no_declared_path_args_is_a_wiring_bug(
    environment: DispatchEnvironment,
) -> None:
    """Fail-closed: an undeclared path arg would skip §7.5 entirely.

    The §6.2 manifest has no per-argument path declaration, so the caller
    supplies one. A tool that declares ``capabilities.fs != none`` and names no
    path argument would sail past canonicalization and reach a handler with a
    raw, un-resolved string — so it is refused rather than trusted.
    """
    with pytest.raises(DispatchError) as excinfo:
        normalize(
            request_for("/x"),
            manifest=make_manifest(),
            environment=environment,
            path_args=(),
        )
    assert "path_args" in str(excinfo.value)


def test_a_tool_with_no_fs_capability_needs_no_path_args(
    environment: DispatchEnvironment,
) -> None:
    normalized = normalize(
        ToolRequest(call_id="c1", tool="sys.info", args={"probe": "uname"}),
        manifest=make_manifest(
            name="sys.info",
            capabilities={"fs": "none", "net": "none", "proc": "spawn_argv"},
            input_schema={
                "type": "object",
                "required": ["probe"],
                "properties": {"probe": {"type": "string"}},
                "additionalProperties": False,
            },
        ),
        environment=environment,
        path_args=(),
    )
    assert normalized.canonical_paths == ()


def test_a_declared_path_arg_that_is_absent_from_args_is_skipped(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """Optional path arguments are legitimate; only PRESENT ones canonicalize."""
    manifest = make_manifest(
        input_schema={
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}, "into": {"type": "string"}},
            "additionalProperties": False,
        }
    )
    normalized = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=manifest,
        environment=environment,
        path_args=("path", "into"),
    )
    assert len(normalized.canonical_paths) == 1


def test_a_non_string_path_argument_is_refused(
    environment: DispatchEnvironment,
) -> None:
    manifest = make_manifest(
        input_schema={
            "type": "object",
            "required": ["path"],
            "properties": {"path": {}},
            "additionalProperties": False,
        }
    )
    with pytest.raises(DispatchError):
        normalize(
            ToolRequest(call_id="c1", tool="fs.read", args={"path": ["/x"]}),
            manifest=manifest,
            environment=environment,
            path_args=("path",),
        )


def test_canonical_paths_are_deterministic_and_deduplicated(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    manifest = make_manifest(
        input_schema={
            "type": "object",
            "required": ["path", "also"],
            "properties": {"path": {"type": "string"}, "also": {"type": "string"}},
            "additionalProperties": False,
        }
    )
    request = ToolRequest(
        call_id="c1",
        tool="fs.read",
        args={"path": str(workspace / "a.txt"), "also": str(workspace / "sub" / ".." / "a.txt")},
    )
    normalized = normalize(
        request, manifest=manifest, environment=environment, path_args=("also", "path")
    )
    assert normalized.canonical_paths == (str(workspace.resolve() / "a.txt"),)


# ==========================================================================
# 3. step 2 — argv is VERBATIM (no interpolation, §7.5 rule 8)
# ==========================================================================
def exec_manifest(**overrides: Any) -> ToolManifest:
    defaults: dict[str, Any] = {
        "name": "proc.exec",
        "permission_class": "CONFIRM_ONCE",
        "capabilities": {"fs": "none", "net": "none", "proc": "spawn_argv"},
        "input_schema": {
            "type": "object",
            "required": ["argv"],
            "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
            "additionalProperties": False,
        },
    }
    defaults.update(overrides)
    return make_manifest(**defaults)


def test_argv_is_carried_verbatim(environment: DispatchEnvironment) -> None:
    """No interpolation, no shell: what the model wrote is what runs (§7.5 rule 8)."""
    argv = ["pytest", "-q", "tests/", "$HOME", "`id`", "a;b"]
    normalized = normalize(
        ToolRequest(call_id="c1", tool="proc.exec", args={"argv": list(argv)}),
        manifest=exec_manifest(),
        environment=environment,
        path_args=(),
    )
    assert normalized.argv == tuple(argv)
    assert normalized.args["argv"] == argv


def test_an_empty_argv_is_refused(environment: DispatchEnvironment) -> None:
    with pytest.raises(DispatchError):
        normalize(
            ToolRequest(call_id="c1", tool="proc.exec", args={"argv": []}),
            manifest=exec_manifest(),
            environment=environment,
            path_args=(),
        )


def test_a_spawn_tool_may_legitimately_take_no_argv(environment: DispatchEnvironment) -> None:
    """§6.4's fixed-argv tools take a SELECTOR; the handler assembles the argv.

    ``sys.info``, ``pkg.query`` and ``git.read`` all declare proc=spawn_argv and
    none of them receives an argv from the model — that is exactly what makes
    them safe. Requiring one here would reject four of the twelve V1 tools.
    """
    manifest = exec_manifest(
        name="sys.info",
        permission_class="AUTO_READ",
        input_schema={
            "type": "object",
            "required": ["probe"],
            "properties": {"probe": {"type": "string"}},
            "additionalProperties": False,
        },
    )
    normalized = normalize(
        ToolRequest(call_id="c1", tool="sys.info", args={"probe": "uname"}),
        manifest=manifest,
        environment=environment,
        path_args=(),
    )
    assert normalized.argv is None


@pytest.mark.parametrize("argv", [[], "ls", ["ls", 1], {"0": "ls"}])
def test_a_malformed_argv_is_refused(environment: DispatchEnvironment, argv: object) -> None:
    """What IS supplied must be a non-empty list of strings, verbatim."""
    manifest = exec_manifest(
        input_schema={
            "type": "object",
            "required": ["argv"],
            "properties": {"argv": {}},
            "additionalProperties": False,
        }
    )
    with pytest.raises(DispatchError):
        normalize(
            ToolRequest(call_id="c1", tool="proc.exec", args={"argv": argv}),
            manifest=manifest,
            environment=environment,
            path_args=(),
        )


def test_a_non_spawn_tool_has_no_argv(environment: DispatchEnvironment, workspace: Path) -> None:
    normalized = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert normalized.argv is None


# ==========================================================================
# 4. step 2 — env is an allowlist PROJECTION, never an inheritance
# ==========================================================================
def test_env_is_projected_from_scratch(
    environment: DispatchEnvironment, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§8.3: the child env is built, not filtered. A parent secret cannot survive."""
    monkeypatch.setenv("LSASSIST_KIMI_API_KEY", "sk-CANARYshouldNEVERappear000000000000")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")

    normalized = normalize(
        request_for(str(Path(environment.workspace_root) / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert set(normalized.env) <= {"PATH", "HOME", "LANG", "PWD", "LC_ALL", "TERM"}
    assert "LSASSIST_KIMI_API_KEY" not in normalized.env
    assert "SSH_AUTH_SOCK" not in normalized.env
    assert not any("CANARY" in value for value in normalized.env.values())


def test_env_digest_is_bound_to_the_projection(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    normalized = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert normalized.env_digest.startswith("sha256:")


def test_a_rejected_env_addition_is_a_wiring_bug(tmp_path: Path, workspace: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    environment = DispatchEnvironment(
        workspace_root=str(workspace),
        cwd=str(workspace),
        stores=stores_for(home),
        session_id="s-1",
        env_extra={"LSASSIST_KIMI_API_KEY": "sk-nope"},
    )
    with pytest.raises(DispatchError):
        normalize(
            request_for(str(workspace / "a.txt")),
            manifest=make_manifest(),
            environment=environment,
            path_args=("path",),
        )


# ==========================================================================
# 5. the action hash binds everything the approval will be checked against
# ==========================================================================
def test_action_hash_covers_tool_args_paths_cwd_and_env(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§7.4: action_hash = sha256(tool + args + paths + cwd + env)."""
    baseline = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    other = normalize(
        request_for(str(workspace / "sub" / "b.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert baseline.action_hash.startswith("sha256:")
    assert baseline.action_hash != other.action_hash


def test_the_same_request_hashes_identically(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    first = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    second = normalize(
        request_for(str(workspace / "sub" / ".." / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert first.action_hash == second.action_hash, "canonicalization must be spelling-invariant"


# ==========================================================================
# 6. the handler contract (§6.1): validated args + execution context ONLY
# ==========================================================================
def test_the_normalized_request_carries_no_llm_context(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """§6.1: "Handler-ები არ ღებულობენ LLM context-ს".

    Enforced structurally: NormalizedRequest's field set is closed and contains
    no message, prompt, transcript or reasoning channel — so there is nowhere
    for model text to ride along into a handler.
    """
    normalized = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    fields = set(NormalizedRequest.__dataclass_fields__)
    assert fields == {
        "tool",
        "args",
        "canonical_paths",
        "workspace_root",
        "cwd_real",
        "env",
        "env_digest",
        "action_hash",
        "argv",
    }
    for forbidden in ("messages", "prompt", "context", "transcript", "reasoning", "system"):
        assert forbidden not in fields
    assert normalized.tool == "fs.read"


def test_the_normalized_request_is_immutable(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    normalized = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    with pytest.raises((AttributeError, TypeError)):
        normalized.tool = "proc.exec"  # type: ignore[misc]
    with pytest.raises(TypeError):
        normalized.args["path"] = "/etc/shadow"  # type: ignore[index]


def test_permission_class_is_never_lowered_below_the_manifest(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """R1: the manifest class is a CEILING that rules may only raise."""
    decision = dispatch(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(permission_class="CONFIRM_EXACT"),
        environment=environment,
        path_args=("path",),
    )
    assert decision.permission_class is PermissionClass.CONFIRM_EXACT


def test_os_environ_is_not_read_for_the_child(
    environment: DispatchEnvironment, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Belt and braces over the projection test: PATH/HOME come from §8.1
    defaults or explicit parameters, never from the ambient process."""
    monkeypatch.setenv("PATH", "/attacker/bin")
    monkeypatch.setenv("HOME", "/attacker/home")
    normalized = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert normalized.env.get("PATH") != "/attacker/bin"
    assert normalized.env.get("HOME") != "/attacker/home"
    assert os.environ["PATH"] == "/attacker/bin", "the test's own premise"


# ==========================================================================
# 7. the defensive arms — reached on purpose, never left unexercised
# ==========================================================================
def test_an_unusable_input_schema_is_reported_as_a_wiring_bug() -> None:
    """A schema that the metaschema itself rejects must not become permissive."""
    manifest = make_manifest(
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "properties": {"path": {"type": "not-a-json-schema-type"}},
        }
    )
    with pytest.raises(DispatchError) as excinfo:
        validate_args(manifest, request_for("/x"))
    assert "not a valid schema" in str(excinfo.value)


def test_an_unresolvable_workspace_root_is_a_wiring_bug(tmp_path: Path, workspace: Path) -> None:
    """The workspace root is canonicalized fail-closed, exactly like an arg path."""
    home = tmp_path / "home"
    home.mkdir()
    environment = DispatchEnvironment(
        workspace_root=str(tmp_path / "does-not-exist"),
        cwd=str(workspace),
        stores=stores_for(home),
        session_id="s-1",
    )
    with pytest.raises(DispatchError) as excinfo:
        normalize(
            request_for(str(workspace / "a.txt")),
            manifest=make_manifest(),
            environment=environment,
            path_args=("path",),
        )
    assert "workspace_root" in str(excinfo.value)


def test_an_unresolvable_cwd_is_a_wiring_bug(tmp_path: Path, workspace: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    environment = DispatchEnvironment(
        workspace_root=str(workspace),
        cwd=str(tmp_path / "gone"),
        stores=stores_for(home),
        session_id="s-1",
    )
    with pytest.raises(DispatchError) as excinfo:
        normalize(
            request_for(str(workspace / "a.txt")),
            manifest=make_manifest(),
            environment=environment,
            path_args=("path",),
        )
    assert "cwd" in str(excinfo.value)


def test_a_wiring_bug_is_never_converted_into_a_budget_refund(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """``dispatch`` catches ONLY the model's schema violation.

    Every other ``DispatchError`` propagates, so an operator's misconfiguration
    can never be reported as "the model sent bad arguments" — the N4 line the
    kernel draws between a WIRING stall and a decision.
    """
    with pytest.raises(DispatchError) as excinfo:
        dispatch(
            request_for(str(workspace / "a.txt")),
            manifest=make_manifest(),
            environment=environment,
            path_args=(),  # fs tool with no declared path args
        )
    assert MALFORMED_TOOL_REQUEST not in str(excinfo.value)


# ==========================================================================
# 8. REGRESSION PINS — defects the adversarial critic round reproduced
# ==========================================================================
def test_the_model_cannot_disguise_a_wiring_bug_as_its_own_error(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """MEDIUM, reproduced: the split was ``if MALFORMED_TOOL_REQUEST not in
    str(exc)``, and the model controls part of that string because a path
    argument is echoed into the jsonschema diagnostic. A request naming
    ``/ws/malformed_tool_request.txt`` could have a WIRING failure reported as a
    model error, complete with a budget refund. A distinct EXCEPTION TYPE now
    does the dispatching, so nothing the model writes can pick the branch."""
    # The vector has to be a wiring-class failure whose MESSAGE carries the magic
    # substring, and only a path-bearing one does: a request for a NON-EXISTENT
    # file named `malformed_tool_request.txt` raises
    #   "path argument 'path' does not canonicalize: dangling/missing path
    #    component: '<ws>/malformed_tool_request.txt'"
    # (verified). Under the old substring test that propagating error was
    # swallowed into a BLOCKED decision with budget_refund=True.
    absent = workspace / "malformed_tool_request.txt"
    assert not absent.exists()
    with pytest.raises(DispatchError) as excinfo:
        dispatch(
            request_for(str(absent)),
            manifest=make_manifest(),
            environment=environment,
            path_args=("path",),
        )
    assert MALFORMED_TOOL_REQUEST in str(excinfo.value), "the vector's premise"
    assert not isinstance(excinfo.value, MalformedToolRequest), (
        "a wiring failure must PROPAGATE, whatever the model wrote into its message"
    )


def test_the_error_message_never_echoes_the_argument_value(
    environment: DispatchEnvironment,
) -> None:
    """HIGH, reproduced: ``jsonschema``'s message embeds the offending INSTANCE
    verbatim, and the instance is model-supplied — a secret passed as an
    argument landed in ``ToolError.message_redacted``, a field whose name
    promises the opposite (I8, §12.4)."""
    secret = "sk-CANARYshouldNEVERbeEchoed0000000000"
    # A TYPE failure on the property itself: this is the shape where jsonschema
    # renders "<instance> is not of type 'string'", i.e. the one that actually
    # embeds the model-supplied value. An additionalProperties failure names only
    # the KEY, so testing with that shape would pass even unfixed.
    manifest = make_manifest(
        input_schema={
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "integer"}},
            "additionalProperties": False,
        }
    )
    decision = dispatch(
        ToolRequest(call_id="c1", tool="fs.read", args={"path": secret}),
        manifest=manifest,
        environment=environment,
        path_args=("path",),
    )
    assert decision.error is not None
    assert decision.error.kind == MALFORMED_TOOL_REQUEST
    assert secret not in decision.error.message_redacted
    assert "CANARY" not in decision.error.message_redacted


def test_a_mistyped_path_arg_is_refused_not_silently_ignored(
    environment: DispatchEnvironment,
) -> None:
    """MEDIUM, reproduced: the guard only checked that ``path_args`` was
    non-empty, so a typo satisfied it while canonicalizing nothing — §7.5 became
    a no-op for a tool that looked correctly wired."""
    with pytest.raises(DispatchError) as excinfo:
        normalize(
            request_for("/x"),
            manifest=make_manifest(),
            environment=environment,
            path_args=("paht",),
        )
    assert "paht" in str(excinfo.value)


def test_create_if_missing_is_refused_for_a_tool_that_creates_nothing(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """MEDIUM: waiving §7.5's dangling-target check for a READ tool weakens it
    for a tool that never creates a target."""
    with pytest.raises(DispatchError) as excinfo:
        normalize(
            request_for(str(workspace / "nope.txt")),
            manifest=make_manifest(),  # fs=read_scoped
            environment=environment,
            path_args=("path",),
            create_if_missing=True,
        )
    assert "write_scoped" in str(excinfo.value)


def test_the_bound_env_is_the_one_the_sandbox_will_build(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """HIGH, reproduced: the digest bound ``HOME=<the real home>``, an
    environment no child ever gets — §8.1 gives the sandbox its own HOME. The
    user would approve an env digest describing something that never runs."""
    from lsassist.sandbox.env import DEFAULT_HOME, DEFAULT_PATH

    normalized = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert normalized.env["HOME"] == DEFAULT_HOME
    assert normalized.env["HOME"] != environment.stores.home
    assert normalized.env["PATH"] == DEFAULT_PATH


def test_the_bound_path_rule_matches_what_build_argv_would_emit() -> None:
    """§8.2 lets a workspace ``.venv/bin`` outrank system tools, and the approval
    binds a NAME (§7.4) — so the digest has to describe THAT PATH. The rule is
    pinned against ``sandbox.profiles.build_argv``'s own output, so the two
    encodings of §8.2 cannot drift (recorded obligation 3).

    Compared on a synthetic root rather than ``tmp_path``: ``build_argv`` refuses
    a workspace under ``/tmp`` because the profile masks it with a tmpfs, and
    the PATH rule under test is pure string work either way.
    """
    from lsassist.contracts.sandbox_profile import Profile
    from lsassist.sandbox.profiles import build_argv
    from lsassist.tools.dispatcher import _child_path

    root = "/srv/ws"
    for venv_exists in (False, True):
        argv = build_argv(
            profile=Profile.WS,
            workspace=root,
            cwd=root,
            cache_dir="/srv/cache",
            argv=["true"],
            venv_exists=venv_exists,
        )
        sandbox_path = argv[argv.index("PATH") + 1]
        assert _child_path(root, venv_exists=venv_exists) == sandbox_path
    assert _child_path(root, venv_exists=True).startswith(f"{root}/.venv/bin:")


def test_normalize_binds_the_venv_path_when_one_exists(
    tmp_path: Path, workspace: Path
) -> None:
    """The rule above, actually applied by the dispatcher."""
    home = tmp_path / "home"
    home.mkdir()
    environment = DispatchEnvironment(
        workspace_root=str(workspace),
        cwd=str(workspace),
        stores=stores_for(home),
        session_id="s-1",
        venv_exists=True,
    )
    normalized = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert normalized.env["PATH"].startswith(f"{workspace.resolve()}/.venv/bin:")


def test_pwd_is_not_written_past_the_env_allowlist(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """MEDIUM, reproduced: ``env["PWD"] = cwd_real`` wrote a key straight past
    the closed §8.3 allowlist that ``project_env`` exists to enforce. PWD is the
    sandbox profile builder's to set, from ``--chdir``."""
    from lsassist.sandbox.env import ENV_ALLOWLIST, TOOL_ENV_ALLOWLIST

    normalized = normalize(
        request_for(str(workspace / "a.txt")),
        manifest=make_manifest(),
        environment=environment,
        path_args=("path",),
    )
    assert set(normalized.env) <= ENV_ALLOWLIST | TOOL_ENV_ALLOWLIST
    assert "PWD" not in normalized.env


def test_the_normalized_args_do_not_alias_the_callers_structures(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """MEDIUM, reproduced: a shallow copy left the "frozen" NormalizedRequest
    sharing the caller's nested mutable structures, so a later mutation could
    change what the action_hash was supposed to have bound."""
    nested = [str(workspace / "a.txt")]
    manifest = make_manifest(
        input_schema={
            "type": "object",
            "required": ["path", "roots"],
            "properties": {
                "path": {"type": "string"},
                "roots": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": False,
        }
    )
    request = ToolRequest(
        call_id="c1",
        tool="fs.read",
        args={"path": str(workspace / "a.txt"), "roots": nested},
    )
    normalized = normalize(
        request, manifest=manifest, environment=environment, path_args=("path",)
    )
    nested.append("/etc/shadow")
    assert normalized.args["roots"] == [str(workspace / "a.txt")]
