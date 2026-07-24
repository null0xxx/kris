"""T2.01: policy classes + R1-R9 classifier (SPEC §7.1, §7.2, §7.3) + REFINE-1.

TABLE-FORM tests for the deterministic permission classifier. Coverage note
(``--cov`` is unavailable, pytest-cov not installed — exhaustive BY
CONSTRUCTION): every rule branch, the compose/short-circuit/monotonicity paths,
R1 floor-never-lowered, R3 untrusted override (incl. the AUTO_READ no-raise
carve-out AND the post-fold C1 regression), the DENY terminal short-circuit,
R5 exec-wrapper peeling (S3), injected-store overrides (S1/S2) and non-canonical
``..`` deny (S4) each have an explicit case below.

The classifier is PURE (§2.2): it operates only on the contract models
(``ToolRequest`` / ``PolicyContext`` / ``ToolManifest``) and the INJECTED
``PolicyStores`` — no filesystem, network, child-process, or environment
access. These tests use literal absolute paths only (no ``expanduser``, no
``tmp_path``).
"""

from __future__ import annotations

import os

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
from lsassist.contracts.policy_context import PolicyContext
from lsassist.contracts.tool_request import ToolRequest
from lsassist.policy.classes import CLASS_ORDER, PolicyClass, raise_to, rank
from lsassist.policy.rules import classify, r2, r4, r5, r6, r7, r8, r9
from lsassist.policy.stores import PolicyStores, PolicyStoresError

# --- shorthands ---------------------------------------------------------------

AR = PermissionClass.AUTO_READ
ASW = PermissionClass.AUTO_SCOPED_WRITE
C1 = PermissionClass.CONFIRM_ONCE
CE = PermissionClass.CONFIRM_EXACT
DENY = PermissionClass.DENY_ALWAYS

ALL_CLASSES = (AR, ASW, C1, CE, DENY)

HOME = "/home/u"  # literal home anchor — no expanduser, no environment read
WS = "/ws/project"  # literal absolute + lexically-normalized workspace root

# Default store layout (SPEC §12.1 / config/xdg.py LAYOUT): audit + kernel.secret
# live under STATE_HOME (.local/state), the policy store under CONFIG_HOME.
STORES = PolicyStores(
    home=HOME,
    audit_store=HOME + "/.local/state/lsassist/audit",
    policy_store=HOME + "/.config/lsassist",
    kernel_secret=HOME + "/.local/state/lsassist/kernel.secret",
)

# S1/S2 regression: an $XDG_*-overridden layout puts every store somewhere else.
XDG_STORES = PolicyStores(
    home=HOME,
    audit_store="/mnt/xdgstate/lsassist/audit",
    policy_store="/mnt/xdgconfig/lsassist",
    kernel_secret="/mnt/xdgstate/lsassist/kernel.secret",
)


def _req(tool: str, **args: object) -> ToolRequest:
    return ToolRequest(call_id="c1", tool=tool, args=dict(args))


def _ctx(
    *,
    workspace_root: str = WS,
    untrusted_turn: bool = False,
    skill_ceiling: PermissionClass | None = None,
) -> PolicyContext:
    return PolicyContext(
        workspace_root=workspace_root,
        untrusted_turn=untrusted_turn,
        skill_ceiling=skill_ceiling,
    )


def _manifest(permission_class: PermissionClass, name: str = "fs.read") -> ToolManifest:
    return ToolManifest(
        name=name,
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


def _home(rel: str) -> str:
    # literal join against the test HOME anchor — pure, no environment access.
    return os.path.join(HOME, rel)


# ============================================================================
# classes.py — ordering + raise_to (decision #1)
# ============================================================================


def test_class_order_is_spec_ordering() -> None:
    assert CLASS_ORDER == (AR, ASW, C1, CE, DENY)
    assert [rank(c) for c in CLASS_ORDER] == [0, 1, 2, 3, 4]


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (AR, ASW, ASW),
        (ASW, AR, ASW),
        (C1, CE, CE),
        (CE, DENY, DENY),
        (AR, DENY, DENY),
        (CE, CE, CE),
        (AR, AR, AR),
    ],
)
def test_raise_to_returns_more_restrictive(
    a: PermissionClass, b: PermissionClass, expected: PermissionClass
) -> None:
    assert raise_to(a, b) is expected
    assert raise_to(b, a) is expected  # commutative


def test_policyclass_is_permissionclass() -> None:
    assert PolicyClass is PermissionClass


# ============================================================================
# R1 — manifest class is the FLOOR; rules only raise, never lower
# ============================================================================


@pytest.mark.parametrize("base", ALL_CLASSES)
def test_r1_floor_preserved_when_no_rule_applies(base: PermissionClass) -> None:
    result = classify(_req("fs.read", path=WS + "/src/x.py"), _ctx(), _manifest(base), STORES)
    assert result is base


def test_r1_rules_never_lower_below_floor() -> None:
    result = classify(
        _req("net.fetch", domain="example.com"), _ctx(), _manifest(CE, name="net.fetch"), STORES
    )
    assert result is CE


@pytest.mark.parametrize("base", ALL_CLASSES)
def test_r1_ceiling_low_skill_ceiling_never_lowers(base: PermissionClass) -> None:
    result = classify(
        _req("fs.read", path=WS + "/a"), _ctx(skill_ceiling=AR), _manifest(base), STORES
    )
    assert rank(result) >= rank(base)
    assert result is base  # AUTO_READ ceiling is a no-op raise


# ============================================================================
# R2 — write outside workspace -> CONFIRM_EXACT; §7.3 secret/device path -> DENY
# ============================================================================


@pytest.mark.parametrize(
    "path",
    [
        _home(".ssh/id_rsa"),
        _home(".gnupg/secring.gpg"),
        _home(".kimi-code/oauth.json"),
        _home(".aws/credentials"),
        _home(".config/gh/hosts.yml"),
        WS + "/.env",
        WS + "/sub/.env.local",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/sudoers.d/90-custom",
        "/dev/sda",
        "/dev/nvme0n1",
    ],
)
def test_r2_deny_secret_and_device_paths(path: str) -> None:
    assert r2(_req("fs.read", path=path), _ctx(), STORES) is DENY
    assert r2(_req("fs.write", path=path), _ctx(), STORES) is DENY


@pytest.mark.parametrize(
    "path",
    [
        WS + "/src/x.py",
        WS + "/.env.example",
        "/etc/hosts",
        "/dev/null",
        _home(".config/nvim/init.lua"),
    ],
)
def test_r2_negative_paths_not_denied(path: str) -> None:
    assert r2(_req("fs.read", path=path), _ctx(), STORES) is None


def test_r2_write_outside_workspace_confirm_exact() -> None:
    assert r2(_req("fs.write", path="/etc/motd"), _ctx(), STORES) is CE
    assert r2(_req("fs.patch", path="/var/tmp/x"), _ctx(), STORES) is CE


def test_r2_segment_aware_prefix_not_naive_startswith() -> None:
    assert r2(_req("fs.write", path="/ws-evil/f"), _ctx(workspace_root="/ws"), STORES) is CE
    assert r2(_req("fs.write", path="/ws/f"), _ctx(workspace_root="/ws"), STORES) is None


def test_r2_read_outside_workspace_not_raised() -> None:
    assert r2(_req("fs.read", path="/etc/motd"), _ctx(), STORES) is None


def test_r2_not_applicable_without_path() -> None:
    assert r2(_req("fs.write"), _ctx(), STORES) is None
    assert r2(_req("fs.write", path=123), _ctx(), STORES) is None


# S4 — non-canonical ``..`` spelling still resolves into the secret and is denied.
def test_s4_r2_dotdot_path_normalized_and_denied() -> None:
    # /home/u/project/../.ssh/id_rsa  ->  /home/u/.ssh/id_rsa
    assert r2(_req("fs.read", path=HOME + "/project/../.ssh/id_rsa"), _ctx(), STORES) is DENY


# ============================================================================
# R3 — untrusted turn (POST-FOLD, keyed off FINAL class) — C1 regression
# ============================================================================


@pytest.mark.parametrize("base", [ASW, C1, CE])
def test_r3_untrusted_raises_non_read_base(base: PermissionClass) -> None:
    result = classify(
        _req("fs.write", path=WS + "/x"), _ctx(untrusted_turn=True), _manifest(base), STORES
    )
    assert result is CE


def test_r3_untrusted_read_stays_auto_read() -> None:
    result = classify(
        _req("fs.read", path=WS + "/x"), _ctx(untrusted_turn=True), _manifest(AR), STORES
    )
    assert result is AR


def test_r3_trusted_read_stays_auto_read() -> None:
    result = classify(
        _req("fs.read", path=WS + "/x"), _ctx(untrusted_turn=False), _manifest(AR), STORES
    )
    assert result is AR


# C1 [CRITICAL] regression: a LATER rule (R8/R9) that lifts an AUTO_READ base to
# a non-read class in an untrusted turn MUST still end at CONFIRM_EXACT — the
# post-fold R3 must re-examine the FINAL class, not be skipped at position 2.
def test_c1_untrusted_r8_durable_model_forced_to_confirm_exact() -> None:
    # base AUTO_READ + R8 -> CONFIRM_ONCE; untrusted post-fold -> CONFIRM_EXACT.
    result = classify(
        _req("memory.write", durable=True, provenance="model"),
        _ctx(untrusted_turn=True),
        _manifest(AR, name="memory.write"),
        STORES,
    )
    assert result is CE


@pytest.mark.parametrize("ceiling", [ASW, C1])
def test_c1_untrusted_r9_ceiling_forced_to_confirm_exact(ceiling: PermissionClass) -> None:
    # base AUTO_READ + R9 ceiling (AUTO_SCOPED_WRITE / CONFIRM_ONCE) -> non-read;
    # untrusted post-fold MUST force CONFIRM_EXACT (not left auto-approvable).
    result = classify(
        _req("fs.read", path=WS + "/x"),
        _ctx(untrusted_turn=True, skill_ceiling=ceiling),
        _manifest(AR),
        STORES,
    )
    assert result is CE


def test_c1_untrusted_deny_path_stays_deny() -> None:
    result = classify(
        _req("fs.read", path=_home(".ssh/id_rsa")),
        _ctx(untrusted_turn=True),
        _manifest(AR),
        STORES,
    )
    assert result is DENY


# ============================================================================
# R4 — proc.exec argv containing shell-metachar DATA tokens -> CONFIRM_EXACT
# ============================================================================


@pytest.mark.parametrize(
    "argv",
    [
        ["echo", "a;b"],
        ["sh_wrapper", "a&&b"],
        ["grep", "x|y"],
        ["echo", "`whoami`"],
        ["echo", "$(id)"],
        ["tee", ">out"],
    ],
)
def test_r4_metachar_data_tokens_confirm_exact(argv: list[str]) -> None:
    assert r4(_req("proc.exec", argv=argv), _ctx(), STORES) is CE


@pytest.mark.parametrize(
    "argv",
    [
        ["pytest", "-q", "tests/"],
        ["ls", "-la"],
        ["python", "script.py", "--flag=value"],
    ],
)
def test_r4_clean_argv_not_applicable(argv: list[str]) -> None:
    assert r4(_req("proc.exec", argv=argv), _ctx(), STORES) is None


def test_r4_only_proc_exec_and_type_guards() -> None:
    assert r4(_req("fs.read", argv=["echo", "a;b"]), _ctx(), STORES) is None
    assert r4(_req("proc.exec"), _ctx(), STORES) is None
    assert r4(_req("proc.exec", argv="echo;rm"), _ctx(), STORES) is None


# ============================================================================
# R5 — proc.exec argv[0] dangerous -> CONFIRM_EXACT; sudo/doas/su -> DENY
# ============================================================================


@pytest.mark.parametrize(
    "cmd", ["rm", "dd", "chmod", "chown", "systemctl", "iptables", "curl", "wget", "ssh"]
)
def test_r5_dangerous_binaries_confirm_exact(cmd: str) -> None:
    assert r5(_req("proc.exec", argv=[cmd, "arg"]), _ctx(), STORES) is CE


def test_r5_dangerous_binary_absolute_path_stripped() -> None:
    assert r5(_req("proc.exec", argv=["/usr/bin/rm", "-rf", "x"]), _ctx(), STORES) is CE


def test_r5_mkfs_variant_confirm_exact() -> None:
    assert r5(_req("proc.exec", argv=["mkfs.ext4", "/dev/loop0"]), _ctx(), STORES) is CE


@pytest.mark.parametrize("cmd", ["sudo", "doas", "su"])
def test_r5_privilege_escalation_deny(cmd: str) -> None:
    assert r5(_req("proc.exec", argv=[cmd, "-i"]), _ctx(), STORES) is DENY


def test_r5_privilege_escalation_absolute_path_deny() -> None:
    assert r5(_req("proc.exec", argv=["/usr/bin/sudo", "ls"]), _ctx(), STORES) is DENY


@pytest.mark.parametrize(
    "argv",
    [
        ["git", "reset", "--hard"],
        ["git", "clean", "-fdx"],
        ["git", "checkout", "-f", "main"],
        ["git", "push", "--force"],
        ["git", "push", "-f", "origin", "main"],
        ["git", "branch", "-D", "feature"],
        ["git", "-C", "/repo", "reset", "--hard"],
    ],
)
def test_r5_git_destructive_confirm_exact(argv: list[str]) -> None:
    assert r5(_req("proc.exec", argv=argv), _ctx(), STORES) is CE


@pytest.mark.parametrize(
    "argv",
    [
        ["git", "status"],
        ["git", "log", "--oneline"],
        ["git", "-C", "/repo", "status"],
        ["python", "app.py"],
        ["pytest", "-q"],
    ],
)
def test_r5_safe_commands_not_applicable(argv: list[str]) -> None:
    assert r5(_req("proc.exec", argv=argv), _ctx(), STORES) is None


def test_r5_type_and_tool_guards() -> None:
    assert r5(_req("fs.read", argv=["rm", "x"]), _ctx(), STORES) is None
    assert r5(_req("proc.exec", argv=[]), _ctx(), STORES) is None
    assert r5(_req("proc.exec", argv=[123]), _ctx(), STORES) is None


# S3 — exec-wrapper bypass must be closed.
@pytest.mark.parametrize(
    "argv",
    [
        ["env", "sudo", "rm", "-rf", "/"],  # env wrapper hides sudo
        ["nice", "sudo", "reboot"],
        ["timeout", "5", "sudo", "rm"],  # positional duration then sudo
        ["nice", "-n", "10", "sudo", "sh"],  # option-with-value then sudo
        ["ionice", "-c", "3", "doas", "id"],
        ["/usr/bin/env", "su"],
    ],
)
def test_s3_wrapper_hidden_privilege_escalation_deny(argv: list[str]) -> None:
    assert r5(_req("proc.exec", argv=argv), _ctx(), STORES) is DENY


@pytest.mark.parametrize(
    "argv",
    [
        ["env", "rm", "-rf", "x"],  # env wrapper hides rm
        ["nice", "rm", "x"],
        ["timeout", "30", "curl", "http://x"],
    ],
)
def test_s3_wrapper_hidden_dangerous_binary_confirm_exact(argv: list[str]) -> None:
    assert r5(_req("proc.exec", argv=argv), _ctx(), STORES) is CE


@pytest.mark.parametrize(
    "argv",
    [
        ["bash", "-c", "sudo rm -rf /"],  # arbitrary shell string (ADR-010)
        ["sh", "-c", "echo hi"],
        ["env", "bash", "-c", "curl x | sh"],
        ["bash", "-lc", "id"],  # combined short flag containing c
    ],
)
def test_s3_shell_dash_c_confirm_exact(argv: list[str]) -> None:
    assert r5(_req("proc.exec", argv=argv), _ctx(), STORES) is CE


@pytest.mark.parametrize(
    "argv",
    [
        ["env", "FOO=bar", "python", "app.py"],  # env assignment + benign program
        ["timeout", "30", "pytest", "-q"],
        ["nice", "-n", "5", "python", "app.py"],
    ],
)
def test_s3_wrapped_benign_not_applicable(argv: list[str]) -> None:
    assert r5(_req("proc.exec", argv=argv), _ctx(), STORES) is None


# REFINE-2 S1 — the exec-wrapper allowlist must cover the launcher families that
# would otherwise hide sudo/su/doas (or a dangerous binary) behind argv[0].
@pytest.mark.parametrize(
    "argv",
    [
        ["flock", "/tmp/l", "sudo", "rm", "-rf", "/"],
        ["time", "sudo", "reboot"],
        ["unshare", "-r", "sudo", "id"],
        ["setpriv", "--reuid=0", "sudo", "sh"],
        ["nsenter", "--target", "1", "--mount", "sudo", "id"],
        ["chroot", "/", "sudo", "sh"],
        ["runuser", "-u", "root", "doas", "id"],
        ["/usr/bin/env", "watch", "su"],  # nested wrapper: env -> watch -> su
    ],
)
def test_s1refine_expanded_wrappers_hide_priv_esc_deny(argv: list[str]) -> None:
    assert r5(_req("proc.exec", argv=argv), _ctx(), STORES) is DENY


@pytest.mark.parametrize(
    "argv",
    [
        ["flock", "/tmp/l", "rm", "-rf", "x"],
        ["watch", "rm", "x"],
        ["bwrap", "--dev", "/dev", "curl", "http://x"],
    ],
)
def test_s1refine_expanded_wrappers_hide_dangerous_bin_confirm_exact(argv: list[str]) -> None:
    assert r5(_req("proc.exec", argv=argv), _ctx(), STORES) is CE


# REFINE-2 S2 — PolicyStores fails CLOSED on a malformed (empty/relative) field.
def test_s2_all_absolute_constructs_fine() -> None:
    s = PolicyStores(home="/h", audit_store="/a", policy_store="/b", kernel_secret="/c")
    assert (s.home, s.audit_store, s.policy_store, s.kernel_secret) == ("/h", "/a", "/b", "/c")


@pytest.mark.parametrize("field", ["home", "audit_store", "policy_store", "kernel_secret"])
@pytest.mark.parametrize("bad", ["", "relative/path", ".", "..", "rel"])
def test_s2_empty_or_relative_field_raises(field: str, bad: str) -> None:
    kwargs = {"home": "/h", "audit_store": "/a", "policy_store": "/b", "kernel_secret": "/c"}
    kwargs[field] = bad
    with pytest.raises(PolicyStoresError):
        PolicyStores(**kwargs)


# ============================================================================
# R6 — net.fetch domain not in allowlist -> CONFIRM_EXACT (default allowlist empty)
# ============================================================================


@pytest.mark.parametrize("domain", ["example.com", "raw.githubusercontent.com", "pypi.org"])
def test_r6_domain_not_in_allowlist_confirm_exact(domain: str) -> None:
    assert r6(_req("net.fetch", domain=domain), _ctx(), STORES) is CE


def test_r6_guards() -> None:
    assert r6(_req("fs.read", domain="example.com"), _ctx(), STORES) is None
    assert r6(_req("net.fetch"), _ctx(), STORES) is None
    assert r6(_req("net.fetch", domain=123), _ctx(), STORES) is None
    assert r6(_req("net.fetch", domain=""), _ctx(), STORES) is None


# ============================================================================
# R7 — write to .git internals / policy store / audit / kernel secret -> DENY
# ============================================================================


@pytest.mark.parametrize(
    "path",
    [
        WS + "/.git/config",
        WS + "/repo/.git/hooks/pre-commit",
        _home(".config/lsassist/policy.json"),
        _home(".config/lsassist/policy.d/rules.yml"),
        _home(".local/state/lsassist/audit/journal.jsonl"),
        _home(".local/state/lsassist/kernel.secret"),
    ],
)
def test_r7_self_tamper_paths_deny(path: str) -> None:
    assert r7(_req("fs.write", path=path), _ctx(), STORES) is DENY


@pytest.mark.parametrize(
    "path",
    [
        WS + "/.gitignore",
        WS + "/.github/workflows/ci.yml",
        _home(".config/lsassist/config.toml"),
        # S1: the OLD wrong audit location (.local/share) is NOT the store now.
        _home(".local/share/lsassist/audit/journal.jsonl"),
    ],
)
def test_r7_negative_paths_not_denied(path: str) -> None:
    assert r7(_req("fs.write", path=path), _ctx(), STORES) is None


def test_r7_not_applicable_without_path() -> None:
    assert r7(_req("memory.write", durable=True), _ctx(), STORES) is None


# S1/S2 [CRITICAL] regression: with an $XDG_*-overridden layout, the REAL
# (relocated) kernel.secret / audit / policy stores MUST still be denied, and
# reading the HMAC kernel.secret is denied (I8) — via the injected stores.
@pytest.mark.parametrize(
    "path",
    [
        "/mnt/xdgstate/lsassist/kernel.secret",
        "/mnt/xdgstate/lsassist/audit/journal.jsonl",
        "/mnt/xdgconfig/lsassist/policy.toml",
    ],
)
def test_s1_xdg_override_stores_are_denied(path: str) -> None:
    assert r7(_req("fs.read", path=path), _ctx(), XDG_STORES) is DENY
    assert r7(_req("fs.write", path=path), _ctx(), XDG_STORES) is DENY


def test_s1_default_store_paths_not_denied_under_xdg_override() -> None:
    # Under the override, the DEFAULT ~/.local/state paths are no longer stores.
    assert r7(_req("fs.write", path=_home(".local/state/lsassist/kernel.secret")),
              _ctx(), XDG_STORES) is None


def test_s4_r7_dotdot_policy_path_normalized_and_denied() -> None:
    # /home/u/x/../.config/lsassist/policy.toml -> /home/u/.config/lsassist/policy.toml
    assert r7(
        _req("fs.write", path=HOME + "/x/../.config/lsassist/policy.toml"), _ctx(), STORES
    ) is DENY


# ============================================================================
# R8 — memory.write durable + provenance=model -> CONFIRM_ONCE
# ============================================================================


def test_r8_durable_model_provenance_confirm_once() -> None:
    assert r8(_req("memory.write", durable=True, provenance="model"), _ctx(), STORES) is C1


@pytest.mark.parametrize(
    "args",
    [
        {"durable": True, "provenance": "user"},
        {"durable": False, "provenance": "model"},
        {"provenance": "model"},
        {"durable": True},
    ],
)
def test_r8_negative_cases_not_applicable(args: dict[str, object]) -> None:
    assert r8(_req("memory.write", **args), _ctx(), STORES) is None


def test_r8_wrong_tool_not_applicable() -> None:
    assert r8(_req("fs.write", durable=True, provenance="model"), _ctx(), STORES) is None


# ============================================================================
# R9 — skill ceiling present -> raise to ceiling; None -> no-op
# ============================================================================


@pytest.mark.parametrize("ceiling", [ASW, C1, CE, DENY])
def test_r9_returns_ceiling_when_present(ceiling: PermissionClass) -> None:
    assert r9(_req("fs.read"), _ctx(skill_ceiling=ceiling), STORES) is ceiling


def test_r9_none_ceiling_not_applicable() -> None:
    assert r9(_req("fs.read"), _ctx(skill_ceiling=None), STORES) is None


def test_r9_raises_class_via_classify() -> None:
    result = classify(
        _req("fs.read", path=WS + "/x"), _ctx(skill_ceiling=CE), _manifest(AR), STORES
    )
    assert result is CE


def test_r9_none_is_noop_via_classify() -> None:
    result = classify(
        _req("fs.read", path=WS + "/x"), _ctx(skill_ceiling=None), _manifest(AR), STORES
    )
    assert result is AR


def test_r9_deny_ceiling_denies_via_classify() -> None:
    result = classify(
        _req("fs.read", path=WS + "/x"), _ctx(skill_ceiling=DENY), _manifest(AR), STORES
    )
    assert result is DENY


# ============================================================================
# classify() — composition, DENY short-circuit, monotonicity
# ============================================================================


def test_classify_accumulates_multiple_raises() -> None:
    # base AUTO_SCOPED_WRITE + untrusted (post-fold -> CONFIRM_EXACT) + R4 metachar.
    result = classify(
        _req("proc.exec", argv=["echo", "a;b"]),
        _ctx(untrusted_turn=True),
        _manifest(ASW, name="proc.exec"),
        STORES,
    )
    assert result is CE


def test_classify_deny_short_circuits_over_other_rules() -> None:
    result = classify(
        _req("proc.exec", argv=["sudo", "rm", "-rf", "/"]),
        _ctx(),
        _manifest(AR, name="proc.exec"),
        STORES,
    )
    assert result is DENY


def test_classify_deny_from_secret_path_short_circuits() -> None:
    result = classify(
        _req("fs.read", path=_home(".ssh/id_rsa")), _ctx(), _manifest(AR), STORES
    )
    assert result is DENY


@pytest.mark.parametrize("base", ALL_CLASSES)
def test_classify_monotonic_never_below_floor(base: PermissionClass) -> None:
    result = classify(
        _req("net.fetch", domain="x.com"), _ctx(), _manifest(base, name="net.fetch"), STORES
    )
    assert rank(result) >= rank(base)


@pytest.mark.parametrize("base", ALL_CLASSES)
def test_classify_benign_returns_floor_exactly(base: PermissionClass) -> None:
    result = classify(_req("fs.read", path=WS + "/x"), _ctx(), _manifest(base), STORES)
    assert result is base
