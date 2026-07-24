"""T2.02: pure §7.3 DENY_ALWAYS matcher over CANONICAL paths.

One positive case per §7.3 pattern (secret dirs, ``.env`` family, ``/etc``
secrets, raw block devices, injected audit/policy/kernel stores, ``.git``
internals) plus the carve-outs and segment-aware negatives (``.env.example``
allowed; ``.gitignore``/``.github`` NOT ``.git``; ``config.toml`` under the
policy store NOT ``policy*``; ``/ws-evil`` NOT within ``/ws``).

``deny_match`` accepts ONLY a :data:`CanonicalPath` (T2.02 decision #1) so every
literal below is wrapped with ``CanonicalPath(...)``; the matcher is PURE and is
exercised with a literal :class:`PolicyStores` (no ``tmp_path``, no I/O).
"""

from __future__ import annotations

import pytest

from lsassist.policy.canonical import CanonicalPath
from lsassist.policy.denylist import deny_match
from lsassist.policy.stores import PolicyStores

C = CanonicalPath

HOME = "/home/u"

STORES = PolicyStores(
    home=HOME,
    audit_store=HOME + "/.local/state/lsassist/audit",
    policy_store=HOME + "/.config/lsassist",
    kernel_secret=HOME + "/.local/state/lsassist/kernel.secret",
)

# Segment-aware regression store: a bare "/ws" root to prove /ws-evil is NOT in.
WS_STORES = PolicyStores(
    home="/home/u", audit_store="/ws", policy_store="/pol", kernel_secret="/ks"
)


# ---------------------------------------------------------------------------
# POSITIVE: one match per §7.3 pattern
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern_id", "path"),
    [
        # secret home dirs (~/.ssh ~/.gnupg ~/.kimi-code ~/.aws ~/.config/gh)
        ("~/.ssh", HOME + "/.ssh/id_rsa"),
        ("~/.gnupg", HOME + "/.gnupg/secring.gpg"),
        ("~/.kimi-code", HOME + "/.kimi-code/oauth.json"),
        ("~/.aws", HOME + "/.aws/credentials"),
        ("~/.config/gh", HOME + "/.config/gh/hosts.yml"),
        # dotenv family
        ("**/.env", "/ws/.env"),
        ("**/.env.*", "/ws/sub/.env.local"),
        ("**/.env.* (prod)", HOME + "/proj/.env.production"),
        # /etc secrets
        ("/etc/shadow", "/etc/shadow"),
        ("/etc/sudoers", "/etc/sudoers"),
        ("/etc/sudoers.d/*", "/etc/sudoers.d/90-custom"),
        # raw block devices
        ("/dev/sd*", "/dev/sda"),
        ("/dev/sd* (part)", "/dev/sdb1"),
        ("/dev/nvme*n*", "/dev/nvme0n1"),
        ("/dev/nvme*n* (part)", "/dev/nvme1n1p2"),
        # injected stores
        ("audit store", HOME + "/.local/state/lsassist/audit/journal.jsonl"),
        ("policy store policy*", HOME + "/.config/lsassist/policy.toml"),
        ("policy store policy.d", HOME + "/.config/lsassist/policy.d/rules.yml"),
        ("kernel secret", HOME + "/.local/state/lsassist/kernel.secret"),
        # .git internals
        (".git internals", "/ws/.git/config"),
        (".git nested", "/ws/repo/.git/hooks/pre-commit"),
    ],
)
def test_deny_match_covers_each_7_3_pattern(pattern_id: str, path: str) -> None:
    assert deny_match(C(path), STORES) is True, pattern_id


def test_deny_match_audit_store_segment_aware() -> None:
    # /ws is the audit store: a file inside is denied, a sibling prefix is NOT.
    assert deny_match(C("/ws/f"), WS_STORES) is True
    assert deny_match(C("/ws-evil/f"), WS_STORES) is False


# ---------------------------------------------------------------------------
# NEGATIVE: carve-outs + segment-aware non-matches
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("case_id", "path"),
    [
        ("dotenv example carve-out", "/ws/.env.example"),
        ("dotenv example nested", HOME + "/proj/.env.example"),
        (".gitignore is not .git", "/ws/.gitignore"),
        (".github is not .git", "/ws/.github/workflows/ci.yml"),
        ("policy store non-policy file", HOME + "/.config/lsassist/config.toml"),
        ("nvim config not gh", HOME + "/.config/nvim/init.lua"),
        ("/etc/hosts safe", "/etc/hosts"),
        ("/dev/null safe", "/dev/null"),
        ("/dev/tty safe", "/dev/tty"),
        ("plain source file", "/ws/src/x.py"),
        ("home dotfile not secret", HOME + "/.bashrc"),
    ],
)
def test_deny_match_negatives(case_id: str, path: str) -> None:
    assert deny_match(C(path), STORES) is False, case_id


def test_deny_match_empty_or_root_not_denied() -> None:
    assert deny_match(C("/"), STORES) is False


def test_deny_match_store_roots_themselves_denied() -> None:
    # the injected store ROOTS (exact match) are denied, not only descendants.
    assert deny_match(C(HOME + "/.local/state/lsassist/audit"), STORES) is True
    assert deny_match(C(HOME + "/.ssh"), STORES) is True
