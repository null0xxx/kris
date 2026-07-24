"""T1.09 RED: kernel_secret (SPEC §7.4).

``$XDG_STATE_HOME/lsassist/kernel.secret`` — 32 random bytes, generated at
install/first run with mode 0600, ownership/mode/symlink/length-checked at
every startup load (fail-closed :class:`ConfigSecurityError`). Generation is
idempotent: a second load returns the same bytes, never regenerates. The
kernel secret is entirely independent of the Kimi API-key resolver chain —
this module never imports ``lsassist.config.secrets`` and never consults env
or keyring.
"""

from __future__ import annotations

import ast
import hashlib
import os
import stat
from pathlib import Path

import pytest

from lsassist.config import ConfigSecurityError, XdgPaths
from lsassist.config.kernel_secret import (
    KERNEL_SECRET_LEN,
    load_or_generate_kernel_secret,
)


@pytest.fixture()
def paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> XdgPaths:
    """All four XDG roots at fresh tmp dirs."""
    for var, name in (
        ("XDG_CONFIG_HOME", "cfg"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_CACHE_HOME", "cache"),
    ):
        root = tmp_path / name
        root.mkdir()
        monkeypatch.setenv(var, str(root))
    return XdgPaths.resolve()


def _kernel_path(paths: XdgPaths) -> Path:
    return paths.state_home / "lsassist" / "kernel.secret"


def _plant(paths: XdgPaths, content: bytes, mode: int = 0o600) -> Path:
    target = _kernel_path(paths)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.parent.chmod(0o700)  # §12.1: state/lsassist dir at most 0700
    target.write_bytes(content)
    target.chmod(mode)
    return target


# --- (10) first run: absent -> generated, exactly 32 random bytes, mode 0600 ---


def test_first_run_generates_32_random_bytes_0600(paths: XdgPaths) -> None:
    secret = load_or_generate_kernel_secret(paths)
    target = _kernel_path(paths)

    assert isinstance(secret, bytes)
    assert len(secret) == KERNEL_SECRET_LEN == 32
    st = os.lstat(target)
    assert stat.S_ISREG(st.st_mode)
    assert stat.S_IMODE(st.st_mode) == 0o600
    assert target.read_bytes() == secret  # persisted verbatim


# --- (11) idempotency: second load returns same bytes, no regeneration ---------


def test_second_load_is_idempotent(paths: XdgPaths) -> None:
    first = load_or_generate_kernel_secret(paths)
    target = _kernel_path(paths)
    digest_before = hashlib.sha256(target.read_bytes()).hexdigest()
    mtime_before = target.stat().st_mtime_ns

    second = load_or_generate_kernel_secret(paths)

    assert second == first
    assert hashlib.sha256(target.read_bytes()).hexdigest() == digest_before
    assert target.stat().st_mtime_ns == mtime_before  # never rewritten


# --- (12) symlink at the kernel.secret path -> fail-closed ---------------------


def test_symlink_path_fails_closed(paths: XdgPaths) -> None:
    target = _plant(paths, os.urandom(32))
    elsewhere = paths.state_home / "elsewhere"
    target.rename(elsewhere)
    target.symlink_to(elsewhere)
    with pytest.raises(ConfigSecurityError):
        load_or_generate_kernel_secret(paths)


# --- (13) owned by another uid -> fail-closed ----------------------------------


def test_foreign_owner_fails_closed(
    paths: XdgPaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    _plant(paths, os.urandom(32))
    real_euid = os.geteuid()
    # Simulate a file owned by someone else: reported euid no longer matches.
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    with pytest.raises(ConfigSecurityError):
        load_or_generate_kernel_secret(paths)


# --- (14) mode looser than 0600 -> fail-closed ---------------------------------


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o777])
def test_loose_mode_fails_closed(paths: XdgPaths, mode: int) -> None:
    _plant(paths, os.urandom(32), mode=mode)
    with pytest.raises(ConfigSecurityError):
        load_or_generate_kernel_secret(paths)


# --- (15) length != 32 bytes -> fail-closed ------------------------------------


@pytest.mark.parametrize("length", [0, 16, 31, 33, 64])
def test_wrong_length_fails_closed(paths: XdgPaths, length: int) -> None:
    _plant(paths, os.urandom(length))
    with pytest.raises(ConfigSecurityError):
        load_or_generate_kernel_secret(paths)


# --- (16) independence from the Kimi resolver chain (structural) ----------------


def test_module_never_imports_kimi_secrets_chain() -> None:
    import lsassist.config.kernel_secret as mod

    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name != "lsassist.config.secrets"
        elif isinstance(node, ast.ImportFrom):
            assert node.module != "lsassist.config.secrets"
            assert not (node.level > 0 and node.module == "secrets")


def test_load_ignores_env_and_keyring(
    paths: XdgPaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Kernel secret is kernel-local: env vars never influence it."""
    monkeypatch.setenv("LSASSIST_KIMI_API_KEY", "env-key")
    secret = load_or_generate_kernel_secret(paths)
    assert isinstance(secret, bytes) and len(secret) == 32
    assert secret != b"env-key"
