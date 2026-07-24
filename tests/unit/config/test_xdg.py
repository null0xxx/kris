"""T1.07 RED: XDG resolution, §12.1 layout enforcement, startup checks.

§12.1: XDG layout table (paths + modes) is the source of truth; startup
checks require ownership = current user, permissions at most as listed, and
symlinks fail-closed. §7.5: per-component ``lstat`` symlink defense.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from lsassist.config import (
    LAYOUT,
    ConfigSecurityError,
    XdgPaths,
    check_security,
    ensure_layout,
)

ENV_VARS = ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME")


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Bare HOME with all XDG_* vars unset."""
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


@pytest.fixture()
def xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> XdgPaths:
    """All four XDG roots pointed at fresh tmp dirs."""
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


# --- (1) default fallbacks when env is unset ---------------------------------


@pytest.mark.parametrize(
    ("attr", "suffix"),
    [
        ("config_home", ".config"),
        ("data_home", ".local/share"),
        ("state_home", ".local/state"),
        ("cache_home", ".cache"),
    ],
)
def test_default_fallbacks(home: Path, attr: str, suffix: str) -> None:
    assert getattr(XdgPaths.resolve(), attr) == home / suffix


@pytest.mark.parametrize(
    ("var", "attr"),
    [
        ("XDG_CONFIG_HOME", "config_home"),
        ("XDG_DATA_HOME", "data_home"),
        ("XDG_STATE_HOME", "state_home"),
        ("XDG_CACHE_HOME", "cache_home"),
    ],
)
def test_env_override(home: Path, monkeypatch: pytest.MonkeyPatch, var: str, attr: str) -> None:
    custom = home / "custom"
    monkeypatch.setenv(var, str(custom))
    assert getattr(XdgPaths.resolve(), attr) == custom


def test_relative_env_value_ignored(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # XDG basedir spec: relative values are invalid and must be ignored.
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative/path")
    assert XdgPaths.resolve().config_home == home / ".config"


# --- (2) ensure_layout creates §12.1 directories with exact modes -------------


@pytest.mark.parametrize(
    ("relpath", "mode"),
    [
        ("config/lsassist", 0o700),
        ("config/lsassist/secrets", 0o700),
        ("config/lsassist/canary", 0o700),
        ("data/lsassist", 0o700),
        ("data/lsassist/skills", 0o700),
        ("data/lsassist/evals", 0o644),
        ("state/lsassist", 0o700),
        ("state/lsassist/audit", 0o700),
        ("state/lsassist/checkpoints", 0o700),
        ("cache/lsassist", 0o700),
    ],
)
def test_ensure_layout_creates_dirs_with_exact_modes(
    xdg: XdgPaths, relpath: str, mode: int
) -> None:
    ensure_layout(xdg)
    target = xdg.layout_path(relpath)
    assert target.is_dir()
    assert stat.S_IMODE(target.stat().st_mode) == mode


# --- (3) existing dir with loose permissions -> corrected ("at most as listed")


def test_ensure_layout_tightens_loose_permissions(xdg: XdgPaths) -> None:
    secrets = xdg.config_home / "lsassist" / "secrets"
    secrets.mkdir(parents=True)
    os.chmod(secrets, 0o755)
    ensure_layout(xdg)
    assert stat.S_IMODE(secrets.stat().st_mode) == 0o700


def test_ensure_layout_keeps_tighter_permissions(xdg: XdgPaths) -> None:
    evals = xdg.data_home / "lsassist" / "evals"
    evals.mkdir(parents=True)
    os.chmod(evals, 0o600)  # tighter than the listed 0644 — must be kept
    ensure_layout(xdg)
    assert stat.S_IMODE(evals.stat().st_mode) == 0o600


# --- (4) symlink on any layout path -> ConfigSecurityError, fail-closed -------


@pytest.mark.parametrize(
    "relpath",
    ["config/lsassist/secrets", "config/lsassist/canary", "data/lsassist/skills"],
)
def test_ensure_layout_symlinked_dir_fails_closed(xdg: XdgPaths, relpath: str) -> None:
    target = xdg.layout_path(relpath)
    target.parent.mkdir(parents=True, exist_ok=True)
    elsewhere = target.parent / "elsewhere"
    elsewhere.mkdir()
    target.symlink_to(elsewhere)
    with pytest.raises(ConfigSecurityError):
        ensure_layout(xdg)


def test_ensure_layout_symlinked_file_fails_closed(xdg: XdgPaths) -> None:
    secret = xdg.state_home / "lsassist" / "kernel.secret"
    secret.parent.mkdir(parents=True)
    elsewhere = xdg.state_home / "elsewhere"
    elsewhere.write_text("x", encoding="utf-8")
    secret.symlink_to(elsewhere)
    with pytest.raises(ConfigSecurityError):
        ensure_layout(xdg)


@pytest.mark.parametrize("relpath", ["config/lsassist/secrets", "state/lsassist/audit"])
def test_check_security_symlink_fails_closed(xdg: XdgPaths, relpath: str) -> None:
    ensure_layout(xdg)
    target = xdg.layout_path(relpath)
    elsewhere = target.parent / "elsewhere"
    target.rename(elsewhere)
    target.symlink_to(elsewhere)
    with pytest.raises(ConfigSecurityError):
        check_security(xdg)


# --- (5) directory owned by a different uid -> ConfigSecurityError ------------


def test_check_security_foreign_owner_fails_closed(
    xdg: XdgPaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    ensure_layout(xdg)
    real_euid = os.geteuid()
    # Simulate files owned by someone else: reported euid no longer matches.
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    with pytest.raises(ConfigSecurityError):
        check_security(xdg)


def test_check_security_clean_layout_passes(xdg: XdgPaths) -> None:
    ensure_layout(xdg)
    check_security(xdg)  # must not raise


def test_check_security_too_loose_file_mode_fails_closed(xdg: XdgPaths) -> None:
    secret = xdg.state_home / "lsassist"
    secret.mkdir(parents=True)
    kernel_secret = secret / "kernel.secret"
    kernel_secret.write_text("key", encoding="utf-8")
    os.chmod(kernel_secret, 0o644)  # exceeds the listed 0600
    with pytest.raises(ConfigSecurityError):
        check_security(xdg)


# --- (6) declarative LAYOUT table matches §12.1 rows (+ canary/ from §19) -----


def test_layout_kernel_secret_expected_mode() -> None:
    table = {rel: (kind, mode) for rel, kind, mode in LAYOUT}
    assert table["state/lsassist/kernel.secret"] == ("file", 0o600)


def test_layout_matches_spec_12_1_rows() -> None:
    expected = [
        ("config/lsassist/config.toml", "file", 0o600),
        ("config/lsassist/policy.toml", "file", 0o600),
        ("config/lsassist/secrets", "dir", 0o700),
        ("data/lsassist/memory.db", "file", 0o600),
        ("data/lsassist/skills", "dir", 0o700),
        ("data/lsassist/evals", "dir", 0o644),
        ("state/lsassist/audit", "dir", 0o700),
        ("state/lsassist/kernel.secret", "file", 0o600),
        ("state/lsassist/checkpoints", "dir", 0o700),
        ("cache/lsassist", "dir", 0o700),
        # §19 scenario 1: canary honeyfile directory.
        ("config/lsassist/canary", "dir", 0o700),
    ]
    for row in expected:
        assert row in LAYOUT
