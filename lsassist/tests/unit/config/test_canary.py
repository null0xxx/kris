"""T1.07 RED: canary honeyfiles (SPEC §19 scenario 1).

Decoys are synthetic and deliberately invalid — no real secret material is
ever handled here. Detection-on-read (alert/freeze) belongs to the
kernel/audit layers, not this task.
"""

from __future__ import annotations

import hashlib
import stat
from pathlib import Path

import pytest

from lsassist.config import (
    CANARY_HONEYFILES,
    ConfigSecurityError,
    XdgPaths,
    canary_registry,
    expected_canary_digests,
    provision_canaries,
)


@pytest.fixture()
def xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> XdgPaths:
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


def _canary_dir(paths: XdgPaths) -> Path:
    return paths.config_home / "lsassist" / "canary"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- (a) provisioning creates dir 0700 + decoy files 0600 ---------------------


def test_provision_creates_canary_dir_0700(xdg: XdgPaths) -> None:
    provision_canaries(xdg)
    canary_dir = _canary_dir(xdg)
    assert canary_dir.is_dir()
    assert stat.S_IMODE(canary_dir.stat().st_mode) == 0o700


@pytest.mark.parametrize("name", [name for name, _ in CANARY_HONEYFILES])
def test_provision_creates_honeyfile_0600(xdg: XdgPaths, name: str) -> None:
    provision_canaries(xdg)
    honeyfile = _canary_dir(xdg) / name
    assert honeyfile.is_file()
    assert not honeyfile.is_symlink()
    assert stat.S_IMODE(honeyfile.stat().st_mode) == 0o600
    assert _digest(honeyfile) == expected_canary_digests()[name]


def test_decoys_are_synthetic_and_marked_invalid() -> None:
    assert len(CANARY_HONEYFILES) >= 3  # API key, AWS-style creds, private-key block
    for _name, content in CANARY_HONEYFILES:
        marker = content.lower()
        assert "canary" in marker or "decoy" in marker


# --- (b) idempotency — second run is a no-op ----------------------------------


def test_provision_idempotent(xdg: XdgPaths) -> None:
    provision_canaries(xdg)
    canary_dir = _canary_dir(xdg)
    first = {name: (_digest(canary_dir / name), (canary_dir / name).stat().st_mtime_ns)
             for name, _ in CANARY_HONEYFILES}
    provision_canaries(xdg)
    second = {name: (_digest(canary_dir / name), (canary_dir / name).stat().st_mtime_ns)
              for name, _ in CANARY_HONEYFILES}
    assert first == second


# --- (c) registry returns path + sha256 per honeyfile -------------------------


def test_registry_returns_path_and_digest(xdg: XdgPaths) -> None:
    provision_canaries(xdg)
    entries = canary_registry(xdg)
    assert len(entries) == len(CANARY_HONEYFILES)
    expected = expected_canary_digests()
    for entry in entries:
        assert entry.path.parent == _canary_dir(xdg)
        assert entry.sha256 == expected[entry.path.name]


# --- (d) external tamper -> digest mismatch -> ConfigSecurityError ------------


def test_registry_tampered_decoy_fails_closed(xdg: XdgPaths) -> None:
    provision_canaries(xdg)
    victim = _canary_dir(xdg) / CANARY_HONEYFILES[0][0]
    victim.write_text("tampered", encoding="utf-8")
    with pytest.raises(ConfigSecurityError):
        canary_registry(xdg)


def test_provision_tampered_decoy_fails_closed(xdg: XdgPaths) -> None:
    provision_canaries(xdg)
    victim = _canary_dir(xdg) / CANARY_HONEYFILES[1][0]
    victim.write_text("tampered", encoding="utf-8")
    with pytest.raises(ConfigSecurityError):
        provision_canaries(xdg)


def test_registry_missing_honeyfile_fails_closed(xdg: XdgPaths) -> None:
    provision_canaries(xdg)
    (_canary_dir(xdg) / CANARY_HONEYFILES[0][0]).unlink()
    with pytest.raises(ConfigSecurityError):
        canary_registry(xdg)


# --- (e) symlink in canary dir -> ConfigSecurityError -------------------------


def test_registry_symlinked_honeyfile_fails_closed(xdg: XdgPaths) -> None:
    provision_canaries(xdg)
    victim = _canary_dir(xdg) / CANARY_HONEYFILES[0][0]
    elsewhere = xdg.config_home / "elsewhere"
    elsewhere.write_text("x", encoding="utf-8")
    victim.unlink()
    victim.symlink_to(elsewhere)
    with pytest.raises(ConfigSecurityError):
        canary_registry(xdg)


def test_provision_symlinked_canary_dir_fails_closed(xdg: XdgPaths) -> None:
    base = xdg.config_home / "lsassist"
    base.mkdir()
    elsewhere = xdg.config_home / "elsewhere"
    elsewhere.mkdir()
    (base / "canary").symlink_to(elsewhere)
    with pytest.raises(ConfigSecurityError):
        provision_canaries(xdg)
