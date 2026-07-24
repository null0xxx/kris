"""T1.09 RED: secrets resolution order (SPEC §12.3, ADR-004).

Order: ``LSASSIST_KIMI_API_KEY`` env → OS keyring (``secretstorage``, lazily
imported) → ``0600`` fallback file ``$XDG_CONFIG_HOME/lsassist/secrets/<name>``.
Every source is fail-closed (symlink / foreign uid / loose mode →
:class:`ConfigSecurityError`); no source → typed :class:`SecretNotFoundError`
with a first-run wizard hint. Resolved values are wrapped in :class:`Secret`
whose ``str``/``repr`` never leak — materialization only via ``.reveal()``
(§12.3 short-lived, memory-only).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from lsassist.config import ConfigSecurityError, XdgPaths
from lsassist.config.secrets import (
    KEYRING_ITEM_PREFIX,
    KeyringUnavailableError,
    Secret,
    SecretNotFoundError,
    resolve_secret,
    store_secret,
    store_secret_file,
)

NAME = "kimi-api-key"
ENV_VAR = "LSASSIST_KIMI_API_KEY"
KEYRING_ITEM = f"{KEYRING_ITEM_PREFIX}/{NAME}"


class FakeKeyring:
    """In-memory keyring stand-in with an access counter (order guarantee probe)."""

    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values = dict(values or {})
        self.get_calls = 0
        self.set_calls: list[tuple[str, str]] = []

    def get(self, item: str) -> str | None:
        self.get_calls += 1
        return self.values.get(item)

    def set(self, item: str, value: str) -> None:
        self.set_calls.append((item, value))
        self.values[item] = value


@pytest.fixture()
def paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> XdgPaths:
    """All four XDG roots at fresh tmp dirs; the API-key env var removed."""
    for var, name in (
        ("XDG_CONFIG_HOME", "cfg"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_CACHE_HOME", "cache"),
    ):
        root = tmp_path / name
        root.mkdir()
        monkeypatch.setenv(var, str(root))
    monkeypatch.delenv(ENV_VAR, raising=False)
    return XdgPaths.resolve()


def _write_fallback(paths: XdgPaths, value: str = "file-key", mode: int = 0o600) -> Path:
    secrets_dir = paths.config_home / "lsassist" / "secrets"
    secrets_dir.mkdir(parents=True)
    target = secrets_dir / NAME
    target.write_text(value, encoding="utf-8")
    target.chmod(mode)
    return target


# --- (1) env var set -> env wins; keyring and file never touched --------------


def test_env_wins_and_short_circuits(
    paths: XdgPaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_VAR, "env-key")
    keyring = FakeKeyring({KEYRING_ITEM: "keyring-key"})
    fallback = _write_fallback(paths, "file-key")
    before = fallback.stat().st_mtime_ns

    secret = resolve_secret(NAME, paths=paths, keyring=keyring)

    assert secret.reveal() == "env-key"
    assert keyring.get_calls == 0  # order guarantee: keyring never consulted
    assert fallback.stat().st_mtime_ns == before  # file untouched


# --- (2) env absent -> keyring ------------------------------------------------


def test_keyring_second_in_order(paths: XdgPaths) -> None:
    keyring = FakeKeyring({KEYRING_ITEM: "keyring-key"})
    _write_fallback(paths, "file-key")

    secret = resolve_secret(NAME, paths=paths, keyring=keyring)

    assert secret.reveal() == "keyring-key"
    assert keyring.get_calls == 1


# --- (3) keyring unavailable -> 0600 file fallback ----------------------------


@pytest.mark.parametrize(
    "cause",
    [
        "secretstorage not installed",  # import error
        "keyring backend unreachable: DBusError(...)",  # D-Bus absent
    ],
)
def test_keyring_unavailable_falls_back_to_file(
    paths: XdgPaths, monkeypatch: pytest.MonkeyPatch, cause: str
) -> None:
    _write_fallback(paths, "file-key")

    def _boom() -> FakeKeyring:
        raise KeyringUnavailableError(cause)

    # Import error / D-Bus absent both surface as an unavailable default backend.
    monkeypatch.setattr("lsassist.config.secrets._default_keyring", _boom)

    secret = resolve_secret(NAME, paths=paths)

    assert secret.reveal() == "file-key"


# --- (4) fallback file mode looser than 0600 -> refuse -------------------------


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o777])
def test_fallback_loose_mode_refused(paths: XdgPaths, mode: int) -> None:
    _write_fallback(paths, mode=mode)
    with pytest.raises(ConfigSecurityError):
        resolve_secret(NAME, paths=paths, keyring=FakeKeyring())


# --- (5) fallback file is a symlink -> refuse ----------------------------------


def test_fallback_symlink_refused(paths: XdgPaths) -> None:
    target = _write_fallback(paths)
    elsewhere = paths.config_home / "elsewhere"
    target.rename(elsewhere)
    target.symlink_to(elsewhere)
    with pytest.raises(ConfigSecurityError):
        resolve_secret(NAME, paths=paths, keyring=FakeKeyring())


# --- (6) fallback file owned by another uid -> refuse --------------------------


def test_fallback_foreign_owner_refused(
    paths: XdgPaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_fallback(paths)
    real_euid = os.geteuid()
    # Simulate a file owned by someone else: reported euid no longer matches.
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    with pytest.raises(ConfigSecurityError):
        resolve_secret(NAME, paths=paths, keyring=FakeKeyring())


# --- (7) no source at all -> typed error with first-run wizard hint ------------


def test_no_source_raises_typed_error_with_hint(paths: XdgPaths) -> None:
    with pytest.raises(SecretNotFoundError) as excinfo:
        resolve_secret(NAME, paths=paths, keyring=FakeKeyring())
    message = str(excinfo.value)
    assert "lsassist setup" in message  # first-run wizard hint, not a crash
    assert ENV_VAR in message


# --- (8) Secret wrapper never leaks via str/repr/format ------------------------


def test_secret_wrapper_redacts_stringification() -> None:
    secret = Secret("sk-super-secret-value")
    for rendered in (str(secret), repr(secret), f"{secret}", "%s" % secret):
        assert rendered == "[REDACTED:secret]"
        assert "sk-super-secret-value" not in rendered
    assert secret.reveal() == "sk-super-secret-value"  # explicit, short-lived


def test_secret_wrapper_has_no_public_value_attribute() -> None:
    secret = Secret("sk-super-secret-value")
    assert not hasattr(secret, "value")
    assert not hasattr(secret, "__dict__")


# --- (9) resolution writes nothing to disk and logs nothing --------------------


def test_resolution_is_read_only_and_silent(
    paths: XdgPaths, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(ENV_VAR, "env-key")
    before = {p for p in paths.config_home.rglob("*")}

    with caplog.at_level("DEBUG"):  # noqa: SIM115 - level name is stable
        resolve_secret(NAME, paths=paths, keyring=FakeKeyring())

    after = {p for p in paths.config_home.rglob("*")}
    assert before == after  # nothing materialized on disk
    assert caplog.records == []  # nothing logged


# --- write-side helpers (setup wizard, Phase 5) --------------------------------


def test_store_secret_writes_keyring_only(paths: XdgPaths) -> None:
    keyring = FakeKeyring()
    store_secret(NAME, "new-key", keyring=keyring)
    assert keyring.set_calls == [(KEYRING_ITEM, "new-key")]
    assert not (paths.config_home / "lsassist" / "secrets" / NAME).exists()


def test_store_secret_file_creates_0600(paths: XdgPaths) -> None:
    target = store_secret_file(NAME, "file-key", paths=paths)
    st = os.lstat(target)
    assert stat.S_IMODE(st.st_mode) == 0o600
    assert target.read_text(encoding="utf-8") == "file-key"
    assert resolve_secret(NAME, paths=paths, keyring=FakeKeyring()).reveal() == "file-key"


def test_store_secret_file_refuses_symlink(paths: XdgPaths) -> None:
    target = _write_fallback(paths)
    elsewhere = paths.config_home / "elsewhere"
    target.rename(elsewhere)
    target.symlink_to(elsewhere)
    with pytest.raises(ConfigSecurityError):
        store_secret_file(NAME, "file-key", paths=paths)
