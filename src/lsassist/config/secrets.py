"""Secrets resolution (SPEC §12.3, ADR-004).

Resolution order for a named secret (e.g. ``kimi-api-key``):

1. env var ``LSASSIST_KIMI_API_KEY`` (``LSASSIST_`` + uppercased name),
2. OS keyring item ``lsassist/<name>`` via ``secretstorage`` (lazily
   imported; import error or absent D-Bus = backend unavailable, fall
   through — headless SSH sessions may have no keyring, ADR-004),
3. fallback file ``$XDG_CONFIG_HOME/lsassist/secrets/<name>`` with
   fail-closed checks mirroring :func:`lsassist.config.xdg.check_security`
   (symlink / non-regular / foreign uid / mode looser than 0600 →
   :class:`ConfigSecurityError`).

No source → :class:`SecretNotFoundError` with a first-run wizard hint (typed
error, never a crash). Resolution is strictly read-only: nothing is written
to disk and nothing is logged.

Materialization (§12.3): resolved values live only inside :class:`Secret`,
whose ``str``/``repr``/``format`` render ``[REDACTED:secret]``; the plaintext
is reachable solely via the explicit, short-lived :meth:`Secret.reveal`.
Never: config dump, logs, audit, prompt, child env, sandbox env.

Write-side helpers exist for the first-run setup wizard (Phase 5):
:func:`store_secret` writes to the keyring only; :func:`store_secret_file`
writes the 0600 fallback file with ``O_NOFOLLOW``.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from lsassist.config.xdg import ConfigSecurityError, XdgPaths

if TYPE_CHECKING:
    import secretstorage.collection

__all__ = [
    "ENV_VAR_PREFIX",
    "KEYRING_ITEM_PREFIX",
    "Keyring",
    "KeyringUnavailableError",
    "Secret",
    "SecretNotFoundError",
    "resolve_secret",
    "store_secret",
    "store_secret_file",
]

ENV_VAR_PREFIX = "LSASSIST_"
KEYRING_ITEM_PREFIX = "lsassist"
_FALLBACK_MODE = 0o600


class SecretNotFoundError(Exception):
    """No secret source yielded a value; message carries the first-run wizard hint."""


class KeyringUnavailableError(Exception):
    """Default keyring backend cannot be used (no secretstorage, no D-Bus)."""


class Keyring(Protocol):
    """Minimal keyring backend surface (real: libsecret via ``secretstorage``)."""

    def get(self, item: str) -> str | None: ...
    def set(self, item: str, value: str) -> None: ...


class Secret:
    """Resolved secret value; accidental stringification renders the redaction tag."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        """Return the plaintext — explicit, short-lived, adapter memory only (§12.3)."""
        return self._value

    def __repr__(self) -> str:
        return "[REDACTED:secret]"

    def __str__(self) -> str:
        return "[REDACTED:secret]"


def _env_var(name: str) -> str:
    return ENV_VAR_PREFIX + name.upper().replace("-", "_")


def _keyring_item(name: str) -> str:
    return f"{KEYRING_ITEM_PREFIX}/{name}"


def _fallback_path(paths: XdgPaths, name: str) -> Path:
    return paths.config_home / "lsassist" / "secrets" / name


class _SecretStorageKeyring:
    """``Keyring`` adapter over a ``secretstorage`` collection."""

    def __init__(self, collection: secretstorage.collection.Collection) -> None:
        self._collection = collection

    def get(self, item: str) -> str | None:
        for entry in self._collection.search_items(
            {"service": KEYRING_ITEM_PREFIX, "item": item}
        ):
            if entry.is_locked():
                entry.unlock()
            return entry.get_secret().decode("utf-8")
        return None

    def set(self, item: str, value: str) -> None:
        self._collection.create_item(
            item,
            {"service": KEYRING_ITEM_PREFIX, "item": item},
            value.encode("utf-8"),
            replace=True,
        )


def _default_keyring() -> Keyring:
    """Connect to the default libsecret collection; lazily imports ``secretstorage``."""
    try:
        import secretstorage
    except ImportError as exc:
        raise KeyringUnavailableError("secretstorage not installed") from exc
    try:
        connection = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(connection)
    except Exception as exc:  # D-Bus absent/unreachable (headless session, ADR-004)
        raise KeyringUnavailableError(f"keyring backend unreachable: {exc!r}") from exc
    return _SecretStorageKeyring(collection)


def _from_env(name: str, env: Mapping[str, str]) -> str | None:
    value = env.get(_env_var(name))
    return value if value else None


def _from_keyring(name: str, keyring: Keyring | None) -> str | None:
    backend = keyring
    if backend is None:
        try:
            backend = _default_keyring()
        except KeyringUnavailableError:
            return None
    value = backend.get(_keyring_item(name))
    return value if value else None


def _from_file(paths: XdgPaths, name: str) -> str | None:
    """0600 fallback file; fail-closed checks mirror xdg.check_security (§12.1)."""
    target = _fallback_path(paths, name)
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode):
        raise ConfigSecurityError(f"secret fallback file is a symlink (fail-closed): {target}")
    if not stat.S_ISREG(st.st_mode):
        raise ConfigSecurityError(f"secret fallback file is not a regular file: {target}")
    if st.st_uid != os.geteuid():
        raise ConfigSecurityError(
            f"secret fallback file owned by uid {st.st_uid}, expected {os.geteuid()}: {target}"
        )
    actual = stat.S_IMODE(st.st_mode)
    if actual & ~_FALLBACK_MODE:
        raise ConfigSecurityError(
            f"secret fallback file mode {actual:04o} exceeds {_FALLBACK_MODE:04o}: {target}"
        )
    value = target.read_text(encoding="utf-8").strip()
    return value if value else None


def resolve_secret(
    name: str,
    *,
    paths: XdgPaths | None = None,
    env: Mapping[str, str] | None = None,
    keyring: Keyring | None = None,
) -> Secret:
    """Resolve ``name`` per the §12.3 order: env → keyring → 0600 file.

    The first source yielding a value wins; later sources are never
    consulted. Read-only and silent; raises :class:`SecretNotFoundError`
    (with the first-run wizard hint) when no source has the secret, and
    :class:`ConfigSecurityError` when the fallback file violates §12.1.
    """
    resolved_paths = XdgPaths.resolve() if paths is None else paths
    source_env = os.environ if env is None else env
    resolvers: tuple[Callable[[], str | None], ...] = (
        lambda: _from_env(name, source_env),
        lambda: _from_keyring(name, keyring),
        lambda: _from_file(resolved_paths, name),
    )
    for resolver in resolvers:
        value = resolver()
        if value is not None:
            return Secret(value)
    raise SecretNotFoundError(
        f"secret {name!r} not found in env ({_env_var(name)}), OS keyring "
        f"({_keyring_item(name)}), or {_fallback_path(resolved_paths, name)}; "
        f"run `lsassist setup` (first-run wizard) or export {_env_var(name)}"
    )


def store_secret(name: str, value: str, *, keyring: Keyring | None = None) -> None:
    """Write ``value`` to the OS keyring only (first-run setup wizard, ADR-004)."""
    backend = keyring if keyring is not None else _default_keyring()
    backend.set(_keyring_item(name), value)


def store_secret_file(name: str, value: str, *, paths: XdgPaths | None = None) -> Path:
    """Write the 0600 fallback file (wizard fallback when no keyring, ADR-004).

    Uses ``O_NOFOLLOW`` — a symlink at the target raises
    :class:`ConfigSecurityError` (fail-closed) instead of being followed.
    """
    resolved_paths = XdgPaths.resolve() if paths is None else paths
    secrets_dir = resolved_paths.config_home / "lsassist" / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = secrets_dir / name
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, _FALLBACK_MODE)
    except OSError as exc:
        raise ConfigSecurityError(
            f"refusing to write secret fallback file (fail-closed): {target}"
        ) from exc
    try:
        data = value.encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)
    os.chmod(target, _FALLBACK_MODE)  # pre-existing file may have had a looser mode
    return target
