"""XDG directory resolution and §12.1 layout enforcement (SPEC §12.1, §7.5).

``XdgPaths.resolve()`` is the single point where XDG base directories are
resolved (env override, else ``~/.config`` / ``~/.local/share`` /
``~/.local/state`` / ``~/.cache`` fallbacks; relative env values are invalid
per the basedir spec and ignored).

``LAYOUT`` is the declarative §12.1 table: ``(relpath, kind, mode)`` rows
where ``relpath`` is ``<root>/<path>`` with ``root`` one of
``config|data|state|cache``. The §12.1 table does not list modes for the
intermediate ``<root>/lsassist`` base directories; they are pinned to 0700
(safe default, tighter than every listed row except none). The
``config/lsassist/canary`` row comes from §19 scenario 1.

Startup checks (§12.1): ownership = current euid, permissions at most as
listed, symlink anywhere in a layout path → fail-closed
(:class:`ConfigSecurityError`). Symlink checks use per-component ``lstat``
(§7.5) — never ``stat`` on an unverified path.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

__all__ = [
    "LAYOUT",
    "ConfigSecurityError",
    "LayoutKind",
    "XdgPaths",
    "check_security",
    "ensure_layout",
]


class ConfigSecurityError(Exception):
    """Fail-closed startup error: layout violates §12.1 (symlink, ownership, mode)."""


LayoutKind = Literal["dir", "file"]

# Declarative §12.1 table (rows in parent-before-child order) + canary/ (§19.1).
LAYOUT: list[tuple[str, LayoutKind, int]] = [
    ("config/lsassist", "dir", 0o700),
    ("config/lsassist/config.toml", "file", 0o600),
    ("config/lsassist/policy.toml", "file", 0o600),
    ("config/lsassist/secrets", "dir", 0o700),
    ("config/lsassist/canary", "dir", 0o700),
    ("data/lsassist", "dir", 0o700),
    ("data/lsassist/memory.db", "file", 0o600),
    ("data/lsassist/skills", "dir", 0o700),
    ("data/lsassist/evals", "dir", 0o644),
    ("state/lsassist", "dir", 0o700),
    ("state/lsassist/audit", "dir", 0o700),
    ("state/lsassist/kernel.secret", "file", 0o600),
    ("state/lsassist/checkpoints", "dir", 0o700),
    ("cache/lsassist", "dir", 0o700),
]


def _xdg_dir(env: Mapping[str, str], var: str, default: Path) -> Path:
    value = env.get(var)
    if value and os.path.isabs(value):
        return Path(value)
    return default


@dataclass(frozen=True)
class XdgPaths:
    """Resolved XDG base directories (resolution happens only in :meth:`resolve`)."""

    config_home: Path
    data_home: Path
    state_home: Path
    cache_home: Path

    @classmethod
    def resolve(cls, env: Mapping[str, str] | None = None) -> XdgPaths:
        source: Mapping[str, str] = os.environ if env is None else env
        home = Path.home()
        return cls(
            config_home=_xdg_dir(source, "XDG_CONFIG_HOME", home / ".config"),
            data_home=_xdg_dir(source, "XDG_DATA_HOME", home / ".local" / "share"),
            state_home=_xdg_dir(source, "XDG_STATE_HOME", home / ".local" / "state"),
            cache_home=_xdg_dir(source, "XDG_CACHE_HOME", home / ".cache"),
        )

    def root(self, name: str) -> Path:
        roots = {
            "config": self.config_home,
            "data": self.data_home,
            "state": self.state_home,
            "cache": self.cache_home,
        }
        try:
            return roots[name]
        except KeyError:
            raise ValueError(f"unknown XDG root {name!r}") from None

    def layout_path(self, relpath: str) -> Path:
        """Resolve a LAYOUT relpath (``<root>/<path>``) to an absolute path."""
        root_name, _, rest = relpath.partition("/")
        return self.root(root_name) / rest


def _split(relpath: str) -> tuple[str, tuple[str, ...]]:
    root_name, _, rest = relpath.partition("/")
    return root_name, tuple(part for part in rest.split("/") if part)


def _tighten(path: Path, mode: int) -> None:
    """Chmod only when current permissions exceed the listed mode (§12.1 "at most")."""
    current = stat.S_IMODE(os.lstat(path).st_mode)
    if current & ~mode:
        os.chmod(path, mode)


def _ensure_dir(root: Path, parts: tuple[str, ...], mode: int) -> None:
    current = root
    for part in parts:
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            os.mkdir(current, mode)
            continue
        if stat.S_ISLNK(st.st_mode):
            raise ConfigSecurityError(f"layout path is a symlink (fail-closed): {current}")
        if not stat.S_ISDIR(st.st_mode):
            raise ConfigSecurityError(f"layout path is not a directory: {current}")
    _tighten(current, mode)


def _check_file(path: Path, mode: int) -> None:
    """Verify an existing LAYOUT file (symlink/kind/mode); missing files are skipped."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return  # owned by another module (kernel, memory, config writer)
    if stat.S_ISLNK(st.st_mode):
        raise ConfigSecurityError(f"layout path is a symlink (fail-closed): {path}")
    if not stat.S_ISREG(st.st_mode):
        raise ConfigSecurityError(f"layout path is not a regular file: {path}")
    _tighten(path, mode)


def ensure_layout(paths: XdgPaths) -> None:
    """Create all §12.1 directories with their listed modes; verify listed files.

    Existing looser permissions are tightened to the listed mode; tighter
    permissions are kept ("at most as listed"). Any symlink in a layout path
    raises :class:`ConfigSecurityError` (fail-closed).
    """
    for root in {paths.config_home, paths.data_home, paths.state_home, paths.cache_home}:
        root.mkdir(parents=True, exist_ok=True)
    for relpath, kind, mode in LAYOUT:
        root_name, parts = _split(relpath)
        if kind == "dir":
            _ensure_dir(paths.root(root_name), parts, mode)
        else:
            _check_file(paths.layout_path(relpath), mode)


def check_security(paths: XdgPaths) -> None:
    """Startup checks (§12.1): ownership, mode-at-most-listed, no symlinks.

    Every existing component of every layout path is ``lstat``-checked
    (§7.5); any violation raises :class:`ConfigSecurityError` (fail-closed).
    """
    euid = os.geteuid()
    for relpath, kind, mode in LAYOUT:
        root_name, parts = _split(relpath)
        current = paths.root(root_name)
        for index, part in enumerate(parts):
            current = current / part
            try:
                st = os.lstat(current)
            except FileNotFoundError:
                break  # not yet created; deeper components cannot exist either
            if stat.S_ISLNK(st.st_mode):
                raise ConfigSecurityError(f"layout path is a symlink (fail-closed): {current}")
            if st.st_uid != euid:
                raise ConfigSecurityError(
                    f"layout path owned by uid {st.st_uid}, expected {euid}: {current}"
                )
            if index == len(parts) - 1:
                if kind == "dir" and not stat.S_ISDIR(st.st_mode):
                    raise ConfigSecurityError(f"layout path is not a directory: {current}")
                if kind == "file" and not stat.S_ISREG(st.st_mode):
                    raise ConfigSecurityError(f"layout path is not a regular file: {current}")
                actual = stat.S_IMODE(st.st_mode)
                if actual & ~mode:
                    raise ConfigSecurityError(
                        f"layout path mode {actual:04o} exceeds listed {mode:04o}: {current}"
                    )
