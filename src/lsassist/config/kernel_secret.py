"""Kernel secret (SPEC §7.4).

``$XDG_STATE_HOME/lsassist/kernel.secret`` — the HMAC key for approval
tokens. 32 random bytes, generated at install/first run with
``secrets.token_bytes(32)`` via ``os.open(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,
0o600)``; generation is idempotent (a second load returns the same bytes,
the file is never rewritten).

Startup load is fail-closed: :func:`lsassist.config.xdg.check_security`
re-validates the whole §12.1 chain (ownership = current euid, mode at most
0600, no symlink anywhere in the path), the read itself uses ``O_NOFOLLOW``
with an ``fstat`` re-check (§7.5 TOCTOU), and the content must be exactly
:data:`KERNEL_SECRET_LEN` bytes. Any violation raises
:class:`ConfigSecurityError`.

This secret is kernel-local: it is entirely independent of the Kimi API-key
resolver chain (``lsassist.config.secrets``) — no env var, no keyring — and
materializes only in kernel memory.
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

from lsassist.config.xdg import ConfigSecurityError, XdgPaths, check_security

__all__ = ["KERNEL_SECRET_LEN", "load_or_generate_kernel_secret"]

KERNEL_SECRET_LEN = 32
_FILE_MODE = 0o600


def _kernel_secret_path(paths: XdgPaths) -> Path:
    return paths.state_home / "lsassist" / "kernel.secret"


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _generate(paths: XdgPaths, target: Path) -> bytes:
    """First-run generation: 32 random bytes, O_EXCL|O_NOFOLLOW, mode 0600."""
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    secret = secrets.token_bytes(KERNEL_SECRET_LEN)
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, _FILE_MODE)
    except FileExistsError:
        return _load(paths, target)  # lost a first-run race; load the winner's file
    try:
        _write_all(fd, secret)
    finally:
        os.close(fd)
    return secret


def _load(paths: XdgPaths, target: Path) -> bytes:
    """Startup load: §12.1 chain checks + O_NOFOLLOW read + exact-length check."""
    check_security(paths)  # ownership / mode-at-most / no symlink, per-component lstat
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ConfigSecurityError(f"kernel.secret unreadable (fail-closed): {target}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigSecurityError(f"kernel.secret is not a regular file: {target}")
        if st.st_uid != os.geteuid():
            raise ConfigSecurityError(
                f"kernel.secret owned by uid {st.st_uid}, expected {os.geteuid()}: {target}"
            )
        actual = stat.S_IMODE(st.st_mode)
        if actual & ~_FILE_MODE:
            raise ConfigSecurityError(
                f"kernel.secret mode {actual:04o} exceeds {_FILE_MODE:04o}: {target}"
            )
        data = os.read(fd, KERNEL_SECRET_LEN + 1)
    finally:
        os.close(fd)
    if len(data) != KERNEL_SECRET_LEN:
        raise ConfigSecurityError(
            f"kernel.secret must be exactly {KERNEL_SECRET_LEN} bytes, got {len(data)}: {target}"
        )
    return data


def load_or_generate_kernel_secret(paths: XdgPaths | None = None) -> bytes:
    """Return the kernel secret, generating it on first run (§7.4).

    Load path is ownership/mode/symlink/length-checked at every call
    ("ownership-checked at startup"); generation happens only when the file
    is absent and is idempotent thereafter.
    """
    resolved_paths = XdgPaths.resolve() if paths is None else paths
    target = _kernel_secret_path(resolved_paths)
    if os.path.lexists(target):
        return _load(resolved_paths, target)
    return _generate(resolved_paths, target)
