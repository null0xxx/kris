"""Fail-closed opening of the SQLite memory database (SPEC §§10.2, 12.1, 14.5)."""

from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import suppress
from pathlib import Path
from typing import Final

from lsassist.config.xdg import XdgPaths
from lsassist.memory.migrations import UnknownSchemaVersionError, migrate

__all__ = [
    "MemoryCorruptedError",
    "MemorySecurityError",
    "MemoryStoreError",
    "open_memory",
]

_DATABASE_MODE: Final = 0o600
_CREATE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_CHECK_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_PROC_SELF_FD: Final = Path("/proc/self/fd")
_RECOVERY_GUIDANCE: Final = (
    "Restore from the latest session checkpoint, then rebuild memory from the episodic "
    "archive; the user has been informed."
)


class MemoryStoreError(RuntimeError):
    """Base error for memory-store startup failures."""


class MemorySecurityError(MemoryStoreError):
    """The database path violates the §12.1 fail-closed boundary."""


class MemoryCorruptedError(MemoryStoreError):
    """SQLite rejected the database or its startup integrity check failed."""


class _MemoryConnection(sqlite3.Connection):
    """Connection that keeps the authorized parent and database descriptors alive."""

    _authority_fds: tuple[int, ...] = ()

    def bind_authority(self, *descriptors: int) -> None:
        self._authority_fds = descriptors

    def _release_authority(self) -> None:
        for descriptor in self._authority_fds:
            with suppress(OSError):
                os.close(descriptor)
        self._authority_fds = ()

    def close(self) -> None:
        try:
            super().close()
        finally:
            self._release_authority()

    def __del__(self) -> None:
        with suppress(Exception):
            super().close()
        self._release_authority()


def _open_parent_authority(path: Path, *, secure_final: bool) -> int:
    """Open ``path`` component-wise with openat/O_NOFOLLOW, creating missing dirs."""
    absolute = Path(os.path.abspath(path))
    descriptor = os.open(absolute.anchor, _DIRECTORY_FLAGS)
    try:
        for part in absolute.parts[1:]:
            try:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=descriptor)
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as exc:
                raise MemorySecurityError(
                    f"memory database ancestor is a symlink or unsafe directory "
                    f"(fail-closed): {absolute}"
                ) from exc
            os.close(descriptor)
            descriptor = child

        if secure_final:
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid():
                raise MemorySecurityError(
                    f"memory database directory is owned by uid {info.st_uid}, "
                    f"expected {os.geteuid()}: {absolute}"
                )
            mode = stat.S_IMODE(info.st_mode)
            if mode & ~0o700:
                os.fchmod(descriptor, 0o700)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _secure_file(parent_fd: int, name: str, display_path: Path) -> int:
    """Open the DB leaf with O_NOFOLLOW relative to pinned parent authority."""
    try:
        descriptor = os.open(name, _CREATE_FLAGS, _DATABASE_MODE, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        created = False
        try:
            descriptor = os.open(name, _CHECK_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            raise MemorySecurityError(
                f"memory database path is a symlink or unsafe file (fail-closed): {display_path}"
            ) from exc
    except OSError as exc:
        raise MemorySecurityError(
            f"cannot create memory database safely: {display_path}: {exc}"
        ) from exc

    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise MemorySecurityError(f"memory database is not a regular file: {display_path}")
        if info.st_uid != os.geteuid():
            raise MemorySecurityError(
                f"memory database is owned by uid {info.st_uid}, expected {os.geteuid()}: "
                f"{display_path}"
            )
        mode = stat.S_IMODE(info.st_mode)
        if created:
            os.fchmod(descriptor, _DATABASE_MODE)
        elif mode & ~_DATABASE_MODE:
            raise MemorySecurityError(
                f"memory database mode {mode:04o} exceeds listed 0600: {display_path}"
            )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _descriptor_path(descriptor: int) -> str:
    """Return Linux's descriptor-backed path or fail before SQLite can open."""
    path = _PROC_SELF_FD / str(descriptor)
    try:
        os.stat(path)
    except OSError as exc:
        raise MemorySecurityError(
            "Linux /proc/self/fd authority is unavailable; refusing memory startup (fail-closed)"
        ) from exc
    return os.fspath(path)


def _check_integrity(connection: sqlite3.Connection) -> None:
    results = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
    if results != ["ok"]:
        detail = "; ".join(results) if results else "no result"
        raise MemoryCorruptedError(
            f"memory database integrity_check failed ({detail}). {_RECOVERY_GUIDANCE}"
        )


def open_memory(path: str | os.PathLike[str] | None = None) -> sqlite3.Connection:
    """Open, migrate, and integrity-check ``memory.db`` before returning it.

    With no explicit path, the database resolves to
    ``$XDG_DATA_HOME/lsassist/memory.db`` through the project's §12.1 XDG
    layout implementation. The returned connection is owned by the caller.
    """
    if path is None:
        database = XdgPaths.resolve().data_home / "lsassist" / "memory.db"
        secure_parent = True
    else:
        database = Path(path).expanduser()
        secure_parent = False
    database = Path(os.path.abspath(database))
    parent_fd = _open_parent_authority(database.parent, secure_final=secure_parent)
    database_fd = -1
    connection: _MemoryConnection | None = None
    try:
        database_fd = _secure_file(parent_fd, database.name, database)
        # Python's sqlite3.connect() cannot pass SQLITE_OPEN_NOFOLLOW. Opening
        # the already-authorized database descriptor through Linux procfs is
        # the equivalent atomic boundary: a later replacement of the public
        # leaf cannot change which inode SQLite opens. SQLite resolves that
        # descriptor to the inode's current name, keeping WAL/SHM beside the
        # authorized database after an ancestor or leaf rename.
        authority_path = _descriptor_path(database_fd)
        connection = sqlite3.connect(authority_path, factory=_MemoryConnection)
        connection.bind_authority(parent_fd, database_fd)
        parent_fd = -1
        database_fd = -1
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        migrate(connection)
        _check_integrity(connection)
        return connection
    except UnknownSchemaVersionError:
        if connection is not None:
            connection.close()
        raise
    except MemoryStoreError:
        if connection is not None:
            connection.close()
        raise
    except sqlite3.DatabaseError as exc:
        if connection is not None:
            connection.close()
        raise MemoryCorruptedError(
            f"memory database is corrupted; startup stopped fail-closed. {_RECOVERY_GUIDANCE}"
        ) from exc
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
        if database_fd >= 0:
            os.close(database_fd)
