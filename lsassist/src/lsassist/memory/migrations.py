"""Ordered, transactional SQLite schema migrations for the memory store.

V1 is intentionally loaded from :mod:`schema.sql`: that file mirrors SPEC
§10.2 verbatim, followed only by the migration ledger required by T4.07.
Schema versions newer than this binary understands are refused at startup.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "MIGRATIONS",
    "UnknownSchemaVersionError",
    "get_schema_version",
    "migrate",
]


class UnknownSchemaVersionError(RuntimeError):
    """The database was written by a newer, unsupported lsassist version."""


_SCHEMA_PATH: Final = Path(__file__).with_name("schema.sql")
_SCHEMA_V1: Final = _SCHEMA_PATH.read_text(encoding="utf-8")

# PRAGMAs are connection state, not schema changes. ``migrate`` applies them
# before opening the DDL transaction; the remaining text is exactly the DDL in
# schema.sql and is executed statement-by-statement in one transaction.
_V1_PRAGMA_PREFIX: Final = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"
if not _SCHEMA_V1.startswith(_V1_PRAGMA_PREFIX):
    raise RuntimeError("memory/schema.sql must begin with the SPEC §10.2 PRAGMAs")

MIGRATIONS: list[tuple[int, str]] = [(1, _SCHEMA_V1.removeprefix(_V1_PRAGMA_PREFIX))]
CURRENT_SCHEMA_VERSION: Final = MIGRATIONS[-1][0]


def _statements(sql: str) -> Iterator[str]:
    """Yield complete SQLite statements without weakening transaction control."""
    pending = ""
    for line in sql.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statement = pending.strip()
            if statement:
                yield statement
            pending = ""
    if pending.strip():
        raise sqlite3.DatabaseError("incomplete SQL in memory migration")


def get_schema_version(connection: sqlite3.Connection) -> int:
    """Return the highest applied schema version, or zero for a fresh database."""
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    if exists is None:
        return 0
    row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    return 0 if row is None or row[0] is None else int(row[0])


def migrate(connection: sqlite3.Connection) -> int:
    """Apply every pending migration atomically and return the resulting version.

    Each version is its own transaction. A failed DDL statement and its ledger
    row are rolled back together, so restarting can safely retry that version.
    """
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")

    current = get_schema_version(connection)
    if current > CURRENT_SCHEMA_VERSION:
        raise UnknownSchemaVersionError(
            f"memory database schema version {current} is newer than supported version "
            f"{CURRENT_SCHEMA_VERSION}; refusing to start"
        )

    for version, sql in MIGRATIONS:
        if version <= current:
            continue
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = get_schema_version(connection)
            if current > CURRENT_SCHEMA_VERSION:
                raise UnknownSchemaVersionError(
                    f"memory database schema version {current} is newer than supported version "
                    f"{CURRENT_SCHEMA_VERSION}; refusing to start"
                )
            if version <= current:
                connection.commit()
                continue
            for statement in _statements(sql):
                connection.execute(statement)
            applied_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, applied_at),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        current = version
    return current
