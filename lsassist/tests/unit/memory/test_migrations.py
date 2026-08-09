"""T4.07 migration contract: transactional, ordered, idempotent, fail-closed."""

from __future__ import annotations

import sqlite3
import threading
import tomllib
from pathlib import Path

import pytest

from lsassist.memory import migrations as migration_module
from lsassist.memory.migrations import (
    CURRENT_SCHEMA_VERSION,
    MIGRATIONS,
    UnknownSchemaVersionError,
    get_schema_version,
    migrate,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture()
def connection(tmp_path: Path) -> sqlite3.Connection:
    database = sqlite3.connect(tmp_path / "migration.db")
    yield database
    database.close()


def test_schema_migrations_table_is_created(connection: sqlite3.Connection) -> None:
    migrate(connection)
    row = connection.execute(
        "SELECT type FROM sqlite_master WHERE name = 'schema_migrations'"
    ).fetchone()
    assert row == ("table",)


def test_migrate_zero_to_one_applies_v1_schema(connection: sqlite3.Connection) -> None:
    assert get_schema_version(connection) == 0
    migrate(connection)
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
        )
    }
    assert {"prefs", "episodic", "episodic_fts", "sessions"} <= tables
    assert get_schema_version(connection) == 1


def test_migrate_records_applied_version_and_timestamp(connection: sqlite3.Connection) -> None:
    migrate(connection)
    row = connection.execute("SELECT version, applied_at FROM schema_migrations").fetchone()
    assert row[0] == 1
    assert row[1].endswith("Z")


def test_migration_list_is_ordered_and_complete() -> None:
    assert [version for version, _sql in MIGRATIONS] == list(range(1, CURRENT_SCHEMA_VERSION + 1))


def test_migrate_is_idempotent(connection: sqlite3.Connection) -> None:
    migrate(connection)
    first = connection.execute("SELECT version, applied_at FROM schema_migrations").fetchall()
    migrate(connection)
    second = connection.execute("SELECT version, applied_at FROM schema_migrations").fetchall()
    assert second == first


def test_concurrent_migrator_rereads_version_after_acquiring_lock(tmp_path: Path) -> None:
    path = tmp_path / "concurrent.db"
    leader = sqlite3.connect(path)
    follower = sqlite3.connect(path, check_same_thread=False, timeout=5)
    leader.execute("PRAGMA journal_mode=WAL")
    follower.execute("PRAGMA journal_mode=WAL")
    lock_attempted = threading.Event()
    errors: list[BaseException] = []
    follower.set_trace_callback(
        lambda sql: lock_attempted.set() if sql == "BEGIN IMMEDIATE" else None
    )
    leader.execute("BEGIN IMMEDIATE")

    def run_follower() -> None:
        try:
            migrate(follower)
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=run_follower)
    worker.start()
    assert lock_attempted.wait(2), "follower never attempted the migration lock"
    for statement in migration_module._statements(MIGRATIONS[0][1]):
        leader.execute(statement)
    leader.execute("INSERT INTO schema_migrations VALUES (1, 'leader')")
    leader.commit()
    worker.join(5)
    leader.close()
    follower.close()

    assert not worker.is_alive()
    assert errors == []


def test_unknown_newer_version_is_rejected_with_exact_message(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT)"
    )
    connection.execute("INSERT INTO schema_migrations VALUES (2, 'future')")
    connection.commit()
    with pytest.raises(
        UnknownSchemaVersionError,
        match=(
            r"^memory database schema version 2 is newer than supported version 1; "
            r"refusing to start$"
        ),
    ):
        migrate(connection)


def test_schema_sql_is_declared_as_package_data() -> None:
    """A non-editable wheel must include the SQL that migrations load at import."""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = pyproject["tool"]["setuptools"]["package-data"]
    globs = package_data["lsassist.memory"]
    assert any(Path("schema.sql").match(pattern) for pattern in globs), (
        f"memory/schema.sql is not covered by {globs}"
    )


def test_failed_migration_rolls_back_all_changes(
    connection: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "lsassist.memory.migrations.MIGRATIONS",
        [(1, "CREATE TABLE transient (id INTEGER); INVALID SQL;")],
    )
    with pytest.raises(sqlite3.DatabaseError):
        migrate(connection)
    assert (
        connection.execute("SELECT name FROM sqlite_master WHERE name = 'transient'").fetchone()
        is None
    )
    assert (
        connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'schema_migrations'"
        ).fetchone()
        is None
    )
