"""T4.07 store contract: §10.2 DDL, §12.1 mode, and §14.5 recovery."""

from __future__ import annotations

import sqlite3
import stat
from pathlib import Path

import pytest

from lsassist.memory import MemoryCorruptedError, MemorySecurityError, open_memory


@pytest.fixture()
def database(tmp_path: Path) -> Path:
    return tmp_path / "memory.db"


def test_open_memory_enables_wal(database: Path) -> None:
    with open_memory(database) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)


def test_open_memory_enables_foreign_keys(database: Path) -> None:
    with open_memory(database) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone() == (1,)


@pytest.mark.parametrize("table", ["prefs", "episodic", "sessions"])
def test_schema_contains_required_table(database: Path, table: str) -> None:
    with open_memory(database) as connection:
        row = connection.execute(
            "SELECT type FROM sqlite_master WHERE name = ?", (table,)
        ).fetchone()
    assert row == ("table",)


def test_schema_contains_external_content_fts5_table(database: Path) -> None:
    with open_memory(database) as connection:
        sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'episodic_fts'"
        ).fetchone()[0]
    normalized = " ".join(sql.lower().split())
    assert "virtual table episodic_fts using fts5" in normalized
    assert "content='episodic'" in normalized
    assert "content_rowid='id'" in normalized


def test_prefs_columns_match_spec(database: Path) -> None:
    with open_memory(database) as connection:
        columns = {
            row[1]: (row[2], row[3], row[4], row[5])
            for row in connection.execute("PRAGMA table_info(prefs)")
        }
    assert columns == {
        "id": ("INTEGER", 0, None, 1),
        "key": ("TEXT", 1, None, 0),
        "value": ("TEXT", 1, None, 0),
        "provenance": ("TEXT", 1, None, 0),
        "confidence": ("REAL", 1, "1.0", 0),
        "sensitivity": ("TEXT", 1, "'normal'", 0),
        "created_at": ("TEXT", 1, None, 0),
        "updated_at": ("TEXT", 1, None, 0),
        "ttl": ("TEXT", 0, None, 0),
    }


def test_episodic_columns_match_spec(database: Path) -> None:
    with open_memory(database) as connection:
        columns = {
            row[1]: (row[2], row[3], row[4], row[5])
            for row in connection.execute("PRAGMA table_info(episodic)")
        }
    assert columns == {
        "id": ("INTEGER", 0, None, 1),
        "session_id": ("TEXT", 1, None, 0),
        "task_summary": ("TEXT", 1, None, 0),
        "verdict": ("TEXT", 0, None, 0),
        "evidence_refs": ("TEXT", 0, None, 0),
        "provenance": ("TEXT", 1, "'kernel'", 0),
        "created_at": ("TEXT", 1, None, 0),
        "archived": ("INTEGER", 1, "0", 0),
    }


def test_sessions_columns_match_spec(database: Path) -> None:
    with open_memory(database) as connection:
        columns = {
            row[1]: (row[2], row[3], row[4], row[5])
            for row in connection.execute("PRAGMA table_info(sessions)")
        }
    assert columns == {
        "session_id": ("TEXT", 0, None, 1),
        "state_json": ("TEXT", 1, None, 0),
        "journal_seq": ("INTEGER", 1, None, 0),
        "checkpoint_ref": ("TEXT", 0, None, 0),
        "updated_at": ("TEXT", 1, None, 0),
    }


def _insert_pref(connection: sqlite3.Connection, **overrides: object) -> None:
    values = {
        "key": "editor",
        "value": "vim",
        "provenance": "user",
        "sensitivity": "normal",
        "created_at": "2026-08-09T00:00:00Z",
        "updated_at": "2026-08-09T00:00:00Z",
        **overrides,
    }
    connection.execute(
        """INSERT INTO prefs
        (key, value, provenance, sensitivity, created_at, updated_at)
        VALUES (:key, :value, :provenance, :sensitivity, :created_at, :updated_at)""",
        values,
    )


@pytest.mark.parametrize("provenance", ["kernel", "model", "unknown"])
def test_prefs_rejects_unknown_provenance(database: Path, provenance: str) -> None:
    with (
        open_memory(database) as connection,
        pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"),
    ):
        _insert_pref(connection, provenance=provenance)


@pytest.mark.parametrize("sensitivity", ["secret", "private", "unknown"])
def test_prefs_rejects_unknown_sensitivity(database: Path, sensitivity: str) -> None:
    with (
        open_memory(database) as connection,
        pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"),
    ):
        _insert_pref(connection, sensitivity=sensitivity)


def test_prefs_key_is_unique(database: Path) -> None:
    with open_memory(database) as connection:
        _insert_pref(connection)
        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE constraint failed"):
            _insert_pref(connection, value="neovim")


def test_database_file_is_created_with_mode_0600(database: Path) -> None:
    with open_memory(database):
        pass
    assert stat.S_IMODE(database.stat().st_mode) == 0o600


def test_default_path_uses_xdg_data_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data_home = tmp_path / "data"
    monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    with open_memory() as connection:
        path = connection.execute("PRAGMA database_list").fetchone()[2]
    assert Path(path) == data_home / "lsassist" / "memory.db"


def test_symlinked_database_is_refused(database: Path, tmp_path: Path) -> None:
    target = tmp_path / "target.db"
    target.write_bytes(b"")
    database.symlink_to(target)
    with pytest.raises(MemorySecurityError, match=r"symlink.*fail-closed"):
        open_memory(database)


def test_explicit_database_path_with_symlinked_ancestor_is_refused(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-data"
    real_parent.mkdir()
    (real_parent / "nested").mkdir()
    linked_parent = tmp_path / "linked-data"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(MemorySecurityError, match=r"ancestor.*symlink.*fail-closed"):
        open_memory(linked_parent / "nested" / "memory.db")

    assert not (real_parent / "nested" / "memory.db").exists()


def test_symlinked_xdg_data_home_is_refused_before_layout_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_data_home = tmp_path / "real-data"
    real_data_home.mkdir()
    linked_data_home = tmp_path / "linked-data"
    linked_data_home.symlink_to(real_data_home, target_is_directory=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(linked_data_home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    with pytest.raises(MemorySecurityError, match=r"ancestor.*symlink.*fail-closed"):
        open_memory()

    assert not (real_data_home / "lsassist").exists()


def test_ancestor_swap_before_sqlite_open_cannot_redirect_database_or_wal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    original_connect = sqlite3.connect
    swapped = False

    def swap_then_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        nonlocal swapped
        if not swapped:
            swapped = True
            data.rename(tmp_path / "authorized-data")
            data.symlink_to(redirected, target_is_directory=True)
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", swap_then_connect)
    connection = open_memory(data / "memory.db")
    try:
        connection.execute(
            """INSERT INTO prefs
            (key, value, provenance, created_at, updated_at)
            VALUES ('shell', 'bash', 'user', '2026-08-09', '2026-08-09')"""
        )
        connection.commit()
        assert (tmp_path / "authorized-data" / "memory.db-wal").is_file()
        assert (tmp_path / "authorized-data" / "memory.db-shm").is_file()
        assert connection.execute("SELECT value FROM prefs WHERE key = 'shell'").fetchone() == (
            "bash",
        )
    finally:
        connection.close()

    assert not (redirected / "memory.db").exists()
    assert not (redirected / "memory.db-wal").exists()
    assert not (redirected / "memory.db-shm").exists()


def test_leaf_swap_before_sqlite_open_cannot_redirect_database_or_wal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    database = data / "memory.db"
    authorized_database = data / "authorized-memory.db"
    original_connect = sqlite3.connect
    swapped = False

    def swap_then_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        nonlocal swapped
        if not swapped:
            swapped = True
            database.rename(authorized_database)
            database.symlink_to(redirected / "memory.db")
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", swap_then_connect)
    connection = open_memory(database)
    try:
        connection.execute(
            """INSERT INTO prefs
            (key, value, provenance, created_at, updated_at)
            VALUES ('terminal', 'zellij', 'user', '2026-08-09', '2026-08-09')"""
        )
        connection.commit()
        assert authorized_database.is_file()
        assert (data / "authorized-memory.db-wal").is_file()
        assert (data / "authorized-memory.db-shm").is_file()
    finally:
        connection.close()

    assert not (redirected / "memory.db").exists()
    assert not (redirected / "memory.db-wal").exists()
    assert not (redirected / "memory.db-shm").exists()


def test_missing_proc_fd_authority_fails_closed(
    database: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "lsassist.memory.store._PROC_SELF_FD", tmp_path / "missing-proc-fd", raising=False
    )
    with pytest.raises(MemorySecurityError, match=r"proc/self/fd.*unavailable.*fail-closed"):
        open_memory(database)


def test_corrupted_database_fails_closed_with_recovery_guidance(database: Path) -> None:
    connection = open_memory(database)
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.close()
    original = database.read_bytes()
    database.write_bytes(original[:100] + bytes([original[100] ^ 0xFF]) + original[101:])
    with pytest.raises(MemoryCorruptedError) as caught:
        open_memory(database)
    message = str(caught.value).lower()
    assert "restore from the latest session checkpoint" in message
    assert "rebuild memory from the episodic archive" in message
    assert "user has been informed" in message


def test_integrity_check_runs_on_every_open(
    database: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with open_memory(database):
        pass
    original_connect = sqlite3.connect
    statements: list[str] = []

    def traced_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        connection = original_connect(*args, **kwargs)
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(sqlite3, "connect", traced_connect)
    with open_memory(database):
        pass
    assert any(statement.lower().startswith("pragma integrity_check") for statement in statements)
