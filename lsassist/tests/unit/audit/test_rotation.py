"""T4.02 RED: §14.1 rotation — 50 MB / 10 files, with the chain carried across.

§14.1: "Rotation: 50 MB / 10 files."

Rotation is where a hash chain usually breaks, because the obvious
implementation starts the new file from the genesis hash and quietly forks the
history into two internally-consistent halves. The chain must CONTINUE: the
first record of a rotated file carries the hash of the last record of the file
before it, and ``seq`` keeps counting.
"""

from __future__ import annotations

import json
from itertools import pairwise
from pathlib import Path

import pytest

from lsassist.audit.schema import GENESIS_HASH, record_hash
from lsassist.audit.writer import (
    MAX_JOURNAL_BYTES,
    MAX_JOURNAL_FILES,
    AuditWriter,
    ChainStatus,
    verify_chain,
)


def rows(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def journals(directory: Path) -> list[Path]:
    return sorted(p for p in directory.glob("session-s-1*.jsonl"))


# ==========================================================================
# 1. the §14.1 thresholds
# ==========================================================================
def test_the_thresholds_are_the_section_141_ones() -> None:
    assert MAX_JOURNAL_BYTES == 50 * 1024 * 1024
    assert MAX_JOURNAL_FILES == 10


def test_no_rotation_below_the_threshold(tmp_path: Path) -> None:
    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        for index in range(20):
            audit.write("tool_result", {"n": index}, task_id="t-1")
    assert len(journals(tmp_path)) == 1


# ==========================================================================
# 2. rotation carries the chain
# ==========================================================================
@pytest.fixture
def tiny(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rotate at a size the test can actually reach. The THRESHOLD is pinned by
    the test above; what the cases below exercise is the BEHAVIOUR at it."""
    from lsassist.audit import writer as module

    monkeypatch.setattr(module, "MAX_JOURNAL_BYTES", 512)


def test_the_journal_rotates_at_the_threshold(tmp_path: Path, tiny: None) -> None:
    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        for index in range(20):
            audit.write("tool_result", {"n": index}, task_id="t-1")
    assert len(journals(tmp_path)) > 1


def test_the_chain_continues_across_a_rotation(tmp_path: Path, tiny: None) -> None:
    """The failure this exists to prevent: a new file starting from GENESIS,
    forking one history into two internally-consistent halves."""
    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        for index in range(20):
            audit.write("tool_result", {"n": index}, task_id="t-1")

    files = journals(tmp_path)
    assert len(files) > 1
    for older, newer in pairwise(files):
        last = rows(older)[-1]
        first = rows(newer)[0]
        assert first["prev_hash"] == record_hash(last), "the chain forked at a rotation"
        assert first["prev_hash"] != GENESIS_HASH


def test_seq_keeps_counting_across_a_rotation(tmp_path: Path, tiny: None) -> None:
    """Dense and ascending across file boundaries. Not asserted to start at 0:
    the 10-file cap may already have dropped a prefix, and pretending the
    journal starts at zero is exactly the dishonesty the gap exists to avoid."""
    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        for index in range(20):
            audit.write("tool_result", {"n": index}, task_id="t-1")
    seqs = [int(row["seq"]) for path in journals(tmp_path) for row in rows(path)]
    assert seqs == list(range(seqs[0], seqs[0] + len(seqs)))


def test_each_rotated_file_verifies_on_its_own(tmp_path: Path, tiny: None) -> None:
    """§14.5's recovery path reads one file at a time."""
    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        for index in range(20):
            audit.write("tool_result", {"n": index}, task_id="t-1")
    for path in journals(tmp_path):
        assert verify_chain(path).status is ChainStatus.VALID


def test_a_rotated_file_keeps_the_0600_mode(tmp_path: Path, tiny: None) -> None:
    import stat

    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        for index in range(20):
            audit.write("tool_result", {"n": index}, task_id="t-1")
    for path in journals(tmp_path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_rotation_is_decided_before_the_write_not_after(
    tmp_path: Path, tiny: None
) -> None:
    """Checking afterwards lets one oversized record push a file past the cap
    and only then rotate — the cap would be advisory rather than enforced."""
    from lsassist.audit import writer as module

    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        for index in range(40):
            audit.write("tool_result", {"n": index, "pad": "x" * 40}, task_id="t-1")
    for path in journals(tmp_path):
        assert path.stat().st_size <= module.MAX_JOURNAL_BYTES + 2048, (
            "a file grew well past the threshold before rotating"
        )


# ==========================================================================
# 3. the 10-file cap
# ==========================================================================
def test_the_oldest_file_is_dropped_beyond_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lsassist.audit import writer as module

    monkeypatch.setattr(module, "MAX_JOURNAL_BYTES", 256)
    monkeypatch.setattr(module, "MAX_JOURNAL_FILES", 3)

    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        for index in range(60):
            audit.write("tool_result", {"n": index}, task_id="t-1")

    files = journals(tmp_path)
    assert len(files) <= 3


def test_the_surviving_files_still_verify_after_a_drop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§14.1: "rotation-ის შემდეგ ``verify_chain()`` active files-ზე valid
    რჩება". Dropping the oldest file breaks the link INTO the oldest surviving
    one — which is expected and must not be reported as tampering, so the chain
    is verified per file."""
    from lsassist.audit import writer as module

    monkeypatch.setattr(module, "MAX_JOURNAL_BYTES", 256)
    monkeypatch.setattr(module, "MAX_JOURNAL_FILES", 3)

    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        for index in range(60):
            audit.write("tool_result", {"n": index}, task_id="t-1")

    for path in journals(tmp_path):
        assert verify_chain(path).status is ChainStatus.VALID


def test_a_dropped_prefix_leaves_a_visible_seq_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Honesty about what rotation costs: history is DISCARDED, and the seq of
    the first surviving record says so rather than pretending the journal starts
    at zero."""
    from lsassist.audit import writer as module

    monkeypatch.setattr(module, "MAX_JOURNAL_BYTES", 256)
    monkeypatch.setattr(module, "MAX_JOURNAL_FILES", 3)

    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        for index in range(60):
            audit.write("tool_result", {"n": index}, task_id="t-1")

    first_surviving = rows(journals(tmp_path)[0])[0]
    assert first_surviving["seq"] > 0


def test_the_index_records_every_rotation(tmp_path: Path, tiny: None) -> None:
    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        for index in range(20):
            audit.write("tool_result", {"n": index}, task_id="t-1")
    index_rows = [
        json.loads(line)
        for line in (tmp_path / "index.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert {row["file"] for row in index_rows} >= {path.name for path in journals(tmp_path)}


def test_another_sessions_files_are_untouched_by_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cap is per SESSION: dropping another session's history because this
    one is chatty would delete an audit trail nobody asked to rotate."""
    from lsassist.audit import writer as module

    monkeypatch.setattr(module, "MAX_JOURNAL_BYTES", 256)
    monkeypatch.setattr(module, "MAX_JOURNAL_FILES", 2)

    with AuditWriter(directory=tmp_path, session_id="s-2") as other:
        other.write("intent", {"keep": True}, task_id="t-1")
    survivor = other.path

    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        for index in range(40):
            audit.write("tool_result", {"n": index}, task_id="t-1")

    assert survivor.exists()
    assert verify_chain(survivor).status is ChainStatus.VALID
