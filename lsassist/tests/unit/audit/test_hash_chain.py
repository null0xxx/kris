"""T4.02 RED: the §14.1 hash chain — tamper-evident, and it names the position.

§14.1: "hash-chained: თითო record შეიცავს ``prev_hash`` → tamper-evident
(truncation/rewrite detectable)."

Detectable is the weak reading. A chain that only answers "something is wrong"
leaves an operator with a 50 MB file and no idea where to look, so
:func:`verify_chain` reports the exact record. The three §14.1 tamper vectors —
byte MUTATION, TRUNCATION, and REWRITE (a record replaced with a well-formed
one) — each get their own case, because they fail in different places: mutation
and rewrite break the link at the FOLLOWING record, truncation breaks nothing at
all inside the file and is only visible as a missing continuation.
"""

from __future__ import annotations

import json
from itertools import pairwise
from pathlib import Path

import pytest

from lsassist.audit.schema import GENESIS_HASH, canonical_bytes, record_hash
from lsassist.audit.writer import AuditWriter, ChainStatus, verify_chain


def journal(directory: Path, count: int = 5) -> Path:
    writer = AuditWriter(directory=directory, session_id="s-1")
    try:
        for index in range(count):
            writer.write("tool_result", {"n": index}, task_id="t-1")
    finally:
        writer.close()
    return writer.path


def lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def rewrite(path: Path, rows: list[str]) -> None:
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


# ==========================================================================
# 1. a clean chain
# ==========================================================================
def test_each_record_carries_the_previous_records_hash(tmp_path: Path) -> None:
    path = journal(tmp_path)
    rows = [json.loads(line) for line in lines(path)]

    assert rows[0]["prev_hash"] == GENESIS_HASH
    for previous, current in pairwise(rows):
        assert current["prev_hash"] == record_hash(previous)


def test_seq_numbers_are_dense_and_ascending(tmp_path: Path) -> None:
    rows = [json.loads(line) for line in lines(journal(tmp_path))]
    assert [row["seq"] for row in rows] == list(range(len(rows)))


def test_verify_chain_accepts_a_clean_journal(tmp_path: Path) -> None:
    verdict = verify_chain(journal(tmp_path))
    assert verdict.status is ChainStatus.VALID
    assert verdict.broken_at is None
    assert verdict.records == 5


def test_verify_chain_accepts_an_empty_journal(tmp_path: Path) -> None:
    """A session that wrote nothing is not a broken session."""
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    verdict = verify_chain(empty)
    assert verdict.status is ChainStatus.VALID
    assert verdict.records == 0


# ==========================================================================
# 2. the three §14.1 tamper vectors
# ==========================================================================
def test_a_byte_mutation_in_the_middle_is_detected_at_its_position(
    tmp_path: Path,
) -> None:
    path = journal(tmp_path)
    rows = lines(path)
    tampered = json.loads(rows[2])
    tampered["payload"] = {"n": 999}
    rows[2] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    rewrite(path, rows)

    verdict = verify_chain(path)
    assert verdict.status is ChainStatus.BROKEN
    assert verdict.broken_at == 3, "the LINK breaks at the record that follows the edit"


def test_a_truncated_journal_is_detected(tmp_path: Path) -> None:
    """Truncation leaves every surviving link intact, so it is only visible
    against the chain's own record of how far it got."""
    path = journal(tmp_path)
    rows = lines(path)
    rewrite(path, rows[:3])

    verdict = verify_chain(path, expected_records=5)
    assert verdict.status is ChainStatus.TRUNCATED
    assert verdict.records == 3


def test_truncation_is_not_reported_without_an_expectation(tmp_path: Path) -> None:
    """The counterweight: a journal being read while it is still being written
    is short, not broken. Only a caller who knows the expected length can tell
    the difference, so the check is opt-in rather than a guess."""
    path = journal(tmp_path)
    rewrite(path, lines(path)[:3])
    assert verify_chain(path).status is ChainStatus.VALID


def test_a_rewritten_record_is_detected_even_when_well_formed(tmp_path: Path) -> None:
    """The dangerous vector: the attacker keeps the file parseable and the seq
    numbers dense, and only changes what the record SAYS."""
    path = journal(tmp_path)
    rows = lines(path)
    forged = json.loads(rows[1])
    forged["event"] = "verdict"
    forged["payload"] = {"status": "VERIFIED"}
    rows[1] = json.dumps(forged, sort_keys=True, separators=(",", ":"))
    rewrite(path, rows)

    verdict = verify_chain(path)
    assert verdict.status is ChainStatus.BROKEN
    assert verdict.broken_at == 2


def test_rewriting_a_record_AND_its_successor_link_is_still_detected(
    tmp_path: Path,
) -> None:
    """Repairing the immediate link does not repair the chain: the fix changes
    the successor, whose own hash then fails to match ITS successor. Without a
    kernel secret the chain is tamper-EVIDENT, not tamper-PROOF — an attacker
    who rewrites every record from the edit to the end produces a consistent
    file, which is why §14.1 pairs it with 0600 permissions and why this test
    documents the boundary rather than claiming more."""
    path = journal(tmp_path)
    rows = [json.loads(line) for line in lines(path)]
    rows[1]["payload"] = {"n": 999}
    rows[2]["prev_hash"] = record_hash(rows[1])
    rewrite(path, [json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows])

    verdict = verify_chain(path)
    assert verdict.status is ChainStatus.BROKEN
    assert verdict.broken_at == 3, "the break simply moves one record along"


def test_a_reordered_journal_is_detected(tmp_path: Path) -> None:
    path = journal(tmp_path)
    rows = lines(path)
    rows[1], rows[2] = rows[2], rows[1]
    rewrite(path, rows)
    assert verify_chain(path).status is ChainStatus.BROKEN


def test_an_appended_forgery_is_detected(tmp_path: Path) -> None:
    """Append-only does not mean append-safe: anyone who can write to the file
    can add a line."""
    path = journal(tmp_path)
    rows = lines(path)
    forged = json.loads(rows[-1])
    forged["seq"] = forged["seq"] + 1
    forged["payload"] = {"n": "injected"}
    rows.append(json.dumps(forged, sort_keys=True, separators=(",", ":")))
    rewrite(path, rows)
    assert verify_chain(path).status is ChainStatus.BROKEN


# ==========================================================================
# 3. malformed input is a verdict, never an exception
# ==========================================================================
@pytest.mark.parametrize("garbage", ["{not json", "[]", '"a string"', "null", "42"])
def test_an_unparseable_line_is_reported_not_raised(tmp_path: Path, garbage: str) -> None:
    """``verify_chain`` runs on a journal an attacker may have touched. Raising
    would make the recovery path (§14.5) crash on exactly the input it exists to
    diagnose."""
    path = journal(tmp_path)
    rows = lines(path)
    rows[2] = garbage
    rewrite(path, rows)

    verdict = verify_chain(path)
    assert verdict.status is ChainStatus.MALFORMED
    assert verdict.broken_at == 2


def test_a_schema_invalid_record_is_reported_not_raised(tmp_path: Path) -> None:
    path = journal(tmp_path)
    rows = lines(path)
    row = json.loads(rows[2])
    row["event"] = "not_a_real_event"
    rows[2] = json.dumps(row, sort_keys=True, separators=(",", ":"))
    rewrite(path, rows)

    verdict = verify_chain(path)
    assert verdict.status is ChainStatus.MALFORMED
    assert verdict.broken_at == 2


def test_a_missing_journal_is_reported_not_raised(tmp_path: Path) -> None:
    verdict = verify_chain(tmp_path / "absent.jsonl")
    assert verdict.status is ChainStatus.MALFORMED
    assert verdict.records == 0


def test_a_blank_line_does_not_break_the_chain(tmp_path: Path) -> None:
    """A trailing newline is normal JSONL; an interior blank line is not data."""
    path = journal(tmp_path)
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert verify_chain(path).status is ChainStatus.VALID


def test_the_chain_survives_a_writer_restart(tmp_path: Path) -> None:
    """A new writer over an existing journal must continue the chain, not
    restart it — otherwise every process restart silently forks the history."""
    first = AuditWriter(directory=tmp_path, session_id="s-1")
    first.write("intent", {"n": 0}, task_id="t-1")
    first.close()

    second = AuditWriter(directory=tmp_path, session_id="s-1")
    second.write("verdict", {"n": 1}, task_id="t-1")
    second.close()

    verdict = verify_chain(second.path)
    assert verdict.status is ChainStatus.VALID
    assert verdict.records == 2
    rows = [json.loads(line) for line in lines(second.path)]
    assert rows[1]["seq"] == 1
    assert rows[1]["prev_hash"] == record_hash(rows[0])


def test_canonical_bytes_of_a_stored_row_matches_the_written_line(
    tmp_path: Path,
) -> None:
    """The line on disk IS the canonical serialization — a reader must not have
    to guess how to re-derive the bytes that were hashed."""
    from lsassist.audit.schema import AuditRecord

    path = journal(tmp_path, count=1)
    line = lines(path)[0]
    assert canonical_bytes(AuditRecord.model_validate_json(line)).decode() == line


def test_a_seq_gap_inside_one_file_is_reported(tmp_path: Path) -> None:
    """A dense ``seq`` is part of the chain's claim: a hole means a record was
    removed, even if every surviving link still hashes correctly."""
    path = journal(tmp_path)
    rows_ = [json.loads(line) for line in lines(path)]
    rows_[3]["seq"] = 99
    rows_[3] = json.loads(json.dumps(rows_[3]))
    # re-link so ONLY the seq is wrong, isolating the check under test
    from lsassist.audit.schema import record_hash as rh

    for index in range(1, len(rows_)):
        if index != 3:
            rows_[index]["prev_hash"] = rh(rows_[index - 1])
    rows_[3]["prev_hash"] = rh(rows_[2])
    rows_[4]["prev_hash"] = rh(rows_[3])
    rewrite(path, [json.dumps(r, sort_keys=True, separators=(",", ":")) for r in rows_])

    verdict = verify_chain(path)
    assert verdict.status is ChainStatus.BROKEN
    assert verdict.broken_at == 3
