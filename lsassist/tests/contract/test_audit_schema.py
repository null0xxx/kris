"""T4.02 RED (contract): every record a fuzzed session writes is schema-valid.

The precondition for AC-17. §14.1's journal is only tamper-evident if every line
in it parses as an :class:`AuditRecord`; a single record the writer emits but the
schema rejects makes ``verify_chain`` report MALFORMED on an untampered file,
which is the false positive that trains an operator to ignore the alarm.

Hypothesis drives the WRITER over arbitrary event sequences and payload shapes,
and the assertions run against what actually landed on disk — not against what
the writer says it wrote.
"""

from __future__ import annotations

import json
from itertools import pairwise
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lsassist.audit.schema import AuditEvent, AuditRecord, record_hash
from lsassist.audit.writer import AuditRefusedError, AuditWriter, ChainStatus, verify_chain

#: Every §14.1 event, plus the ``lab_*`` family the schema admits by pattern.
events = st.one_of(
    st.sampled_from([member.value for member in AuditEvent]),
    st.from_regex(r"\Alab_[a-z][a-z0-9_]{0,8}\Z", fullmatch=True),
)

#: JSON-shaped payloads: the writer's input contract is "anything a caller can
#: serialize", so the fuzz explores that whole space rather than a tidy corner.
json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(max_size=40),
)
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(min_size=1, max_size=12), children, max_size=4),
    ),
    max_leaves=12,
)
payloads = st.dictionaries(st.text(min_size=1, max_size=12), json_values, max_size=5)

_FUZZ = settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)


def _lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@_FUZZ
@given(sequence=st.lists(st.tuples(events, payloads), min_size=1, max_size=12))
def test_every_written_record_parses_as_an_audit_record(
    tmp_path_factory: Any, sequence: list[tuple[str, dict[str, Any]]]
) -> None:
    directory = tmp_path_factory.mktemp("audit")
    written = 0
    with AuditWriter(directory=directory, session_id="s-1") as audit:
        for event, payload in sequence:
            try:
                audit.write(event, payload, task_id="t-1")
            except AuditRefusedError:
                continue  # a refusal is a valid outcome; it must journal nothing
            written += 1

    stored = _lines(audit.path)
    assert len(stored) == written, "a refused write must leave no line behind"
    for line in stored:
        AuditRecord.model_validate(line)


@_FUZZ
@given(sequence=st.lists(st.tuples(events, payloads), min_size=1, max_size=12))
def test_a_fuzzed_session_always_verifies(
    tmp_path_factory: Any, sequence: list[tuple[str, dict[str, Any]]]
) -> None:
    """No payload a caller can supply may break the chain it is written into."""
    directory = tmp_path_factory.mktemp("audit")
    with AuditWriter(directory=directory, session_id="s-1") as audit:
        for event, payload in sequence:
            try:
                audit.write(event, payload, task_id="t-1")
            except AuditRefusedError:
                continue
    assert verify_chain(audit.path).status is ChainStatus.VALID


@_FUZZ
@given(sequence=st.lists(st.tuples(events, payloads), min_size=2, max_size=8))
def test_seq_and_prev_hash_stay_consistent(
    tmp_path_factory: Any, sequence: list[tuple[str, dict[str, Any]]]
) -> None:
    directory = tmp_path_factory.mktemp("audit")
    with AuditWriter(directory=directory, session_id="s-1") as audit:
        for event, payload in sequence:
            try:
                audit.write(event, payload, task_id="t-1")
            except AuditRefusedError:
                continue

    stored = _lines(audit.path)
    assert [row["seq"] for row in stored] == list(range(len(stored)))
    for previous, current in pairwise(stored):
        assert current["prev_hash"] == record_hash(previous)


@_FUZZ
@given(payload=payloads)
def test_no_payload_survives_into_the_journal_unredacted(
    tmp_path_factory: Any, payload: dict[str, Any]
) -> None:
    """The §14.3 pass is unconditional: whatever shape the payload takes, the
    record carries the redaction verdict rather than the caller's raw text."""
    directory = tmp_path_factory.mktemp("audit")
    with AuditWriter(directory=directory, session_id="s-1") as audit:
        try:
            audit.write("tool_result", payload, task_id="t-1")
        except AuditRefusedError:
            return
    stored = _lines(audit.path)[0]
    assert "_redaction" in stored["payload"]
    assert stored["payload_digest"].startswith("sha256:")
