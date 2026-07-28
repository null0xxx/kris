"""T4.02 RED: the §14.1 append-only writer — fsync policy, permissions, redaction.

§14.1: "Append-only JSONL, ერთი ფაილი session-ზე + global index; hash-chained
… fsync policy: on every ``approval``, ``verdict``, ``policy_decision(deny)``
event; batched otherwise."
§12.1: the audit store is dir 0700, files 0600.
§14.1 **Never recorded:** secrets, full sensitive file bodies, chain-of-thought /
``reasoning_content`` (I16), raw prompts beyond a redacted summary + digest.

The never-recorded list is enforced as a REFUSAL, not a filter. A writer that
silently drops a forbidden key still accepts the call, so the caller believes it
journalled something it did not; and a caller that can be wrong about what
reached the journal is a caller that cannot be audited.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from lsassist.audit.redactor import CLASS_ENGINE_ERROR, Redactor
from lsassist.audit.writer import (
    FSYNC_EVENTS,
    NEVER_RECORDED_KEYS,
    AuditRefusedError,
    AuditWriteError,
    AuditWriter,
)
from lsassist.config.redaction_patterns import CLASS_AWS_ACCESS_KEY, CLASS_PRIVATE_KEY

CANARY_AWS = "AKIACANARYDECOY00000"
CANARY_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "U1lOVEhFVElDLUNBTkFSWS1ERUNPWQ==\n"
    "-----END RSA PRIVATE KEY-----"
)


@pytest.fixture
def writer(tmp_path: Path) -> Any:
    audit = AuditWriter(directory=tmp_path / "audit", session_id="s-1")
    yield audit
    audit.close()


def rows(path: Path) -> list[dict[str, Any]]:
    """Every RECORD in a journal. Blank lines are framing, not data."""
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ==========================================================================
# 1. append-only, and the §12.1 permissions
# ==========================================================================
def test_the_store_directory_is_created_0700(tmp_path: Path) -> None:
    audit = AuditWriter(directory=tmp_path / "audit", session_id="s-1")
    audit.close()
    assert stat.S_IMODE((tmp_path / "audit").stat().st_mode) == 0o700


def test_the_journal_file_is_0600(writer: AuditWriter) -> None:
    writer.write("intent", {"text": "hi"}, task_id="t-1")
    assert stat.S_IMODE(writer.path.stat().st_mode) == 0o600


def test_the_descriptor_is_append_only(writer: AuditWriter) -> None:
    """``O_APPEND`` is what makes "append-only" a property of the DESCRIPTOR
    rather than a promise about how the code happens to seek."""
    writer.write("intent", {"text": "hi"}, task_id="t-1")
    import fcntl

    flags = fcntl.fcntl(writer.fileno(), fcntl.F_GETFL)
    assert flags & os.O_APPEND
    assert not flags & os.O_TRUNC
    accmode = flags & os.O_ACCMODE
    assert accmode == os.O_WRONLY, "a read-write journal descriptor can rewrite history"


def test_an_existing_journal_is_never_truncated(tmp_path: Path) -> None:
    first = AuditWriter(directory=tmp_path, session_id="s-1")
    first.write("intent", {"n": 0}, task_id="t-1")
    first.close()
    before = first.path.read_bytes()

    second = AuditWriter(directory=tmp_path, session_id="s-1")
    second.write("verdict", {"n": 1}, task_id="t-1")
    second.close()

    assert second.path.read_bytes().startswith(before)


def test_a_symlinked_journal_is_refused(tmp_path: Path) -> None:
    """§12.1's "symlink → fail-closed": a redirected journal is an unaudited one."""
    audit = tmp_path / "audit"
    audit.mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere.jsonl"
    elsewhere.write_text("", encoding="utf-8")
    (audit / "session-s-1.jsonl").symlink_to(elsewhere)

    with pytest.raises(AuditWriteError):
        AuditWriter(directory=audit, session_id="s-1")


def test_one_file_per_session(tmp_path: Path) -> None:
    one = AuditWriter(directory=tmp_path, session_id="s-1")
    two = AuditWriter(directory=tmp_path, session_id="s-2")
    try:
        assert one.path != two.path
        assert "s-1" in one.path.name and "s-2" in two.path.name
    finally:
        one.close()
        two.close()


def test_a_session_id_cannot_escape_the_store(tmp_path: Path) -> None:
    """The session id reaches a FILENAME, so it is a path-traversal channel."""
    for hostile in ("../escape", "a/b", "..", "", "x" * 200, "with\x00nul"):
        with pytest.raises(AuditWriteError):
            AuditWriter(directory=tmp_path, session_id=hostile)


def test_the_global_index_records_each_session_file(tmp_path: Path) -> None:
    """§14.1: "ერთი ფაილი session-ზე + global index"."""
    one = AuditWriter(directory=tmp_path, session_id="s-1")
    one.write("intent", {}, task_id="t-1")
    one.close()
    two = AuditWriter(directory=tmp_path, session_id="s-2")
    two.write("intent", {}, task_id="t-1")
    two.close()

    index = tmp_path / "index.jsonl"
    assert stat.S_IMODE(index.stat().st_mode) == 0o600
    sessions = [json.loads(line)["session_id"] for line in index.read_text().splitlines()]
    assert sessions == ["s-1", "s-2"]


# ==========================================================================
# 2. the §14.1 fsync policy
# ==========================================================================
def test_the_fsync_event_set_is_the_section_141_one() -> None:
    assert set(FSYNC_EVENTS) == {"approval", "verdict", "policy_decision"}


@pytest.mark.parametrize("event", ["approval", "verdict"])
def test_durable_events_fsync_on_every_write(
    writer: AuditWriter, monkeypatch: pytest.MonkeyPatch, event: str
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    writer.write(event, {"x": 1}, task_id="t-1")
    assert calls, f"{event} must be durable before the call returns"


def test_a_policy_decision_deny_fsyncs(
    writer: AuditWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§14.1 names ``policy_decision(deny)`` — the DENY, not every decision."""
    calls: list[int] = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    writer.write("policy_decision", {"decision": "deny"}, task_id="t-1")
    assert calls


def test_a_policy_decision_allow_is_batched(
    writer: AuditWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    writer.write("policy_decision", {"decision": "allow"}, task_id="t-1")
    assert not calls


@pytest.mark.parametrize("event", ["intent", "ground", "tool_request", "tool_result"])
def test_ordinary_events_are_batched(
    writer: AuditWriter, monkeypatch: pytest.MonkeyPatch, event: str
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    writer.write(event, {"x": 1}, task_id="t-1")
    assert not calls, "batching is what keeps the journal off the hot path"


def test_close_flushes_and_fsyncs(
    writer: AuditWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Batched does not mean lost: whatever is pending is durable at close."""
    writer.write("intent", {"x": 1}, task_id="t-1")
    calls: list[int] = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    writer.close()
    assert calls


def test_a_batched_record_is_readable_immediately(writer: AuditWriter) -> None:
    """Batched fsync must not mean a buffered write: the bytes are on the file
    at once, only the DURABILITY barrier is deferred."""
    writer.write("intent", {"x": 1}, task_id="t-1")
    assert len(rows(writer.path)) == 1


# ==========================================================================
# 3. every payload goes through the §14.3 redactor
# ==========================================================================
def test_a_secret_in_the_payload_is_redacted(writer: AuditWriter) -> None:
    writer.write("tool_result", {"stdout": f"key={CANARY_AWS}"}, task_id="t-1")
    stored = rows(writer.path)[0]
    assert CANARY_AWS not in json.dumps(stored)
    assert f"[REDACTED:{CLASS_AWS_ACCESS_KEY}]" in stored["payload"]["stdout"]


def test_the_fact_of_redaction_is_recorded(writer: AuditWriter) -> None:
    """§12.4: "audit records the fact of redaction"."""
    writer.write("tool_result", {"stdout": CANARY_AWS}, task_id="t-1")
    stored = rows(writer.path)[0]
    assert stored["payload"]["_redaction"] == [{"class": CLASS_AWS_ACCESS_KEY, "count": 1}]


def test_a_secret_nested_in_a_list_is_redacted(writer: AuditWriter) -> None:
    """Recursion is the point: a string is a string wherever it sits."""
    writer.write("tool_result", {"lines": ["ok", {"deep": CANARY_AWS}]}, task_id="t-1")
    assert CANARY_AWS not in json.dumps(rows(writer.path)[0])


def test_a_private_key_block_survives_json_nesting(writer: AuditWriter) -> None:
    """The reason values are redacted INDIVIDUALLY rather than by redacting the
    serialized document: JSON escapes newlines, and the §12.4 private-key rule
    matches a real ``\\n``. Redacting the serialized form would miss the block
    and leave the base64 body in the journal."""
    writer.write("tool_result", {"body": CANARY_KEY}, task_id="t-1")
    stored = rows(writer.path)[0]
    assert "U1lOVEhFVElD" not in json.dumps(stored)
    assert stored["payload"]["body"] == f"[REDACTED:{CLASS_PRIVATE_KEY}]"


def test_a_digest_only_redaction_stores_no_payload(
    writer: AuditWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§14.3's fail-closed branch reaching the journal: digest, never a body."""
    monkeypatch.setattr(writer, "_redactor", Redactor(patterns=()))
    writer.write("tool_result", {"stdout": "anything"}, task_id="t-1")
    stored = rows(writer.path)[0]
    assert stored["payload"] == {"_redaction": [{"class": CLASS_ENGINE_ERROR, "count": 1}]}
    assert stored["payload_digest"].startswith("sha256:")


def test_the_payload_digest_binds_the_pre_redaction_payload(
    writer: AuditWriter,
) -> None:
    """Two payloads that redact to the same text must remain distinguishable."""
    writer.write("tool_result", {"s": "AKIACANARYDECOY00000"}, task_id="t-1")
    writer.write("tool_result", {"s": "AKIACANARYDECOY11111"}, task_id="t-1")
    stored = rows(writer.path)
    assert stored[0]["payload"] == stored[1]["payload"]
    assert stored[0]["payload_digest"] != stored[1]["payload_digest"]


def test_configured_secrets_are_redacted_by_exact_match(tmp_path: Path) -> None:
    """§12.4's exact-match class: the writer holds the resolved values so the
    engine can match them, and it holds ONE Redactor rather than rebuilding the
    rule set on every event."""
    secret = "CANARY-CONFIGURED-SECRET-VALUE-0000"
    audit = AuditWriter(directory=tmp_path, session_id="s-1", configured_secrets=(secret,))
    try:
        audit.write("tool_result", {"stdout": f"token={secret}"}, task_id="t-1")
        assert secret not in json.dumps(rows(audit.path)[0])
    finally:
        audit.close()


# ==========================================================================
# 4. §14.1 "Never recorded" — refused, not filtered
# ==========================================================================
def test_the_never_recorded_set_covers_the_section_141_names() -> None:
    assert "reasoning_content" in NEVER_RECORDED_KEYS
    assert "raw_prompt" in NEVER_RECORDED_KEYS
    assert "prompt_body" in NEVER_RECORDED_KEYS


@pytest.mark.parametrize("key", ["reasoning_content", "raw_prompt", "prompt_body"])
def test_a_never_recorded_key_is_refused(writer: AuditWriter, key: str) -> None:
    with pytest.raises(AuditRefusedError) as excinfo:
        writer.write("tool_result", {key: "..."}, task_id="t-1")
    assert key in str(excinfo.value)


@pytest.mark.parametrize("key", ["reasoning_content", "RAW_PROMPT", "Reasoning_Content"])
def test_the_refusal_is_case_insensitive(writer: AuditWriter, key: str) -> None:
    with pytest.raises(AuditRefusedError):
        writer.write("tool_result", {key: "..."}, task_id="t-1")


def test_a_never_recorded_key_is_refused_at_any_depth(writer: AuditWriter) -> None:
    with pytest.raises(AuditRefusedError):
        writer.write(
            "tool_result", {"turn": {"inner": [{"reasoning_content": "..."}]}}, task_id="t-1"
        )


def test_a_refused_write_journals_nothing(writer: AuditWriter) -> None:
    """Refusal must be total: a partially-written record is a corrupt chain."""
    writer.write("intent", {"ok": 1}, task_id="t-1")
    with pytest.raises(AuditRefusedError):
        writer.write("tool_result", {"reasoning_content": "..."}, task_id="t-1")
    assert len(rows(writer.path)) == 1


def test_a_refused_write_does_not_consume_a_seq_number(writer: AuditWriter) -> None:
    """A gap in ``seq`` reads as truncation to §14.5's recovery path."""
    writer.write("intent", {"ok": 1}, task_id="t-1")
    with pytest.raises(AuditRefusedError):
        writer.write("tool_result", {"raw_prompt": "..."}, task_id="t-1")
    writer.write("verdict", {"ok": 2}, task_id="t-1")
    assert [row["seq"] for row in rows(writer.path)] == [0, 1]


def test_a_non_serializable_payload_is_refused(writer: AuditWriter) -> None:
    with pytest.raises(AuditRefusedError):
        writer.write("tool_result", {"obj": object()}, task_id="t-1")


def test_a_non_string_key_is_refused(writer: AuditWriter) -> None:
    """JSON object keys are strings; anything else would be coerced silently,
    and a coerced key is a key the never-recorded check never saw."""
    with pytest.raises(AuditRefusedError):
        writer.write("tool_result", {1: "x"}, task_id="t-1")  # type: ignore[dict-item]


def test_an_unknown_event_is_refused(writer: AuditWriter) -> None:
    with pytest.raises(AuditRefusedError):
        writer.write("not_an_event", {}, task_id="t-1")


def test_the_reserved_redaction_key_cannot_be_supplied(writer: AuditWriter) -> None:
    """``_redaction`` is the writer's own field. A caller able to set it could
    forge "nothing was redacted" on a record that was."""
    with pytest.raises(AuditRefusedError):
        writer.write("tool_result", {"_redaction": []}, task_id="t-1")


# ==========================================================================
# 5. the record the writer produces
# ==========================================================================
def test_the_record_carries_the_section_141_fields(tmp_path: Path) -> None:
    audit = AuditWriter(
        directory=tmp_path, session_id="s-1", model="kimi-for-coding", provider="kimi-coding"
    )
    try:
        audit.write("tool_result", {"tool": "fs.read"}, task_id="t-9")
    finally:
        audit.close()
    stored = rows(audit.path)[0]
    assert set(stored) == {
        "seq", "ts", "session_id", "task_id", "event", "payload",
        "payload_digest", "prev_hash", "model", "provider",
    }
    assert stored["session_id"] == "s-1"
    assert stored["task_id"] == "t-9"
    assert stored["model"] == "kimi-for-coding"
    assert stored["provider"] == "kimi-coding"


def test_write_returns_the_record_it_journalled(writer: AuditWriter) -> None:
    written = writer.write("intent", {"text": "hi"}, task_id="t-1")
    assert written.seq == 0
    assert json.loads(written.model_dump_json())["event"] == "intent"


def test_writing_after_close_is_refused(writer: AuditWriter) -> None:
    writer.close()
    with pytest.raises(AuditWriteError):
        writer.write("intent", {}, task_id="t-1")


def test_close_is_idempotent(writer: AuditWriter) -> None:
    writer.close()
    writer.close()


def test_the_writer_works_as_a_context_manager(tmp_path: Path) -> None:
    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        audit.write("intent", {}, task_id="t-1")
    with pytest.raises(AuditWriteError):
        audit.write("intent", {}, task_id="t-1")


# ==========================================================================
# 6. the fail-closed arms — an audit sink that swallows its own failure is
#    worse than none, so every one of them is exercised rather than assumed
# ==========================================================================
def _oserror(*args: object, **kwargs: object) -> None:
    raise OSError(13, "injected")


def test_an_unwritable_store_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "mkdir", _oserror)
    with pytest.raises(AuditWriteError, match="audit store"):
        AuditWriter(directory=tmp_path / "audit", session_id="s-1")


def test_a_symlinked_store_directory_is_refused(tmp_path: Path) -> None:
    """§12.1: a redirected STORE is as unaudited as a redirected file."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "audit"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(AuditWriteError, match="symlink"):
        AuditWriter(directory=link, session_id="s-1")


def test_an_unopenable_journal_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "open", _oserror)
    with pytest.raises(AuditWriteError, match="cannot open"):
        AuditWriter(directory=tmp_path, session_id="s-1")


def test_a_non_regular_journal_is_refused(tmp_path: Path) -> None:
    """A FIFO planted at the journal path.

    Without ``O_NONBLOCK`` this HANGS rather than failing: a write-only open of
    a FIFO blocks until a reader appears, so the constructor never returns and
    the caller waits with it. Reproduced — the first draft of this writer had
    ``O_NOFOLLOW`` and the ``fstat`` check but not the third flag of HARDEN-01's
    pattern, and this test did not fail, it hung.
    """
    tmp_path.mkdir(exist_ok=True)
    os.mkfifo(tmp_path / "session-s-1.jsonl")
    with pytest.raises(AuditWriteError):
        AuditWriter(directory=tmp_path, session_id="s-1")


def test_an_unsecurable_journal_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The descriptor is closed before the error propagates, so a failure to
    tighten the mode cannot also leak an fd."""
    monkeypatch.setattr(os, "fstat", _oserror)
    with pytest.raises(AuditWriteError, match="cannot secure"):
        AuditWriter(directory=tmp_path, session_id="s-1")


def test_a_loose_mode_is_tightened_on_open(tmp_path: Path) -> None:
    """§12.1 says files are 0600; an existing journal left group-readable is
    corrected rather than accepted."""
    tmp_path.mkdir(exist_ok=True)
    journal = tmp_path / "session-s-1.jsonl"
    journal.touch(mode=0o644)
    journal.chmod(0o644)
    with AuditWriter(directory=tmp_path, session_id="s-1"):
        assert stat.S_IMODE(journal.stat().st_mode) == 0o600


def test_appending_to_an_unreadable_chain_is_refused(tmp_path: Path) -> None:
    """Resuming means reading the last record. If it cannot be read, the new
    record's ``prev_hash`` would be a guess — so the writer refuses rather than
    silently starting a second history."""
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "session-s-1.jsonl").write_text("{not json\n", encoding="utf-8")
    with pytest.raises(AuditWriteError, match="unparseable"):
        AuditWriter(directory=tmp_path, session_id="s-1")


def test_a_symlinked_index_is_refused(tmp_path: Path) -> None:
    tmp_path.mkdir(exist_ok=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("", encoding="utf-8")
    (tmp_path / "index.jsonl").symlink_to(elsewhere)
    with pytest.raises(AuditWriteError, match="symlink"):
        AuditWriter(directory=tmp_path, session_id="s-1")


def test_an_unopenable_index_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lsassist.audit import writer as module

    audit = AuditWriter(directory=tmp_path, session_id="s-1")
    real_open = os.open

    def only_index_fails(path: object, *args: object, **kwargs: object) -> int:
        if str(path).endswith(module._INDEX_NAME):
            raise OSError(13, "injected")
        return real_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", only_index_fails)
    with pytest.raises(AuditWriteError, match="audit index"):
        audit._index(audit.path)
    audit.close()


def test_a_failed_append_does_not_advance_the_chain(
    writer: AuditWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The seq and prev_hash advance only AFTER the bytes are committed: a
    failed write must not leave a gap that reads as truncation."""
    writer.write("intent", {"n": 0}, task_id="t-1")
    monkeypatch.setattr(os, "write", _oserror)
    with pytest.raises(AuditWriteError, match="cannot append"):
        writer.write("intent", {"n": 1}, task_id="t-1")
    monkeypatch.undo()
    writer.write("intent", {"n": 2}, task_id="t-1")
    assert [row["seq"] for row in rows(writer.path)] == [0, 1]


def test_an_unsizeable_journal_is_reported(
    writer: AuditWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rotation is decided from the file size; a size that cannot be read is a
    rotation decision that cannot be made, so the write fails closed."""
    monkeypatch.setattr(os, "fstat", _oserror)
    with pytest.raises(AuditWriteError, match="cannot size"):
        writer.write("intent", {}, task_id="t-1")


def test_an_unprunable_rotation_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lsassist.audit import writer as module

    monkeypatch.setattr(module, "MAX_JOURNAL_BYTES", 256)
    monkeypatch.setattr(module, "MAX_JOURNAL_FILES", 1)
    audit = AuditWriter(directory=tmp_path, session_id="s-1")
    monkeypatch.setattr(Path, "unlink", _oserror)
    with pytest.raises(AuditWriteError, match="cannot prune"):
        for index in range(40):
            audit.write("tool_result", {"n": index}, task_id="t-1")


def test_an_oversized_journal_is_refused_rather_than_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reading is bounded: a file above the rotation cap is either corrupt or
    not ours, and slurping it would be a memory DoS on the recovery path."""
    from lsassist.audit import writer as module

    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "session-s-1.jsonl").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(module, "_MAX_READ_BYTES", 0)
    with pytest.raises(AuditWriteError, match="refusing to read"):
        AuditWriter(directory=tmp_path, session_id="s-1")


def test_an_unreadable_journal_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "session-s-1.jsonl").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(os, "read", _oserror)
    with pytest.raises(AuditWriteError, match="cannot read"):
        AuditWriter(directory=tmp_path, session_id="s-1")


def test_a_non_utf8_journal_is_reported(tmp_path: Path) -> None:
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "session-s-1.jsonl").write_bytes(b"\xff\xfe not utf-8\n")
    with pytest.raises(AuditWriteError, match="not valid UTF-8"):
        AuditWriter(directory=tmp_path, session_id="s-1")


def test_a_symlinked_journal_is_refused_before_it_is_opened(tmp_path: Path) -> None:
    """The symlink guard fires on the READ path too, which runs first."""
    tmp_path.mkdir(exist_ok=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("", encoding="utf-8")
    (tmp_path / "session-s-1.1.jsonl").symlink_to(elsewhere)
    with pytest.raises(AuditWriteError):
        AuditWriter(directory=tmp_path, session_id="s-1")


def test_a_journal_that_becomes_a_directory_is_refused(tmp_path: Path) -> None:
    """``fstat`` on the DESCRIPTOR, not a guess from the name."""
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "session-s-1.jsonl").mkdir()
    with pytest.raises(AuditWriteError):
        AuditWriter(directory=tmp_path, session_id="s-1")


def test_a_blank_line_in_an_existing_journal_is_skipped_on_resume(tmp_path: Path) -> None:
    """A trailing newline is normal JSONL; resume must not read it as a record."""
    with AuditWriter(directory=tmp_path, session_id="s-1") as audit:
        audit.write("intent", {"n": 0}, task_id="t-1")
    audit.path.write_text(audit.path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with AuditWriter(directory=tmp_path, session_id="s-1") as second:
        second.write("verdict", {"n": 1}, task_id="t-1")
    assert [row["seq"] for row in rows(second.path)] == [0, 1]


@pytest.mark.parametrize("plant", ["symlink", "fifo", "directory"])
def test_a_hostile_rotation_target_is_refused(tmp_path: Path, plant: str) -> None:
    """``_open`` is called again at every rotation, on a path that did not exist
    when the writer was constructed — so the §12.1 guards have to hold there too,
    not only at startup.

    Exercised through the helper rather than by staging a rotation: the rotation
    target is derived from the files already present, so planting anything at it
    changes which name gets chosen. The guards under test are the same ones the
    rotation path calls.
    """
    tmp_path.mkdir(exist_ok=True)
    audit = AuditWriter(directory=tmp_path, session_id="s-1")
    target = tmp_path / "rotation-target.jsonl"
    if plant == "symlink":
        (tmp_path / "elsewhere").write_text("", encoding="utf-8")
        target.symlink_to(tmp_path / "elsewhere")
    elif plant == "fifo":
        os.mkfifo(target)
    else:
        target.mkdir()
    try:
        with pytest.raises(AuditWriteError):
            audit._open(target)
    finally:
        audit.close()


def test_a_device_node_journal_is_refused_and_its_descriptor_closed(
    tmp_path: Path,
) -> None:
    """The one non-regular file that OPENS successfully, so the ``fstat`` check
    is the only thing standing between the journal and ``/dev/null``.

    A FIFO and a directory both fail at ``os.open`` (ENXIO, EISDIR) and never
    reach the check; a character device does not. Journalling to ``/dev/null``
    would report every write as successful and record nothing — the exact
    failure §14.1 exists to make impossible. The descriptor is closed on the way
    out, so a refused open cannot also leak an fd.
    """
    audit = AuditWriter(directory=tmp_path, session_id="s-1")
    try:
        with pytest.raises(AuditWriteError, match="not a regular file"):
            audit._open(Path("/dev/null"))
    finally:
        audit.close()
