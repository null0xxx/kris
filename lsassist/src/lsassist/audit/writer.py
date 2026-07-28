"""Append-only, hash-chained §14.1 audit journal writer.

§14.1: "Append-only JSONL, ერთი ფაილი session-ზე + global index; **hash-chained**
… fsync policy: on every ``approval``, ``verdict``, ``policy_decision(deny)``
event; batched otherwise. Rotation: 50 MB / 10 files."
§12.1: the audit store is dir ``0700``, files ``0600``, symlink → fail-closed.

**APPEND-ONLY IS A PROPERTY OF THE DESCRIPTOR.** The journal is opened
``O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW`` — never ``O_TRUNC``, never
read-write. With ``O_APPEND`` the kernel places every write at the current end
regardless of the file offset, so no code path in this module (or any future one)
can seek back over history. Written as a promise in a docstring it would be
exactly as strong as the next person's memory.

**EVERY PAYLOAD GOES THROUGH THE §14.3 REDACTOR, VALUE BY VALUE.** Not by
redacting the serialized document: JSON escapes a newline as ``\\n``, and §12.4's
private-key rule matches a REAL newline, so a PEM block inside a JSON string
would sail past and leave its base64 body in the journal. The walk descends into
nested dicts and lists because a string is a string wherever it sits. If any
value's redaction fails closed, the WHOLE record goes digest-only: a payload the
engine could not fully judge is not a payload to publish in part.

**"NEVER RECORDED" IS A REFUSAL, NOT A FILTER (§14.1).** ``reasoning_content``
(I16), ``raw_prompt`` and ``prompt_body`` cause :class:`AuditRefusedError`, and
the write journals nothing and consumes no ``seq``. Silently dropping the key
would leave the caller believing it journalled something it did not — and a
caller that can be wrong about what reached the journal is a caller nobody can
audit. A gap in ``seq`` would read as truncation to §14.5's recovery path, so a
refusal must not create one.

**THE CHAIN CONTINUES ACROSS EVERYTHING.** A rotation carries the previous
file's last hash into the new file's first record, and a writer opened over an
existing journal resumes from the last line rather than restarting from
:data:`~lsassist.audit.schema.GENESIS_HASH`. Both failures produce two
internally-consistent halves of one history, which is the shape of tampering
that a naive chain check reports as fine.

**WHAT THE CHAIN DOES AND DOES NOT PROVE.** It is tamper-EVIDENT, not
tamper-PROOF: there is no secret in the link, so an attacker who can write the
file and rewrites every record from the edit to the end produces a consistent
journal. What the chain guarantees is that a PARTIAL edit — the realistic one,
and the one an accident produces — cannot hide. §12.1's ``0600`` and the §7.3
DENY entry on the audit store are what make the full rewrite hard;
:func:`verify_chain` is what makes anything less than that visible.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise
from pathlib import Path
from types import TracebackType
from typing import Any, Final, Self, final

from lsassist.audit.redactor import CLASS_ENGINE_ERROR, AuditRedaction, Redactor
from lsassist.audit.schema import GENESIS_HASH, AuditRecord, canonical_bytes, record_hash

__all__ = [
    "FSYNC_EVENTS",
    "MAX_JOURNAL_BYTES",
    "MAX_JOURNAL_FILES",
    "NEVER_RECORDED_KEYS",
    "REDACTION_FIELD",
    "AuditRefusedError",
    "AuditWriteError",
    "AuditWriter",
    "ChainStatus",
    "ChainVerdict",
    "verify_chain",
]

#: §14.1's durable events. ``policy_decision`` is listed there as
#: ``policy_decision(deny)`` — the DENY, not every decision — so membership here
#: is necessary but not sufficient; see :func:`_needs_fsync`.
FSYNC_EVENTS: Final[frozenset[str]] = frozenset({"approval", "verdict", "policy_decision"})

#: §14.1 rotation thresholds.
MAX_JOURNAL_BYTES: Final = 50 * 1024 * 1024
MAX_JOURNAL_FILES: Final = 10

#: §14.1 "Never recorded". ``reasoning_content`` is I16's blob; the two prompt
#: fields are the "raw prompts beyond a redacted summary + digest" clause.
#: Matched case-insensitively, at every depth.
NEVER_RECORDED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "reasoning_content",
        "reasoning_opaque",
        "raw_prompt",
        "prompt_body",
        "raw_messages",
        "chain_of_thought",
    }
)

#: Where the §12.4 "fact of redaction" is recorded inside the payload. Reserved:
#: a caller able to supply it could forge "nothing was redacted" on a record
#: that was.
REDACTION_FIELD: Final = "_redaction"

#: A session id reaches a FILENAME, so it is a path-traversal channel.
_SESSION_ID_RE: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

_DIR_MODE: Final = 0o700
_FILE_MODE: Final = 0o600
_INDEX_NAME: Final = "index.jsonl"

#: Built once. The rule table is compiled at construction, and putting a regex
#: compile on the journal's hot path would tax every event in the session.
_REDACTOR: Final = Redactor()


class AuditWriteError(Exception):
    """The journal could not be opened or written — never a silent no-op.

    An audit sink that swallows its own failures is worse than none: the caller
    proceeds believing the action was recorded.
    """


class AuditRefusedError(Exception):
    """The record was REFUSED by §14.1's never-recorded rule, or is unwritable.

    Distinct from :class:`AuditWriteError`: the journal is healthy and the
    CALLER handed it something that must not be journalled. Nothing is written
    and no ``seq`` is consumed.
    """


class ChainStatus(StrEnum):
    """What :func:`verify_chain` found."""

    VALID = "valid"
    #: A link does not match: a record was mutated, rewritten, reordered or
    #: appended. ``broken_at`` names the record whose ``prev_hash`` failed.
    BROKEN = "broken"
    #: Fewer records than the caller expected; every surviving link is intact.
    TRUNCATED = "truncated"
    #: A line does not parse, or does not validate as a §14.1 record.
    MALFORMED = "malformed"


@final
@dataclass(frozen=True, slots=True)
class ChainVerdict:
    """The result of verifying one journal file.

    :ivar broken_at: the 0-based index of the offending record, or ``None``. A
        verdict that only says "something is wrong" leaves an operator with a
        50 MB file and nowhere to look.
    """

    status: ChainStatus
    records: int
    broken_at: int | None = None
    detail: str = ""


#: Largest journal file this module will read into memory at once. Sized off the
#: rotation cap plus headroom: a file above it is either corrupt or not ours.
_MAX_READ_BYTES: Final = MAX_JOURNAL_BYTES * 2


def _read_regular_text(path: Path) -> str:
    """Read a journal through HARDEN-01's sanctioned pattern.

    ``O_NOFOLLOW`` so a symlinked journal is refused rather than followed;
    ``O_NONBLOCK`` so a FIFO planted at a journal path fails instead of blocking
    forever; ``fstat`` on the DESCRIPTOR so what was opened is confirmed to be a
    regular file rather than what the name suggested.

    Reproduced on the first draft, which used ``Path.read_text()``: a FIFO named
    ``session-<id>.jsonl`` hung the CONSTRUCTOR — before any journal file was
    even opened for writing — because resuming the chain reads the previous
    record first. The write path had been hardened and the READ path, which runs
    earlier, had not.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise AuditWriteError(f"cannot read {path.name}: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise AuditWriteError(f"{path.name} is not a regular file")
        if info.st_size > _MAX_READ_BYTES:
            raise AuditWriteError(f"{path.name} is {info.st_size} bytes; refusing to read")
        chunks: list[bytes] = []
        while chunk := os.read(fd, 1 << 20):
            chunks.append(chunk)
    except OSError as exc:
        raise AuditWriteError(f"cannot read {path.name}: {exc}") from exc
    finally:
        os.close(fd)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditWriteError(f"{path.name} is not valid UTF-8: {exc}") from exc


def _needs_fsync(event: str, payload: Mapping[str, Any]) -> bool:
    """§14.1: approval, verdict, and policy_decision **(deny)**.

    The parenthesis is load-bearing. Syncing every ``policy_decision`` would put
    an fsync on the common AUTO path, which is exactly the cost §14.1 avoids by
    batching; syncing none of them would leave the refusal that BLOCKED an action
    at the mercy of a crash.
    """
    if event not in FSYNC_EVENTS:
        return False
    if event != "policy_decision":
        return True
    return str(payload.get("decision", "")).lower() in {"deny", "denied", "blocked"}


def _reject_forbidden_keys(value: object, *, path: str = "") -> None:
    """Walk the payload and refuse a §14.1 never-recorded key at ANY depth."""
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise AuditRefusedError(
                    f"payload key {key!r} at {path or '<root>'} is not a string; a coerced "
                    "key is a key the never-recorded check never saw"
                )
            if key.lower() in NEVER_RECORDED_KEYS:
                raise AuditRefusedError(f"§14.1 never records {key!r} (at {path or '<root>'})")
            if key == REDACTION_FIELD:
                raise AuditRefusedError(
                    f"{REDACTION_FIELD!r} is the writer's own field; a caller able to set it "
                    "could forge 'nothing was redacted'"
                )
            _reject_forbidden_keys(nested, path=f"{path}.{key}" if path else key)
        return
    if isinstance(value, list | tuple):
        for index, item in enumerate(value):
            _reject_forbidden_keys(item, path=f"{path}[{index}]")


def _redact_tree(
    value: object, hits: dict[str, int], failures: list[str], redactor: Redactor
) -> object:
    """Redact every STRING in the payload, in place-by-copy.

    Value-by-value rather than over the serialized document: JSON escapes a
    newline, and §12.4's private-key rule matches a real one.

    The engine is PASSED IN, not read from the module: a writer constructed with
    configured secrets holds its own rule set, and reaching for the module-level
    default here would silently drop the §12.4 exact-match class for exactly the
    caller who supplied the secrets.
    """
    if isinstance(value, str):
        verdict: AuditRedaction = redactor.redact(value)
        if verdict.digest_only:
            failures.append(verdict.error_detail)
            return ""
        for hit in verdict.hits:
            hits[hit.class_label] = hits.get(hit.class_label, 0) + hit.count
        return verdict.text
    if isinstance(value, Mapping):
        return {
            key: _redact_tree(item, hits, failures, redactor) for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [_redact_tree(item, hits, failures, redactor) for item in value]
    return value


def _payload_digest(payload: Mapping[str, Any]) -> str:
    """sha256 over the PRE-redaction payload (§14.1's ``payload_digest``).

    Two payloads that redact to the same text stay distinguishable, which is
    what makes the field evidence rather than decoration. It is a confirmation
    oracle for a guessable secret — the same named residual the redactor
    carries, and inherent to digest-based evidence (§6.5 does it for stdout).
    """
    return record_hash(dict(payload))


def _hits_field(hits: Mapping[str, int]) -> list[dict[str, Any]]:
    """§12.4: "audit records the fact of redaction" — class and count, never a
    sample of what was replaced."""
    return [{"class": label, "count": hits[label]} for label in sorted(hits)]


@final
class AuditWriter:
    """One session's append-only §14.1 journal.

    :param directory: the §12.1 audit store. Created ``0700`` if absent.
    :param session_id: names the file; validated as a filename component.
    :param configured_secrets: resolved §12.4 exact-match values. Supplied once
        so the rule set is compiled once — the facade would rebuild it per event.
    """

    __slots__ = (
        "_closed",
        "_directory",
        "_fd",
        "_model",
        "_path",
        "_pending",
        "_prev_hash",
        "_provider",
        "_redactor",
        "_seq",
        "_session_id",
    )

    def __init__(
        self,
        *,
        directory: Path | str,
        session_id: str,
        model: str = "unknown",
        provider: str = "unknown",
        configured_secrets: Sequence[str] = (),
        deny_paths: Sequence[str] = (),
    ) -> None:
        if not _SESSION_ID_RE.match(session_id):
            raise AuditWriteError(
                f"session_id {session_id!r} is not a safe filename component; it names a "
                "file in the audit store and would otherwise be a path-traversal channel"
            )
        self._directory = Path(directory)
        self._session_id = session_id
        self._model = model
        self._provider = provider
        self._closed = False
        self._pending = False
        self._redactor = (
            Redactor(configured_secrets=configured_secrets, deny_paths=deny_paths)
            if configured_secrets or deny_paths
            else _REDACTOR
        )
        self._ensure_directory()
        self._path = self._journal_path(0)
        self._seq, self._prev_hash = self._resume()
        self._fd = self._open(self._path)
        self._index(self._path)

    # -- construction helpers ------------------------------------------------
    def _ensure_directory(self) -> None:
        try:
            self._directory.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        except OSError as exc:
            raise AuditWriteError(f"cannot create the audit store: {exc}") from exc
        if self._directory.is_symlink():
            raise AuditWriteError(f"{self._directory} is a symlink (§12.1 fail-closed)")

    def _journal_path(self, index: int) -> Path:
        suffix = "" if index == 0 else f".{index}"
        return self._directory / f"session-{self._session_id}{suffix}.jsonl"

    def _open(self, path: Path) -> int:
        """``O_APPEND|O_CREAT|O_WRONLY|O_NOFOLLOW|O_NONBLOCK`` at ``0600`` (§12.1).

        ``O_NONBLOCK`` completes HARDEN-01's sanctioned pattern and is not
        decoration: opening a FIFO write-only BLOCKS until a reader appears, so a
        FIFO planted at the journal path hung the constructor forever — an audit
        sink that never returns is one that never records, and the caller waits
        with it. On a regular file the flag is a no-op for writes, and the
        ``fstat`` below then refuses the FIFO outright.
        """
        if path.is_symlink():
            raise AuditWriteError(f"{path} is a symlink (§12.1 fail-closed)")
        try:
            fd = os.open(
                path,
                os.O_WRONLY
                | os.O_APPEND
                | os.O_CREAT
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | os.O_CLOEXEC,
                _FILE_MODE,
            )
        except OSError as exc:
            raise AuditWriteError(f"cannot open {path.name}: {exc}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise AuditWriteError(f"{path.name} is not a regular file")
            if stat.S_IMODE(info.st_mode) != _FILE_MODE:
                os.fchmod(fd, _FILE_MODE)
        except OSError as exc:
            os.close(fd)
            raise AuditWriteError(f"cannot secure {path.name}: {exc}") from exc
        except AuditWriteError:
            os.close(fd)
            raise
        return fd

    def _resume(self) -> tuple[int, str]:
        """Continue an existing chain rather than forking a second history."""
        last: dict[str, Any] | None = None
        for path in self._existing_journals():
            for line in _read_regular_text(path).splitlines():
                if line.strip():
                    try:
                        last = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise AuditWriteError(
                            f"{path.name} ends in an unparseable record; refusing to append "
                            f"to a journal whose chain cannot be read ({exc})"
                        ) from exc
        if last is None:
            return 0, GENESIS_HASH
        return int(last["seq"]) + 1, record_hash(last)

    def _existing_journals(self) -> list[Path]:
        """This session's journals, oldest first."""
        prefix = f"session-{self._session_id}"
        found = [
            path
            for path in self._directory.iterdir()
            if path.name.startswith(prefix) and path.name.endswith(".jsonl")
        ]
        return sorted(found, key=self._rotation_index)

    @staticmethod
    def _rotation_index(path: Path) -> int:
        """``session-s.jsonl`` is 0; ``session-s.7.jsonl`` is 7."""
        stem = path.name.removesuffix(".jsonl")
        _, _, tail = stem.rpartition(".")
        return int(tail) if tail.isdigit() else 0

    def _index(self, path: Path) -> None:
        """§14.1's global index: one line per journal file."""
        entry = json.dumps(
            {"session_id": self._session_id, "file": path.name},
            sort_keys=True,
            separators=(",", ":"),
        )
        index_path = self._directory / _INDEX_NAME
        if index_path.is_symlink():
            raise AuditWriteError(f"{index_path} is a symlink (§12.1 fail-closed)")
        try:
            fd = os.open(
                index_path,
                os.O_WRONLY
                | os.O_APPEND
                | os.O_CREAT
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | os.O_CLOEXEC,
                _FILE_MODE,
            )
        except OSError as exc:
            raise AuditWriteError(f"cannot open the audit index: {exc}") from exc
        try:
            os.write(fd, (entry + "\n").encode("utf-8"))
        finally:
            os.close(fd)

    # -- public surface ------------------------------------------------------
    @property
    def path(self) -> Path:
        """The journal currently being appended to."""
        return self._path

    def fileno(self) -> int:
        """The journal descriptor — so a caller can assert its flags."""
        return self._fd

    def write(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        task_id: str,
        model: str | None = None,
        provider: str | None = None,
        now: datetime.datetime | None = None,
    ) -> AuditRecord:
        """Journal one §14.1 event. Returns the record that was written.

        :raises AuditRefusedError: the payload carries a never-recorded key, is
            not JSON-serializable, or the event is outside §14.1's vocabulary.
            Nothing is written and no ``seq`` is consumed.
        :raises AuditWriteError: the journal itself failed.
        """
        if self._closed:
            raise AuditWriteError("the journal is closed")

        _reject_forbidden_keys(payload)
        digest = self._digest_or_refuse(payload)

        hits: dict[str, int] = {}
        failures: list[str] = []
        redacted = _redact_tree(dict(payload), hits, failures, self._redactor)
        body: dict[str, Any]
        if failures:
            # §14.3's fail-closed branch reaching the journal: a payload the
            # engine could not fully judge is stored as evidence only.
            body = {REDACTION_FIELD: [{"class": CLASS_ENGINE_ERROR, "count": 1}]}
        else:
            body = dict(redacted) if isinstance(redacted, dict) else {}
            body[REDACTION_FIELD] = _hits_field(hits)

        record = self._build(event, body, digest, task_id, model, provider, now)
        self._append(record, fsync=_needs_fsync(event, payload))
        return record

    def close(self) -> None:
        """Flush, make anything batched durable, and release the descriptor."""
        if self._closed:
            return
        self._closed = True
        try:
            if self._pending:
                os.fsync(self._fd)
                self._pending = False
        finally:
            os.close(self._fd)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- internals -----------------------------------------------------------
    def _digest_or_refuse(self, payload: Mapping[str, Any]) -> str:
        try:
            return _payload_digest(payload)
        except (TypeError, ValueError) as exc:
            raise AuditRefusedError(f"payload is not JSON-serializable: {exc}") from exc

    def _build(
        self,
        event: str,
        body: dict[str, Any],
        digest: str,
        task_id: str,
        model: str | None,
        provider: str | None,
        now: datetime.datetime | None,
    ) -> AuditRecord:
        try:
            return AuditRecord(
                seq=self._seq,
                ts=now or datetime.datetime.now(datetime.UTC),
                session_id=self._session_id,
                task_id=task_id,
                event=event,
                payload=body,
                payload_digest=digest,
                prev_hash=self._prev_hash,
                model=model or self._model,
                provider=provider or self._provider,
            )
        except ValueError as exc:
            raise AuditRefusedError(f"record refused by the §14.1 schema: {exc}") from exc

    def _append(self, record: AuditRecord, *, fsync: bool) -> None:
        line = canonical_bytes(record) + b"\n"
        self._rotate_if_needed(len(line))
        try:
            os.write(self._fd, line)
        except OSError as exc:
            raise AuditWriteError(f"cannot append to {self._path.name}: {exc}") from exc
        # The record is committed: only now may the chain advance, so a failed
        # write cannot leave a gap the recovery path reads as truncation.
        self._seq += 1
        self._prev_hash = record_hash(record)
        if fsync:
            os.fsync(self._fd)
            self._pending = False
        else:
            self._pending = True

    def _rotate_if_needed(self, incoming: int) -> None:
        """Rotate BEFORE the write, so the cap is enforced rather than advisory.

        Checking afterwards lets one record push a file past 50 MB and only then
        rotate, which makes the threshold a suggestion.
        """
        try:
            size = os.fstat(self._fd).st_size
        except OSError as exc:
            raise AuditWriteError(f"cannot size {self._path.name}: {exc}") from exc
        if size == 0 or size + incoming <= MAX_JOURNAL_BYTES:
            return

        highest = max(self._rotation_index(path) for path in self._existing_journals())
        rotated = self._journal_path(highest + 1)
        new_fd = self._open(rotated)
        os.close(self._fd)
        self._fd = new_fd
        self._path = rotated
        self._pending = False
        self._index(rotated)
        self._prune()

    def _prune(self) -> None:
        """§14.1's 10-file cap, applied to THIS session only.

        Dropping another session's history because this one is chatty would
        delete an audit trail nobody asked to rotate.
        """
        journals = self._existing_journals()
        for path in journals[: max(0, len(journals) - MAX_JOURNAL_FILES)]:
            try:
                path.unlink()
            except OSError as exc:
                raise AuditWriteError(f"cannot prune {path.name}: {exc}") from exc


def _rows(path: Path) -> tuple[list[dict[str, Any]], int | None, str]:
    """Parse a journal into records; returns ``(rows, bad_index, detail)``."""
    try:
        text = _read_regular_text(path)
    except AuditWriteError as exc:
        # `verify_chain` never raises: §14.5's recovery path calls it on exactly
        # the input it exists to diagnose.
        return [], 0, str(exc)
    rows: list[dict[str, Any]] = []
    for index, line in enumerate(text.splitlines()):
        if not line.strip():
            continue  # a trailing newline is normal JSONL, not data
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            return rows, index, f"line {index} is not JSON: {exc}"
        if not isinstance(parsed, dict):
            return rows, index, f"line {index} is not a JSON object"
        try:
            AuditRecord.model_validate(parsed)
        except ValueError as exc:
            return rows, index, f"line {index} is not a §14.1 record: {exc}"
        rows.append(parsed)
    return rows, None, ""


def verify_chain(path: Path | str, *, expected_records: int | None = None) -> ChainVerdict:
    """Verify one journal file's hash chain (§14.1). NEVER raises.

    :param expected_records: how many records the caller believes the file holds.
        Truncation leaves every surviving link intact, so it is invisible from
        inside the file — and a journal being read WHILE it is written is short,
        not broken. Only a caller who knows the expected length can tell the two
        apart, so the check is opt-in rather than a guess.

    Runs on a file an attacker may have touched, and §14.5's recovery path calls
    it on exactly the input it exists to diagnose — so a malformed journal is a
    VERDICT, never an exception.
    """
    rows, bad_index, detail = _rows(Path(path))
    if bad_index is not None:
        return ChainVerdict(
            status=ChainStatus.MALFORMED,
            records=len(rows),
            broken_at=bad_index,
            detail=detail,
        )

    for index, (previous, current) in enumerate(pairwise(rows), start=1):
        if current["prev_hash"] != record_hash(previous):
            return ChainVerdict(
                status=ChainStatus.BROKEN,
                records=len(rows),
                broken_at=index,
                detail=f"record {index} does not link to record {index - 1}",
            )
        if int(current["seq"]) != int(previous["seq"]) + 1:
            return ChainVerdict(
                status=ChainStatus.BROKEN,
                records=len(rows),
                broken_at=index,
                detail=f"seq jumps from {previous['seq']} to {current['seq']}",
            )

    if expected_records is not None and len(rows) < expected_records:
        return ChainVerdict(
            status=ChainStatus.TRUNCATED,
            records=len(rows),
            detail=f"expected {expected_records} records, found {len(rows)}",
        )
    return ChainVerdict(status=ChainStatus.VALID, records=len(rows))
