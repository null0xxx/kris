"""§6.5 tool-result assembly — the OBSERVATION half of the dispatch tail.

SPEC §6.5 fixes the shape of every execution's answer::

    {"tool", "status", "exit_code", "duration_ms",
     "stdout_digest", "stderr_digest", "result", "evidence", "error"}

and adds the rule that governs this module: "დიდი bodies digest-only +
reference". This is where output becomes EVIDENCE — bounded, digested, and
labelled with what it is.

**TCB (§2.3 "tools/ dispatcher core").** Not a handler: it never touches the
filesystem, never spawns anything, and never sees a tool's arguments. It is
counted in ``scripts/tcb-loc-manifest.txt`` and measured by the
``dispatcher-coverage`` job alongside :mod:`~lsassist.tools.dispatcher`, because
the §6.2 ``output_limits`` it enforces are described there as KERNEL-enforced
ceilings and the digests it produces are the kernel's I12 evidence.

**PURE.** :func:`~lsassist.tools.dispatcher.spawn_capped` owns the syscalls and
drives :class:`OutputSink` with whatever it read; everything here is a value
transformation. That split is what lets the cap, the digest and the status rules
be tested without a child process.

**THE DIGEST COVERS THE WHOLE STREAM, THE BODY DOES NOT.** :class:`OutputSink`
stops KEEPING bytes at the cap and never stops HASHING them. A digest taken over
the truncated body would attest less than the tool actually produced while still
being called ``stdout_digest`` — an I12 evidence downgrade wearing the costume of
a size limit. Bounded memory comes from discarding the tail, not from ignoring it.

**STATUS IS ONE VALUE, SO THE THREE CONDITIONS NEED AN ORDER.** §6.5's enum is
``ok | error | truncated`` and a run can be two of them at once. A failure that
also overflowed its cap is reported as ``error``: calling it ``truncated`` would
tell the kernel the tool SUCCEEDED with a clipped body, and §4.5's verdict
machinery would take that at face value (I12 — never fabricate success).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, final

from lsassist.contracts.tool_result import (
    ToolError,
    ToolResult,
    ToolResultEvidence,
    ToolResultStatus,
)

__all__ = [
    "DIGEST_PREFIX",
    "EXIT_STATUS_ERROR",
    "MAX_SIGNAL",
    "RESULT_CHARS_KEY",
    "RESULT_DIGEST_KEY",
    "SIGNAL_EXIT_BASE",
    "TIMEOUT_ERROR",
    "ExecObservation",
    "OutputSink",
    "ResultError",
    "Verification",
    "build_result",
    "cap_result",
    "normalize_exit_code",
    "sha256_digest",
]

#: §6.5's ``*_digest`` fields carry the algorithm, so a reader never has to
#: guess which one produced the hex.
DIGEST_PREFIX: Final = "sha256:"

#: The shell's rendering of "died on signal N", and the one ``bwrap`` itself
#: reports (measured: 137 for SIGKILL in ``tests/e2e/test_sandbox_exec.py``).
SIGNAL_EXIT_BASE: Final = 128
MAX_SIGNAL: Final = 127

#: §6.5 ``error.kind`` values this module synthesizes when the runner reports a
#: failure without one of its own.
TIMEOUT_ERROR: Final = "timeout"
EXIT_STATUS_ERROR: Final = "exit_status"

#: The digest-only replacement for an oversized ``result`` (§6.5 "reference").
RESULT_DIGEST_KEY: Final = "result_digest"
RESULT_CHARS_KEY: Final = "result_chars"


class ResultError(Exception):
    """A §6.5 result could not be assembled — never a silently repaired one.

    Every raise below is a case where the honest answer is unavailable: a cap
    that is not a size, an exit status outside the range §6.5 admits. Repairing
    either would produce a record that reads as evidence and is not.
    """


class Verification(StrEnum):
    """What §7.5 step 6 concluded about the paths this execution touched.

    Three values, because two would force a lie. §7.5 step 6 is scoped to WRITE
    tools (SPEC:564), so for a read or exec tool there is no post-exec snapshot
    to compare — and reporting :data:`VERIFIED` there would manufacture evidence
    the SPEC never collects. :data:`NOT_APPLICABLE` says exactly that, and keeps
    the read/exec gap NAMED rather than disguised as a pass.
    """

    #: Every declared path still resolves to itself inside the approved parent.
    VERIFIED = "verified"
    #: §7.5 step 6 mismatch → the caller must not treat the run as evidence, and
    #: an audit alert is due.
    UNVERIFIED = "unverified"
    #: Not a write tool: §7.5 step 6 does not apply. A NAMED residual, not a pass.
    NOT_APPLICABLE = "not_applicable"


def sha256_digest(data: bytes) -> str:
    """``sha256:<hex>`` over ``data`` — the §6.5 digest spelling."""
    return DIGEST_PREFIX + hashlib.sha256(data).hexdigest()


@final
class OutputSink:
    """A capped, fully-digested byte stream (§6.3 step 6's "stdout/stderr caps").

    Feed it whatever the runner read. It keeps the first ``cap`` bytes, hashes
    everything, and remembers how much there was. The runner NEVER stops reading:
    a reader that stops draining at the cap deadlocks the child against a full
    pipe, and the execution then reports ``timeout`` for a tool whose only sin
    was talking too much.
    """

    __slots__ = ("_cap", "_hash", "_kept", "_parts", "_total")

    def __init__(self, cap: int) -> None:
        """:raises ResultError: ``cap`` is not a non-negative ``int``.

        ``bool`` is refused despite ``isinstance(True, int)``: ``OutputSink(True)``
        would silently mean "keep one byte of every tool's output".
        """
        if isinstance(cap, bool) or not isinstance(cap, int) or cap < 0:
            raise ResultError(f"cap must be a non-negative int, got {cap!r}")
        self._cap = cap
        self._parts: list[bytes] = []
        self._kept = 0
        self._total = 0
        self._hash = hashlib.sha256()

    def feed(self, chunk: bytes) -> None:
        """Hash every byte; keep the ones that still fit."""
        self._hash.update(chunk)
        self._total += len(chunk)
        room = self._cap - self._kept
        if room > 0:
            kept = chunk[:room]
            self._parts.append(kept)
            self._kept += len(kept)

    @property
    def body(self) -> bytes:
        """The retained prefix, at most ``cap`` bytes."""
        return b"".join(self._parts)

    @property
    def digest(self) -> str:
        """§6.5's digest over EVERYTHING fed, truncated or not."""
        return DIGEST_PREFIX + self._hash.hexdigest()

    @property
    def truncated(self) -> bool:
        """Did the stream exceed the cap?"""
        return self._total > self._cap

    @property
    def total_bytes(self) -> int:
        """How many bytes the tool actually produced."""
        return self._total


def normalize_exit_code(returncode: int) -> int:
    """Map a ``Popen`` return code onto §6.5's ``exit_code`` (0..255).

    ``Popen.returncode`` is NEGATIVE for a signal death, and
    :class:`~lsassist.contracts.tool_result.ToolResult` bounds ``exit_code`` to
    ``0..255`` — so handing pydantic a ``-9`` raises a ``ValidationError`` out of
    the observation path and a KILLED tool crashes the dispatcher instead of
    being reported. ``128 + signal`` is the shell's convention and is also what
    ``bwrap`` itself reports for a killed child, so the two agree.

    :raises ResultError: a value no ``wait()`` can produce. NOT clamped: a
        silently clamped exit status is indistinguishable from a real one.

    The two bounds are not equally load-bearing. ``255`` is an ORDINARY exit code
    that any tool can return, so the upper bound has to admit it exactly; the
    signal bound is defensive only — Linux tops out near ``SIGRTMAX`` (~64), so
    a ``wait()`` cannot actually produce a signal above 127.
    """
    if returncode < 0:
        signal_number = -returncode
        if signal_number > MAX_SIGNAL:
            raise ResultError(f"signal {signal_number} is outside 1..{MAX_SIGNAL}")
        return SIGNAL_EXIT_BASE + signal_number
    if returncode > 255:
        raise ResultError(f"exit code {returncode} is outside §6.5's 0..255")
    return returncode


@final
@dataclass(frozen=True, slots=True)
class ExecObservation:
    """§6.3 step 7 — "exit code, duration, output digests, truncated flags".

    The bodies travel alongside the digests because a handler still has to READ
    the tool's output to build its ``result``; what never travels is a body
    larger than the manifest's cap. ``timed_out`` is the runner's OWN verdict
    from its OWN clock — see :attr:`timed_out`.
    """

    exit_code: int
    duration_ms: int
    stdout: bytes
    stderr: bytes
    stdout_digest: str
    stderr_digest: str
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_bytes: int
    stderr_bytes: int
    #: The RUNNER's wall-clock deadline fired. Deliberately not inferred from the
    #: exit status: ``prlimit --cpu`` also kills with ``SIGKILL`` (measured — see
    #: :mod:`~lsassist.sandbox.prlimit`'s HOST FINDING), so ``137`` alone cannot
    #: tell a wall-clock timeout from an rlimit breach, and §8.3 asks for both as
    #: distinct evidence.
    timed_out: bool

    @classmethod
    def from_sinks(
        cls,
        *,
        returncode: int,
        duration_ms: int,
        stdout: OutputSink,
        stderr: OutputSink,
        timed_out: bool,
    ) -> ExecObservation:
        """Assemble the observation from the two sinks the runner drove."""
        return cls(
            exit_code=normalize_exit_code(returncode),
            duration_ms=duration_ms,
            stdout=stdout.body,
            stderr=stderr.body,
            stdout_digest=stdout.digest,
            stderr_digest=stderr.digest,
            stdout_truncated=stdout.truncated,
            stderr_truncated=stderr.truncated,
            stdout_bytes=stdout.total_bytes,
            stderr_bytes=stderr.total_bytes,
            timed_out=timed_out,
        )


def cap_result(result: Mapping[str, Any], max_chars: int) -> tuple[dict[str, Any], bool]:
    """Apply §6.2's ``max_result_chars``: over the cap, keep a REFERENCE (§6.5).

    Runs AFTER ``output_schema`` validation, never before: the schema describes
    the tool's real answer, and validating the digest-only stand-in against it
    would reject every oversized result for the wrong reason.

    :returns: ``(result, truncated)``.
    :raises ResultError: the payload is not JSON-serializable. MEASURED: a
        handler returning ``{"stdout": {1, 2}}`` passes ``output_schema``
        validation — jsonschema only checks the properties a schema constrains,
        and a ``set`` matches no declared type — and then dies here. Unhandled,
        that ``TypeError`` escapes AFTER the tool has already run and BEFORE the
        §14.1 record is written, which is the one outcome this module's whole
        error discipline exists to prevent.

    The message names the exception TYPE and nothing else. ``str(exc)`` from a
    serializer can quote the offending value, and the value is tool output
    (I8, §12.4) — the same rule the §14.3 redactor follows for its own failures.
    """
    try:
        text = json.dumps(
            dict(result), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    except (TypeError, ValueError) as exc:
        raise ResultError(
            f"the result is not JSON-serializable ({type(exc).__name__}); §6.5 cannot record it"
        ) from exc
    if len(text) <= max_chars:
        return dict(result), False
    return {
        RESULT_DIGEST_KEY: sha256_digest(text.encode("utf-8")),
        RESULT_CHARS_KEY: len(text),
    }, True


def build_result(
    *,
    tool: str,
    observation: ExecObservation,
    result: Mapping[str, Any],
    evidence: ToolResultEvidence | None = None,
    error: ToolError | None = None,
    result_truncated: bool = False,
) -> ToolResult:
    """Assemble the §6.5 record. The ordering of the status rules is the point.

    ``error`` wins, then ``truncated``, then ``ok`` — see the module docstring.
    When the run failed but the caller supplied no ``error``, one is synthesized
    from the observation, because
    :class:`~lsassist.contracts.tool_result.ToolResult` refuses
    ``status=error`` without an ``error.kind`` and a failure with no stated
    reason is not a report.

    The output BODY never enters ``result``: it is evidence by DIGEST (§6.5), and
    copying it here would put unredacted tool output into every record that
    quotes the result.
    """
    failed = error is not None or observation.timed_out or observation.exit_code != 0
    if failed:
        status = ToolResultStatus.ERROR
        error = error or _failure_of(observation)
    elif observation.stdout_truncated or observation.stderr_truncated or result_truncated:
        status = ToolResultStatus.TRUNCATED
    else:
        status = ToolResultStatus.OK
    return ToolResult(
        tool=tool,
        status=status,
        exit_code=observation.exit_code,
        duration_ms=observation.duration_ms,
        stdout_digest=observation.stdout_digest,
        stderr_digest=observation.stderr_digest,
        result=dict(result),
        evidence=evidence,
        error=error,
    )


def _failure_of(observation: ExecObservation) -> ToolError:
    """Name the failure the observation describes, without quoting any output.

    ``message_redacted`` is built from NUMBERS only. The tool's own stderr is the
    obvious thing to put here and is exactly what must not be: it is
    attacker-influenced text in a field whose name promises redaction (I8).
    """
    if observation.timed_out:
        return ToolError(
            kind=TIMEOUT_ERROR,
            message_redacted=(
                f"the tool exceeded its wall-clock budget and its process group "
                f"was killed after {observation.duration_ms} ms"
            ),
        )
    return ToolError(
        kind=EXIT_STATUS_ERROR,
        message_redacted=f"the tool exited {observation.exit_code}",
    )
