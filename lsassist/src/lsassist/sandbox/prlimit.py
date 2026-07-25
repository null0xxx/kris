"""Pure ``prlimit`` prefix builder for the §8.1 resource caps (ADR-002; T-14).

SPEC §8.1 caps every sandboxed exec with::

    prlimit --nproc=256 --nofile=1024 --as=4G --cpu=<timeout+10>

:func:`prlimit_prefix` renders exactly that five-element fragment. It is the §18
T-14 control: ``nproc`` caps fork bombs, ``nofile`` caps descriptor exhaustion,
``as`` caps address space, ``cpu`` caps CPU time. Where the fragment goes is not
where §8.1 literally puts it — see PLACEMENT below.

**MANDATORY DEVIATION FROM THE §8.1 TEXT: ``--as=4G`` → ``--as=4294967296``.**
util-linux ``prlimit`` has NO size-suffix parser. Verified on the host
(``prlimit from util-linux 2.39.3``):

- ``prlimit --as=4G /bin/echo hi`` → ``prlimit: failed to execute /bin/echo:
  Argument list too long`` (exit 126). The ``G`` is discarded and the limit
  becomes **4 BYTES** of address space, so the very first ``execve`` under it
  dies with ``E2BIG``. Transcribing §8.1 literally therefore breaks EVERY
  sandboxed exec — a silent, total outage of the exec path.
- ``prlimit --as=4294967296 /bin/echo hi`` → ``hi``; inside,
  ``ulimit -v`` reports ``4194304`` KB = exactly 4 GiB, i.e. the §8.1 INTENT.

The rule generalizes: every numeric limit below is emitted as a PLAIN INTEGER of
the unit ``prlimit`` actually uses (bytes for ``--as``, seconds for ``--cpu``,
counts for ``--nproc``/``--nofile``). Never a suffix, never a unit letter — the
failure mode is not a rejected flag but a wildly wrong limit that is accepted.

**PROGRAM PATH.** ``prlimit_path`` defaults to the bare ``"prlimit"`` of the
§8.1 spelling, but the exec path passes an ABSOLUTE, validated path (see
:func:`~lsassist.sandbox.availability.probe`): a bare name is resolved against
``PATH`` at spawn time, and a writable early ``PATH`` entry is a shim that can
replace the limits with nothing. This module stays pure — it renders whatever
path it is given and checks no filesystem.

**PLACEMENT: THIS PREFIX RUNS INSIDE THE SANDBOX, NOT AROUND IT (HARDEN-03 —
implemented, human-approved; a deliberate, documented deviation from the §8.1
literal template, which SPEC §8.1 is being updated to match).**
:func:`~lsassist.sandbox.availability.compose_exec_argv` emits
``bwrap … -- prlimit --nproc… <tool argv…>``, i.e. this fragment is the HEAD OF
THE INNER COMMAND. The template's outer position was measured to be broken:
``RLIMIT_NPROC`` is charged per REAL UID and counts TASKS (threads), not
processes, so it is already near its ceiling in a desktop session (this host:
1472 to 2024 threads for uid 1000). Applying it to the OUTER process makes
``bwrap``'s ``clone(CLONE_NEWUSER)`` fail before the sandbox exists — the flag
enforces NOTHING and takes the entire exec path down with it::

    $ prlimit --nproc=256 bwrap --unshare-all … -- /bin/true
    bwrap: Creating new namespace failed: Resource temporarily unavailable
    $ prlimit --nproc=4096 bwrap --unshare-all … -- /bin/true   # succeeds

``--nofile``/``--as``/``--cpu`` were unaffected in that position; only
``--nproc`` broke it. Applied INSIDE, all four caps work as §8.1 intends,
because the child's user namespace starts its own task count near zero::

    $ bwrap … -- prlimit --nproc=256 --nofile=1024 --as=4294967296 --cpu=40 \
          bash -c 'echo $(ulimit -u) $(ulimit -n) $(ulimit -v) $(ulimit -t)'
    256 1024 4194304 40
    # with --nproc=32 inside: spawned=29 refused=31

Four measured facts make the inner position safe: ``/usr/bin/prlimit`` is
ALREADY in the mount view via the §8.1 ``--ro-bind /usr /usr`` (no new bind, and
:func:`~lsassist.sandbox.availability.compose_exec_argv` refuses a ``prlimit``
path the sandbox would not mount); util-linux ``prlimit`` ``execve``s rather
than forking, so pid, exit status and signals stay transparent (``exit 42`` →
rc 42, ``kill -9`` → rc 137) and §6.3's process-group SIGKILL semantics are
untouched; ``prlimit`` sets soft == hard and an unprivileged process may only
LOWER a hard limit, so the sandboxed tool cannot raise its own caps (verified
``EPERM``/``EINVAL``); and ``tests/e2e/test_sandbox_exec.py`` spawns the real
composed argv and reads the limits back out from inside.

**The alternative "fix" — DELETING the outer ``--nproc`` — was rejected**: it
removes the §18 T-14 fork-bomb control entirely, a security regression wearing
the costume of a bug fix. A test asserts that ``--nproc=`` survives somewhere in
the composed argv, so the control cannot be dropped silently.

**HOST FINDING — what ``--cpu`` ACTUALLY does (measured; the §8.1 value is
kept verbatim, only the rationale is corrected).** ``RLIMIT_CPU`` is a CPU-time
budget, NOT a wall-clock backstop:

- It sums CPU across the THREADS of one process, so it fires at roughly
  ``(timeout+10)/N`` WALL seconds for an N-threaded tool. Measured with
  ``--cpu=3`` on a thread-parallel hash burner: wall **3.00 s** (1 thread),
  **0.77 s** (4 threads), **0.40 s** (8 threads). For a multithreaded runner
  (``cargo test``, ``pytest -n``) the CPU cap therefore fires EARLY, well before
  the tool's own wall-clock timeout — a competing deadline, not a backstop.
- ``fork`` RESETS the child's counter. Measured: under ``--cpu=2`` a shell
  spawned three children burning ~1.8 s CPU each — 5.4 s of tree CPU — and
  nothing was killed. Aggregate tree CPU is bounded only by
  ``nproc * (timeout+10)``, so this is a weak tree-level DoS control.
- ``prlimit`` sets soft == hard, so a breach arrives as **SIGKILL / exit 137**
  (measured), which is exactly what the runner's own timeout kill produces.

T3.03 consequences: the runner MUST still enforce its own wall-clock
process-group SIGKILL (this flag does not do it), and it CANNOT infer §8.3's
``timeout`` vs "rlimit breach" evidence from the exit status alone — it needs
its own elapsed-time / ``getrusage`` record to tell them apart.

**Fail-closed input validation.** ``timeout_s`` must be a real ``int`` (``bool``
is rejected despite ``isinstance(True, int)``), strictly positive, and at most
:data:`MAX_TIMEOUT_S` = 600 s — the largest per-exec ``timeout_s`` in the §6.4
tool catalog (``test.run``). §4.3's ``max_wall_clock`` (30 min) is a per-TASK
budget summed over up to 25 tool calls, so it is NOT the ceiling for one exec.
The value is never clamped, because a silently clamped limit is
indistinguishable from an honoured one at the call site (§8.3: a sandbox that
cannot be built correctly BLOCKS the exec).

PURE (§2.2): no imports, no filesystem, no environment, no child processes.
"""

from __future__ import annotations

__all__ = [
    "AS_LIMIT_BYTES",
    "CPU_GRACE_S",
    "MAX_TIMEOUT_S",
    "NOFILE_LIMIT",
    "NPROC_LIMIT",
    "PrlimitError",
    "prlimit_prefix",
]

#: §8.1 ``--nproc``: max processes/threads (fork-bomb cap, §18 T-14). Enforced
#: against the SANDBOX's own task count — see PLACEMENT in the module docstring
#: for why the outer position enforced nothing, and why deleting the flag would
#: have been a security regression rather than a fix.
NPROC_LIMIT = 256

#: §8.1 ``--nofile``: max open file descriptors.
NOFILE_LIMIT = 1024

#: §8.1 ``--as``: max address space, in BYTES. 4 GiB — the §8.1 intent, spelled
#: as a plain integer because ``prlimit`` reads ``4G`` as the number 4 (see the
#: module docstring). ``4 * 1024**3 == 4294967296``.
AS_LIMIT_BYTES = 4 * 1024**3

#: §8.1 ``--cpu = timeout + 10``: seconds of CPU time. The margin over the wall
#: timeout is the §8.1 formula, kept verbatim; see HOST FINDING 2 for what the
#: limit actually enforces (a CPU budget that fires early on threads, resets on
#: fork, and kills with SIGKILL).
CPU_GRACE_S = 10

#: Largest per-exec timeout in the §6.4 tool catalog (``test.run`` = 600 s).
#: NOT §4.3's ``max_wall_clock``, which is a separate per-task budget.
MAX_TIMEOUT_S = 600

#: §8.1 spelling of the program. The exec path overrides it with an absolute,
#: validated path — see the PROGRAM PATH note in the module docstring.
_DEFAULT_PRLIMIT = "prlimit"


class PrlimitError(ValueError):
    """A resource-cap prefix could not be built — the caller gets no argv at all.

    §8.3 failure behavior: an exec whose caps cannot be expressed correctly must
    be BLOCKED, never run with weaker (or absent) limits.
    """


def prlimit_prefix(timeout_s: int, *, prlimit_path: str = _DEFAULT_PRLIMIT) -> list[str]:
    """Build the §8.1 ``prlimit`` prefix for an exec with ``timeout_s`` wall budget.

    :param timeout_s: the runner's wall-clock timeout for this exec, in seconds.
        Must be an ``int`` in ``1..600`` (§6.4). ``bool`` is refused.
    :param prlimit_path: the program placed at the HEAD OF THE FRAGMENT (which
        the exec path splices in after ``bwrap``'s ``--``, so it is the inner
        command's program, not the composed argv's ``argv[0]``). Defaults to the
        §8.1 bare name; callers on the exec path pass the absolute path the
        availability probe validated. Rendered verbatim — this function performs
        no lookup and no filesystem check (§2.2 purity).
    :returns: a fresh ``list[str]``::

            [<prlimit_path>, "--nproc=256", "--nofile=1024",
             "--as=4294967296", "--cpu=<timeout_s + 10>"]

        Deterministic, and the caller may mutate it freely.
    :raises PrlimitError: ``timeout_s`` is not an ``int``, is a ``bool``, is
        non-positive, exceeds :data:`MAX_TIMEOUT_S`, or ``prlimit_path`` is not
        a non-empty NUL-free ``str``.
    """
    # `bool` first: `isinstance(True, int)` is True, so `prlimit_prefix(True)`
    # would otherwise silently mean "1 second".
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, int):
        raise PrlimitError(f"timeout_s must be an int, got {type(timeout_s).__name__}")
    if timeout_s <= 0:
        raise PrlimitError(f"timeout_s must be > 0, got {timeout_s}")
    if timeout_s > MAX_TIMEOUT_S:
        raise PrlimitError(
            f"timeout_s must be <= {MAX_TIMEOUT_S} (SPEC 6.4 per-exec ceiling), got {timeout_s}"
        )
    if not isinstance(prlimit_path, str) or not prlimit_path:
        raise PrlimitError(f"prlimit_path must be a non-empty str, got {prlimit_path!r}")
    if "\x00" in prlimit_path:
        raise PrlimitError("prlimit_path contains NUL")

    # PLAIN INTEGERS ONLY — see the module docstring's `4G` finding.
    return [
        prlimit_path,
        f"--nproc={NPROC_LIMIT}",
        f"--nofile={NOFILE_LIMIT}",
        f"--as={AS_LIMIT_BYTES}",
        f"--cpu={timeout_s + CPU_GRACE_S}",
    ]
