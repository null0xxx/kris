"""Fail-closed bwrap availability probe + full exec-argv composition (§8.3, I11).

This is the ONLY module in ``sandbox/`` permitted to touch the outside world.
Everything else in the package (:mod:`~lsassist.sandbox.profiles`,
:mod:`~lsassist.sandbox.env`, :mod:`~lsassist.sandbox.prlimit`) stays pure.

**§8.3 failure contract.** "bwrap spawn failure → typed error
``sandbox_unavailable`` → exec tool BLOCKED (never … unsandboxed exec —
fail-closed)." Every way the probe can fail — binary absent, resolved outside
the trusted directories, non-zero exit, unparseable output, a version below the
ADR-002 minimum, a namespace that cannot be created, or ANY exception out of the
runner — collapses into one :class:`SandboxUnavailable` carrying the reason code
:data:`SANDBOX_UNAVAILABLE_REASON`. No caller-visible degraded path exists: the
probe issues a token or raises, and nothing in this package catches that
exception and continues.

**WHAT THE PROBE ATTESTS (and what it does not).** It verifies that a specific,
trusted-path ``bwrap`` binary exists, reports a supported version, AND can
actually create a user+pid namespace over the profile's own mount set — the
functional step exists because ``--version`` creates no namespace and therefore
cannot detect a userns-disabled host (this repository's ``scripts/verify-env.sh``
sets the same precedent). It attests nothing about the moment of exec: the host
can change between probe and spawn, and the probe does not evaluate the caller's
mount arguments.

**THE PROBE AND THE SPAWN NOW START THE SAME WAY (HARDEN-03).** The functional
step runs ``bwrap`` directly, and since the §8.1 ``prlimit`` caps moved INSIDE
the sandbox (see :func:`compose_exec_argv`) so does the composed argv — the two
share an outer program, so a passing probe and a working exec no longer
disagree. They did before: with the caps applied to the OUTER process the probe
PASSED while every real exec died with ``bwrap: Creating new namespace failed:
Resource temporarily unavailable``, because ``RLIMIT_NPROC`` is charged per REAL
UID and counts TASKS (measured here: ~1.5k threads for uid 1000 against
``--nproc=256``). ``tests/e2e/test_sandbox_exec.py`` spawns the composed argv
for real and reads the limits back out, so that gap cannot reopen silently.

**PROGRAM PATHS ARE PINNED (this is load-bearing).** ``bwrap`` and ``prlimit``
are located ONCE, resolved with :func:`os.path.realpath`, required to live in
:data:`_TRUSTED_BIN_DIRS`, and then carried in the token so that the probe and
the eventual spawn refer to the SAME binary. Emitting the bare names instead
would resolve ``PATH`` three separate times (probe, compose, spawn); with a
writable early ``PATH`` entry — ``~/.local/bin`` is position 1 and mode 0775 on
this host — a planted ``bwrap`` shim can answer ``--version`` convincingly and
then ``exec "$@"`` with no namespaces at all, while §8.3 reports the sandbox
AVAILABLE. Pinning removes that entirely and does not depend on the runner
remembering to spawn with ``env={}``.

**THE TOKEN IS AN AVAILABILITY GATE, NOT THE SECURITY BOUNDARY.**
:class:`SandboxAvailable` makes "a passing probe happened before this argv
existed" a type-level fact: :func:`compose_exec_argv` cannot be called without
one, the class has no public constructor, and the checks below reject instances
minted by ``object.__new__``, ``copy``/``pickle``,
:func:`dataclasses.replace`, or a subclass. But the LOAD-BEARING boundary is the
argv CONTENT — the ``bwrap`` flags emitted by
:func:`~lsassist.sandbox.profiles.build_argv` and the pinned program paths —
because that is what the kernel enforces. Code holding a forged token still
cannot produce an argv that lacks the namespace flags; the token gate is
defense in depth over that, not a substitute for it.

**Composition detail.** ``profiles.build_argv`` already terminates with
``--chdir <cwd> -- <inner command…>``, and the inner command handed to it is
``prlimit_prefix(…) + tool argv``. The composed argv therefore contains exactly
ONE ``--`` separator (assuming the tool's own argv carries none), with the
``prlimit`` fragment immediately after it; appending a second would hand
``bwrap`` a literal ``--`` as the program name.

**BECAUSE ``prlimit`` RUNS INSIDE, ITS PATH MUST BE VISIBLE INSIDE.** The pinned
paths are validated against the HOST filesystem's trusted directories, which
says nothing about the sandbox's mount view. :func:`compose_exec_argv` therefore
also requires ``prlimit_path`` to lie under one of
:data:`~lsassist.sandbox.profiles.SYSTEM_RO_BINDS` — today every trusted
directory does (``/usr/bin`` and ``/usr/local/bin`` under the ``/usr`` bind,
``/bin`` under its own), so no new bind is needed; the check exists so that
widening the trusted set later cannot silently produce an argv whose every exec
is an ENOENT. ``bwrap`` itself is deliberately NOT subject to it: it executes on
the host, before any mount view exists.

**No shell, ever (§7.6 rule 8).** The default runner invokes an argv LIST. The
sandboxed exec itself is not performed here — the T3.03 runner receives the
composed list and spawns it directly.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import ClassVar, Final, NamedTuple

from lsassist.contracts.sandbox_profile import Profile
from lsassist.sandbox.prlimit import prlimit_prefix
from lsassist.sandbox.profiles import SYSTEM_RO_BINDS, build_argv, checked_argv

__all__ = [
    "BWRAP",
    "MIN_BWRAP_VERSION",
    "PRLIMIT",
    "SANDBOX_UNAVAILABLE_REASON",
    "ProbeResult",
    "SandboxAvailable",
    "SandboxUnavailable",
    "compose_exec_argv",
    "functional_probe_argv",
    "probe",
]

#: The sandbox binary, and the resource-cap wrapper of §8.1. Both are located
#: and PINNED to an absolute path by :func:`probe`; neither is ever spawned as a
#: bare name, and neither is ever invoked through a shell string.
BWRAP: Final = "bwrap"
PRLIMIT: Final = "prlimit"

#: §8.3 reason code. Travels in :attr:`SandboxUnavailable.reason` and in the
#: message, so audit/verdict layers can key on it without parsing prose.
SANDBOX_UNAVAILABLE_REASON: Final = "sandbox_unavailable"

#: ADR-002 minimum: the host was verified at ``bubblewrap 0.9.0`` (unprivileged
#: userns, no setuid helper). Compared as a NUMERIC tuple — a string compare
#: would rank ``"0.10.0"`` BELOW ``"0.9.0"`` and reject a newer bwrap.
MIN_BWRAP_VERSION: Final[tuple[int, int, int]] = (0, 9, 0)

#: Directories a security-critical program may be resolved from. Everything
#: else — ``~/.local/bin``, a workspace, ``/tmp`` — is user-writable on a normal
#: desktop and is therefore a shim location, not a trusted one.
_TRUSTED_BIN_DIRS: Final[frozenset[str]] = frozenset({"/usr/bin", "/bin", "/usr/local/bin"})

#: Wall-clock cap for the probe's own child processes.
PROBE_TIMEOUT_S: Final = 10

#: Longest stderr excerpt attached to a failure message. bwrap's own diagnostic
#: ("Creating new namespace failed: …") is the difference between a debuggable
#: refusal and a mystery; it is the sandbox program's output, not tool data.
_STDERR_EXCERPT_CHARS: Final = 200

#: The program the functional probe runs inside the throwaway sandbox.
_PROBE_TARGET: Final = "/bin/true"

# `bwrap --version` prints exactly `bubblewrap X.Y.Z`. Anchored at both ends and
# digit-bounded: anything else (a two-component version, a trailing suffix, a
# different program's banner) is UNPARSEABLE and therefore unavailable. Being
# strict here is the fail-closed direction — a version we cannot read is a
# version we cannot vouch for.
_VERSION_RE: Final = re.compile(r"\Abubblewrap[ \t]+(\d{1,6})\.(\d{1,6})\.(\d{1,6})\Z")

# Issuance sentinel: only `_issue` ever writes it onto a token, and only `probe`
# calls `_issue`. Module-private and never exported.
_ISSUED_BY_PROBE: Final = object()


class SandboxUnavailable(RuntimeError):
    """§8.3 ``sandbox_unavailable``: no usable ``bwrap`` — exec is BLOCKED.

    Raised by :func:`probe` for every failure mode, and by
    :func:`compose_exec_argv` when handed anything other than a probe-issued
    token. Callers must let it propagate: catching it and running the tool
    anyway is precisely the unsandboxed execution §8.3 forbids.
    """

    #: The §8.3 reason code, as a class attribute so `except` handlers and
    #: audit records can read it off any instance.
    reason: ClassVar[str] = SANDBOX_UNAVAILABLE_REASON

    def __init__(self, detail: str) -> None:
        super().__init__(f"{SANDBOX_UNAVAILABLE_REASON}: {detail}")
        self.detail = detail


class ProbeResult(NamedTuple):
    """What an injected ``run_fn`` must return.

    ``stderr`` defaults to ``""`` so a fake may supply two fields, but the real
    runner always fills it: a probe that refuses without a diagnostic is a probe
    nobody can debug.
    """

    returncode: int
    stdout: str
    stderr: str = ""


@dataclass(frozen=True, slots=True)
class SandboxAvailable:
    """A probe receipt: a supported ``bwrap`` was observed AND ran (I11).

    THERE IS NO PUBLIC CONSTRUCTOR. ``__post_init__`` raises unconditionally, so
    every route through ``__init__`` — direct construction,
    :func:`dataclasses.replace` (which would otherwise forge the pinned paths)
    — fails. :func:`probe` builds instances through :func:`_issue`, which
    bypasses ``__init__`` and stamps the private issuance sentinel; routes that
    bypass ``__init__`` WITHOUT the sentinel (``object.__new__``, ``copy``,
    ``pickle``, a subclass) are rejected by :func:`compose_exec_argv` instead.

    Holding one is not a capability to run something unsandboxed — see the
    module docstring: the enforced boundary is the argv content.
    """

    #: The detected ``(major, minor, patch)``, ``>= MIN_BWRAP_VERSION``.
    version: tuple[int, int, int]
    #: Absolute, realpath-resolved, trusted-directory path to ``bwrap`` — the
    #: exact binary the probe exercised, and the one the argv will run.
    bwrap_path: str
    #: Absolute, realpath-resolved, trusted-directory path to ``prlimit``.
    prlimit_path: str
    #: The §8.1 binds that EXIST on this host, in template order (HARDEN-05).
    #: This is the set the functional probe exercised and the set
    #: :func:`compose_exec_argv` renders — the two cannot drift apart, because
    #: there is only one of them.
    system_binds: tuple[str, ...] = SYSTEM_RO_BINDS
    #: The §8.1 binds this host does NOT have. Empty on a Debian-family host.
    #: Carried so the omission is ATTESTED rather than silent: a reader of the
    #: receipt can see exactly which part of the §8.1 mount view was not applied.
    omitted_binds: tuple[str, ...] = ()

    # Never passed to __init__ (so `replace` cannot carry it over) and excluded
    # from repr and equality.
    _issuance: object = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        raise SandboxUnavailable(
            "SandboxAvailable has no public constructor; only probe() issues one"
        )


def _issue(
    *,
    version: tuple[int, int, int],
    bwrap_path: str,
    prlimit_path: str,
    system_binds: tuple[str, ...],
    omitted_binds: tuple[str, ...],
) -> SandboxAvailable:
    """Mint a receipt WITHOUT running ``__init__`` (the only issuance path)."""
    token = object.__new__(SandboxAvailable)
    object.__setattr__(token, "version", version)
    object.__setattr__(token, "bwrap_path", bwrap_path)
    object.__setattr__(token, "prlimit_path", prlimit_path)
    object.__setattr__(token, "system_binds", system_binds)
    object.__setattr__(token, "omitted_binds", omitted_binds)
    object.__setattr__(token, "_issuance", _ISSUED_BY_PROBE)
    return token


def _resolve_system_binds(
    exists_fn: Callable[[str], bool],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Measure which §8.1 binds this host actually has (HARDEN-05).

    ``bwrap --ro-bind`` on a source that does not exist is a HARD error, and the
    §8.1 template is not universal: ``/etc/alternatives`` belongs to Debian's
    ``update-alternatives`` and does not exist on Arch, so on such a host the
    functional probe exited 1 and every exec was BLOCKED — measured on Garuda
    Linux with a fully working bwrap 0.11.2 and userns enabled.

    Omitting an absent bind cannot weaken the sandbox: a ``--ro-bind`` that is
    not emitted strictly SHRINKS the child's mount view. What it could do is
    produce a mount view too thin to execute anything — and that is decided by
    MEASUREMENT rather than by a hand-maintained "required" list, which would
    just re-introduce the distro assumption this removes: the surviving set is
    what :func:`_check_functional` then RUNS. If it cannot execute
    :data:`_PROBE_TARGET`, the probe fails and exec stays BLOCKED.

    :returns: ``(present, missing)``, both in template order.
    :raises SandboxUnavailable: ``exists_fn`` raised, or NOTHING exists.
    """
    present: list[str] = []
    missing: list[str] = []
    for path in SYSTEM_RO_BINDS:
        try:
            found = exists_fn(path)
        # Broad on purpose: a host we cannot interrogate is a host we cannot
        # vouch for. `os.path.exists` swallows OSError, but an injected probe
        # (or a future stat-based one) need not.
        except Exception as exc:
            raise SandboxUnavailable(
                f"could not determine whether the §8.1 bind {path!r} exists: {exc!r}"
            ) from exc
        (present if found else missing).append(path)
    if not present:
        raise SandboxUnavailable(
            f"none of the §8.1 system binds {list(SYSTEM_RO_BINDS)} exist on this host; "
            "a sandbox with no system mounts cannot execute anything"
        )
    return tuple(present), tuple(missing)


def _is_trusted_program(path: object) -> bool:
    """True when ``path`` is an absolute program in a trusted directory (PURE)."""
    return (
        isinstance(path, str)
        and bool(path)
        and "\x00" not in path
        and os.path.isabs(path)
        and os.path.dirname(path) in _TRUSTED_BIN_DIRS
    )


def _is_in_mount_view(path: str, system_binds: Sequence[str]) -> bool:
    """True when ``path`` is reachable inside the profile's own mount view (PURE).

    Segment-aware, so ``/binary/prlimit`` is not "inside" the ``/bin`` bind and
    ``/usrlocal/…`` is not inside ``/usr``. Mirrors
    :func:`lsassist.sandbox.profiles._is_within` deliberately rather than
    importing it: this is availability's fail-closed decision, and profiles must
    stay free of any notion of which programs the exec path runs.

    ``system_binds`` is the RESOLVED set from the receipt, never the template
    (HARDEN-05): a ``prlimit`` sitting under a bind THIS host lacks is invisible
    to the child, so checking it against the template would wave through an argv
    whose every exec is an ENOENT.
    """
    return any(path == bind or path.startswith(bind.rstrip("/") + "/") for bind in system_binds)


def _excerpt(stderr: object) -> str:
    """Render a short, whitespace-collapsed stderr tail for a failure message."""
    if not isinstance(stderr, str) or not stderr.strip():
        return ""
    text = " ".join(stderr.split())
    if len(text) > _STDERR_EXCERPT_CHARS:
        text = text[:_STDERR_EXCERPT_CHARS] + "..."
    return f" (stderr: {text})"


def _default_run(argv: Sequence[str]) -> ProbeResult:
    """Run ``argv`` as a LIST and capture its output (§7.6 rule 8: no shell).

    ``check=False`` because a non-zero exit is DATA here — :func:`probe` turns
    it into :class:`SandboxUnavailable` itself, with the same reason code as
    every other failure mode.
    """
    # A fixed argv LIST, never a shell string (§7.6 rule 8).
    completed = subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        timeout=PROBE_TIMEOUT_S,
        check=False,
    )
    return ProbeResult(completed.returncode, completed.stdout, completed.stderr)


def _locate(name: str, which_fn: Callable[[str], str | None]) -> str:
    """Resolve ``name`` to a pinned, trusted absolute path, or raise (§8.3)."""
    try:
        located = which_fn(name)
    # Broad on purpose: every failure to LOOK for the program means "no sandbox".
    except Exception as exc:
        raise SandboxUnavailable(f"locating {name!r} failed: {exc!r}") from exc
    if not located or not isinstance(located, str):
        raise SandboxUnavailable(f"{name!r} was not found on PATH")

    try:
        resolved = os.path.realpath(located)
    except OSError as exc:
        raise SandboxUnavailable(f"resolving {located!r} failed: {exc!r}") from exc

    if not _is_trusted_program(resolved):
        raise SandboxUnavailable(
            f"{name!r} resolved to {resolved!r}, which is not in a trusted program "
            f"directory {sorted(_TRUSTED_BIN_DIRS)} — an early writable PATH entry "
            "is a shim, and a shimmed sandbox is no sandbox"
        )
    return resolved


def _run(run_fn: Callable[[Sequence[str]], ProbeResult], argv: list[str], what: str) -> ProbeResult:
    """Call an injected runner, funnelling every failure into §8.3."""
    try:
        result = run_fn(argv)
    # Broad on purpose: OSError, TimeoutExpired, CalledProcessError and any
    # surprise from an injected runner are all one §8.3 outcome.
    except Exception as exc:
        # The §8.3 "bwrap spawn failure" case. Wrapped, never re-raised raw: a
        # caller that must distinguish "no sandbox" from "some OSError" would be
        # a caller deciding whether to proceed unsandboxed.
        raise SandboxUnavailable(f"{what} failed: {exc!r}") from exc
    if not isinstance(result, ProbeResult):
        raise SandboxUnavailable(
            f"probe runner must return a ProbeResult, got {type(result).__name__}"
        )
    return result


def _parse_version(stdout: object) -> tuple[int, int, int] | None:
    """Return the ``bubblewrap X.Y.Z`` triple, or ``None`` if unreadable."""
    if not isinstance(stdout, str):
        return None
    match = _VERSION_RE.match(stdout.strip())
    if match is None:
        return None
    return (int(match[1]), int(match[2]), int(match[3]))


def _check_version(
    bwrap_path: str, run_fn: Callable[[Sequence[str]], ProbeResult]
) -> tuple[int, int, int]:
    """Step 1: the pinned binary reports a supported version."""
    result = _run(run_fn, [bwrap_path, "--version"], f"{bwrap_path} --version")
    if result.returncode != 0:
        raise SandboxUnavailable(
            f"{bwrap_path} --version exited {result.returncode}{_excerpt(result.stderr)}"
        )
    version = _parse_version(result.stdout)
    if version is None:
        raise SandboxUnavailable(
            f"could not parse a bubblewrap version from {result.stdout!r}"
            f"{_excerpt(result.stderr)}"
        )
    if version < MIN_BWRAP_VERSION:
        detected = ".".join(str(part) for part in version)
        minimum = ".".join(str(part) for part in MIN_BWRAP_VERSION)
        raise SandboxUnavailable(f"bubblewrap {detected} is older than the required {minimum}")
    return version


def functional_probe_argv(
    bwrap_path: str, system_binds: Sequence[str] = SYSTEM_RO_BINDS
) -> list[str]:
    """The throwaway sandbox used to prove namespaces actually work here.

    It mirrors the PROFILE's own system binds rather than a minimal ``/usr``
    bind, because a probe that succeeds where the real profile fails attests
    nothing. Measured on this host: ``--ro-bind /usr /usr -- /bin/true`` fails
    with ``bwrap: execvp /bin/true: No such file or directory`` — the ELF
    interpreter ``/lib64/ld-linux-x86-64.so.2`` is not in that mount view, and
    ``execvp`` reports the MISSING LOADER as a missing binary. Binding the
    profile's set (``/usr``, ``/bin``, ``/lib``, ``/lib64``, …) exits 0.

    **HARDEN-05: the set is the RESOLVED one, not the template.** It used to be
    :data:`~lsassist.sandbox.profiles.SYSTEM_RO_BINDS` verbatim, on the reasoning
    that "a distribution missing one of those binds fails here exactly as the
    real profile would — the intended, fail-closed coupling". The coupling was
    right; the conclusion was not. The probe was faithfully reporting an
    unbuildable profile on every host without ``/etc/alternatives`` — i.e. all of
    Arch — so the whole assistant was unusable there rather than protected. The
    coupling is PRESERVED by construction: :func:`probe` measures once and both
    this argv and :func:`compose_exec_argv` render that single set.

    The default remains the full template so that a caller who omits the argument
    gets the §8.1 literal, never a silently narrowed sandbox.
    """
    argv = [bwrap_path, "--unshare-user", "--unshare-pid"]
    for path in system_binds:
        argv += ["--ro-bind", path, path]
    argv += ["--", _PROBE_TARGET]
    return argv


def _check_functional(
    bwrap_path: str,
    system_binds: Sequence[str],
    run_fn: Callable[[Sequence[str]], ProbeResult],
) -> None:
    """Step 2: a namespace can actually be created on THIS host, right now.

    This is also what bounds HARDEN-05's omission: the argv runs the set that
    SURVIVED the existence measurement, so a host whose remaining binds cannot
    execute :data:`_PROBE_TARGET` fails here instead of composing an exec that
    would ENOENT.
    """
    result = _run(
        run_fn, functional_probe_argv(bwrap_path, system_binds), "the bwrap functional probe"
    )
    if result.returncode != 0:
        raise SandboxUnavailable(
            f"{bwrap_path} exists and is new enough, but cannot create a namespace on "
            f"this host (functional probe exited {result.returncode})"
            f"{_excerpt(result.stderr)}"
        )


def probe(
    *,
    which_fn: Callable[[str], str | None] = shutil.which,
    run_fn: Callable[[Sequence[str]], ProbeResult] = _default_run,
    exists_fn: Callable[[str], bool] = os.path.exists,
) -> SandboxAvailable:
    """Verify that a usable ``bwrap`` sandbox can be built here, or raise (§8.3).

    Five steps, all fail-closed: locate+pin ``bwrap``, locate+pin ``prlimit``,
    check the version, MEASURE which §8.1 binds this host has (HARDEN-05), then
    RUN a throwaway sandbox (:func:`functional_probe_argv`) over exactly that set
    to prove namespace creation works.

    The measurement happens ONCE, here, and the result is carried in the receipt.
    Re-measuring at compose time would open a window in which the probe attested
    one mount view and the exec rendered another — the very drift HARDEN-03 shut.

    :param which_fn: ``PATH`` lookup, injected for testability. Asked for
        exactly ``"bwrap"`` and ``"prlimit"``; each result is realpath-resolved
        and required to sit in :data:`_TRUSTED_BIN_DIRS`.
    :param run_fn: runner for the two probe command lines, injected so the unit
        tests spawn nothing. Must return a :class:`ProbeResult`.
    :param exists_fn: existence check for the §8.1 binds, injected so unit tests
        do not depend on the filesystem of whoever runs them. Asked about the
        template paths and nothing else.
    :returns: a :class:`SandboxAvailable` carrying the detected version, the two
        pinned absolute paths — the same binaries the composed argv runs — and
        the resolved/omitted bind sets.
    :raises SandboxUnavailable: binary absent, untrusted location, lookup
        failed, runner raised, malformed runner result, non-zero exit,
        unparseable version, version below :data:`MIN_BWRAP_VERSION`, no §8.1
        bind present at all, ``exists_fn`` raised, or a namespace that could not
        be created. There is no other outcome: this function returns a receipt
        or raises.
    """
    bwrap_path = _locate(BWRAP, which_fn)
    prlimit_path = _locate(PRLIMIT, which_fn)
    version = _check_version(bwrap_path, run_fn)
    system_binds, omitted_binds = _resolve_system_binds(exists_fn)
    _check_functional(bwrap_path, system_binds, run_fn)
    return _issue(
        version=version,
        bwrap_path=bwrap_path,
        prlimit_path=prlimit_path,
        system_binds=system_binds,
        omitted_binds=omitted_binds,
    )


def compose_exec_argv(
    *,
    available: SandboxAvailable,
    profile: Profile,
    workspace: str,
    cwd: str,
    cache_dir: str,
    argv: Sequence[str],
    timeout_s: int,
    venv_exists: bool = False,
    lc_all: str | None = None,
    term: str | None = None,
    env_extra: Mapping[str, str] | None = None,
) -> list[str]:
    """Compose the COMPLETE §8.1 exec argv: ``bwrap`` profile + ``prlimit`` caps.

    This is the only supported way to obtain a runnable command line for a
    sandboxed tool. The result is::

        <abs bwrap>   --unshare-all … --chdir <cwd> --  (profiles.build_argv)
        <abs prlimit> --nproc… --nofile… --as… --cpu…   (prlimit.prlimit_prefix)
        <tool argv…>

    Both programs are the PINNED absolute paths from the receipt, so no ``PATH``
    lookup happens at spawn time.

    **DELIBERATE, DOCUMENTED DEVIATION FROM THE §8.1 LITERAL TEMPLATE
    (HARDEN-03, human-approved at the T2.06 review checkpoint; SPEC §8.1 is
    being updated to match).** The template writes ``prlimit … bwrap … -- tool``,
    i.e. the caps on the OUTER process. Measured, that does not work:
    ``RLIMIT_NPROC`` is charged per REAL UID and counts TASKS, so with a desktop
    session's ~1.5k threads already charged to uid 1000, ``--nproc=256`` makes
    ``bwrap``'s own ``clone(CLONE_NEWUSER)`` fail — ``bwrap: Creating new
    namespace failed: Resource temporarily unavailable`` — and the §18 T-14
    fork-bomb cap enforces nothing while breaking the whole exec path. Applied to
    the INNER command all four caps land exactly (``256 1024 4194304 40``
    measured inside; a bounded fork loop under ``--nproc=32`` gives
    ``spawned=29 refused=31``), ``/usr/bin/prlimit`` is already in the mount view
    via the §8.1 ``--ro-bind /usr /usr`` (no new bind), util-linux ``prlimit``
    ``execve``s rather than forking (so pid, exit status and signals stay
    transparent and §6.3's process-group SIGKILL semantics are untouched), and
    the caps cannot be raised again because ``prlimit`` sets soft == hard and an
    unprivileged process may only LOWER a hard limit. Deleting ``--nproc``
    instead was rejected as a security regression; a test asserts it survives in
    the composed argv. See :mod:`~lsassist.sandbox.prlimit` for ``--cpu``'s real
    (CPU-budget, not wall-clock) semantics, still a T3.03 runner concern.

    :param available: the receipt from :func:`probe`. REQUIRED and keyword-only,
        so no exec argv exists without a passing probe. It is re-checked by
        IDENTITY of type and issuance sentinel (``object.__new__``, ``copy``,
        ``pickle``, :func:`dataclasses.replace` and subclasses are all refused),
        its pinned paths are re-validated against the trusted directories, and
        ``prlimit_path`` must additionally be reachable INSIDE the mount view —
        those last checks are the ones that still hold if a receipt is forged.
    :param timeout_s: the runner's wall-clock budget; drives ``--cpu``.
    :returns: a fresh ``list[str]`` beginning with the absolute ``bwrap`` path.
        Exactly ONE ``--`` element is added (by ``build_argv``), followed by the
        five-element ``prlimit`` fragment and then the tool's argv, verbatim.
    :raises SandboxUnavailable: ``available`` is not a probe-issued receipt,
        carries a program path outside the trusted directories, or carries a
        ``prlimit`` path the sandbox would not mount.
    :raises ~lsassist.sandbox.prlimit.PrlimitError: invalid ``timeout_s``.
    :raises ~lsassist.sandbox.profiles.SandboxProfileError: invalid profile,
        path, argv, or mount shape.
    :raises ~lsassist.sandbox.env.EnvProjectionError: a rejected env addition.

    Any of these leaves the caller with NO argv at all — which is the point:
    §8.3 blocks the exec instead of weakening it.
    """
    if type(available) is not SandboxAvailable or (
        getattr(available, "_issuance", None) is not _ISSUED_BY_PROBE
    ):
        raise SandboxUnavailable(
            "compose_exec_argv requires a receipt issued by probe(), got "
            f"{type(available).__name__}"
        )
    for label, program in (
        ("bwrap_path", available.bwrap_path),
        ("prlimit_path", available.prlimit_path),
    ):
        if not _is_trusted_program(program):
            raise SandboxUnavailable(
                f"receipt {label}={program!r} is not an absolute path in "
                f"{sorted(_TRUSTED_BIN_DIRS)}"
            )
    # HARDEN-05: the bind set travels on the receipt, so it is re-validated here
    # exactly like the pinned paths are — a receipt that bypassed `__init__`
    # (`object.__new__`, `pickle`) could otherwise carry an arbitrary bind and
    # widen the mount view of an argv still calling itself the §8.1 `ro` profile.
    # Omission is safe; addition is not. `profiles` refuses the same widening,
    # but it raises SandboxProfileError, and a forged RECEIPT is an availability
    # failure — §8.3 must see one reason code, not two.
    # `getattr` with a default, not attribute access: `slots=True` means a receipt
    # minted by `object.__new__` (or restored by `pickle`) has NO such attribute
    # at all, and a bare `available.system_binds` would escape as an AttributeError
    # instead of the one §8.3 reason code every other failure mode collapses into.
    binds = getattr(available, "system_binds", None)
    if not isinstance(binds, tuple) or not binds or not set(binds) <= set(SYSTEM_RO_BINDS):
        raise SandboxUnavailable(
            f"receipt system_binds={binds!r} is not a non-empty subset of the §8.1 "
            f"template {list(SYSTEM_RO_BINDS)}"
        )
    # `prlimit` is the head of the INNER command, so the host-side check above is
    # not enough: a path bwrap never mounts turns every exec into an ENOENT.
    # `bwrap` is exempt — it runs on the host, outside any mount view.
    if not _is_in_mount_view(available.prlimit_path, binds):
        raise SandboxUnavailable(
            f"receipt prlimit_path={available.prlimit_path!r} is not inside the sandbox "
            f"mount view {list(binds)}; the caps run INSIDE the sandbox, so a "
            "prlimit the sandbox cannot see would fail every exec"
        )

    # The caps are the head of the inner command, NOT a wrapper around bwrap —
    # see the deviation note above for the measurement that forced this order.
    # The tool argv is validated FIRST: behind the prefix, `build_argv` would be
    # inspecting `prlimit`, and an empty (or `str`) tool argv would compose into
    # a sandbox that runs the caps program alone.
    inner = prlimit_prefix(timeout_s, prlimit_path=available.prlimit_path) + checked_argv(argv)
    return build_argv(
        profile=profile,
        workspace=workspace,
        cwd=cwd,
        cache_dir=cache_dir,
        argv=inner,
        venv_exists=venv_exists,
        lc_all=lc_all,
        term=term,
        env_extra=env_extra,
        bwrap_path=available.bwrap_path,
        system_binds=binds,
    )
