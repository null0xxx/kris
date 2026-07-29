"""T2.06: fail-closed bwrap probe, program pinning, and exec-argv composition.

Four properties, each structural rather than behavioural:

1. **Programs are PINNED.** ``bwrap`` and ``prlimit`` are located once,
   realpath-resolved, required to live in a trusted directory, and carried in
   the receipt — so the binary the probe attested is the binary the argv runs.
   A bare name would be re-resolved against ``PATH`` at spawn time, and a
   writable early ``PATH`` entry (``~/.local/bin``) is a shim that can answer
   ``--version`` convincingly and then run the tool with no namespaces while
   §8.3 reports the sandbox AVAILABLE.
2. **The probe never leaks a raw exception and never returns a degraded ok.**
   Missing binary, untrusted location, unparseable/empty output, non-zero exit,
   a namespace that cannot be created, or ANY exception out of the injected
   runner collapses to one :class:`SandboxUnavailable` carrying
   ``sandbox_unavailable``. Version comparison is NUMERIC.
3. **The probe attests a WORKING sandbox, not just a binary.** ``--version``
   creates no namespace, so a second, functional step actually runs a throwaway
   sandbox.
4. **A full exec argv is unconstructable without a passing probe**, and — more
   importantly — the pinned paths are re-validated at compose time, so even a
   forged receipt cannot redirect the exec to a shim. Since HARDEN-03 the
   ``prlimit`` path is ALSO required to lie inside the sandbox's own mount view
   (:data:`~lsassist.sandbox.profiles.SYSTEM_RO_BINDS`), because it is now the
   head of the INNER command: a path ``bwrap`` does not mount would turn every
   exec into an ENOENT.

**ARGV ORDER (HARDEN-03, human-approved).** The composed argv is
``<abs bwrap> … -- <abs prlimit> --nproc… <tool argv…>``: the caps are applied
INSIDE the sandbox, not around it. Measured on the host — outside, ``--nproc``
is charged per real UID and counts TASKS, so ``bwrap``'s own
``clone(CLONE_NEWUSER)`` dies with ``Creating new namespace failed: Resource
temporarily unavailable`` in a normal desktop session; inside, all four caps
land (``256 1024 4194304 40``). The order tests below pin CONTENT AND ORDER of
that placement.

NO REAL CHILD PROCESS is spawned anywhere in this file: ``which_fn``/``run_fn``
are injected, and the one test that exercises the default runner monkeypatches
the stdlib call it makes. Fakes RECORD their arguments and the assertions run
OUTSIDE the fake — an ``assert`` inside a fake would be caught by the probe's
own exception funnel and silently reported as ``sandbox_unavailable``.
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import inspect
import pickle
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from lsassist.contracts.sandbox_profile import Profile
from lsassist.sandbox import availability as availability_mod
from lsassist.sandbox.availability import (
    MIN_BWRAP_VERSION,
    SANDBOX_UNAVAILABLE_REASON,
    ProbeResult,
    SandboxAvailable,
    SandboxUnavailable,
    compose_exec_argv,
    functional_probe_argv,
    probe,
)
from lsassist.sandbox.prlimit import PrlimitError, prlimit_prefix
from lsassist.sandbox.profiles import SYSTEM_RO_BINDS, SandboxProfileError, build_argv

WS = "/home/u/proj"
CWD = "/home/u/proj/src"
CACHE = "/home/u/.cache/lsassist/sandbox"
TOOL = ["python", "-m", "pytest", "-q"]
TIMEOUT = 120

KIMI_KEY_NAME = "LSASSIST_KIMI_API_KEY"
KIMI_KEY_VALUE = "sk-kimi-DEADBEEFdeadbeef0123456789"

BWRAP_PATH = "/usr/bin/bwrap"
PRLIMIT_PATH = "/usr/bin/prlimit"
SHIM_BWRAP = "/home/u/.local/bin/bwrap"
SHIM_PRLIMIT = "/home/u/.local/bin/prlimit"
OK_VERSION = "bubblewrap 0.9.0\n"


# ---------------------------------------------------------------------------
# Injected doubles (recording, never asserting — see the module docstring)
# ---------------------------------------------------------------------------


def which_found(name: str) -> str | None:
    return f"/usr/bin/{name}"


def which_missing(name: str) -> str | None:
    return None


def which_at(mapping: dict[str, str | None]) -> Callable[[str], str | None]:
    def _which(name: str) -> str | None:
        return mapping.get(name)

    return _which


def runner(
    stdout: str = OK_VERSION,
    returncode: int = 0,
    *,
    seen: list[list[str]] | None = None,
    stderr: str = "",
    functional_rc: int = 0,
    functional_exc: BaseException | None = None,
    version_exc: BaseException | None = None,
) -> Callable[[Sequence[str]], ProbeResult]:
    """A fake runner that records its argv and answers both probe steps."""

    def _run(argv: Sequence[str]) -> ProbeResult:
        if seen is not None:
            seen.append(list(argv))
        if "--version" in argv:
            if version_exc is not None:
                raise version_exc
            return ProbeResult(returncode, stdout, stderr)
        if functional_exc is not None:
            raise functional_exc
        return ProbeResult(functional_rc, "", stderr)

    return _run


def exists_all(path: str) -> bool:
    """A host where every §8.1 system bind is present (the pre-HARDEN-05 world).

    Unit tests must not depend on the filesystem of whoever runs them: the real
    default is `os.path.exists`, and on Arch `/etc/alternatives` is absent, which
    would silently change the argv these tests pin. Every probe below therefore
    states the host it assumes.
    """
    return True


def exists_without(*missing: str) -> Callable[[str], bool]:
    """A host missing exactly ``missing`` (e.g. Arch, which has no alternatives)."""

    def _exists(path: str) -> bool:
        return path not in missing

    return _exists


def token(*, exists_fn: Callable[[str], bool] = exists_all, **kwargs: Any) -> SandboxAvailable:
    """The ONLY supported way to obtain a receipt: a successful probe."""
    return probe(which_fn=which_found, run_fn=runner(**kwargs), exists_fn=exists_fn)


def compose(**overrides: Any) -> list[str]:
    kwargs: dict[str, Any] = {
        "available": token(),
        "profile": Profile.WS,
        "workspace": WS,
        "cwd": CWD,
        "cache_dir": CACHE,
        "argv": TOOL,
        "timeout_s": TIMEOUT,
    }
    kwargs.update(overrides)
    return compose_exec_argv(**kwargs)


def setenv_map(argv: list[str]) -> dict[str, str]:
    return {argv[i + 1]: argv[i + 2] for i, a in enumerate(argv) if a == "--setenv"}


# ---------------------------------------------------------------------------
# PROGRAM PINNING (S1) — the probe must attest the binary that will RUN
# ---------------------------------------------------------------------------


def test_missing_bwrap_is_sandbox_unavailable() -> None:
    with pytest.raises(SandboxUnavailable) as excinfo:
        probe(which_fn=which_missing, run_fn=runner("bubblewrap 9.9.9"))
    assert excinfo.value.reason == SANDBOX_UNAVAILABLE_REASON == "sandbox_unavailable"
    assert "sandbox_unavailable" in str(excinfo.value)


def test_missing_bwrap_never_runs_anything() -> None:
    seen: list[list[str]] = []
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_missing, run_fn=runner(seen=seen))
    assert seen == []


def test_missing_prlimit_is_sandbox_unavailable() -> None:
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_at({"bwrap": BWRAP_PATH}), run_fn=runner())


def test_a_writable_path_shim_for_bwrap_is_refused() -> None:
    """The demonstrated I11 bypass: ~/.local/bin is PATH[0] and mode 0775."""
    with pytest.raises(SandboxUnavailable) as excinfo:
        probe(
            which_fn=which_at({"bwrap": SHIM_BWRAP, "prlimit": PRLIMIT_PATH}),
            run_fn=runner("bubblewrap 999.0.0"),
        )
    assert SHIM_BWRAP in str(excinfo.value)
    assert excinfo.value.reason == SANDBOX_UNAVAILABLE_REASON


def test_a_writable_path_shim_for_prlimit_is_refused() -> None:
    """prlimit is equally shimmable: a shim silently drops every rlimit."""
    with pytest.raises(SandboxUnavailable) as excinfo:
        probe(which_fn=which_at({"bwrap": BWRAP_PATH, "prlimit": SHIM_PRLIMIT}), run_fn=runner())
    assert SHIM_PRLIMIT in str(excinfo.value)


@pytest.mark.parametrize(
    "planted",
    [
        "/tmp/bwrap",
        "/home/u/bin/bwrap",
        "/home/u/proj/.venv/bin/bwrap",
        "/opt/evil/bwrap",
        "bwrap",
        "./bwrap",
        "",
    ],
)
def test_only_trusted_program_directories_are_accepted(planted: str) -> None:
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_at({"bwrap": planted, "prlimit": PRLIMIT_PATH}), run_fn=runner())


@pytest.mark.parametrize("trusted", ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"])
def test_the_three_trusted_directories_are_accepted(trusted: str) -> None:
    issued = probe(which_fn=which_at({"bwrap": trusted, "prlimit": PRLIMIT_PATH}), run_fn=runner())
    assert issued.bwrap_path.startswith("/")


def test_receipt_carries_both_pinned_absolute_paths() -> None:
    issued = token()
    assert issued.bwrap_path == BWRAP_PATH
    assert issued.prlimit_path == PRLIMIT_PATH


def test_probe_runs_the_absolute_path_not_the_bare_name() -> None:
    seen: list[list[str]] = []
    probe(which_fn=which_found, run_fn=runner(seen=seen))
    assert [call[0] for call in seen] == [BWRAP_PATH, BWRAP_PATH]
    assert all(call[0] != "bwrap" for call in seen)


def test_which_fn_is_asked_for_both_programs() -> None:
    asked: list[str] = []

    def recording_which(name: str) -> str | None:
        asked.append(name)
        return f"/usr/bin/{name}"

    probe(which_fn=recording_which, run_fn=runner())
    assert asked == ["bwrap", "prlimit"]


def test_probe_invokes_an_argv_list_never_a_shell_string() -> None:
    seen: list[list[str]] = []
    probe(which_fn=which_found, run_fn=runner(seen=seen))
    assert seen[0] == [BWRAP_PATH, "--version"]
    assert all(not isinstance(call, str) for call in seen)


def test_which_fn_exception_becomes_sandbox_unavailable() -> None:
    def exploding_which(name: str) -> str | None:
        raise OSError("PATH lookup failed")

    with pytest.raises(SandboxUnavailable):
        probe(which_fn=exploding_which, run_fn=runner())


@pytest.mark.parametrize("odd", [b"/usr/bin/bwrap", 0, [], object()])
def test_non_string_lookup_result_is_sandbox_unavailable(odd: Any) -> None:
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=lambda name: odd, run_fn=runner())


def test_a_failing_path_resolution_is_sandbox_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even ELOOP/ENOTDIR out of realpath must not escape as a raw OSError."""

    def exploding_realpath(path: Any, *args: Any, **kwargs: Any) -> str:
        raise OSError("ELOOP")

    monkeypatch.setattr(availability_mod.os.path, "realpath", exploding_realpath)
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_found, run_fn=runner())


# ---------------------------------------------------------------------------
# VERSION GATE — compared NUMERICALLY
# ---------------------------------------------------------------------------


def test_min_version_is_adr_002_baseline() -> None:
    assert MIN_BWRAP_VERSION == (0, 9, 0)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("bubblewrap 0.9.0", (0, 9, 0)),
        ("bubblewrap 0.9.0\n", (0, 9, 0)),
        ("  bubblewrap 0.9.0  \n", (0, 9, 0)),
        ("bubblewrap 0.9.1", (0, 9, 1)),
        ("bubblewrap 0.10.0", (0, 10, 0)),
        ("bubblewrap 0.11.2", (0, 11, 2)),
        ("bubblewrap 1.0.0", (1, 0, 0)),
        ("bubblewrap 2.13.4", (2, 13, 4)),
    ],
)
def test_supported_versions_yield_a_receipt(text: str, expected: tuple[int, int, int]) -> None:
    issued = probe(which_fn=which_found, run_fn=runner(text))
    assert isinstance(issued, SandboxAvailable)
    assert issued.version == expected


def test_newer_minor_is_not_compared_as_a_string() -> None:
    """`"0.10.0" < "0.9.0"` lexically; numerically it is newer and must pass."""
    assert "0.10.0" < "0.9.0"
    assert token(stdout="bubblewrap 0.10.0").version == (0, 10, 0)


@pytest.mark.parametrize("text", ["bubblewrap 0.8.9", "bubblewrap 0.4.1", "bubblewrap 0.0.1"])
def test_too_old_is_sandbox_unavailable(text: str) -> None:
    with pytest.raises(SandboxUnavailable) as excinfo:
        probe(which_fn=which_found, run_fn=runner(text))
    assert excinfo.value.reason == SANDBOX_UNAVAILABLE_REASON
    assert "older" in str(excinfo.value)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "\n",
        "not a version",
        "bwrap 0.9.0",
        "bubblewrap",
        "bubblewrap 0.9",
        "bubblewrap X.Y.Z",
        "bubblewrap 0.9.0.1",
        "bubblewrap v0.9.0",
        "0.9.0",
        "bubblewrap -1.0.0",
        "bubblewrap 0.9.0; rm -rf /",
        "bubblewrap 99999999999999999999.0.0",
    ],
)
def test_unparseable_output_is_sandbox_unavailable(text: str) -> None:
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_found, run_fn=runner(text))


@pytest.mark.parametrize("returncode", [1, 2, 127, -9])
def test_non_zero_exit_is_sandbox_unavailable(returncode: int) -> None:
    """Even with parseable stdout: a failing probe is not a working sandbox."""
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_found, run_fn=runner(OK_VERSION, returncode))


def test_a_failing_version_check_never_reaches_the_functional_step() -> None:
    seen: list[list[str]] = []
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_found, run_fn=runner("garbage", seen=seen))
    assert len(seen) == 1


# ---------------------------------------------------------------------------
# FUNCTIONAL STEP (C4) — a binary that exists is not a sandbox that works
# ---------------------------------------------------------------------------


def test_probe_runs_exactly_two_commands_version_then_functional() -> None:
    seen: list[list[str]] = []
    probe(which_fn=which_found, run_fn=runner(seen=seen), exists_fn=exists_all)
    assert len(seen) == 2
    assert seen[0] == [BWRAP_PATH, "--version"]
    assert seen[1] == functional_probe_argv(BWRAP_PATH)


def test_functional_argv_actually_creates_a_namespace() -> None:
    argv = functional_probe_argv(BWRAP_PATH)
    assert argv[0] == BWRAP_PATH
    assert "--unshare-user" in argv
    assert "--unshare-pid" in argv
    assert argv[-2:] == ["--", "/bin/true"]
    assert argv.count("--") == 1


def test_functional_argv_mirrors_the_profiles_own_system_binds() -> None:
    """A probe that succeeds where the real profile fails attests nothing.

    Measured: `--ro-bind /usr /usr -- /bin/true` fails with
    `execvp /bin/true: No such file or directory` because the ELF interpreter
    /lib64/ld-linux-x86-64.so.2 is not in that mount view.
    """
    argv = functional_probe_argv(BWRAP_PATH)
    bound = [argv[i + 1] for i, a in enumerate(argv) if a == "--ro-bind"]
    assert bound == list(SYSTEM_RO_BINDS)
    assert "/lib64" in bound


def test_functional_argv_runs_bwrap_directly_like_the_composed_argv() -> None:
    """The probe's OUTER program is the composed argv's outer program (HARDEN-03).

    Before the fix this was a KNOWN RESIDUAL: the probe ran bwrap directly while
    the composed argv wrapped it in `prlimit --nproc=256 …`, so on a busy host the
    probe PASSED and the real exec still died with `Creating new namespace failed:
    Resource temporarily unavailable`. With the caps moved inside the sandbox both
    now start the same way, so a passing probe and a working exec agree.
    """
    argv = functional_probe_argv(BWRAP_PATH)
    assert argv[0] == BWRAP_PATH == compose()[0]
    assert not any(element.startswith("--nproc") for element in argv)
    assert "prlimit" not in " ".join(argv)


@pytest.mark.parametrize("rc", [1, 2, 137])
def test_a_namespace_that_cannot_be_created_is_sandbox_unavailable(rc: int) -> None:
    with pytest.raises(SandboxUnavailable) as excinfo:
        probe(which_fn=which_found, run_fn=runner(functional_rc=rc))
    assert excinfo.value.reason == SANDBOX_UNAVAILABLE_REASON
    assert "namespace" in str(excinfo.value)


def test_the_namespace_failure_is_distinguishable_from_a_missing_binary() -> None:
    with pytest.raises(SandboxUnavailable) as functional:
        probe(which_fn=which_found, run_fn=runner(functional_rc=1))
    with pytest.raises(SandboxUnavailable) as missing:
        probe(which_fn=which_missing, run_fn=runner())
    assert "namespace" in str(functional.value)
    assert "namespace" not in str(missing.value)
    assert "not found on PATH" in str(missing.value)


def test_a_raising_functional_step_is_sandbox_unavailable() -> None:
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_found, run_fn=runner(functional_exc=OSError("EPERM")))


def test_both_steps_passing_yields_a_receipt() -> None:
    assert isinstance(token(), SandboxAvailable)


# ---------------------------------------------------------------------------
# NO RAW EXCEPTION EVER ESCAPES
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        OSError("boom"),
        FileNotFoundError("bwrap vanished"),
        PermissionError("EACCES"),
        subprocess.TimeoutExpired(cmd=["bwrap", "--version"], timeout=5),
        subprocess.CalledProcessError(1, ["bwrap", "--version"]),
        subprocess.SubprocessError("generic"),
        RuntimeError("unexpected"),
        ValueError("unexpected"),
        MemoryError(),
    ],
)
def test_runner_exceptions_become_sandbox_unavailable(exc: BaseException) -> None:
    with pytest.raises(SandboxUnavailable) as excinfo:
        probe(which_fn=which_found, run_fn=runner(version_exc=exc))
    assert excinfo.value.reason == SANDBOX_UNAVAILABLE_REASON


@pytest.mark.parametrize("result", [None, "bubblewrap 0.9.0", 0, (), ("x",)])
def test_malformed_runner_result_is_sandbox_unavailable(result: Any) -> None:
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_found, run_fn=lambda argv: result)


@pytest.mark.parametrize("stdout", [None, b"bubblewrap 0.9.0", 0])
def test_non_string_stdout_is_sandbox_unavailable(stdout: Any) -> None:
    """A NamedTuple does not enforce its field types at runtime."""
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_found, run_fn=lambda argv: ProbeResult(0, stdout))


def test_malformed_result_from_the_functional_step_is_sandbox_unavailable() -> None:
    def half_broken(argv: Sequence[str]) -> Any:
        return ProbeResult(0, OK_VERSION) if "--version" in argv else None

    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_found, run_fn=half_broken)


def test_keyboard_interrupt_is_not_swallowed() -> None:
    """The funnel catches `Exception`, not `BaseException` — Ctrl-C still works."""
    with pytest.raises(KeyboardInterrupt):
        probe(which_fn=which_found, run_fn=runner(version_exc=KeyboardInterrupt()))


# ---------------------------------------------------------------------------
# DIAGNOSTICS (C6) — a refusal without a reason is a refusal nobody can debug
# ---------------------------------------------------------------------------


def test_probe_result_carries_stderr_with_a_default() -> None:
    assert ProbeResult(0, "out").stderr == ""
    assert ProbeResult(1, "out", "err").stderr == "err"


def test_namespace_failure_message_quotes_bwraps_own_diagnostic() -> None:
    diagnostic = "bwrap: Creating new namespace failed: Resource temporarily unavailable"
    with pytest.raises(SandboxUnavailable) as excinfo:
        probe(which_fn=which_found, run_fn=runner(functional_rc=1, stderr=diagnostic))
    assert "Creating new namespace failed" in str(excinfo.value)


def test_non_zero_version_exit_message_quotes_stderr() -> None:
    with pytest.raises(SandboxUnavailable) as excinfo:
        probe(which_fn=which_found, run_fn=runner(OK_VERSION, 1, stderr="permission denied"))
    assert "permission denied" in str(excinfo.value)


def test_unparseable_version_message_quotes_stderr() -> None:
    with pytest.raises(SandboxUnavailable) as excinfo:
        probe(which_fn=which_found, run_fn=runner("junk", stderr="loader error"))
    assert "loader error" in str(excinfo.value)


def test_stderr_excerpt_is_truncated() -> None:
    with pytest.raises(SandboxUnavailable) as excinfo:
        probe(which_fn=which_found, run_fn=runner(functional_rc=1, stderr="E" * 5000))
    message = str(excinfo.value)
    assert "..." in message
    assert len(message) < 600


def test_empty_stderr_adds_no_noise() -> None:
    with pytest.raises(SandboxUnavailable) as excinfo:
        probe(which_fn=which_found, run_fn=runner(functional_rc=1, stderr="   \n  "))
    assert "stderr:" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# THE DEFAULT RUNNER — argv list, no shell, stderr captured
# ---------------------------------------------------------------------------


def test_default_runner_uses_no_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        stdout = OK_VERSION if "--version" in args[0] else ""
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout=stdout, stderr="e")

    monkeypatch.setattr(subprocess, "run", fake_run)
    issued = probe(which_fn=which_found)

    assert issued.version == (0, 9, 0)
    assert len(calls) == 2
    for args, kwargs in calls:
        assert isinstance(args[0], list)
        assert args[0][0] == BWRAP_PATH
        assert kwargs.get("shell", False) is False
        assert kwargs.get("capture_output") is True
        assert kwargs.get("text") is True
        assert kwargs.get("check") is False
        assert isinstance(kwargs.get("timeout"), int | float)
        assert 0 < kwargs["timeout"] <= 30


def test_default_runner_propagates_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=args[0], returncode=1, stdout="", stderr="bwrap: userns disabled"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(SandboxUnavailable) as excinfo:
        probe(which_fn=which_found)
    assert "userns disabled" in str(excinfo.value)


def test_default_runner_source_has_no_shell_true() -> None:
    source = Path(str(availability_mod.__file__)).read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "os.system" not in source


def test_default_which_fn_resolves_through_shutil_which() -> None:
    default = inspect.signature(probe).parameters["which_fn"].default
    assert default("bwrap") == shutil.which("bwrap")
    assert default("lsassist-definitely-not-a-real-binary") is None


# ---------------------------------------------------------------------------
# THE RECEIPT (S2/C3) — every non-probe construction route is refused
# ---------------------------------------------------------------------------


def test_receipt_cannot_be_constructed_by_hand() -> None:
    with pytest.raises(SandboxUnavailable):
        SandboxAvailable(version=(0, 9, 0), bwrap_path=BWRAP_PATH, prlimit_path=PRLIMIT_PATH)


def test_receipt_cannot_be_constructed_positionally() -> None:
    with pytest.raises(SandboxUnavailable):
        SandboxAvailable((9, 9, 9), SHIM_BWRAP, SHIM_PRLIMIT)


def test_dataclasses_replace_cannot_forge_a_path() -> None:
    """`replace` re-runs __init__, so the pinned paths cannot be swapped."""
    with pytest.raises(SandboxUnavailable):
        dataclasses.replace(token(), bwrap_path=SHIM_BWRAP)


def test_object_new_receipt_is_refused_by_compose() -> None:
    forged = object.__new__(SandboxAvailable)
    with pytest.raises(SandboxUnavailable):
        compose(available=forged)


def test_deepcopied_receipt_is_refused_by_compose() -> None:
    with pytest.raises(SandboxUnavailable):
        compose(available=copy.deepcopy(token()))


def test_pickled_receipt_is_refused_by_compose() -> None:
    # SAFE: this unpickles bytes this very test just produced from an in-process
    # object — there is no untrusted input. Pickle is the ATTACK being tested
    # (can a serialization round-trip mint a usable receipt?), not a data format
    # this project reads. No production module imports pickle.
    round_tripped = pickle.loads(pickle.dumps(token()))
    with pytest.raises(SandboxUnavailable):
        compose(available=round_tripped)


def test_subclass_receipt_is_refused_by_compose() -> None:
    class Sneaky(SandboxAvailable):
        def __post_init__(self) -> None:
            return None

    sneaky = Sneaky(version=(9, 9, 9), bwrap_path=SHIM_BWRAP, prlimit_path=SHIM_PRLIMIT)
    with pytest.raises(SandboxUnavailable):
        compose(available=sneaky)


def test_a_shallow_copy_is_an_identical_receipt_and_is_accepted() -> None:
    """Documented, not an oversight: `copy.copy` cannot change a frozen field.

    The copy carries the same version and the same pinned paths, so it IS the
    same receipt. Mutating one afterwards is what the path re-validation in the
    next test exists for.
    """
    duplicate = copy.copy(token())
    assert duplicate == token()
    composed = compose(available=duplicate)
    assert composed[0] == BWRAP_PATH
    assert composed[composed.index("--") + 1] == PRLIMIT_PATH


def test_even_a_fully_forged_receipt_cannot_redirect_the_exec() -> None:
    """The load-bearing check: pinned paths are re-validated at compose time."""
    forged = object.__new__(SandboxAvailable)
    object.__setattr__(forged, "version", (9, 9, 9))
    object.__setattr__(forged, "bwrap_path", SHIM_BWRAP)
    object.__setattr__(forged, "prlimit_path", PRLIMIT_PATH)
    object.__setattr__(forged, "_issuance", availability_mod._ISSUED_BY_PROBE)

    with pytest.raises(SandboxUnavailable) as excinfo:
        compose(available=forged)
    assert SHIM_BWRAP in str(excinfo.value)


def test_a_mutated_genuine_receipt_cannot_redirect_the_exec() -> None:
    mutated = copy.copy(token())
    object.__setattr__(mutated, "prlimit_path", SHIM_PRLIMIT)
    with pytest.raises(SandboxUnavailable) as excinfo:
        compose(available=mutated)
    assert SHIM_PRLIMIT in str(excinfo.value)


def test_receipt_is_frozen() -> None:
    issued = token()
    with pytest.raises(dataclasses.FrozenInstanceError):
        issued.version = (9, 9, 9)


def test_receipt_repr_shows_the_pinned_paths_and_no_sentinel() -> None:
    assert repr(token()) == (
        "SandboxAvailable(version=(0, 9, 0), "
        f"bwrap_path='{BWRAP_PATH}', prlimit_path='{PRLIMIT_PATH}', "
        f"system_binds={SYSTEM_RO_BINDS!r}, omitted_binds=())"
    )


# ---------------------------------------------------------------------------
# COMPOSITION — pinned bwrap argv whose INNER command starts with the pinned
# prlimit prefix (HARDEN-03 order: caps inside the sandbox, not around it)
# ---------------------------------------------------------------------------


def test_composed_argv_is_bwrap_argv_whose_inner_command_carries_the_caps() -> None:
    composed = compose()
    expected = build_argv(
        profile=Profile.WS,
        workspace=WS,
        cwd=CWD,
        cache_dir=CACHE,
        argv=prlimit_prefix(TIMEOUT, prlimit_path=PRLIMIT_PATH) + TOOL,
        bwrap_path=BWRAP_PATH,
    )
    assert composed == expected


def test_the_prlimit_fragment_is_the_head_of_the_inner_command() -> None:
    """ORDER, pinned exactly: `-- <prlimit> --nproc… --cpu… <tool argv…>`.

    Applied to the OUTER process the caps are measurably broken here (RLIMIT_NPROC
    is per-real-UID and counts TASKS, so bwrap cannot create its namespace);
    applied to the inner command all four land. This test is what stops the
    fragment drifting back outside, or being scattered mid-argv.
    """
    composed = compose()
    prefix = prlimit_prefix(TIMEOUT, prlimit_path=PRLIMIT_PATH)
    separator = composed.index("--")
    assert composed[separator + 1 : separator + 1 + len(prefix)] == prefix
    assert composed[separator + 1 + len(prefix) :] == TOOL


def test_composed_argv_uses_the_pinned_absolute_programs() -> None:
    composed = compose()
    assert composed[0] == BWRAP_PATH
    assert composed[composed.index("--") + 1] == PRLIMIT_PATH
    assert "bwrap" not in composed
    assert "prlimit" not in composed


def test_bwrap_is_the_outer_program_and_prlimit_is_never_before_it() -> None:
    """The old §8.1 order (`prlimit … bwrap …`) must not come back."""
    composed = compose()
    assert composed[0] == BWRAP_PATH
    assert composed.index(PRLIMIT_PATH) > composed.index("--")
    assert not any(element.startswith("--nproc") for element in composed[: composed.index("--")])


def test_composed_argv_has_exactly_one_double_dash() -> None:
    """`build_argv` already emits the `--` terminator — never append a second."""
    composed = compose()
    prefix_len = len(prlimit_prefix(TIMEOUT, prlimit_path=PRLIMIT_PATH))
    assert composed.count("--") == 1
    assert composed.index("--") == len(composed) - len(TOOL) - prefix_len - 1


def test_tool_argv_is_last_and_verbatim() -> None:
    assert compose()[-len(TOOL) :] == TOOL


def test_cpu_limit_tracks_the_composed_timeout() -> None:
    assert "--cpu=310" in compose(timeout_s=300)


def test_the_fork_bomb_control_is_present_in_the_composed_argv() -> None:
    """§18 T-14 guard: the placement fix must not DELETE the cap.

    HARDEN-03 moved this flag from the outer process (where it stopped bwrap
    from starting at all on a busy host) to the inner command (where it measures
    the sandbox's own task count and actually bites: `--nproc=32` inside gives
    `spawned=29 refused=31`). The tempting alternative "fix" was to drop the
    flag — a security regression wearing the costume of a bug fix. This test
    makes any such removal loud.
    """
    assert any(element.startswith("--nproc=") for element in compose())


def test_ro_profile_composes_too() -> None:
    composed = compose(profile=Profile.RO)
    assert composed[0] == BWRAP_PATH
    assert composed[composed.index("--") + 1] == PRLIMIT_PATH
    assert composed[composed.index("--dev") + 2 :][:3] == ["--ro-bind", WS, WS]


# ---------------------------------------------------------------------------
# MOUNT-VIEW REACHABILITY (HARDEN-03) — prlimit now runs INSIDE the sandbox
# ---------------------------------------------------------------------------


def forged(
    *,
    bwrap_path: str = BWRAP_PATH,
    prlimit_path: str = PRLIMIT_PATH,
    system_binds: object = SYSTEM_RO_BINDS,
    omit_binds_attr: bool = False,
) -> SandboxAvailable:
    """A receipt carrying the issuance sentinel but arbitrary pinned paths.

    Not reachable through `probe` — the point is to exercise the compose-time
    re-validation, which is the check that still holds if a receipt is forged.

    `omit_binds_attr` leaves `system_binds` UNSET, which is what `object.__new__`
    and `pickle` actually produce under `slots=True`: the attribute does not
    exist at all, rather than holding a wrong value.
    """
    receipt = object.__new__(SandboxAvailable)
    object.__setattr__(receipt, "version", (0, 9, 0))
    object.__setattr__(receipt, "bwrap_path", bwrap_path)
    object.__setattr__(receipt, "prlimit_path", prlimit_path)
    if not omit_binds_attr:
        object.__setattr__(receipt, "system_binds", system_binds)
    object.__setattr__(receipt, "omitted_binds", ())
    object.__setattr__(receipt, "_issuance", availability_mod._ISSUED_BY_PROBE)
    return receipt


@pytest.mark.parametrize(
    "reachable", ["/usr/bin/prlimit", "/bin/prlimit", "/usr/local/bin/prlimit"]
)
def test_a_prlimit_inside_the_mount_view_is_accepted(reachable: str) -> None:
    """`/usr` and `/bin` are already --ro-bind'ed, so no new bind is needed.

    Forged rather than probed on purpose: `probe` realpath-resolves, and on a
    merged-/usr host `/bin/prlimit` would collapse to `/usr/bin/prlimit` before
    the guard ever saw it. The check under test is the compose-time one.
    """
    composed = compose(available=forged(prlimit_path=reachable))
    assert composed[composed.index("--") + 1] == reachable


def test_a_probed_receipt_puts_its_own_pinned_prlimit_inside() -> None:
    issued = probe(which_fn=which_found, run_fn=runner())
    composed = compose(available=issued)
    assert composed[composed.index("--") + 1] == issued.prlimit_path == PRLIMIT_PATH


def test_a_prlimit_outside_every_ro_bind_is_refused() -> None:
    """`/opt/bin/prlimit` is not in the mount view — every exec would be ENOENT."""
    with pytest.raises(SandboxUnavailable) as excinfo:
        compose(available=forged(prlimit_path="/opt/bin/prlimit"))
    assert "/opt/bin/prlimit" in str(excinfo.value)
    assert excinfo.value.reason == SANDBOX_UNAVAILABLE_REASON


@pytest.mark.parametrize(
    "unreachable",
    [
        "/opt/bin/prlimit",
        "/snap/bin/prlimit",
        "/srv/tools/prlimit",
        # Segment traps: a prefix match would wrongly accept these.
        "/usrlocal/bin/prlimit",
        "/binary/prlimit",
    ],
)
def test_the_mount_view_check_fires_even_for_a_trusted_directory(
    monkeypatch: pytest.MonkeyPatch, unreachable: str
) -> None:
    """The guard is INDEPENDENT of the trusted-directory allowlist.

    With the program's directory added to the trusted set, the host-side check
    passes and only the mount-view check can refuse — which is exactly the case
    a future `_TRUSTED_BIN_DIRS` addition would create.
    """
    directory = unreachable.rsplit("/", 1)[0]
    monkeypatch.setattr(availability_mod, "_TRUSTED_BIN_DIRS", frozenset({"/usr/bin", directory}))
    with pytest.raises(SandboxUnavailable) as excinfo:
        compose(available=forged(prlimit_path=unreachable))
    assert "mount view" in str(excinfo.value)
    assert unreachable in str(excinfo.value)


def test_bwrap_is_not_required_to_be_inside_the_mount_view() -> None:
    """bwrap runs on the HOST; only the inner command must be visible inside."""
    composed = compose(available=forged(bwrap_path="/usr/local/bin/bwrap"))
    assert composed[0] == "/usr/local/bin/bwrap"


def test_every_trusted_program_directory_is_inside_the_mount_view() -> None:
    """The two allowlists must not drift apart (a canary, not a tautology).

    Adding a directory to `_TRUSTED_BIN_DIRS` that `SYSTEM_RO_BINDS` does not
    cover would make a probe pass and every composed exec fail with ENOENT.
    """
    for directory in availability_mod._TRUSTED_BIN_DIRS:
        assert any(
            directory == bind or directory.startswith(bind.rstrip("/") + "/")
            for bind in SYSTEM_RO_BINDS
        ), directory


# ---------------------------------------------------------------------------
# COMPOSITION — the T2.05 canaries survive (I8), and the env is FORWARDED (C2)
# ---------------------------------------------------------------------------


def test_composed_argv_keeps_clearenv_before_the_setenv_block() -> None:
    composed = compose()
    assert "--clearenv" in composed
    assert composed.index("--clearenv") < composed.index("--setenv")


def test_composed_argv_never_uses_unsetenv() -> None:
    assert "--unsetenv" not in compose()


def test_composed_argv_carries_no_secret_name_or_value() -> None:
    joined = "\x00".join(compose(env_extra={"CI": "1"}))
    assert KIMI_KEY_NAME not in joined
    assert KIMI_KEY_VALUE not in joined


def test_env_parameters_are_actually_forwarded() -> None:
    """Presence, not just absence: compose must not silently drop these."""
    composed = compose(lc_all="C.UTF-8", term="xterm-256color", env_extra={"CI": "1"})
    env = setenv_map(composed)
    assert env["LC_ALL"] == "C.UTF-8"
    assert env["TERM"] == "xterm-256color"
    assert env["CI"] == "1"
    assert env["HOME"] == "/tmp/lsassist-home"
    assert env["LANG"] == "C.UTF-8"


def test_venv_path_survives_composition() -> None:
    assert setenv_map(compose(venv_exists=True))["PATH"] == f"{WS}/.venv/bin:/usr/bin:/bin"


# ---------------------------------------------------------------------------
# COMPOSITION — fail-closed BY CONSTRUCTION
# ---------------------------------------------------------------------------


def test_compose_requires_the_receipt() -> None:
    with pytest.raises(TypeError):
        compose_exec_argv(  # type: ignore[call-arg]
            profile=Profile.WS,
            workspace=WS,
            cwd=CWD,
            cache_dir=CACHE,
            argv=TOOL,
            timeout_s=TIMEOUT,
        )


def test_compose_is_keyword_only() -> None:
    parameters = inspect.signature(compose_exec_argv).parameters
    assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values())
    assert parameters["available"].default is inspect.Parameter.empty
    assert parameters["available"].annotation in ("SandboxAvailable", SandboxAvailable)


@pytest.mark.parametrize("forged", [None, object(), (0, 9, 0), "0.9.0", True])
def test_compose_rejects_a_forged_receipt(forged: Any) -> None:
    with pytest.raises(SandboxUnavailable):
        compose(available=forged)


def test_compose_propagates_a_bad_timeout_and_returns_no_argv() -> None:
    for bad in (0, -1, 601, 1800, "120"):
        with pytest.raises(PrlimitError):
            compose(timeout_s=bad)


def test_compose_propagates_a_bad_profile_input_and_returns_no_argv() -> None:
    with pytest.raises(SandboxProfileError):
        compose(workspace="/")
    with pytest.raises(SandboxProfileError):
        compose(argv=[])


@pytest.mark.parametrize("bad", [[], "python", ["", "-m", "pytest"], 42, None])
def test_a_tool_argv_the_caps_prefix_could_hide_is_still_refused(bad: Any) -> None:
    """The TOOL argv is validated BEFORE the prlimit fragment is prepended.

    Otherwise `build_argv` would only ever inspect `prlimit`: an empty argv would
    compose into a sandbox that runs the caps program alone (exit 0, no tool), and
    a `str` would be spread into one-character arguments.
    """
    with pytest.raises(SandboxProfileError):
        compose(argv=bad)


def test_compose_reads_no_environment(
    tripwired_environ: Callable[[], contextlib.AbstractContextManager[None]],
) -> None:
    issued = token()
    with tripwired_environ():
        composed = compose_exec_argv(
            available=issued,
            profile=Profile.WS,
            workspace=WS,
            cwd=CWD,
            cache_dir=CACHE,
            argv=TOOL,
            timeout_s=TIMEOUT,
        )
    assert composed[0] == BWRAP_PATH
    assert composed[composed.index("--") + 1] == PRLIMIT_PATH


# ---------------------------------------------------------------------------
# STRUCTURAL GATES — the plan's grep contract, enforced as tests
# ---------------------------------------------------------------------------


def sandbox_sources() -> dict[str, str]:
    package_dir = Path(str(availability_mod.__file__)).parent
    return {
        path.name: path.read_text(encoding="utf-8") for path in sorted(package_dir.glob("*.py"))
    }


def test_no_degraded_path_word_anywhere_in_the_package() -> None:
    """§8.3: exec is BLOCKED when the sandbox is unavailable — never degraded."""
    offenders = [name for name, src in sandbox_sources().items() if "fallback" in src]
    assert offenders == []


def test_child_process_machinery_lives_only_in_the_probe() -> None:
    offenders = [
        name
        for name, src in sandbox_sources().items()
        if name != "availability.py" and ("subprocess" in src or "os.exec" in src)
    ]
    assert offenders == []


def test_no_module_ever_execs_directly() -> None:
    for name, src in sandbox_sources().items():
        assert "os.exec" not in src, name
        assert "os.spawn" not in src, name
        assert "os.popen" not in src, name


def test_the_probe_failure_is_never_caught_and_continued() -> None:
    source = Path(str(availability_mod.__file__)).read_text(encoding="utf-8")
    assert "except SandboxUnavailable" not in source


def test_package_exports_compose_but_not_the_bare_prefix_builder() -> None:
    """S4: the public surface must not hand out a `prlimit …` argv with no bwrap."""
    import lsassist.sandbox as pkg

    for name in ("compose_exec_argv", "probe", "SandboxUnavailable"):
        assert name in pkg.__all__
        assert hasattr(pkg, name)
    assert "prlimit_prefix" not in pkg.__all__
    assert not hasattr(pkg, "prlimit_prefix")


# ---------------------------------------------------------------------------
# HARDEN-05 — the §8.1 bind set is MEASURED on this host, once, at probe time
#
# The template names `/etc/alternatives`, a Debian `update-alternatives`
# directory that does not exist on Arch. `bwrap --ro-bind` on a missing source is
# a HARD error, so the functional probe exited 1 and EVERY exec was BLOCKED with
# `sandbox_unavailable` — measured on Garuda Linux, bwrap 0.11.2, userns enabled.
#
# The fix must not break the property the old code bought with that failure: the
# probe and the real exec must run over the SAME bind set, or a passing probe
# stops attesting a working exec (the HARDEN-03 lesson, one layer down).
# ---------------------------------------------------------------------------

ARCH = exists_without("/etc/alternatives")


def probe_binds(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv) if a == "--ro-bind"]


def test_a_bind_absent_from_the_host_is_omitted_from_the_probe_argv() -> None:
    seen: list[list[str]] = []
    probe(which_fn=which_found, run_fn=runner(seen=seen), exists_fn=ARCH)
    assert "/etc/alternatives" not in probe_binds(seen[1])


def test_the_receipt_carries_the_resolved_and_the_omitted_binds() -> None:
    """Omission must be ATTESTED, not silent — the receipt is the record."""
    receipt = token(exists_fn=ARCH)
    assert receipt.system_binds == tuple(p for p in SYSTEM_RO_BINDS if p != "/etc/alternatives")
    assert receipt.omitted_binds == ("/etc/alternatives",)


def test_a_host_with_every_bind_omits_nothing() -> None:
    receipt = token()
    assert receipt.system_binds == SYSTEM_RO_BINDS
    assert receipt.omitted_binds == ()


def test_the_probe_and_the_composed_exec_share_one_bind_set() -> None:
    """THE invariant. A probe over a different mount set attests nothing.

    Set EQUALITY, not containment: if the composed argv ever gained a bind the
    probe never exercised, this must fail rather than pass by subset.
    """
    seen: list[list[str]] = []
    receipt = probe(which_fn=which_found, run_fn=runner(seen=seen), exists_fn=ARCH)
    composed = compose_exec_argv(
        available=receipt,
        profile=Profile.RO,
        workspace=WS,
        cwd=CWD,
        cache_dir=CACHE,
        argv=TOOL,
        timeout_s=TIMEOUT,
    )
    system_in_composed = [b for b in probe_binds(composed) if b != WS]
    assert system_in_composed == probe_binds(seen[1])
    assert tuple(system_in_composed) == receipt.system_binds


def test_a_bind_absent_at_probe_time_is_absent_from_the_composed_argv() -> None:
    composed = compose_exec_argv(
        available=token(exists_fn=ARCH),
        profile=Profile.RO,
        workspace=WS,
        cwd=CWD,
        cache_dir=CACHE,
        argv=TOOL,
        timeout_s=TIMEOUT,
    )
    assert "/etc/alternatives" not in composed


def test_a_host_with_no_system_binds_at_all_is_sandbox_unavailable() -> None:
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_found, run_fn=runner(), exists_fn=lambda _p: False)


def test_the_functional_probe_still_decides_sufficiency() -> None:
    """Omission is bounded by MEASUREMENT, not by a hand-maintained required list.

    A hand-written "these binds are mandatory" set would re-introduce exactly the
    distro assumption this change removes. Instead the resolved set is RUN: if
    what survived cannot execute /bin/true, the probe fails and exec is BLOCKED.
    """
    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_found, run_fn=runner(functional_rc=1), exists_fn=ARCH)


def test_prlimit_under_an_OMITTED_bind_is_refused() -> None:
    """The mount-view check must read the RESOLVED set, not the template.

    `prlimit` is the head of the INNER command. If it lives under a bind the host
    lacks, the sandbox cannot see it and every exec is an ENOENT — checking it
    against the template would wave that through.
    """
    # `/usr/bin/prlimit` with `/usr` omitted: reachable via no surviving bind
    # ("/usr/bin/prlimit" does not start with "/bin/"). Deliberately NOT
    # "/bin/prlimit" with "/bin" omitted — `_locate` realpaths first, and on a
    # merged-usr host /bin is a symlink to /usr/bin, which would quietly put the
    # path back inside the surviving /usr bind and make this test pass for the
    # wrong reason on some hosts and fail on others.
    receipt = probe(which_fn=which_found, run_fn=runner(), exists_fn=exists_without("/usr"))
    with pytest.raises(SandboxUnavailable, match="mount view"):
        compose_exec_argv(
            available=receipt,
            profile=Profile.RO,
            workspace=WS,
            cwd=CWD,
            cache_dir=CACHE,
            argv=TOOL,
            timeout_s=TIMEOUT,
        )


def test_the_resolved_set_can_never_exceed_the_template() -> None:
    """An `exists_fn` that says yes to everything cannot ADD a bind."""
    receipt = probe(which_fn=which_found, run_fn=runner(), exists_fn=lambda _p: True)
    assert set(receipt.system_binds) <= set(SYSTEM_RO_BINDS)


def test_the_host_is_only_asked_about_template_binds() -> None:
    """The probe measures the §8.1 list and nothing else — no arbitrary stat()."""
    asked: list[str] = []

    def _exists(path: str) -> bool:
        asked.append(path)
        return True

    probe(which_fn=which_found, run_fn=runner(), exists_fn=_exists)
    assert set(asked) == set(SYSTEM_RO_BINDS)


def test_the_host_is_measured_once_per_probe_not_once_per_bind_use() -> None:
    """A TOCTOU between the probe argv and the composed argv would reopen the bug."""
    calls: list[str] = []

    def _exists(path: str) -> bool:
        calls.append(path)
        return path != "/etc/alternatives"

    receipt = probe(which_fn=which_found, run_fn=runner(), exists_fn=_exists)
    before = len(calls)
    compose_exec_argv(
        available=receipt,
        profile=Profile.RO,
        workspace=WS,
        cwd=CWD,
        cache_dir=CACHE,
        argv=TOOL,
        timeout_s=TIMEOUT,
    )
    assert len(calls) == before == len(SYSTEM_RO_BINDS)


def test_an_exists_fn_that_raises_is_sandbox_unavailable() -> None:
    def _boom(path: str) -> bool:
        raise OSError(13, "Permission denied")

    with pytest.raises(SandboxUnavailable):
        probe(which_fn=which_found, run_fn=runner(), exists_fn=_boom)


def test_a_forged_receipt_cannot_widen_the_bind_set() -> None:
    """The receipt is re-validated at compose time, like the pinned paths are."""
    receipt = token()
    object.__setattr__(receipt, "system_binds", ("/usr", "/etc/shadow"))
    with pytest.raises(SandboxUnavailable):
        compose_exec_argv(
            available=receipt,
            profile=Profile.RO,
            workspace=WS,
            cwd=CWD,
            cache_dir=CACHE,
            argv=TOOL,
            timeout_s=TIMEOUT,
        )


@pytest.mark.parametrize("bad", [(), None, "/usr", ["/usr"], ("/usr", "/etc/shadow")])
def test_a_receipt_with_a_bad_bind_set_is_sandbox_unavailable(bad: object) -> None:
    """Every malformed shape lands on the ONE §8.3 reason code, not a TypeError."""
    with pytest.raises(SandboxUnavailable):
        compose(available=forged(system_binds=bad))


def test_a_receipt_missing_the_bind_attribute_entirely_is_sandbox_unavailable() -> None:
    """`slots=True` + `object.__new__` leaves the attribute UNSET, not wrong.

    Reading it with plain attribute access would raise AttributeError straight
    past §8.3's single-reason-code contract — the same reason `_issuance` is read
    with a defaulted `getattr`.
    """
    with pytest.raises(SandboxUnavailable):
        compose(available=forged(omit_binds_attr=True))
