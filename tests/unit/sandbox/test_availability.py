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
   forged receipt cannot redirect the exec to a shim.

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


def token(**kwargs: Any) -> SandboxAvailable:
    """The ONLY supported way to obtain a receipt: a successful probe."""
    return probe(which_fn=which_found, run_fn=runner(**kwargs))


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
    probe(which_fn=which_found, run_fn=runner(seen=seen))
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


def test_functional_argv_is_not_wrapped_in_the_prlimit_prefix() -> None:
    """Pins the KNOWN RESIDUAL rather than letting it be discovered twice.

    The functional step runs bwrap directly, so on a host where the outer
    `--nproc` blocks namespace creation (prlimit.py HOST FINDING 1) the probe
    passes while the composed argv still fails. Reproduced on this host; left
    for the pending human decision on `--nproc` placement.
    """
    argv = functional_probe_argv(BWRAP_PATH)
    assert argv[0] == BWRAP_PATH
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
    assert compose(available=duplicate)[0] == PRLIMIT_PATH


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
        f"bwrap_path='{BWRAP_PATH}', prlimit_path='{PRLIMIT_PATH}')"
    )


# ---------------------------------------------------------------------------
# COMPOSITION — pinned prlimit prefix + pinned bwrap argv, in that order
# ---------------------------------------------------------------------------


def test_composed_argv_is_prlimit_prefix_then_bwrap_argv() -> None:
    composed = compose()
    expected = prlimit_prefix(TIMEOUT, prlimit_path=PRLIMIT_PATH) + build_argv(
        profile=Profile.WS,
        workspace=WS,
        cwd=CWD,
        cache_dir=CACHE,
        argv=TOOL,
        bwrap_path=BWRAP_PATH,
    )
    assert composed == expected


def test_composed_argv_uses_the_pinned_absolute_programs() -> None:
    composed = compose()
    assert composed[0] == PRLIMIT_PATH
    assert composed[5] == BWRAP_PATH
    assert "bwrap" not in composed
    assert "prlimit" not in composed


def test_composed_argv_has_exactly_one_double_dash() -> None:
    """`build_argv` already emits the `--` terminator — never append a second."""
    composed = compose()
    assert composed.count("--") == 1
    assert composed.index("--") == len(composed) - len(TOOL) - 1


def test_tool_argv_is_last_and_verbatim() -> None:
    assert compose()[-len(TOOL) :] == TOOL


def test_cpu_limit_tracks_the_composed_timeout() -> None:
    assert "--cpu=310" in compose(timeout_s=300)


def test_the_fork_bomb_control_is_present_in_the_composed_argv() -> None:
    """§18 T-14 guard: a future `--nproc` placement fix must not DELETE it.

    In the §8.1 outer position this flag currently prevents bwrap from starting
    on a busy host (documented in prlimit.py), and the tempting "fix" is to drop
    it — which would silently remove the fork-bomb cap. This test makes that
    removal loud.
    """
    assert any(element.startswith("--nproc=") for element in compose())


def test_ro_profile_composes_too() -> None:
    composed = compose(profile=Profile.RO)
    assert composed[5] == BWRAP_PATH
    assert composed[composed.index("--dev") + 2 :][:3] == ["--ro-bind", WS, WS]


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
    assert composed[0] == PRLIMIT_PATH


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
