"""T3.03 RED: dispatch steps 5-9 — build, execute, observe, verify, audit.

SPEC §6.3: "5. Sandbox profile build … 6. Execute — ``prlimit`` + ``bwrap`` +
argv; ``start_new_session`` process group; timeout kill (``SIGKILL`` process
group); stdout/stderr caps; child env = allowlist only. 7. Observe — exit code,
duration, output digests, truncated flags. 8. Verify — manifest postconditions
(path hash expectations, schema of result, workspace tree guard). 9. Audit —
append event (redacted) with all digests."

**THE OBLIGATIONS THIS FILE EXISTS TO ENFORCE.** T2.06 recorded five runner
obligations in ``sandbox/profiles.py``'s docstring, and every one of them is a
property of the SPAWN, which no argv-shape assertion can reach:

* ``env={}`` — never ``None``, never a copy of the parent environ. ``--clearenv``
  protects the CHILD; ``env=None`` hands the whole environment to ``bwrap``.
* the argv LIST, never a shell string (§7.6 rule 8).
* the ``prlimit`` caps INSIDE the sandbox (HARDEN-03), via the one sanctioned
  producer :func:`~lsassist.sandbox.availability.compose_exec_argv`.
* ``bwrap`` unavailable → typed ``sandbox_unavailable`` → BLOCKED, and NEVER an
  unsandboxed fallback (I11, §8.3).
* the runner owns its own wall-clock kill: ``--cpu`` is a CPU-time budget that
  fires early on threads and resets on ``fork`` (measured in
  :mod:`~lsassist.sandbox.prlimit`), so ``137`` alone cannot mean "timeout".

**A HANG IS A FAILURE MODE, NOT A PASS.** T4.02's FIFO defect hung the suite
instead of reddening it. Every spawning test here bounds itself, and two exist
only because the unbounded version of the code hangs: an inherited stdin (a tool
that reads it waits forever) and an output flood (a reader that stops draining
deadlocks the child against a full pipe).
"""

from __future__ import annotations

import ast
import dataclasses
import datetime
import json
import os
import shutil
import signal
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from lsassist.audit.writer import AuditWriter
from lsassist.contracts.enums import EvidenceType, PermissionClass
from lsassist.contracts.manifest import ToolManifest
from lsassist.contracts.sandbox_profile import Profile
from lsassist.contracts.tool_request import ToolRequest
from lsassist.contracts.tool_result import ToolResultStatus
from lsassist.policy.recheck import OsFsView, RecheckError
from lsassist.policy.stores import PolicyStores
from lsassist.policy.token import TokenService
from lsassist.sandbox.availability import SandboxAvailable, SandboxUnavailable
from lsassist.sandbox.profiles import SYSTEM_RO_BINDS
from lsassist.tools.dispatcher import (
    ARGV_REBOUND,
    ENV_REBOUND,
    MALFORMED_TOOL_RESULT,
    PATH_INVALIDATED,
    SANDBOX_UNAVAILABLE,
    WORKSPACE_SCOPE,
    ApprovalGrant,
    Decision,
    DispatchEnvironment,
    DispatchError,
    ExecutionNotJournalled,
    _kill_group,
    build_exec_argv,
    dispatch,
    profile_for,
    run,
    spawn_capped,
)
from lsassist.tools.handlers import EXECUTABLE_REFUSED
from lsassist.tools.result import (
    ExecObservation,
    OutputSink,
    ResultError,
    Verification,
    build_result,
    normalize_exit_code,
    sha256_digest,
)

# --- fixtures ----------------------------------------------------------------

#: Never spawn without a bound: a test that hangs reports nothing at all.
SPAWN_BUDGET_S = 20


def manifest_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "sys.info",
        "version": "1.0.0",
        "purpose": "Report static host facts.",
        "input_schema": {
            "type": "object",
            "required": ["probe"],
            "properties": {"probe": {"type": "string"}},
            "additionalProperties": False,
        },
        "output_schema": {
            "type": "object",
            "required": ["stdout"],
            "properties": {"stdout": {"type": "string"}},
            "additionalProperties": False,
        },
        "permission_class": "AUTO_READ",
        "capabilities": {"fs": "none", "net": "none", "proc": "spawn_argv"},
        "timeout_s": 10,
        "output_limits": {
            "max_stdout_bytes": 51200,
            "max_stderr_bytes": 65536,
            "max_result_chars": 200000,
        },
        "concurrency": "shared_read",
        "idempotent": True,
        "dry_run": False,
        "rollback": "none",
        "redaction": ["paths"],
        "path_scope": "workspace",
        "tests": [],
    }
    base.update(overrides)
    return base


def make_manifest(**overrides: Any) -> ToolManifest:
    return ToolManifest.model_validate(manifest_dict(**overrides))


def write_manifest(**overrides: Any) -> ToolManifest:
    """A §6.4 write-class manifest: ``ws`` profile, a declared path argument."""
    base = manifest_dict(
        name="fs.write",
        input_schema={
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}},
            "additionalProperties": False,
        },
        permission_class="AUTO_SCOPED_WRITE",
        capabilities={"fs": "write_scoped", "net": "none", "proc": "none"},
        rollback="checkpoint",
    )
    base.update(overrides)
    return ToolManifest.model_validate(base)


def stores_for(home: Path) -> PolicyStores:
    return PolicyStores(
        home=str(home),
        audit_store=str(home / ".local/state/lsassist/audit"),
        policy_store=str(home / ".config/lsassist"),
        kernel_secret=str(home / ".local/state/lsassist/kernel.secret"),
    )


@pytest.fixture
def workspace() -> Iterator[Path]:
    """A workspace OUTSIDE ``/tmp`` — pytest's ``tmp_path`` cannot be used here.

    §8.1 masks ``/tmp`` with a tmpfs, so
    :func:`~lsassist.sandbox.profiles.build_argv` REFUSES a workspace beneath it
    (under ``ro`` the tool would see an empty directory; under ``ws`` its writes
    would land in a discarded tmpfs while the run reported success). Every step-5
    test composes a real argv through that builder, so the workspace has to live
    somewhere the profile can actually bind. ``~/.cache`` is the same XDG-shaped
    location ``tests/e2e/test_sandbox_exec.py`` already uses.
    """
    ws = Path.home() / ".cache" / "lsassist" / "t303-tests" / uuid.uuid4().hex / "ws"
    ws.mkdir(parents=True)
    (ws / "a.txt").write_text("hello\n", encoding="utf-8")
    try:
        yield ws
    finally:
        shutil.rmtree(ws.parent, ignore_errors=True)


@pytest.fixture
def environment(tmp_path: Path, workspace: Path) -> DispatchEnvironment:
    home = tmp_path / "home"
    home.mkdir(parents=True)
    return DispatchEnvironment(
        workspace_root=str(workspace),
        cwd=str(workspace),
        stores=stores_for(home),
        session_id="s-1",
    )


@pytest.fixture
def cache_dir(tmp_path: Path) -> str:
    return str(tmp_path / "cache" / "lsassist")


@pytest.fixture
def journal(tmp_path: Path) -> Iterator[AuditWriter]:
    """The §14.1 sink every :func:`run` call needs.

    ``run`` takes it as a REQUIRED keyword — an optional audit sink would make
    "every execution is recorded" a property of whoever remembered to pass one.
    That every test here has to supply a real writer is the cost of the guarantee
    being structural, and it is the right price: these tests then exercise the
    journalling path on every execution rather than on the few that opted in.
    """
    with AuditWriter(directory=tmp_path / "audit", session_id="s-1") as writer:
        yield writer


def fake_receipt() -> SandboxAvailable:
    """A receipt shaped like ``probe()``'s, without spawning anything.

    ``SandboxAvailable`` has no public constructor on purpose, so this mirrors
    :func:`~lsassist.sandbox.availability._issue`. It exists so the step-5/6
    tests can compose a real argv on a host with no ``bwrap`` — the tests that
    need a REAL sandbox live in ``tests/integration/tools/``.
    """
    token = object.__new__(SandboxAvailable)
    object.__setattr__(token, "version", (0, 9, 0))
    object.__setattr__(token, "bwrap_path", "/usr/bin/bwrap")
    object.__setattr__(token, "prlimit_path", "/usr/bin/prlimit")
    # HARDEN-05: a real receipt carries the bind set `probe` measured on the host.
    # Stated as the full §8.1 template because that is the host these unit tests
    # describe; the resolved-set behaviour is exercised in tests/unit/sandbox/.
    object.__setattr__(token, "system_binds", SYSTEM_RO_BINDS)
    object.__setattr__(token, "omitted_binds", ())
    object.__setattr__(
        token,
        "_issuance",
        __import__("lsassist.sandbox.availability", fromlist=["_ISSUED_BY_PROBE"])._ISSUED_BY_PROBE,
    )
    return token


def proceeding(
    environment: DispatchEnvironment,
    manifest: ToolManifest,
    args: dict[str, Any],
    **kwargs: Any,
) -> Any:
    """A real §6.3 step-1..4 PROCEED decision — never a hand-built stub."""
    request = ToolRequest(call_id="c1", tool=manifest.name, args=args)
    decision = dispatch(request, manifest=manifest, environment=environment, **kwargs)
    assert decision.decision is Decision.PROCEED, decision
    return decision


def echo_observation(**overrides: Any) -> ExecObservation:
    base: dict[str, Any] = {
        "exit_code": 0,
        "duration_ms": 3,
        "stdout": b"hi\n",
        "stderr": b"",
        "stdout_digest": sha256_digest(b"hi\n"),
        "stderr_digest": sha256_digest(b""),
        "stdout_truncated": False,
        "stderr_truncated": False,
        "stdout_bytes": 3,
        "stderr_bytes": 0,
        "timed_out": False,
    }
    base.update(overrides)
    return ExecObservation(**base)


# ==========================================================================
# A. tools/result.py — §6.5 assembly, PURE
# ==========================================================================
def test_digest_carries_the_algorithm_prefix() -> None:
    digest = sha256_digest(b"")
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64


def test_sink_caps_the_body_but_digests_the_whole_stream() -> None:
    """§6.5's ``stdout_digest`` must attest what the tool ACTUALLY produced.

    A digest of the truncated body would silently attest less than what ran —
    an I12 evidence downgrade wearing the costume of a size limit. The body is
    capped (bounded memory); the hash keeps consuming.
    """
    sink = OutputSink(4)
    sink.feed(b"abcde")
    sink.feed(b"fghij")

    assert sink.body == b"abcd"
    assert sink.truncated is True
    assert sink.total_bytes == 10
    assert sink.digest == sha256_digest(b"abcdefghij")


def test_sink_of_cap_zero_keeps_nothing_and_still_digests() -> None:
    sink = OutputSink(0)
    sink.feed(b"x")
    assert sink.body == b""
    assert sink.truncated is True
    assert sink.digest == sha256_digest(b"x")


def test_sink_under_the_cap_is_not_truncated() -> None:
    sink = OutputSink(8)
    sink.feed(b"abc")
    assert (sink.body, sink.truncated, sink.total_bytes) == (b"abc", False, 3)


def test_sink_refuses_a_negative_or_bool_cap() -> None:
    with pytest.raises(ResultError):
        OutputSink(-1)
    with pytest.raises(ResultError):
        # `bool` is an `int`, so an unguarded sink would read this as "keep 1 byte".
        OutputSink(True)


def test_a_signal_death_becomes_the_shell_s_128_plus_signal() -> None:
    """§6.5 bounds ``exit_code`` to 0..255; ``Popen.returncode`` is NEGATIVE.

    Handing pydantic ``-9`` raises a ValidationError out of the observation
    path, so a killed tool would crash the dispatcher instead of being reported.
    ``128 + SIGKILL`` is also exactly what bwrap itself reports (measured: 137 in
    ``tests/e2e/test_sandbox_exec.py``), so the two agree.
    """
    assert normalize_exit_code(0) == 0
    assert normalize_exit_code(42) == 42
    assert normalize_exit_code(-signal.SIGKILL) == 137
    assert normalize_exit_code(-signal.SIGTERM) == 143


def test_an_out_of_range_return_code_is_refused_not_clamped() -> None:
    """A silently clamped exit status is indistinguishable from a real one."""
    with pytest.raises(ResultError):
        normalize_exit_code(4096)
    with pytest.raises(ResultError):
        normalize_exit_code(-4096)


def test_build_result_reports_ok_error_and_truncated_in_that_priority() -> None:
    """§6.5's status is one value, so the three conditions need an ORDER.

    A run that failed AND overflowed its cap is a FAILURE first: reporting
    ``truncated`` would tell the kernel the tool succeeded with a clipped body.
    """
    ok = build_result(tool="sys.info", observation=echo_observation(), result={"stdout": "hi"})
    assert ok.status is ToolResultStatus.OK

    truncated = build_result(
        tool="sys.info",
        observation=echo_observation(stdout_truncated=True),
        result={"stdout": "hi"},
    )
    assert truncated.status is ToolResultStatus.TRUNCATED

    failed = build_result(
        tool="sys.info",
        observation=echo_observation(exit_code=1, stdout_truncated=True),
        result={},
    )
    assert failed.status is ToolResultStatus.ERROR
    assert failed.error is not None


def test_a_timeout_is_an_error_even_with_exit_code_zero() -> None:
    """A killed tool can still be reaped with a 0 status on some paths."""
    result = build_result(tool="sys.info", observation=echo_observation(timed_out=True), result={})
    assert result.status is ToolResultStatus.ERROR
    assert result.error is not None
    assert result.error.kind == "timeout"


def test_the_result_never_carries_the_output_BODY() -> None:
    """§6.5: "დიდი bodies digest-only + reference". The body is evidence by
    DIGEST; copying it into ``result`` would put unredacted tool output into
    every record that quotes the result."""
    observation = echo_observation(stdout=b"SECRET-LOOKING-PAYLOAD")
    result = build_result(tool="sys.info", observation=observation, result={"stdout": "hi"})
    assert "SECRET-LOOKING-PAYLOAD" not in json.dumps(result.model_dump(mode="json"))


# ==========================================================================
# B. step 5 — sandbox profile build (§6.3, §8)
# ==========================================================================
def test_the_profile_is_derived_from_the_declared_capability_not_guessed() -> None:
    """§8.1 ``ro`` binds the workspace READ-ONLY; §8.2 ``ws`` binds it rw.

    Deriving it from ``capabilities.fs`` is mechanical and total: a tool that
    declares it cannot write must not be handed a writable bind, and a tool that
    must write cannot run under ``ro``.
    """
    assert profile_for(make_manifest()) is Profile.RO
    assert (
        profile_for(
            make_manifest(capabilities={"fs": "read_scoped", "net": "none", "proc": "none"})
        )
        is Profile.RO
    )
    assert profile_for(write_manifest()) is Profile.WS


def test_the_composed_argv_is_the_HARDEN_03_shape(
    environment: DispatchEnvironment, cache_dir: str
) -> None:
    decision = proceeding(environment, make_manifest(), {"probe": "uname"})
    argv = build_exec_argv(
        normalized=decision.normalized,
        manifest=make_manifest(),
        environment=environment,
        available=fake_receipt(),
        cache_dir=cache_dir,
        argv=["/bin/echo", "hi"],
    )

    assert argv[0] == "/usr/bin/bwrap"
    assert "--unshare-all" in argv
    assert argv.count("--") == 1
    separator = argv.index("--")
    assert argv[separator + 1] == "/usr/bin/prlimit"
    assert any(token.startswith("--nproc=") for token in argv), "T-14 fork-bomb cap dropped"
    # --clearenv is what makes §8.3's "constructed from scratch" true; after the
    # --setenv block it would wipe the projected variables instead.
    assert argv.index("--clearenv") < argv.index("--setenv")


def test_the_child_env_is_EXACTLY_the_env_the_approval_bound(
    environment: DispatchEnvironment, cache_dir: str
) -> None:
    """§7.4 binds an ``env_digest``; §8.1 emits the env as ``--setenv`` pairs.

    If those two ever disagree the user approved one environment and a different
    one runs. Nothing downstream re-checks it, so this is the check.
    """
    decision = proceeding(environment, make_manifest(), {"probe": "uname"})
    argv = build_exec_argv(
        normalized=decision.normalized,
        manifest=make_manifest(),
        environment=environment,
        available=fake_receipt(),
        cache_dir=cache_dir,
        argv=["/bin/echo", "hi"],
    )

    emitted = {argv[i + 1]: argv[i + 2] for i, token in enumerate(argv) if token == "--setenv"}
    assert decision.normalized is not None
    assert emitted == dict(decision.normalized.env)


def test_a_venv_that_appeared_after_approval_blocks_instead_of_running(
    environment: DispatchEnvironment, cache_dir: str, workspace: Path
) -> None:
    """§8.2 lets ``<ws>/.venv/bin`` OUTRANK system tools, and approval binds a
    NAME (§7.4) — T2.05's named residual.

    The decision was taken with ``venv_exists=False``, so the approved PATH has
    no venv entry. Creating ``.venv/bin`` before exec would silently change which
    ``python`` runs. The window is small; the consequence is a hijacked approved
    binary, so it is refused rather than reported afterwards.
    """
    manifest = write_manifest(
        capabilities={"fs": "write_scoped", "net": "none", "proc": "spawn_argv"}
    )
    decision = proceeding(
        environment, manifest, {"path": str(workspace / "a.txt")}, path_args=["path"]
    )
    (workspace / ".venv" / "bin").mkdir(parents=True)

    with pytest.raises(DispatchError, match=ENV_REBOUND):
        build_exec_argv(
            normalized=decision.normalized,
            manifest=manifest,
            environment=environment,
            available=fake_receipt(),
            cache_dir=cache_dir,
            argv=["/bin/echo", "hi"],
        )


def test_an_APPROVED_write_outside_the_workspace_is_refused_not_left_to_EROFS(
    tmp_path: Path, environment: DispatchEnvironment, cache_dir: str
) -> None:
    """§7.2 R2 ADMITS an out-of-workspace write — it raises the class to
    CONFIRM_EXACT rather than denying it — and no V1 profile can express one:
    §8.2's ``ws`` binds the workspace and nothing else read-write.

    So the user really can approve an action the sandbox cannot perform. Left
    alone it dies inside as ``EROFS`` and the failure reads like a broken tool.
    Getting here requires a real token, which is the point: the refusal is not
    "policy said no", it is "policy said yes and §8 cannot carry it".
    """
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    manifest = write_manifest()
    service = TokenService(b"k" * 32)
    moment = datetime.datetime(2026, 7, 28, 12, 0, tzinfo=datetime.UTC)
    approving = DispatchEnvironment(
        workspace_root=environment.workspace_root,
        cwd=environment.cwd,
        stores=environment.stores,
        session_id=environment.session_id,
        token_service=service,
    )
    request = ToolRequest(call_id="c1", tool=manifest.name, args={"path": str(outside)})
    asked = dispatch(
        request,
        manifest=manifest,
        environment=approving,
        path_args=["path"],
        now=moment,
    )
    assert asked.decision is Decision.NEEDS_APPROVAL
    assert asked.permission_class is PermissionClass.CONFIRM_EXACT
    assert asked.approval_record is not None
    granted = dispatch(
        request,
        manifest=manifest,
        environment=approving,
        path_args=["path"],
        grant=ApprovalGrant(
            record=asked.approval_record, token=service.mint(asked.approval_record)
        ),
        now=moment,
    )
    assert granted.decision is Decision.PROCEED

    with pytest.raises(DispatchError, match=WORKSPACE_SCOPE):
        build_exec_argv(
            normalized=granted.normalized,
            manifest=manifest,
            environment=approving,
            available=fake_receipt(),
            cache_dir=cache_dir,
            argv=["/bin/echo", "hi"],
        )


# ==========================================================================
# C. step 6 — the runner. Real spawns, every one bounded.
# ==========================================================================
def test_the_child_environment_is_empty_not_inherited() -> None:
    """T2.06 obligation 1. ``env=None`` hands the parent environ to ``bwrap``
    itself; ``--clearenv`` only protects what runs INSIDE it.

    Measured through ``/proc/self/environ`` rather than ``sh -c env``: a shell
    SETS ``PWD`` from ``getcwd()`` on startup, so ``env`` reports a variable the
    child was never given and the assertion would have to be loosened to
    "almost empty" — which is exactly the shape a real leak hides in.
    """
    os.environ["LSASSIST_CANARY_T303"] = "leaked"
    try:
        observation = spawn_capped(
            ["/bin/cat", "/proc/self/environ"],
            timeout_s=SPAWN_BUDGET_S,
            stdout_cap=65536,
            stderr_cap=65536,
        )
    finally:
        del os.environ["LSASSIST_CANARY_T303"]

    assert observation.exit_code == 0
    assert observation.stdout == b"", f"the child inherited: {observation.stdout!r}"


def test_the_argv_is_a_list_not_a_shell_string() -> None:
    """§7.6 rule 8. Under a shell, ``$HOME`` would expand and ``;`` would chain."""
    observation = spawn_capped(
        ["/bin/echo", "$HOME; id"],
        timeout_s=SPAWN_BUDGET_S,
        stdout_cap=65536,
        stderr_cap=65536,
    )
    assert observation.stdout == b"$HOME; id\n"


def test_stdin_is_closed_so_a_reading_tool_cannot_wait_forever() -> None:
    """An inherited stdin is both a hang and a channel to the user's terminal.

    This test is here because the unbounded version does not FAIL — it HANGS,
    which is the failure mode T4.02's FIFO taught this project to hunt.
    """
    started = time.monotonic()
    observation = spawn_capped(
        ["/bin/cat"], timeout_s=SPAWN_BUDGET_S, stdout_cap=65536, stderr_cap=65536
    )
    assert time.monotonic() - started < SPAWN_BUDGET_S
    assert observation.timed_out is False
    assert observation.stdout == b""


def test_an_output_flood_is_truncated_without_deadlocking_the_child() -> None:
    """A reader that stops draining at the cap deadlocks the child on a full
    pipe, and the run then reports ``timeout`` for a tool that merely talked too
    much. Draining-and-discarding keeps memory bounded AND the status honest."""
    observation = spawn_capped(
        ["/bin/sh", "-c", "yes lsassist | head -c 400000"],
        timeout_s=SPAWN_BUDGET_S,
        stdout_cap=1024,
        stderr_cap=1024,
    )
    assert observation.timed_out is False
    assert observation.stdout_truncated is True
    assert len(observation.stdout) == 1024
    assert observation.stdout_bytes == 400000


def test_a_timeout_kills_the_whole_process_GROUP() -> None:
    """§6.3 step 6: "timeout kill (``SIGKILL`` process group)".

    Killing only the direct child leaves a grandchild holding the write end of
    the pipe, so the read never reaches EOF and the runner hangs after its own
    deadline has already passed.
    """
    started = time.monotonic()
    observation = spawn_capped(
        ["/bin/sh", "-c", "sleep 120 & sleep 120"],
        timeout_s=1,
        stdout_cap=1024,
        stderr_cap=1024,
    )
    elapsed = time.monotonic() - started

    assert observation.timed_out is True
    assert elapsed < SPAWN_BUDGET_S, "the runner did not return after its own deadline"
    assert observation.exit_code == 137


def test_timed_out_comes_from_the_runner_s_clock_not_from_exit_137() -> None:
    """``prlimit --cpu`` kills with SIGKILL too (measured, see prlimit.py), so
    ``137`` alone cannot distinguish a wall-clock timeout from an rlimit breach.
    The runner records its own elapsed time and says so."""
    observation = spawn_capped(
        ["/bin/sh", "-c", "kill -9 $$"],
        timeout_s=SPAWN_BUDGET_S,
        stdout_cap=1024,
        stderr_cap=1024,
    )
    assert observation.exit_code == 137
    assert observation.timed_out is False


def test_the_duration_is_measured_on_a_monotonic_clock() -> None:
    observation = spawn_capped(
        ["/bin/sh", "-c", "exit 3"],
        timeout_s=SPAWN_BUDGET_S,
        stdout_cap=1024,
        stderr_cap=1024,
        clock=lambda: 0,
    )
    assert observation.exit_code == 3
    assert observation.duration_ms == 0


def test_only_the_dispatcher_can_reach_the_raw_runner() -> None:
    """The low-level runner spawns EXACTLY the argv it is given — it is not a
    sanctioned exec path. §8.3's guarantee lives in :func:`run`, which composes
    through ``compose_exec_argv`` and re-checks the shape. A second route to
    ``execve`` without that check is the I11 failure (§8.3).

    **This is an AST walk because the substring version was theatre.** The first
    draft grepped ``src/**/*.py`` for ``"spawn_capped("`` — and the ONLY occurrence
    of that substring in ``src/`` is ``def spawn_capped(`` itself, because the real
    invocation is spelled ``runner(...)`` through the injected default. It passed
    on the definition line alone, would have passed with zero callers, and a second
    module adopting the same ``runner=spawn_capped`` idiom would have added no
    matching substring at all. Naming a test after a property it does not check is
    worse than not having it: it spends the reviewer's attention.
    """

    def names_the_runner(node: ast.AST) -> bool:
        """Any spelling that puts the function in another module's hands."""
        if isinstance(node, ast.Name):
            return node.id == "spawn_capped"
        if isinstance(node, ast.Attribute):
            return node.attr == "spawn_capped"
        if isinstance(node, ast.ImportFrom):
            return any(alias.name == "spawn_capped" for alias in node.names)
        return False

    def calls_the_runner(node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        if isinstance(node.func, ast.Name):
            return node.func.id == "spawn_capped"
        if isinstance(node.func, ast.Attribute):
            return node.func.attr == "spawn_capped"
        return False

    src = Path(__file__).resolve().parents[3] / "src"
    naming: set[str] = set()
    calling: set[str] = set()
    for path in src.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if names_the_runner(node):
                naming.add(path.name)
            if calls_the_runner(node):
                calling.add(path.name)

    # Equality, not `<=`: an empty set would mean the one sanctioned reference
    # this test exists to watch has silently disappeared — which is exactly how
    # the substring version managed to assert nothing at all.
    assert naming == {"dispatcher.py"}, f"an unsanctioned module names the raw runner: {naming}"
    assert calling == set(), f"the raw runner is called directly in {calling}"


# ==========================================================================
# D. §8.3 / I11 — never an unsandboxed exec
# ==========================================================================
def test_run_refuses_argv_rewritten_after_action_binding(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
) -> None:
    manifest = make_manifest(
        name="proc.exec",
        input_schema={
            "type": "object",
            "required": ["argv"],
            "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
            "additionalProperties": False,
        },
    )
    decision = proceeding(environment, manifest, {"argv": ["/usr/bin/true"]})
    spawned: list[list[str]] = []

    def record(argv: list[str], **_: Any) -> ExecObservation:
        spawned.append(list(argv))
        return echo_observation()

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-bound-argv",
        audit=journal,
        argv=["/usr/bin/touch", "rewritten"],
        probe_fn=fake_receipt,
        runner=record,
    )
    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == ARGV_REBOUND
    assert spawned == []


def test_proc_exec_public_run_refuses_default_empty_executable_allowlist(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
) -> None:
    manifest = make_manifest(
        name="proc.exec",
        input_schema={
            "type": "object",
            "required": ["argv"],
            "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
            "additionalProperties": False,
        },
    )
    decision = proceeding(environment, manifest, {"argv": ["/usr/bin/true"]})
    spawned: list[list[str]] = []

    def record(argv: list[str], **_: Any) -> ExecObservation:
        spawned.append(list(argv))
        return echo_observation()

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-empty-exec-allowlist",
        audit=journal,
        argv=["/usr/bin/true"],
        probe_fn=fake_receipt,
        runner=record,
    )
    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == EXECUTABLE_REFUSED
    assert "allowlist" in outcome.result.error.message_redacted
    assert spawned == []


def test_proc_exec_public_run_allows_only_an_exact_configured_executable(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
    tmp_path: Path,
) -> None:
    executable = tmp_path / "replaceable"
    executable.write_text("first", encoding="utf-8")
    allowed = dataclasses.replace(
        environment,
        stores=dataclasses.replace(
            environment.stores, exec_allowlist=frozenset({str(executable)})
        ),
    )
    manifest = make_manifest(
        name="proc.exec",
        input_schema={
            "type": "object",
            "required": ["argv"],
            "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
            "additionalProperties": False,
        },
    )
    decision = proceeding(allowed, manifest, {"argv": [str(executable)]})
    executable.write_text("replacement-is-longer", encoding="utf-8")
    spawned: list[list[str]] = []

    def record(argv: list[str], **_: Any) -> ExecObservation:
        spawned.append(list(argv))
        return echo_observation()

    outcome = run(
        decision,
        manifest=manifest,
        environment=allowed,
        cache_dir=cache_dir,
        task_id="t-exact-exec-allowlist",
        audit=journal,
        argv=[str(executable)],
        probe_fn=fake_receipt,
        runner=record,
    )
    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == EXECUTABLE_REFUSED
    assert spawned == []


def test_test_run_public_run_refuses_unbound_touch_before_marker_creation(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
    tmp_path: Path,
) -> None:
    manifest = make_manifest(
        name="test.run",
        input_schema={
            "type": "object",
            "properties": {"extra_args": {"type": "array", "items": {"type": "string"}}},
            "additionalProperties": False,
        },
    )
    decision = proceeding(environment, manifest, {"extra_args": []})
    marker = tmp_path / "must-not-exist"

    def touch_marker(argv: list[str], **_: Any) -> ExecObservation:
        marker.touch()
        return echo_observation()

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-unbound-test-run",
        audit=journal,
        argv=["/usr/bin/touch", str(marker)],
        probe_fn=fake_receipt,
        runner=touch_marker,
    )
    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == ARGV_REBOUND
    assert "approval binding" in outcome.result.error.message_redacted
    assert not marker.exists()


def test_test_run_public_run_rechecks_runner_against_action_hash(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
    tmp_path: Path,
) -> None:
    manifest = make_manifest(
        name="test.run",
        input_schema={
            "type": "object",
            "properties": {"extra_args": {"type": "array", "items": {"type": "string"}}},
            "additionalProperties": False,
        },
    )
    decision = proceeding(
        environment, manifest, {"extra_args": []}, execution_argv=["/usr/bin/true"]
    )
    assert decision.normalized is not None
    marker = tmp_path / "forged-runner"
    forged = dataclasses.replace(
        decision,
        normalized=dataclasses.replace(decision.normalized, argv=("/usr/bin/touch", str(marker))),
    )

    def touch_marker(argv: list[str], **_: Any) -> ExecObservation:
        marker.touch()
        return echo_observation()

    outcome = run(
        forged,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-forged-action-hash",
        audit=journal,
        argv=["/usr/bin/touch", str(marker)],
        probe_fn=fake_receipt,
        runner=touch_marker,
    )
    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == ARGV_REBOUND
    assert not marker.exists()


def test_an_unavailable_sandbox_BLOCKS_and_spawns_nothing(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
) -> None:
    """§8.3: "bwrap spawn failure → typed error ``sandbox_unavailable`` → exec
    tool BLOCKED (never fallback to unsandboxed exec — fail-closed)"."""
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})
    spawned: list[list[str]] = []

    def refuse() -> SandboxAvailable:
        raise SandboxUnavailable("no bwrap on this host")

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        audit=journal,
        argv=["/bin/echo", "hi"],
        probe_fn=refuse,
        runner=lambda argv, **_: spawned.append(list(argv)),  # type: ignore[arg-type,return-value]
    )

    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.status is ToolResultStatus.ERROR
    assert outcome.result.error is not None
    assert outcome.result.error.kind == SANDBOX_UNAVAILABLE
    assert spawned == [], "an unavailable sandbox still reached the runner"


def test_run_refuses_an_argv_that_is_not_sandbox_shaped(
    environment: DispatchEnvironment,
    cache_dir: str,
    monkeypatch: pytest.MonkeyPatch,
    journal: AuditWriter,
) -> None:
    """The receipt gate is defense in depth; the LOAD-BEARING boundary is the
    argv CONTENT (``availability.py``'s own words). If the composed argv ever
    stops carrying the namespace flags, the runner must not spawn it."""
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})
    monkeypatch.setattr(
        "lsassist.tools.dispatcher.compose_exec_argv",
        lambda **_: ["/bin/sh", "-c", "id"],
    )
    spawned: list[list[str]] = []

    with pytest.raises(DispatchError, match="unshare"):
        run(
            decision,
            manifest=manifest,
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-1",
            audit=journal,
            argv=["/bin/echo", "hi"],
            probe_fn=fake_receipt,
            runner=lambda argv, **_: spawned.append(list(argv)),  # type: ignore[arg-type,return-value]
        )
    assert spawned == []


def test_run_refuses_a_decision_that_did_not_proceed(
    environment: DispatchEnvironment,
    cache_dir: str,
    tmp_path: Path,
    journal: AuditWriter,
) -> None:
    """ "Nothing executes without a decision to execute" is structural in
    :class:`DispatchDecision`; running one anyway is a WIRING bug, not policy."""
    manifest = make_manifest()
    request = ToolRequest(call_id="c1", tool="sys.info", args={"probe": "uname"})
    blocked = dispatch(
        request,
        manifest=make_manifest(permission_class="DENY_ALWAYS"),
        environment=environment,
    )
    assert blocked.decision is Decision.BLOCKED

    with pytest.raises(DispatchError):
        run(
            blocked,
            manifest=manifest,
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-1",
            audit=journal,
            argv=["/bin/echo", "hi"],
            probe_fn=fake_receipt,
        )


# ==========================================================================
# E. §7.5 step 3 — pre-exec re-canonicalization
# ==========================================================================
def test_a_path_retargeted_between_approval_and_exec_blocks(
    environment: DispatchEnvironment,
    cache_dir: str,
    workspace: Path,
    tmp_path: Path,
    journal: AuditWriter,
) -> None:
    """§7.5 step 3: "Pre-exec re-canonicalization: თითო path თავიდან resolve →
    hash compare; mismatch → invalid."

    T3.02 stopped at the decision, so nothing re-resolved the target in the
    window between approval and exec. Without this the whole §7.5 chain has a
    hole exactly where the TOCTOU lives.
    """
    manifest = write_manifest()
    target = workspace / "a.txt"
    decision = proceeding(environment, manifest, {"path": str(target)}, path_args=["path"])

    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("attacker\n", encoding="utf-8")
    target.unlink()
    target.symlink_to(elsewhere)

    spawned: list[list[str]] = []
    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        audit=journal,
        argv=["/bin/echo", "hi"],
        probe_fn=fake_receipt,
        runner=lambda argv, **_: spawned.append(list(argv)),  # type: ignore[arg-type,return-value]
    )

    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == PATH_INVALIDATED
    assert spawned == []


def test_normalize_snapshots_the_parent_of_a_create_intent_path(
    environment: DispatchEnvironment, workspace: Path
) -> None:
    """A ``create_if_missing`` target does not exist yet, so it has no node
    identity to snapshot — but its PARENT does, and a swapped parent is how the
    created file lands somewhere else. Snapshotting the parent is the same
    ``recheck`` call with nothing new invented."""
    manifest = write_manifest()
    decision = proceeding(
        environment,
        manifest,
        {"path": str(workspace / "new.txt")},
        path_args=["path"],
        create_if_missing=True,
    )
    assert decision.normalized is not None
    snapshotted = {snapshot.canonical_path for snapshot in decision.normalized.path_snapshots}
    assert snapshotted == {str(workspace)}


# ==========================================================================
# F. step 8 — verify
# ==========================================================================
def test_a_result_that_violates_output_schema_is_an_error_not_an_ok(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
) -> None:
    """§6.3 step 8: "result-ის validation ``output_schema``-ზე"."""
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        audit=journal,
        argv=["/bin/echo", "hi"],
        probe_fn=fake_receipt,
        runner=lambda argv, **_: echo_observation(),
        result_of=lambda observation: {"unexpected": 1},
    )

    assert outcome.result.status is ToolResultStatus.ERROR
    assert outcome.result.error is not None
    assert outcome.result.error.kind == MALFORMED_TOOL_RESULT
    # The invariant the surrounding code exists for, and the one the first
    # version of this test forgot: a payload the schema REJECTED is not
    # published. Without this line, mutating `capped if error is None else {}`
    # to plain `capped` left the whole suite green while §6.3 step 8 handed the
    # kernel exactly the structure it had just refused.
    assert outcome.result.result == {}


def test_a_write_tool_gets_a_post_exec_file_snapshot_as_evidence(
    environment: DispatchEnvironment,
    cache_dir: str,
    workspace: Path,
    journal: AuditWriter,
) -> None:
    """§7.5 step 6: "expected paths-ის inode/hash snapshot compare (write
    tools-ზე)". The snapshot IS the §6.5 ``evidence`` object (I12)."""
    manifest = write_manifest()
    target = workspace / "a.txt"
    decision = proceeding(environment, manifest, {"path": str(target)}, path_args=["path"])

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        audit=journal,
        argv=["/bin/echo", "hi"],
        probe_fn=fake_receipt,
        runner=lambda argv, **_: echo_observation(),
        result_of=lambda observation: {"stdout": "hi"},
    )

    assert outcome.verification is Verification.VERIFIED
    evidence = outcome.result.evidence
    assert evidence is not None
    assert evidence.type is EvidenceType.FILE_SNAPSHOT
    assert evidence.path == str(target)
    assert evidence.inode == target.stat().st_ino


def test_an_atomic_replace_is_verified_because_that_is_what_a_write_IS(
    environment: DispatchEnvironment,
    cache_dir: str,
    workspace: Path,
    journal: AuditWriter,
) -> None:
    """§6.4's ``fs.write`` is "atomic: tmp+``fsync``+``rename``", so the target's
    inode CHANGES on every successful write. A post-exec check demanding a stable
    inode would report every correct write as tampering — and the project would
    learn to ignore the alarm."""
    manifest = write_manifest()
    target = workspace / "a.txt"
    decision = proceeding(environment, manifest, {"path": str(target)}, path_args=["path"])

    def replace_atomically(argv: list[str], **_: Any) -> ExecObservation:
        tmp = workspace / "a.txt.tmp"
        tmp.write_text("rewritten\n", encoding="utf-8")
        os.replace(tmp, target)
        return echo_observation()

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        audit=journal,
        argv=["/bin/echo", "hi"],
        probe_fn=fake_receipt,
        runner=replace_atomically,
        result_of=lambda observation: {"stdout": "hi"},
    )

    assert outcome.verification is Verification.VERIFIED


def test_a_path_retargeted_DURING_the_exec_is_UNVERIFIED_with_an_audit_alert(
    environment: DispatchEnvironment, cache_dir: str, workspace: Path, tmp_path: Path
) -> None:
    """§7.5 step 6: "mismatch = verdict UNVERIFIED + audit alert"."""
    manifest = write_manifest()
    target = workspace / "a.txt"
    decision = proceeding(environment, manifest, {"path": str(target)}, path_args=["path"])
    audit_dir = tmp_path / "audit"

    def retarget(argv: list[str], **_: Any) -> ExecObservation:
        elsewhere = tmp_path / "elsewhere.txt"
        elsewhere.write_text("attacker\n", encoding="utf-8")
        target.unlink()
        target.symlink_to(elsewhere)
        return echo_observation()

    with AuditWriter(directory=audit_dir, session_id="s-1") as writer:
        outcome = run(
            decision,
            manifest=manifest,
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-1",
            argv=["/bin/echo", "hi"],
            probe_fn=fake_receipt,
            runner=retarget,
            result_of=lambda observation: {"stdout": "hi"},
            audit=writer,
        )
        events = [
            json.loads(line)["event"]
            for line in writer.path.read_text(encoding="utf-8").splitlines()
        ]

    assert outcome.verification is Verification.UNVERIFIED
    assert "verify" in events, f"no §7.5 step-6 alert was journalled: {events}"


def test_a_read_tool_reports_verification_as_not_applicable(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
) -> None:
    """NAMED RESIDUAL, not an oversight: SPEC:564 scopes §7.5 step 6 to WRITE
    tools, so a same-path swap has no post-exec backstop for read/exec. Reporting
    ``VERIFIED`` here would manufacture evidence the SPEC does not collect."""
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        audit=journal,
        argv=["/bin/echo", "hi"],
        probe_fn=fake_receipt,
        runner=lambda argv, **_: echo_observation(),
        result_of=lambda observation: {"stdout": "hi"},
    )
    assert outcome.verification is Verification.NOT_APPLICABLE


def test_an_oversized_result_becomes_digest_only(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
) -> None:
    """§6.5: "დიდი bodies digest-only + reference"; §6.2's ``max_result_chars``
    is the per-tool ceiling."""
    manifest = make_manifest(
        output_limits={
            "max_stdout_bytes": 51200,
            "max_stderr_bytes": 65536,
            "max_result_chars": 64,
        }
    )
    decision = proceeding(environment, manifest, {"probe": "uname"})

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        audit=journal,
        argv=["/bin/echo", "hi"],
        probe_fn=fake_receipt,
        runner=lambda argv, **_: echo_observation(),
        result_of=lambda observation: {"stdout": "x" * 4096},
    )

    assert outcome.result.status is ToolResultStatus.TRUNCATED
    assert "x" * 4096 not in json.dumps(outcome.result.model_dump(mode="json"))


# ==========================================================================
# G. step 9 — audit
# ==========================================================================
def test_the_audit_event_carries_every_digest_and_no_body(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    """§6.3 step 9: "Audit — append event (redacted) with all digests"."""
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})
    audit_dir = tmp_path / "audit"

    with AuditWriter(directory=audit_dir, session_id="s-1") as writer:
        outcome = run(
            decision,
            manifest=manifest,
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-1",
            argv=["/bin/echo", "hi"],
            probe_fn=fake_receipt,
            runner=lambda argv, **_: echo_observation(stdout=b"TOP-SECRET-BODY"),
            result_of=lambda observation: {"stdout": "hi"},
            audit=writer,
        )
        text = writer.path.read_text(encoding="utf-8")

    records = [json.loads(line) for line in text.splitlines()]
    tool_results = [record for record in records if record["event"] == "tool_result"]
    assert len(tool_results) == 1
    payload = tool_results[0]["payload"]
    assert payload["stdout_digest"] == outcome.result.stdout_digest
    assert payload["stderr_digest"] == outcome.result.stderr_digest
    assert payload["action_hash"] and payload["env_digest"]
    assert "TOP-SECRET-BODY" not in text
    assert outcome.audit_seq == tool_results[0]["seq"]


def test_an_execution_that_cannot_be_journalled_is_loud_and_keeps_the_result(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    """The tool ALREADY RAN. Swallowing the audit failure leaves an unrecorded
    action; raising a bare error throws away the very digests the caller needs to
    react. The exception carries the result."""
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})
    audit_dir = tmp_path / "audit"
    writer = AuditWriter(directory=audit_dir, session_id="s-1")
    writer.close()

    with pytest.raises(ExecutionNotJournalled) as caught:
        run(
            decision,
            manifest=manifest,
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-1",
            argv=["/bin/echo", "hi"],
            probe_fn=fake_receipt,
            runner=lambda argv, **_: echo_observation(),
            result_of=lambda observation: {"stdout": "hi"},
            audit=writer,
        )
    assert caught.value.result.status is ToolResultStatus.OK


def test_a_blocked_execution_is_journalled_too(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    """A refusal nobody recorded is a refusal nobody can audit (§14.1)."""
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})
    audit_dir = tmp_path / "audit"

    def refuse() -> SandboxAvailable:
        raise SandboxUnavailable("no bwrap on this host")

    with AuditWriter(directory=audit_dir, session_id="s-1") as writer:
        run(
            decision,
            manifest=manifest,
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-1",
            argv=["/bin/echo", "hi"],
            probe_fn=refuse,
            audit=writer,
        )
        records = [
            json.loads(line) for line in writer.path.read_text(encoding="utf-8").splitlines()
        ]

    kinds = [record["payload"].get("error", {}).get("kind") for record in records]
    assert SANDBOX_UNAVAILABLE in kinds


def test_the_audit_payload_survives_the_never_recorded_walk(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    """§14.1's ``AuditWriter`` REFUSES a payload carrying a never-recorded key or
    its own ``_redaction`` field. A dispatcher payload that trips it would make
    every execution unjournallable — and this file's own audit tests would be the
    only thing standing between that and production."""
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})

    with AuditWriter(directory=tmp_path / "audit", session_id="s-1") as writer:
        outcome = run(
            decision,
            manifest=manifest,
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-1",
            argv=["/bin/echo", "hi"],
            probe_fn=fake_receipt,
            runner=lambda argv, **_: echo_observation(),
            result_of=lambda observation: {"stdout": "hi"},
            audit=writer,
        )
    assert outcome.audit_seq is not None


# ==========================================================================
# H. what the journal has to say afterwards
#
# The whole tail against a REAL bwrap lives in
# tests/integration/tools/test_dispatch_sandbox.py. It is deliberately NOT
# here: the `dispatcher-coverage` job measures this directory alone, and a
# test that skips when bwrap is absent would make the §23.1 floor depend on
# what happens to be installed on the runner.
# ==========================================================================
def test_the_permission_class_reaches_the_audit_record(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    """§14.1's journal is what an operator reads afterwards; a ``tool_result``
    that does not say under which class it ran cannot be reviewed."""
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})

    with AuditWriter(directory=tmp_path / "audit", session_id="s-1") as writer:
        run(
            decision,
            manifest=manifest,
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-1",
            argv=["/bin/echo", "hi"],
            probe_fn=fake_receipt,
            runner=lambda argv, **_: echo_observation(),
            result_of=lambda observation: {"stdout": "hi"},
            audit=writer,
        )
        records = [
            json.loads(line) for line in writer.path.read_text(encoding="utf-8").splitlines()
        ]

    payload = next(r["payload"] for r in records if r["event"] == "tool_result")
    assert payload["permission_class"] == PermissionClass.AUTO_READ.value
    assert payload["profile"] == Profile.RO.value


def test_the_audit_timestamp_is_supplied_not_invented_twice(
    environment: DispatchEnvironment, cache_dir: str, tmp_path: Path
) -> None:
    """A journal whose clock the caller cannot control is a journal no test can
    pin — and §14.1 records are hash-chained, so a re-stamped record is a
    different record."""
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})
    moment = datetime.datetime(2026, 7, 28, 12, 0, tzinfo=datetime.UTC)

    with AuditWriter(directory=tmp_path / "audit", session_id="s-1") as writer:
        run(
            decision,
            manifest=manifest,
            environment=environment,
            cache_dir=cache_dir,
            task_id="t-1",
            argv=["/bin/echo", "hi"],
            probe_fn=fake_receipt,
            runner=lambda argv, **_: echo_observation(),
            result_of=lambda observation: {"stdout": "hi"},
            audit=writer,
            now=moment,
        )
        records = [
            json.loads(line) for line in writer.path.read_text(encoding="utf-8").splitlines()
        ]

    assert records[0]["ts"].startswith("2026-07-28T12:00:00")


# ==========================================================================
# I. the refusals that only fire when the world moves under the execution
# ==========================================================================
class DelegatingFsView:
    """The real §7.5 view, with one answer replaced.

    Every §7.5 check here is a comparison between what was measured at approval
    and what is true now, so the only way to test a specific disagreement is to
    control one answer while the rest stay real.
    """

    def __init__(self, **overrides: Any) -> None:
        self._real = OsFsView()
        self._overrides = overrides

    def _call(self, name: str, path: str) -> Any:
        override = self._overrides.get(name)
        if override is not None:
            return override(path)
        return getattr(self._real, name)(path)

    def realpath(self, path: str) -> str:
        return str(self._call("realpath", path))

    def parent_ids(self, path: str) -> tuple[int, int, int]:
        return cast("tuple[int, int, int]", self._call("parent_ids", path))

    def node_ids(self, path: str) -> tuple[int, int, int]:
        return cast("tuple[int, int, int]", self._call("node_ids", path))

    def exists(self, path: str) -> bool:
        return bool(self._call("exists", path))


def run_write(
    environment: DispatchEnvironment,
    cache_dir: str,
    workspace: Path,
    journal: AuditWriter,
    runner: Any,
    **kwargs: Any,
) -> Any:
    """A ``ws``-profile execution over ``<ws>/a.txt``, with a custom runner."""
    manifest = kwargs.pop("manifest", None) or write_manifest()
    target = kwargs.pop("target", None) or str(workspace / "a.txt")
    decision = proceeding(environment, manifest, {"path": target}, path_args=["path"])
    return run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        audit=journal,
        argv=["/bin/echo", "hi"],
        probe_fn=fake_receipt,
        runner=runner,
        result_of=lambda observation: {"stdout": "hi"},
        **kwargs,
    )


def test_a_composed_argv_whose_setenv_block_drifted_is_refused(
    environment: DispatchEnvironment, cache_dir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_child_path`` and ``build_argv`` compute the child's PATH INDEPENDENTLY.

    A unit test pins the two functions against each other; this pins the ARGV
    that is about to be spawned, which is the artifact that actually runs. The
    substituted argv below carries every §8.3 flag — it is a plausible sandbox in
    every respect except that the environment is not the approved one.
    """
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})
    monkeypatch.setattr(
        "lsassist.tools.dispatcher.compose_exec_argv",
        lambda **_: [
            "/usr/bin/bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--setenv",
            "PATH",
            "/attacker/bin:/usr/bin:/bin",
            "--",
            "/bin/echo",
            "hi",
        ],
    )

    with pytest.raises(DispatchError, match=ENV_REBOUND):
        build_exec_argv(
            normalized=decision.normalized,
            manifest=manifest,
            environment=environment,
            available=fake_receipt(),
            cache_dir=cache_dir,
            argv=["/bin/echo", "hi"],
        )


def test_killing_a_group_that_is_already_gone_is_the_desired_end_state() -> None:
    """The private helper on purpose: ``_kill_group`` runs on the timeout path,
    where the child may have exited in the microsecond before the signal. An
    exception there would escape from a runner that had already done its job."""
    _kill_group(2**31 - 1)


def test_a_program_that_cannot_be_spawned_raises_rather_than_reporting_a_run() -> None:
    """``Popen`` raising is not an execution with a bad exit code, and reporting
    one would put a fabricated ``exit_code`` into the §6.5 record."""
    with pytest.raises(DispatchError, match="could not spawn"):
        spawn_capped(
            ["/nonexistent/lsassist-probe"],
            timeout_s=SPAWN_BUDGET_S,
            stdout_cap=1024,
            stderr_cap=1024,
        )


def test_a_write_target_that_vanished_before_the_snapshot_is_UNVERIFIED(
    environment: DispatchEnvironment,
    cache_dir: str,
    workspace: Path,
    journal: AuditWriter,
) -> None:
    """§7.5 step 6 evidence is taken from an ``open``, so the file can still go
    away between the existence check and the read. I12's rule is to DOWNGRADE,
    never to fabricate — and never to let the ``OSError`` escape a TCB function
    that has already let a tool run."""

    def delete_it(argv: list[str], **_: Any) -> ExecObservation:
        (workspace / "a.txt").unlink()
        return echo_observation()

    outcome = run_write(
        environment,
        cache_dir,
        workspace,
        journal,
        delete_it,
        # exists() lies, so the checks above the snapshot all pass and the
        # failure lands exactly on the open.
        fs_view=DelegatingFsView(exists=lambda path: True),
    )
    assert outcome.verification is Verification.UNVERIFIED


def test_a_write_target_that_was_deleted_is_UNVERIFIED(
    environment: DispatchEnvironment,
    cache_dir: str,
    workspace: Path,
    journal: AuditWriter,
) -> None:
    """The ordinary version of the same event, with nothing lying."""

    def delete_it(argv: list[str], **_: Any) -> ExecObservation:
        (workspace / "a.txt").unlink()
        return echo_observation()

    assert (
        run_write(environment, cache_dir, workspace, journal, delete_it).verification
        is Verification.UNVERIFIED
    )


def test_a_swapped_PARENT_directory_is_UNVERIFIED(
    environment: DispatchEnvironment,
    cache_dir: str,
    workspace: Path,
    journal: AuditWriter,
) -> None:
    """The subtle one, and the reason the parent identity is checked at all.

    Everything looks right afterwards: the path exists, resolves to itself, and
    holds a file. It is simply a DIFFERENT directory from the one that was
    approved — so the evidence would describe a file the tool never wrote.
    """

    def swap_the_parent(argv: list[str], **_: Any) -> ExecObservation:
        workspace.rename(workspace.parent / "ws.moved")
        workspace.mkdir()
        (workspace / "a.txt").write_text("planted\n", encoding="utf-8")
        return echo_observation()

    assert (
        run_write(environment, cache_dir, workspace, journal, swap_the_parent).verification
        is Verification.UNVERIFIED
    )


def test_a_write_target_too_large_to_hash_is_UNVERIFIED_not_partially_hashed(
    environment: DispatchEnvironment,
    cache_dir: str,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    journal: AuditWriter,
) -> None:
    """A partial hash published as ``sha256`` is a FALSE measurement, and §7.5
    step 6 asks for the file's. Refusing the evidence is the honest answer."""
    monkeypatch.setattr("lsassist.tools.dispatcher._MAX_EVIDENCE_BYTES", 1)

    outcome = run_write(
        environment, cache_dir, workspace, journal, lambda argv, **_: echo_observation()
    )
    assert outcome.verification is Verification.UNVERIFIED
    assert outcome.result.evidence is None


def test_a_write_target_that_is_a_DIRECTORY_yields_no_snapshot(
    environment: DispatchEnvironment,
    cache_dir: str,
    workspace: Path,
    journal: AuditWriter,
) -> None:
    """``open`` on a directory SUCCEEDS and ``read`` then fails with ``EISDIR``.

    So the failure arrives after the descriptor exists, which is a different code
    path from "the file is not there" — and an unhandled ``OSError`` here would
    escape a TCB function after a tool had already run.
    """
    directory = workspace / "sub"
    directory.mkdir()

    outcome = run_write(
        environment,
        cache_dir,
        workspace,
        journal,
        lambda argv, **_: echo_observation(),
        target=str(directory),
    )
    assert outcome.verification is Verification.UNVERIFIED


def test_a_write_tool_with_no_path_supplied_has_nothing_to_verify(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
) -> None:
    """An OPTIONAL path argument that was not supplied leaves §7.5 step 6 with no
    expected path. ``NOT_APPLICABLE`` says so; ``VERIFIED`` would claim a
    measurement that was never taken (I12)."""
    manifest = write_manifest(
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "additionalProperties": False,
        }
    )
    decision = proceeding(environment, manifest, {}, path_args=["path"])

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        audit=journal,
        argv=["/bin/echo", "hi"],
        probe_fn=fake_receipt,
        runner=lambda argv, **_: echo_observation(),
        result_of=lambda observation: {"stdout": "hi"},
    )
    assert outcome.verification is Verification.NOT_APPLICABLE


def test_a_tool_dispatched_without_a_result_builder_reports_an_empty_result(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
) -> None:
    """§6.1 gives the HANDLER the job of shaping ``result``, so the dispatcher's
    default is nothing at all — and a manifest whose schema requires fields will
    refuse it, which is the correct loud failure for an unwired tool."""
    manifest = make_manifest(output_schema={"type": "object"})
    decision = proceeding(environment, manifest, {"probe": "uname"})

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        audit=journal,
        argv=["/bin/echo", "hi"],
        probe_fn=fake_receipt,
        runner=lambda argv, **_: echo_observation(),
    )
    assert outcome.result.status is ToolResultStatus.OK
    assert outcome.result.result == {}


def test_a_recheck_that_cannot_probe_the_filesystem_BLOCKS(
    environment: DispatchEnvironment,
    cache_dir: str,
    workspace: Path,
    journal: AuditWriter,
) -> None:
    """``RecheckError`` is raised fail-closed by the §7.5 adapter when a path or
    its parent is racing. It must not escape as an untyped error out of a
    function whose whole job is deciding whether to run something."""
    manifest = write_manifest()
    decision = proceeding(
        environment, manifest, {"path": str(workspace / "a.txt")}, path_args=["path"]
    )
    spawned: list[list[str]] = []

    def racing(path: str) -> tuple[int, int, int]:
        raise RecheckError(f"parent stat failed for {path!r}")

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        audit=journal,
        argv=["/bin/echo", "hi"],
        probe_fn=fake_receipt,
        runner=lambda argv, **_: spawned.append(list(argv)),  # type: ignore[arg-type,return-value]
        fs_view=DelegatingFsView(parent_ids=racing),
    )

    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == PATH_INVALIDATED
    assert spawned == []


def test_a_step_5_refusal_becomes_a_BLOCKED_outcome_not_an_exception(
    environment: DispatchEnvironment,
    cache_dir: str,
    workspace: Path,
    journal: AuditWriter,
) -> None:
    """A ``.venv`` that appeared after approval is a fact about the world, so it
    is journallable evidence rather than a stack trace: :func:`run` turns the
    typed refusal into an audited BLOCKED outcome."""
    manifest = write_manifest(
        capabilities={"fs": "write_scoped", "net": "none", "proc": "spawn_argv"}
    )
    # The target lives in a SUBdirectory on purpose: creating `.venv/bin` under
    # the workspace bumps the workspace's own ctime, and with the three-field
    # approval identity the step-3 recheck would (correctly, per I6) refuse a
    # target whose PARENT is the workspace before step 5 ever runs. Isolating
    # the target's parent keeps this test pinned on the step-5 refusal.
    sub = workspace / "d"
    sub.mkdir()
    (sub / "a.txt").write_text("x\n", encoding="utf-8")
    decision = proceeding(
        environment, manifest, {"path": str(sub / "a.txt")}, path_args=["path"]
    )
    (workspace / ".venv" / "bin").mkdir(parents=True)
    spawned: list[list[str]] = []

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        audit=journal,
        argv=["/bin/echo", "hi"],
        probe_fn=fake_receipt,
        runner=lambda argv, **_: spawned.append(list(argv)),  # type: ignore[arg-type,return-value]
    )

    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == ENV_REBOUND
    assert spawned == []


# ==========================================================================
# J. regressions for the adversarial round — one test per defect it found
# ==========================================================================
def test_a_child_that_closes_both_pipes_still_hits_the_wall_clock() -> None:
    """The deadline must outlive the READ LOOP.

    A child can reach EOF on stdout and stderr while still running, simply by
    closing its own copies — and then the selector loop ends, the in-loop
    deadline check never fires again, and ``wait()`` blocks for as long as the
    tool likes. MEASURED on the first draft: ``timeout_s=1`` returned after
    **20.00 s** with ``timed_out=False``. ``prlimit --cpu`` cannot cover it
    either, because a sleeping process burns no CPU — this is the only wall
    clock the tool has, and it was defeated by a one-line shell redirection.

    This is the T4.02 failure shape: it did not go red, it HUNG.
    """
    started = time.monotonic()
    observation = spawn_capped(
        ["/bin/sh", "-c", "exec 1>&- 2>&-; sleep 30"],
        timeout_s=1,
        stdout_cap=1024,
        stderr_cap=1024,
    )
    elapsed = time.monotonic() - started

    assert elapsed < 10, f"the wall-clock timeout did not fire: returned after {elapsed:.2f}s"
    assert observation.timed_out is True
    assert observation.exit_code == 137


def test_a_tool_argv_containing_setenv_is_not_read_as_environment(
    environment: DispatchEnvironment, cache_dir: str, journal: AuditWriter
) -> None:
    """§6.3 step 2 freezes the model's argv VERBATIM — it does not sanitize it.

    Everything after the single ``--`` is the ``prlimit`` fragment plus that
    argv, in the same list. Scanning the whole list read the tool's own arguments
    as env syntax: ``["/bin/echo", "--setenv"]`` ran ``composed[index + 2]`` off
    the end and raised a bare ``IndexError`` — not ``SandboxUnavailable``, not
    ``ExecRefused``, so it escaped :func:`run` entirely and the refusal was never
    journalled. Two tokens further along, the same parse produced a FALSE
    ``ENV_REBOUND`` for an approved, benign call.
    """
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})

    for hostile in (["/bin/echo", "--setenv"], ["/bin/echo", "--setenv", "PATH", "/evil"]):
        argv = build_exec_argv(
            normalized=decision.normalized,
            manifest=manifest,
            environment=environment,
            available=fake_receipt(),
            cache_dir=cache_dir,
            argv=hostile,
        )
        assert argv[-len(hostile) :] == hostile, "the tool argv was not passed through verbatim"


def test_a_parent_swapped_DURING_verification_is_UNVERIFIED_and_still_journalled(
    environment: DispatchEnvironment, cache_dir: str, workspace: Path, journal: AuditWriter
) -> None:
    """The §7.5 adapter raises ``RecheckError`` fail-closed on a racing parent.

    Only the PRE-exec ``recheck`` had a handler. Post-exec the same exception
    escaped :func:`run` — after the tool had already run, and before step 9 — so
    a completed action left no §14.1 record at all. I12 says DOWNGRADE, not
    disappear.
    """
    manifest = write_manifest()
    decision = proceeding(
        environment, manifest, {"path": str(workspace / "a.txt")}, path_args=["path"]
    )
    ran = {"yet": False}

    def racing_after_exec(path: str) -> tuple[int, int, int]:
        if ran["yet"]:
            raise RecheckError(f"parent stat failed for {path!r}")
        return OsFsView().parent_ids(path)

    def runner(argv: list[str], **_: Any) -> ExecObservation:
        ran["yet"] = True
        return echo_observation()

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        argv=["/bin/echo", "hi"],
        audit=journal,
        probe_fn=fake_receipt,
        runner=runner,
        result_of=lambda observation: {"stdout": "hi"},
        fs_view=DelegatingFsView(parent_ids=racing_after_exec),
    )

    assert outcome.verification is Verification.UNVERIFIED
    assert outcome.audit_seq is not None, "an executed action went unrecorded"


def test_a_spawn_that_never_produced_a_child_is_a_journalled_BLOCK(
    environment: DispatchEnvironment,
    cache_dir: str,
    journal: AuditWriter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """§8.3 names this case: "bwrap spawn failure → ``sandbox_unavailable`` →
    BLOCKED".

    ``Popen`` raising means NO child exists, so it is a refusal like every other
    one — but the runner reports it as a ``DispatchError``, which no ``except`` in
    :func:`run` caught, so it escaped past step 9 unrecorded. The trigger is not
    exotic: ``fork`` returns ``EAGAIN`` under ``RLIMIT_NPROC`` pressure, the very
    limit HARDEN-03 watched break the exec path on this host.
    """
    manifest = make_manifest()
    decision = proceeding(environment, manifest, {"probe": "uname"})
    approved = dict(decision.normalized.env)
    setenv: list[str] = []
    for name, value in approved.items():
        setenv += ["--setenv", name, value]
    monkeypatch.setattr(
        "lsassist.tools.dispatcher.compose_exec_argv",
        lambda **_: [
            "/nonexistent/bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            *setenv,
            "--",
            "/bin/echo",
            "hi",
        ],
    )

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        argv=["/bin/echo", "hi"],
        audit=journal,
        probe_fn=fake_receipt,
    )

    assert outcome.decision is Decision.BLOCKED
    assert outcome.result.error is not None
    assert outcome.result.error.kind == SANDBOX_UNAVAILABLE
    assert outcome.audit_seq is not None, "a refusal nobody recorded is a refusal nobody can review"


def test_a_result_that_cannot_be_serialized_is_a_journalled_error(
    environment: DispatchEnvironment, cache_dir: str, journal: AuditWriter
) -> None:
    """``output_schema`` does NOT catch this on its own.

    MEASURED: jsonschema validates only the properties a schema constrains, so
    ``{"stdout": {1, 2}}`` passes a schema declaring ``stdout`` — and then
    ``json.dumps`` raises ``TypeError`` inside ``cap_result``, after the tool has
    run and before the §14.1 record is written.
    """
    manifest = make_manifest(
        output_schema={
            "type": "object",
            "properties": {"stdout": {}},
            "additionalProperties": False,
        }
    )
    decision = proceeding(environment, manifest, {"probe": "uname"})

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        argv=["/bin/echo", "hi"],
        audit=journal,
        probe_fn=fake_receipt,
        runner=lambda argv, **_: echo_observation(),
        result_of=lambda observation: {"stdout": {1, 2}},
    )

    assert outcome.result.status is ToolResultStatus.ERROR
    assert outcome.result.error is not None
    assert outcome.result.error.kind == MALFORMED_TOOL_RESULT
    assert outcome.audit_seq is not None


def test_the_serialization_failure_message_names_the_type_and_nothing_else(
    environment: DispatchEnvironment, cache_dir: str, journal: AuditWriter
) -> None:
    """``message_redacted`` is a field whose name promises redaction (I8).

    A serializer's own message can quote the offending value, and the value here
    is tool output — the same rule the §14.3 redactor follows when its own
    substitution fails: record the exception TYPE, never its text.
    """
    manifest = make_manifest(
        output_schema={
            "type": "object",
            "properties": {"stdout": {}},
            "additionalProperties": False,
        }
    )
    decision = proceeding(environment, manifest, {"probe": "uname"})

    outcome = run(
        decision,
        manifest=manifest,
        environment=environment,
        cache_dir=cache_dir,
        task_id="t-1",
        argv=["/bin/echo", "hi"],
        audit=journal,
        probe_fn=fake_receipt,
        runner=lambda argv, **_: echo_observation(),
        result_of=lambda observation: {"stdout": {"SUPER-SECRET-VALUE"}},
    )

    assert outcome.result.error is not None
    assert "SUPER-SECRET-VALUE" not in outcome.result.error.message_redacted
    assert "TypeError" in outcome.result.error.message_redacted


def test_the_upper_exit_code_bound_admits_255_exactly() -> None:
    """``255`` is an ORDINARY exit code any tool can return, so the bound has to
    admit it exactly; ``>=`` there would reject a legitimate status.

    The signal-side bound is defensive only, and this pins it as such: Linux tops
    out near ``SIGRTMAX`` (~64), so ``wait()`` cannot produce a signal above 127
    and the guard exists to keep the arithmetic total, not to catch a real case.
    """
    assert normalize_exit_code(255) == 255
    with pytest.raises(ResultError):
        normalize_exit_code(256)
    assert normalize_exit_code(-127) == 255
    with pytest.raises(ResultError):
        normalize_exit_code(-128)
