"""HARDEN-03 END-TO-END: the composed argv really runs, and the caps really land.

This is the test the T2.06 unit suite could not be: every assertion there is
about the SHAPE of a list of strings, and the outage this file exists to prevent
was invisible at that level. The §8.1 template applies the ``prlimit`` caps to
the OUTER process (``prlimit … bwrap … -- tool``); composed that way the argv is
structurally perfect and dies on a normal desktop session, because
``RLIMIT_NPROC`` is charged per REAL UID and counts TASKS — with ~1.5k threads
already running for uid 1000, ``--nproc=256`` makes ``bwrap``'s own
``clone(CLONE_NEWUSER)`` fail::

    $ prlimit --nproc=256 bwrap --unshare-all … -- /bin/true
    bwrap: Creating new namespace failed: Resource temporarily unavailable

HARDEN-03 (human-approved) moved the whole prefix INSIDE the sandbox, where the
child namespace starts its own task count near zero and all four caps apply to
the tool. The tests below SPAWN the real thing and read the limits back out of
the sandbox, so the same regression cannot land silently again.

**Costs one bwrap spawn per assertion** (measured at ~5 ms each on this host) and
skips entirely when no ``bwrap`` is installed, so it stays cheap enough for the
default run.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from lsassist.contracts.sandbox_profile import Profile
from lsassist.sandbox import SandboxUnavailable, compose_exec_argv, probe

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Wall budget handed to the composer; drives ``--cpu = timeout + 10``.
TIMEOUT_S = 30

#: A §8.1-shaped cache subdirectory. It need NOT exist on the host: bwrap
#: creates the mount point inside its own namespace, and nothing is written to
#: the real filesystem by these tests.
CACHE_DIR = str(Path.home() / ".cache" / "lsassist" / "sandbox-e2e")

requires_bwrap = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bwrap is not installed on this host"
)


def sandbox_argv(inner: list[str]) -> list[str]:
    """Compose a real exec argv for ``inner``, or skip if this host has no sandbox.

    The workspace is the repository itself under the read-only ``ro`` profile:
    a real, non-``/tmp`` directory (``/tmp`` is masked by the profile's own
    tmpfs, and :func:`~lsassist.sandbox.profiles.build_argv` refuses a workspace
    under it), and nothing in these tests writes to it.
    """
    try:
        available = probe()
    except SandboxUnavailable as exc:  # pragma: no cover - host-dependent
        pytest.skip(f"no usable sandbox on this host: {exc}")
    if str(REPO_ROOT) == "/tmp" or str(REPO_ROOT).startswith("/tmp/"):  # pragma: no cover
        pytest.skip("repository is under /tmp, which the profile masks with a tmpfs")
    return compose_exec_argv(
        available=available,
        profile=Profile.RO,
        workspace=str(REPO_ROOT),
        cwd=str(REPO_ROOT),
        cache_dir=CACHE_DIR,
        argv=inner,
        timeout_s=TIMEOUT_S,
    )


def run_sandboxed(inner: list[str]) -> subprocess.CompletedProcess[str]:
    """Spawn the composed argv the way the T3.03 runner must: a LIST, ``env={}``.

    ``env={}`` is not cosmetic — ``env=None`` would hand the whole parent
    environment to bwrap itself (``--clearenv`` protects the CHILD, not bwrap).
    """
    # A fixed argv LIST, never a shell string (§7.6 rule 8).
    return subprocess.run(
        sandbox_argv(inner),
        env={},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@requires_bwrap
def test_the_composed_argv_runs_and_the_caps_are_visible_inside() -> None:
    """rc == 0 AND the §8.1 limits are the ones the tool actually sees.

    ``ulimit -v`` is reported in KB, so 4 GiB reads as 4194304; ``ulimit -t`` is
    the ``timeout + 10`` CPU budget. A run that merely exits 0 would not prove
    the caps survived the move inside, and caps that are set on a process that
    never starts prove nothing at all — this asserts both halves.
    """
    completed = run_sandboxed(["/bin/sh", "-c", "ulimit -n; ulimit -v; ulimit -t"])

    assert completed.returncode == 0, f"sandboxed exec failed: {completed.stderr!r}"
    assert completed.stdout.split() == ["1024", "4194304", str(TIMEOUT_S + 10)]


@requires_bwrap
def test_the_inner_prlimit_stays_transparent_to_the_exit_status() -> None:
    """util-linux ``prlimit`` ``execve``s — it does not fork.

    So the exit status the runner observes is the TOOL's, not a wrapper's:
    inserting the caps inside the sandbox does not perturb §6.3's process-group
    SIGKILL semantics or §8.3's exit-status evidence. ``137`` is bwrap's own
    ``128 + SIGKILL`` rendering of a killed child, measured identical with and
    without the inner prefix.
    """
    assert run_sandboxed(["/bin/sh", "-c", "exit 42"]).returncode == 42
    assert run_sandboxed(["/bin/sh", "-c", "kill -9 $$"]).returncode == 137
