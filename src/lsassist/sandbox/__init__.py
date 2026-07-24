"""sandbox/ — bwrap profile builder + resource caps + availability probe (§8, ADR-002).

Three of the four modules are PURE (§2.2): stdlib + ``contracts`` only, no
filesystem, no environment, no child processes. They BUILD the §8.1/§8.2 argv,
the §8.1 ``prlimit`` caps and the §8.3 child environment; they never DECIDE
which profile applies (policy/kernel's call, passed in as a parameter).

The single exception is :mod:`~lsassist.sandbox.availability`, which performs
the one I/O this package needs — the ``bwrap --version`` check — and is where
the §8.3 failure contract is made STRUCTURAL: a complete exec argv can only be
built by :func:`compose_exec_argv`, which requires a :class:`SandboxAvailable`
token that only a successful :func:`probe` can issue. There is no route to a
runnable, unsandboxed command line. Public surface:

- :func:`compose_exec_argv` — the ONLY complete exec argv: ``prlimit`` caps +
  ``bwrap`` profile + the tool argv, gated on a probe receipt and emitting the
  pinned absolute program paths.
- :func:`probe` / :class:`SandboxAvailable` / :class:`SandboxUnavailable` — the
  §8.3 availability gate and its ``sandbox_unavailable`` reason code.
- :func:`build_argv` — ``(Profile, workspace, cwd, cache_dir, argv, …)`` → the
  exact ``bwrap`` command line, fail-closed on unknown profiles.

``prlimit_prefix`` is deliberately NOT re-exported: on its own it renders a
``prlimit …`` command line with no ``bwrap`` in it, and a package-level export
of an argv fragment that runs a tool UNSANDBOXED is a footgun aimed at exactly
the §8.3 boundary. It stays importable from
:mod:`lsassist.sandbox.prlimit` for its own tests, while
:func:`compose_exec_argv` is the only argv producer on the public surface.
- :func:`project_env` — the §8.3 child env, constructed from scratch out of the
  allowlist; credential-shaped names are refused (I8).
- The typed rejections (:class:`SandboxProfileError`, :class:`EnvProjectionError`,
  :class:`PrlimitError`, :class:`SandboxUnavailable`) — every one of them leaves
  the caller with NO argv (§8.3: a broken sandbox blocks the exec).
"""

from lsassist.sandbox.availability import (
    BWRAP,
    MIN_BWRAP_VERSION,
    PRLIMIT,
    SANDBOX_UNAVAILABLE_REASON,
    ProbeResult,
    SandboxAvailable,
    SandboxUnavailable,
    compose_exec_argv,
    probe,
)
from lsassist.sandbox.env import (
    DEFAULT_HOME,
    DEFAULT_LANG,
    DEFAULT_PATH,
    ENV_ALLOWLIST,
    SECRET_KEY_MARKERS,
    TOOL_ENV_ALLOWLIST,
    EnvProjectionError,
    project_env,
)
from lsassist.sandbox.prlimit import (
    AS_LIMIT_BYTES,
    CPU_GRACE_S,
    MAX_TIMEOUT_S,
    NOFILE_LIMIT,
    NPROC_LIMIT,
    PrlimitError,
)
from lsassist.sandbox.profiles import (
    SYSTEM_RO_BINDS,
    SandboxProfileError,
    build_argv,
)

__all__ = [
    "AS_LIMIT_BYTES",
    "BWRAP",
    "CPU_GRACE_S",
    "DEFAULT_HOME",
    "DEFAULT_LANG",
    "DEFAULT_PATH",
    "ENV_ALLOWLIST",
    "MAX_TIMEOUT_S",
    "MIN_BWRAP_VERSION",
    "NOFILE_LIMIT",
    "NPROC_LIMIT",
    "PRLIMIT",
    "SANDBOX_UNAVAILABLE_REASON",
    "SECRET_KEY_MARKERS",
    "SYSTEM_RO_BINDS",
    "TOOL_ENV_ALLOWLIST",
    "EnvProjectionError",
    "PrlimitError",
    "ProbeResult",
    "SandboxAvailable",
    "SandboxProfileError",
    "SandboxUnavailable",
    "build_argv",
    "compose_exec_argv",
    "probe",
    "project_env",
]
