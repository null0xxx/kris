"""sandbox/ — pure bwrap profile builder (SPEC §8, ADR-002).

PURE (§2.2): this package imports only ``contracts`` plus stdlib and performs NO
I/O — no filesystem, no environment reads, no child processes. It BUILDS the
§8.1/§8.2 argv and the §8.3 child environment; it never DECIDES which profile
applies (that is policy/kernel's call, passed in as a parameter) and never
spawns anything (T2.06 runner). Public surface:

- :func:`build_argv` — ``(Profile, workspace, cwd, cache_dir, argv, …)`` → the
  exact ``bwrap`` command line, fail-closed on unknown profiles.
- :func:`project_env` — the §8.3 child env, constructed from scratch out of the
  allowlist; credential-shaped names are refused (I8).
- :class:`SandboxProfileError` / :class:`EnvProjectionError` — typed, fail-closed
  rejections (§8.3: a broken sandbox blocks the exec, it never degrades it).
"""

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
from lsassist.sandbox.profiles import (
    SYSTEM_RO_BINDS,
    SandboxProfileError,
    build_argv,
)

__all__ = [
    "DEFAULT_HOME",
    "DEFAULT_LANG",
    "DEFAULT_PATH",
    "ENV_ALLOWLIST",
    "SECRET_KEY_MARKERS",
    "SYSTEM_RO_BINDS",
    "TOOL_ENV_ALLOWLIST",
    "EnvProjectionError",
    "SandboxProfileError",
    "build_argv",
    "project_env",
]
