"""Pure bwrap argv builder for the §8.1 ``ro`` and §8.2 ``ws`` profiles (ADR-002).

:func:`build_argv` turns already-decided inputs into the exact ``bwrap`` command
line of SPEC §8.1/§8.2. It is the mechanical half of exec isolation (I11: the
word "sandbox" means precisely this argv — mount/pid/ipc/uts/net namespaces,
``--new-session`` for TIOCSTI defense, ``--die-with-parent``).

**NOT A DECIDER.** The §2.2 dependency table gives ``sandbox/`` exactly one
permitted import — ``contracts`` — and forbids policy decisions: it "only builds
the profile". The :class:`~lsassist.contracts.sandbox_profile.Profile` is a
REQUIRED PARAMETER, never inferred: this module imports nothing from
``policy``/``kernel``, has no rules table, no default profile, and no branch
that could pick a laxer one. An unknown/absent profile raises rather than
falling back (fail-closed). Path AUTHORIZATION (may this caller reach this
workspace?) belongs to the policy layer and is deliberately not attempted here.
The structural refusals below (:data:`_FORBIDDEN_WORKSPACE_ROOTS`, the masking
checks) are not authorization: they reject mount SHAPES that cannot mean what
the profile claims — ``--bind / /`` is not a sandbox, whoever asked for it.

**PURE (§2.2).** No filesystem, no environment, no child processes. §8.2's
"``PATH`` may contain ``<workspace>/.venv/bin`` (exists-check)" arrives as the
``venv_exists`` BOOLEAN parameter; the actual check is the T2.06 runner's job,
which keeps this module deterministic and unit-testable without ``tmp_path``.

**SCOPE.** §8.1 shows a ``prlimit …`` prefix; that wrapper is T2.06. The argv
returned here starts at ``bwrap_path`` (the §8.1 bare ``"bwrap"`` by default,
an absolute validated path on the real exec path — a bare name is re-resolved
against ``PATH`` at spawn time, and an early writable ``PATH`` entry is a shim
that would run the tool with no namespaces at all) and ends with
``--chdir <cwd> -- <argv…>``.

**NAMED RESIDUAL — under ``ws`` with ``venv_exists=True``, workspace content
outranks system tools BY DESIGN (§8.2).** ``<workspace>/.venv/bin`` is PREPENDED
ahead of ``/usr/bin``, and under ``ws`` the workspace is BOTH writable and
untrusted, so a planted ``.venv/bin/python`` hijacks an approved ``python``
(verified inside a real bwrap child). Appending instead would defeat the point
of §8.2 — a project venv MUST win for build/test tooling — so the order is
deliberately NOT changed here. Two things bound and must close it: the blast
radius is the sandbox itself (network off, writes confined to the workspace,
no host view), and approval binds a NAME (§7.4), which is the gap — the T3.x
approval renderer/dispatcher owns surfacing WHICH binary will actually run, or
requiring an absolute ``argv[0]``, so the user is not approving ``python`` while
``<workspace>/.venv/bin/python`` executes. Flagged for the tools phase.

**DEVIATION from the §8.1 template (line 586): ``--clearenv`` + scratch
``--setenv``, never ``--unsetenv``.** bwrap does NOT clear the environment by
default — the child INHERITS the parent's environ, and ``--setenv`` merely
adds/overrides on top of it. Verified empirically on bwrap 0.9.0: this argv
WITHOUT ``--clearenv`` handed the sandboxed child 81 inherited variables,
including ``LSASSIST_KIMI_API_KEY``, ``SSH_AUTH_SOCK``, ``XAUTHORITY`` and
``DBUS_SESSION_BUS_ADDRESS``. §8.3's "env constructed from scratch, not
inherited" is therefore a property of the ARGV (I11), not of a dict the builder
returns — so ``--clearenv`` is emitted immediately after ``--new-session``,
BEFORE the ``--setenv`` block: bwrap applies these ops in order, and a
``--clearenv`` placed afterwards wipes the projected variables too (verified:
child env is exactly ``{HOME, LANG, PATH, PWD}`` with the flag in the position
used here, and only ``{PWD}`` with it at the end).

The template's ``--unsetenv LSASSIST_KIMI_API_KEY`` is still NOT emitted, on two
counts. It is insufficient: it removes exactly one name out of the ~80 the child
would otherwise inherit — leaving ``SSH_AUTH_SOCK`` (a live agent-forwarding
capability), ``XAUTHORITY``, and the rest. And it is harmful: it writes the
SECRET'S NAME into the child's argv, landing in world-readable
``/proc/<pid>/cmdline``, in ``ps`` output for every local user, and in
audit/journal records — telling an observer exactly which variable to fish for.
``--clearenv`` + explicit ``--setenv`` is the strictly stronger guarantee and
names no secret; both halves are asserted by the T2.05 canary tests (I8).

**RUNNER OBLIGATIONS (T2.06), not satisfiable here.** ``--clearenv`` is
defense-in-depth, not a substitute for a clean spawn: the runner MUST start the
child with an explicitly emptied environment — spawn with ``env={}``, since
``env=None`` or a copy of the parent environ hands the whole thing to bwrap
itself — and MUST exec this argv LIST directly, never through a shell string
(§7.6 rule 8: argv exec, no shell). The runner also owns the ``prlimit`` wrapper
and every filesystem check — including whether the §8.1 system binds exist
(``/lib64`` is absent on some distributions); whether to degrade a missing bind
is a decision made against a real filesystem, which this builder never consults.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence

from lsassist.contracts.sandbox_profile import Profile
from lsassist.sandbox.env import DEFAULT_PATH, project_env

__all__ = [
    "SYSTEM_RO_BINDS",
    "SandboxProfileError",
    "build_argv",
]

#: §8.1 read-only system binds, in template order. bwrap applies mount
#: operations SEQUENTIALLY, so this order is semantic, not cosmetic.
SYSTEM_RO_BINDS: tuple[str, ...] = (
    "/usr",
    "/bin",
    "/lib",
    "/lib64",
    "/etc/ld.so.cache",
    "/etc/alternatives",
)

# Mount shapes that cannot express "a workspace": binding any of these hands the
# child the host's own tree (``--bind / /`` under `ws` = the entire system, RW,
# inside something we would then be calling a sandbox — an I11 lie). This is the
# LAST gate before the OS boundary; nothing downstream re-checks the shape.
_FORBIDDEN_WORKSPACE_ROOTS: frozenset[str] = frozenset(
    {
        "/",
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
        "/etc",
        "/home",
        "/root",
        "/var",
        "/tmp",
        "/proc",
        "/dev",
        "/sys",
        "/boot",
    }
)


class SandboxProfileError(ValueError):
    """Profile/paths/argv rejected — the caller gets no argv at all (fail-closed).

    §8.3 failure behavior: an exec that cannot be built correctly must be
    BLOCKED, never degraded into a weaker (or unsandboxed) invocation.
    """


def _is_within(inner: str, outer: str) -> bool:
    """True when ``inner`` IS ``outer`` or lies beneath it (segment-aware, pure).

    Segment-aware, so ``/ws-evil`` is not "within" ``/ws``. Both arguments are
    already-normalized absolute paths (see :func:`_checked_path`).
    """
    return inner == outer or inner.startswith(outer.rstrip("/") + "/")


def _checked_path(name: str, value: object) -> str:
    """Return ``value`` if it is a safely-spelled absolute path, else raise.

    Spelling rules, all PURE string tests (no filesystem, no symlink
    resolution):

    - absolute, non-empty, NUL-free;
    - already normalized (``normpath(v) == v``), so the emitted bind source and
      destination are byte-identical to what policy canonicalized (§7.5): a
      trailing slash or an embedded ``..`` would let the string policy approved
      and the string bwrap mounts drift apart;
    - no leading ``//``. POSIX preserves an exactly-double leading slash through
      ``normpath`` (``//srv/data`` survives unchanged), but ``policy.canonical``
      resolves symlinks (real-path semantics) and can only ever emit
      ``/srv/data`` — accepting both would mean two spellings for one directory,
      and every downstream string compare (approved-target re-check, audit
      evidence) would diverge;
    - no ``:``. ``PATH`` is colon-delimited, so a colon in ``workspace`` splits
      the §8.2 ``<workspace>/.venv/bin`` entry in half: the intended entry
      vanishes, an unintended absolute directory is prepended ahead of
      ``/usr/bin``, and the tail becomes a RELATIVE entry resolved against
      ``--chdir <cwd>`` — i.e. inside the untrusted (under ``ws``, WRITABLE)
      workspace, letting workspace content shadow system tools.
    """
    if not isinstance(value, str) or not value:
        raise SandboxProfileError(f"{name} must be a non-empty absolute path, got {value!r}")
    if "\x00" in value:
        raise SandboxProfileError(f"{name} contains NUL: {value!r}")
    if not os.path.isabs(value):
        raise SandboxProfileError(f"{name} must be absolute, got {value!r}")
    if os.path.normpath(value) != value:
        raise SandboxProfileError(
            f"{name} must be normalized (no trailing slash, no '.'/'..'), got {value!r}"
        )
    if value.startswith("//"):
        raise SandboxProfileError(
            f"{name} must not start with '//' (not a canonical spelling), got {value!r}"
        )
    if ":" in value:
        raise SandboxProfileError(f"{name} must not contain ':' (PATH separator), got {value!r}")
    return value


def _checked_argv(argv: object) -> list[str]:
    """Return the tool argv as a fresh list, or raise :class:`SandboxProfileError`."""
    if isinstance(argv, str) or not isinstance(argv, Sequence):
        raise SandboxProfileError(f"argv must be a sequence of str, got {type(argv).__name__}")
    items = list(argv)
    if not items:
        raise SandboxProfileError("argv must not be empty")
    for i, item in enumerate(items):
        if not isinstance(item, str):
            raise SandboxProfileError(f"argv[{i}] must be str, got {type(item).__name__}")
        if "\x00" in item:
            raise SandboxProfileError(f"argv[{i}] contains NUL")
    if not items[0]:
        raise SandboxProfileError("argv[0] (the program) must not be empty")
    return items


def _check_mount_shape(workspace: str, cache_dir: str) -> None:
    """Reject mount layouts that cannot mean what the profile claims (§8.1/§8.2).

    STRUCTURAL, not authorization: each case makes the resulting argv a
    misdescription of itself — a host-wide bind that is no longer isolation, or
    a tmpfs that silently swallows the very tree the profile promised to expose.
    """
    if workspace in _FORBIDDEN_WORKSPACE_ROOTS:
        raise SandboxProfileError(
            f"workspace {workspace!r} is a system root; binding it is not a sandbox"
        )
    if _is_within(workspace, "/tmp"):
        # `--tmpfs /tmp` mounts over it: under `ro` the tool sees an empty
        # directory, and under `ws` its writes land in a discarded tmpfs while
        # the run reports success. Fail closed rather than report a phantom write.
        raise SandboxProfileError(
            f"workspace {workspace!r} is under /tmp, which this profile masks with a tmpfs"
        )
    if cache_dir == "/":
        raise SandboxProfileError("cache_dir must not be '/' (a tmpfs over the whole tree)")
    for system_path in SYSTEM_RO_BINDS:
        if _is_within(system_path, cache_dir):
            raise SandboxProfileError(
                f"cache_dir {cache_dir!r} would mask the system bind {system_path!r}"
            )
    if _is_within(workspace, cache_dir):
        raise SandboxProfileError(
            f"cache_dir {cache_dir!r} contains (or equals) workspace {workspace!r}; "
            "the cache tmpfs would mask the workspace bind"
        )


def build_argv(
    *,
    profile: Profile,
    workspace: str,
    cwd: str,
    cache_dir: str,
    argv: Sequence[str],
    venv_exists: bool = False,
    lc_all: str | None = None,
    term: str | None = None,
    env_extra: Mapping[str, str] | None = None,
    bwrap_path: str = "bwrap",
) -> list[str]:
    """Build the §8.1/§8.2 ``bwrap`` argv for ``profile``.

    :param profile: §8 profile to materialize. REQUIRED and never inferred —
        the caller (policy/kernel) decides; this builder only renders.
    :param workspace: absolute, normalized workspace root; bound read-only for
        ``ro`` (§8.1) and read-write for ``ws`` (§8.2).
    :param cwd: absolute, normalized ``--chdir`` target inside the sandbox.
    :param cache_dir: absolute, normalized cache subdirectory to shadow with a
        tmpfs (§8.1 ``--tmpfs <XDG_CACHE_HOME-subdir>``).
    :param argv: the tool command line placed after ``--`` (argv exec, no shell
        — §7.6 rule 8).
    :param venv_exists: caller-supplied result of the §8.2 exists-check, i.e.
        "``<workspace>/.venv/bin`` is present". Valid for ``ws`` ONLY: §8.2
        scopes that ``PATH`` entry to build/test tooling, so the read-only
        observation profile must not gain extra executable search paths — asking
        for it under ``ro`` is a caller bug and RAISES rather than being dropped.
    :param lc_all: optional ``LC_ALL`` for the child (§8.3 allowlist).
    :param term: optional ``TERM`` for the child (§8.3 allowlist).
    :param env_extra: §8.3 tool-specific env additions (e.g. ``{"CI": "1"}``),
        validated by :func:`lsassist.sandbox.env.project_env`.
    :param bwrap_path: program placed at ``argv[0]``. Defaults to the §8.1 bare
        name (T2.05 behaviour); the exec path passes the absolute path that
        :func:`~lsassist.sandbox.availability.probe` located and validated, so
        the binary that was attested is the binary that runs. Rendered verbatim
        — no lookup, no filesystem check (§2.2 purity).
    :returns: a fresh ``list[str]`` starting with ``bwrap_path``. Deterministic:
        identical inputs always yield an identical argv (env keys are sorted).
    :raises SandboxProfileError: unknown/absent profile, a structurally invalid
        path/argv, or a mount shape that contradicts the profile.
    :raises ~lsassist.sandbox.env.EnvProjectionError: a rejected env addition.
    """
    workspace = _checked_path("workspace", workspace)
    cwd = _checked_path("cwd", cwd)
    cache_dir = _checked_path("cache_dir", cache_dir)
    tool_argv = _checked_argv(argv)
    _check_mount_shape(workspace, cache_dir)
    if not isinstance(bwrap_path, str) or not bwrap_path or "\x00" in bwrap_path:
        raise SandboxProfileError(
            f"bwrap_path must be a non-empty NUL-free str, got {bwrap_path!r}"
        )

    # THE profile gate: one exhaustive, fail-closed dispatch. Anything that is
    # not a rendered V1 member — a bare "ro" string, ``None``, or a profile
    # added to the contract enum later (a future `ws-net`) — lands in `else` and
    # RAISES, instead of inheriting whichever branch happens to come first. This
    # is rendering, not deciding: the profile arrived as a parameter.
    if profile is Profile.RO:
        if venv_exists:
            raise SandboxProfileError(
                "venv_exists is meaningless for `ro` (§8.2 scopes .venv/bin to `ws`)"
            )
        workspace_bind = "--ro-bind"
        path = DEFAULT_PATH
    elif profile is Profile.WS:
        workspace_bind = "--bind"
        venv_bin = os.path.join(workspace, ".venv", "bin")
        path = f"{venv_bin}:{DEFAULT_PATH}" if venv_exists else DEFAULT_PATH
    else:
        raise SandboxProfileError(
            "profile must be a contracts Profile member with a V1 argv template "
            f"(ro|ws), got {profile!r}"
        )

    env = project_env(path=path, lc_all=lc_all, term=term, extra=env_extra)

    out: list[str] = [
        bwrap_path,
        # §8.3 boundary: mount/pid/ipc/uts/net namespaces (net OFF — there is no
        # --share-net in either V1 profile), TIOCSTI defense, orphan prevention.
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        # MUST precede the --setenv block: bwrap inherits the parent environ by
        # default and applies these ops in order, so this is the flag that makes
        # §8.3's "constructed from scratch, not inherited" true of the CHILD.
        "--clearenv",
    ]
    for system_path in SYSTEM_RO_BINDS:
        out += ["--ro-bind", system_path, system_path]
    out += ["--proc", "/proc", "--dev", "/dev"]
    out += [workspace_bind, workspace, workspace]
    out += ["--tmpfs", "/tmp", "--tmpfs", cache_dir]
    for name, value in env.items():
        out += ["--setenv", name, value]
    out += ["--chdir", cwd, "--", *tool_argv]
    return out
