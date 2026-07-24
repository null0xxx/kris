"""T2.05: pure §8.1/§8.2 bwrap argv builder for the ``ro`` / ``ws`` profiles.

Two SNAPSHOT tests pin the complete argv of each profile element-by-element —
content AND order, since bwrap applies mount and env operations sequentially and
a reordered builder is a different sandbox. The remaining tests cover the axes a
snapshot cannot: the single-axis ``ws`` delta, the I8 canaries (``--clearenv``
present and ordered before the ``--setenv`` block; no secret NAME or VALUE
anywhere; no ``--unsetenv``), determinism, and fail-closed rejection of unknown
profiles, unsafe path spellings, and nonsensical mount shapes.

PURE (§2.2): no ``tmp_path``, no filesystem, no environment — every input is a
literal, including ``venv_exists`` (the real check belongs to the T2.06 runner).
"""

from __future__ import annotations

import contextlib
import inspect
from collections.abc import Callable
from typing import Any

import pytest

from lsassist.contracts.sandbox_profile import Profile
from lsassist.sandbox import profiles as profiles_mod
from lsassist.sandbox.env import EnvProjectionError
from lsassist.sandbox.profiles import SandboxProfileError, build_argv

WS = "/home/u/proj"
CWD = "/home/u/proj/src"
CACHE = "/home/u/.cache/lsassist/sandbox"
TOOL = ["python", "-m", "pytest", "-q"]

KIMI_KEY_NAME = "LSASSIST_KIMI_API_KEY"
KIMI_KEY_VALUE = "sk-kimi-DEADBEEFdeadbeef0123456789"


def ro(**kw: Any) -> list[str]:
    """Build a ``ro`` argv with the shared fixture inputs."""
    return build_argv(profile=Profile.RO, workspace=WS, cwd=CWD, cache_dir=CACHE, argv=TOOL, **kw)


def ws(**kw: Any) -> list[str]:
    """Build a ``ws`` argv with the shared fixture inputs."""
    return build_argv(profile=Profile.WS, workspace=WS, cwd=CWD, cache_dir=CACHE, argv=TOOL, **kw)


def pairs(argv: list[str], flag: str) -> list[tuple[str, str]]:
    """Return every ``(src, dst)`` operand pair following ``flag`` in ``argv``."""
    return [(argv[i + 1], argv[i + 2]) for i, a in enumerate(argv) if a == flag]


def setenv_map(argv: list[str]) -> dict[str, str]:
    """Return the ``--setenv`` projection carried by ``argv``."""
    return {argv[i + 1]: argv[i + 2] for i, a in enumerate(argv) if a == "--setenv"}


def setenv_keys(argv: list[str]) -> list[str]:
    """Return the ``--setenv`` names in emission order."""
    return [argv[i + 1] for i, a in enumerate(argv) if a == "--setenv"]


# ---------------------------------------------------------------------------
# SNAPSHOTS — the complete argv, pinning content AND order (bwrap is sequential)
# ---------------------------------------------------------------------------

EXPECTED_RO = [
    "bwrap",
    "--unshare-all",
    "--die-with-parent",
    "--new-session",
    "--clearenv",
    "--ro-bind", "/usr", "/usr",
    "--ro-bind", "/bin", "/bin",
    "--ro-bind", "/lib", "/lib",
    "--ro-bind", "/lib64", "/lib64",
    "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache",
    "--ro-bind", "/etc/alternatives", "/etc/alternatives",
    "--proc", "/proc",
    "--dev", "/dev",
    "--ro-bind", WS, WS,
    "--tmpfs", "/tmp",
    "--tmpfs", CACHE,
    "--setenv", "HOME", "/tmp/lsassist-home",
    "--setenv", "LANG", "C.UTF-8",
    "--setenv", "PATH", "/usr/bin:/bin",
    "--chdir", CWD,
    "--", "python", "-m", "pytest", "-q",
]

EXPECTED_WS_WITH_VENV = [
    "bwrap",
    "--unshare-all",
    "--die-with-parent",
    "--new-session",
    "--clearenv",
    "--ro-bind", "/usr", "/usr",
    "--ro-bind", "/bin", "/bin",
    "--ro-bind", "/lib", "/lib",
    "--ro-bind", "/lib64", "/lib64",
    "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache",
    "--ro-bind", "/etc/alternatives", "/etc/alternatives",
    "--proc", "/proc",
    "--dev", "/dev",
    "--bind", WS, WS,
    "--tmpfs", "/tmp",
    "--tmpfs", CACHE,
    "--setenv", "HOME", "/tmp/lsassist-home",
    "--setenv", "LANG", "C.UTF-8",
    "--setenv", "PATH", f"{WS}/.venv/bin:/usr/bin:/bin",
    "--chdir", CWD,
    "--", "python", "-m", "pytest", "-q",
]


def test_ro_argv_snapshot() -> None:
    assert ro() == EXPECTED_RO


def test_ws_argv_snapshot() -> None:
    assert ws(venv_exists=True) == EXPECTED_WS_WITH_VENV


# ---------------------------------------------------------------------------
# §8.1 — the `ro` profile argv
# ---------------------------------------------------------------------------


def test_ro_starts_with_bwrap_not_prlimit() -> None:
    # The §8.1 `prlimit ...` prefix is the T2.06 runner's wrapper, NOT T2.05.
    argv = ro()
    assert argv[0] == "bwrap"
    assert "prlimit" not in argv


@pytest.mark.parametrize("flag", ["--unshare-all", "--die-with-parent", "--new-session"])
def test_ro_isolation_flags_present(flag: str) -> None:
    assert flag in ro()


@pytest.mark.parametrize(
    "path",
    ["/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache", "/etc/alternatives"],
)
def test_ro_binds_system_paths_readonly(path: str) -> None:
    assert (path, path) in pairs(ro(), "--ro-bind")


def test_ro_proc_and_dev() -> None:
    argv = ro()
    assert argv[argv.index("--proc") + 1] == "/proc"
    assert argv[argv.index("--dev") + 1] == "/dev"


def test_ro_workspace_is_ro_bound() -> None:
    assert (WS, WS) in pairs(ro(), "--ro-bind")
    assert "--bind" not in ro()


def test_ro_tmpfs_tmp_and_cache() -> None:
    argv = ro()
    tmpfs = [argv[i + 1] for i, a in enumerate(argv) if a == "--tmpfs"]
    assert tmpfs == ["/tmp", CACHE]


def test_ro_has_no_network_share() -> None:
    # Net stays off via --unshare-all; there is no ws-net profile in V1 (§8.2).
    argv = ro()
    assert "--share-net" not in argv
    assert not any("share-net" in a for a in argv)


def test_ro_ends_with_chdir_then_double_dash_then_tool_argv() -> None:
    argv = ro()
    assert argv[-len(TOOL) - 3 :] == ["--chdir", CWD, "--", *TOOL]


def test_setenv_block_precedes_chdir() -> None:
    argv = ro()
    last_setenv = max(i for i, a in enumerate(argv) if a == "--setenv")
    assert last_setenv < argv.index("--chdir")


def test_ro_setenv_carries_the_8_1_defaults() -> None:
    env = setenv_map(ro())
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == "/tmp/lsassist-home"
    assert env["LANG"] == "C.UTF-8"


# ---------------------------------------------------------------------------
# S1 — --clearenv: without it bwrap hands the child the parent's environ
# ---------------------------------------------------------------------------

PROFILE_CASES = [(Profile.RO, False), (Profile.WS, False), (Profile.WS, True)]


@pytest.mark.parametrize(("profile", "venv"), PROFILE_CASES)
def test_clearenv_present_in_both_profiles(profile: Profile, venv: bool) -> None:
    argv = build_argv(
        profile=profile, workspace=WS, cwd=CWD, cache_dir=CACHE, argv=TOOL, venv_exists=venv
    )
    assert "--clearenv" in argv


@pytest.mark.parametrize(("profile", "venv"), PROFILE_CASES)
def test_clearenv_sits_after_new_session_and_before_every_setenv(
    profile: Profile, venv: bool
) -> None:
    # Placement is load-bearing: bwrap applies these ops in order, so a
    # --clearenv AFTER the --setenv block would wipe the projection instead of
    # the inherited environment (leaving the child with only PWD).
    argv = build_argv(
        profile=profile, workspace=WS, cwd=CWD, cache_dir=CACHE, argv=TOOL, venv_exists=venv
    )
    clear = argv.index("--clearenv")
    assert argv.index("--new-session") < clear
    assert clear < min(i for i, a in enumerate(argv) if a == "--setenv")


# ---------------------------------------------------------------------------
# §8.2 — `ws` differs from `ro` on exactly one (or two) axes
# ---------------------------------------------------------------------------


def diff_indices(a: list[str], b: list[str]) -> list[tuple[int, str, str]]:
    assert len(a) == len(b), "ws must not add or drop argv elements"
    return [(i, x, y) for i, (x, y) in enumerate(zip(a, b, strict=True)) if x != y]


def test_ws_differs_from_ro_only_by_bind_mode_when_no_venv() -> None:
    argv = ro()
    workspace_bind_index = argv.index("--ro-bind", argv.index("--dev"))
    assert diff_indices(argv, ws(venv_exists=False)) == [
        (workspace_bind_index, "--ro-bind", "--bind")
    ]


def test_ws_differs_from_ro_by_bind_mode_and_path_when_venv_exists() -> None:
    diff = diff_indices(ro(), ws(venv_exists=True))
    assert len(diff) == 2
    assert diff[0][1:] == ("--ro-bind", "--bind")
    assert diff[1][1] == "/usr/bin:/bin"
    assert diff[1][2] == f"{WS}/.venv/bin:/usr/bin:/bin"


def test_ws_workspace_is_rw_bound() -> None:
    argv = ws()
    assert (WS, WS) in pairs(argv, "--bind")
    assert (WS, WS) not in pairs(argv, "--ro-bind")


def test_ws_venv_absent_keeps_plain_path() -> None:
    argv = ws(venv_exists=False)
    assert setenv_map(argv)["PATH"] == "/usr/bin:/bin"
    assert not any(".venv" in a for a in argv)


def test_ws_venv_present_prepends_venv_bin() -> None:
    path = setenv_map(ws(venv_exists=True))["PATH"]
    assert path.split(":")[0] == f"{WS}/.venv/bin"
    assert path == f"{WS}/.venv/bin:/usr/bin:/bin"


def test_ro_refuses_venv_exists_instead_of_dropping_it() -> None:
    # C6: §8.2 scopes .venv/bin to `ws`. Silently discarding the caller's
    # intent is exactly the failure mode env.py refuses to have.
    with pytest.raises(SandboxProfileError, match="venv_exists"):
        ro(venv_exists=True)


def test_ws_accepts_venv_exists() -> None:
    assert ws(venv_exists=True) != ws(venv_exists=False)


# ---------------------------------------------------------------------------
# I8 CANARY — no secret name, no secret value, no --unsetenv
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("profile", "venv"), PROFILE_CASES)
def test_no_secret_name_or_value_anywhere_in_argv(profile: Profile, venv: bool) -> None:
    argv = build_argv(
        profile=profile, workspace=WS, cwd=CWD, cache_dir=CACHE, argv=TOOL, venv_exists=venv
    )
    assert not any(KIMI_KEY_NAME in a for a in argv)
    assert not any(KIMI_KEY_VALUE in a for a in argv)
    for canary in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "SSH_AUTH_SOCK", "API_KEY"):
        assert not any(canary in a for a in argv)


@pytest.mark.parametrize(("profile", "venv"), PROFILE_CASES)
def test_no_unsetenv_is_ever_emitted(profile: Profile, venv: bool) -> None:
    # T2.05 deviation: §8.1 line 586 shows `--unsetenv LSASSIST_KIMI_API_KEY`,
    # but that removes ONE name out of the ~80 a child would otherwise inherit
    # and writes the secret's NAME into /proc/<pid>/cmdline. `--clearenv` plus
    # scratch `--setenv` supersedes it and names no secret.
    argv = build_argv(
        profile=profile, workspace=WS, cwd=CWD, cache_dir=CACHE, argv=TOOL, venv_exists=venv
    )
    assert "--unsetenv" not in argv
    assert not any("unsetenv" in a for a in argv)


def test_secret_shaped_env_extra_is_rejected_not_emitted() -> None:
    with pytest.raises(EnvProjectionError) as exc:
        ro(env_extra={KIMI_KEY_NAME: KIMI_KEY_VALUE})
    assert KIMI_KEY_VALUE not in str(exc.value)


def test_secret_shaped_term_value_is_rejected_not_emitted() -> None:
    # S3: --setenv VALUES land in /proc/<pid>/cmdline too.
    with pytest.raises(EnvProjectionError) as exc:
        ro(lc_all="AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in str(exc.value)


def test_optional_locale_and_term_are_forwarded_to_setenv() -> None:
    env = setenv_map(ro(lc_all="C.UTF-8", term="dumb"))
    assert env["LC_ALL"] == "C.UTF-8"
    assert env["TERM"] == "dumb"


def test_allowed_tool_env_addition_is_emitted() -> None:
    assert setenv_map(ro(env_extra={"CI": "1"}))["CI"] == "1"


# ---------------------------------------------------------------------------
# PURITY / DETERMINISM
# ---------------------------------------------------------------------------


def test_deterministic_for_identical_inputs() -> None:
    assert ro() == ro()
    assert ws(venv_exists=True, env_extra={"CI": "1"}) == ws(
        venv_exists=True, env_extra={"CI": "1"}
    )


def test_setenv_keys_are_sorted() -> None:
    keys = setenv_keys(ro(env_extra={"CI": "1", "NO_COLOR": "1"}))
    assert keys == sorted(keys)


def test_input_argv_is_not_mutated() -> None:
    tool = list(TOOL)
    build_argv(profile=Profile.RO, workspace=WS, cwd=CWD, cache_dir=CACHE, argv=tool)
    assert tool == TOOL


def test_build_argv_never_reads_the_process_environment(
    tripwired_environ: Callable[[], contextlib.AbstractContextManager[None]],
) -> None:
    with tripwired_environ():
        built = (ro(), ws(venv_exists=True))
    assert built[0][0] == "bwrap"
    assert built[1][0] == "bwrap"


def test_module_source_contains_no_io_primitives() -> None:
    src = inspect.getsource(profiles_mod)
    for forbidden in ("subprocess", "os.environ", "getenv", "os.path.exists", "open("):
        assert forbidden not in src, f"{forbidden} in a PURE module"


def test_module_imports_only_contracts_and_stdlib() -> None:
    # §2.2: sandbox/ may not import policy/kernel/providers/cli/tools.
    src = inspect.getsource(profiles_mod)
    for forbidden in (
        "lsassist.policy",
        "lsassist.kernel",
        "lsassist.providers",
        "lsassist.cli",
        "lsassist.tools",
    ):
        assert forbidden not in src


# ---------------------------------------------------------------------------
# FAIL-CLOSED input validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["ws-net", "ro", "", None, 0, object()])
def test_unknown_or_absent_profile_fails_closed(bad: object) -> None:
    with pytest.raises(SandboxProfileError):
        build_argv(
            profile=bad,  # type: ignore[arg-type]
            workspace=WS,
            cwd=CWD,
            cache_dir=CACHE,
            argv=TOOL,
        )


def with_field(field: str, value: str) -> dict[str, Any]:
    """Shared valid kwargs with one path field replaced by ``value``."""
    kwargs: dict[str, Any] = {"workspace": WS, "cwd": CWD, "cache_dir": CACHE}
    kwargs[field] = value
    return kwargs


@pytest.mark.parametrize("field", ["workspace", "cwd", "cache_dir"])
@pytest.mark.parametrize("bad", ["", "rel/path", "/ws/", "/ws/../etc", "/ws/./x", "."])
def test_non_canonical_absolute_paths_rejected(field: str, bad: str) -> None:
    with pytest.raises(SandboxProfileError):
        build_argv(profile=Profile.RO, argv=TOOL, **with_field(field, bad))


@pytest.mark.parametrize("field", ["workspace", "cwd", "cache_dir"])
@pytest.mark.parametrize("bad", ["//srv/data", "//ws"])
def test_double_slash_spelling_rejected(field: str, bad: str) -> None:
    # C2: normpath preserves a leading '//' on POSIX, but policy.canonical
    # (realpath-based) can never emit it - one directory, two spellings.
    with pytest.raises(SandboxProfileError, match="//"):
        build_argv(profile=Profile.RO, argv=TOOL, **with_field(field, bad))


@pytest.mark.parametrize("field", ["workspace", "cwd", "cache_dir"])
@pytest.mark.parametrize("bad", ["/home/u/a:b", "/home/u/proj:", "/a:b/c"])
def test_colon_in_path_rejected(field: str, bad: str) -> None:
    # C1: a colon in `workspace` splits the §8.2 venv PATH entry in two,
    # prepending an unintended absolute dir plus a workspace-RELATIVE one.
    with pytest.raises(SandboxProfileError, match="PATH separator"):
        build_argv(profile=Profile.RO, argv=TOOL, **with_field(field, bad))


def test_colon_workspace_cannot_reach_the_venv_path_computation() -> None:
    # The same input under `ws` + venv is where the corruption would land.
    with pytest.raises(SandboxProfileError, match="PATH separator"):
        build_argv(
            profile=Profile.WS,
            workspace="/home/u/a:b",
            cwd=CWD,
            cache_dir=CACHE,
            argv=TOOL,
            venv_exists=True,
        )


@pytest.mark.parametrize(
    "root",
    ["/", "/usr", "/bin", "/lib", "/lib64", "/etc", "/home", "/root", "/var", "/proc",
     "/dev", "/sys", "/boot"],
)
@pytest.mark.parametrize("profile", [Profile.RO, Profile.WS])
def test_system_root_workspace_rejected(root: str, profile: Profile) -> None:
    # S2/C4: `--bind / /` under `ws` is the entire host, RW, in a "sandbox".
    with pytest.raises(SandboxProfileError, match="system root"):
        build_argv(profile=profile, workspace=root, cwd=CWD, cache_dir=CACHE, argv=TOOL)


@pytest.mark.parametrize("workspace", ["/tmp", "/tmp/scratch", "/tmp/a/b"])
def test_workspace_under_tmp_rejected(workspace: str) -> None:
    # S4: `--tmpfs /tmp` masks it; under `ws` the tool's writes would vanish
    # into the tmpfs while the run reports success.
    with pytest.raises(SandboxProfileError):
        build_argv(profile=Profile.WS, workspace=workspace, cwd=CWD, cache_dir=CACHE, argv=TOOL)


def test_workspace_not_under_tmp_lookalike_is_accepted() -> None:
    # Segment-aware: /tmpfoo is NOT under /tmp.
    argv = build_argv(
        profile=Profile.WS, workspace="/tmpfoo", cwd="/tmpfoo", cache_dir=CACHE, argv=TOOL
    )
    assert ("/tmpfoo", "/tmpfoo") in pairs(argv, "--bind")


@pytest.mark.parametrize("cache_dir", ["/", "/usr", "/etc", "/home/u"])
def test_cache_dir_masking_a_system_bind_or_the_workspace_rejected(cache_dir: str) -> None:
    # S4/C4: the cache tmpfs would mount over /usr, /etc/ld.so.cache, or the
    # workspace bind itself.
    with pytest.raises(SandboxProfileError):
        build_argv(profile=Profile.RO, workspace=WS, cwd=CWD, cache_dir=cache_dir, argv=TOOL)


def test_cache_dir_equal_to_workspace_rejected() -> None:
    with pytest.raises(SandboxProfileError, match="mask the workspace"):
        build_argv(profile=Profile.WS, workspace=WS, cwd=CWD, cache_dir=WS, argv=TOOL)


def test_cache_dir_sibling_lookalike_is_accepted() -> None:
    # Segment-aware: /home/u/proj-cache does not contain /home/u/proj.
    argv = build_argv(
        profile=Profile.RO, workspace=WS, cwd=CWD, cache_dir="/home/u/proj-cache", argv=TOOL
    )
    second_tmpfs = argv.index("--tmpfs", argv.index("--tmpfs") + 1)
    assert argv[second_tmpfs + 1] == "/home/u/proj-cache"


@pytest.mark.parametrize("bad", [[], [""], ["ls", "a\x00b"], ["ls", 3], "ls"])
def test_malformed_tool_argv_rejected(bad: object) -> None:
    with pytest.raises(SandboxProfileError):
        build_argv(
            profile=Profile.RO,
            workspace=WS,
            cwd=CWD,
            cache_dir=CACHE,
            argv=bad,  # type: ignore[arg-type]
        )


def test_nul_in_path_rejected() -> None:
    with pytest.raises(SandboxProfileError):
        build_argv(
            profile=Profile.RO,
            workspace="/home/u/pr\x00oj",
            cwd=CWD,
            cache_dir=CACHE,
            argv=TOOL,
        )


# ---------------------------------------------------------------------------
# T2.06 addition: the program at argv[0] is a PARAMETER, defaulting to §8.1
# ---------------------------------------------------------------------------


def test_default_program_is_the_spec_bare_name() -> None:
    """T2.05 behaviour is preserved exactly when the caller says nothing."""
    assert ro()[0] == "bwrap"
    assert ws()[0] == "bwrap"


def test_absolute_program_path_is_rendered_verbatim() -> None:
    """The exec path pins the probed binary so no PATH lookup happens at spawn."""
    argv = ro(bwrap_path="/usr/bin/bwrap")
    assert argv[0] == "/usr/bin/bwrap"
    assert argv[1:] == EXPECTED_RO[1:]


@pytest.mark.parametrize("bad", ["", None, 0, b"/usr/bin/bwrap", "/usr/bin/bw\x00rap"])
def test_malformed_program_path_rejected(bad: object) -> None:
    with pytest.raises(SandboxProfileError):
        ro(bwrap_path=bad)


def test_program_path_is_keyword_only() -> None:
    with pytest.raises(TypeError):
        build_argv(  # type: ignore[misc]
            Profile.RO, workspace=WS, cwd=CWD, cache_dir=CACHE, argv=TOOL
        )
