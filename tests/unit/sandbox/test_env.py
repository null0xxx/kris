"""T2.05: §8.3 child-env allowlist projection (constructed FROM SCRATCH).

``project_env`` never inherits: it starts from an empty dict, fills the §8.3
allowlist (``PATH``, ``HOME``, ``LANG``, ``LC_ALL``, ``TERM``) from parameters,
and admits tool-specific additions only from a second, equally closed allowlist
(§8.3 "tool-specific additions like ``CI=1``"). Anything else — a parent-env
leftover, a secret-shaped name, a malformed POSIX name — is REJECTED with a
typed error, never silently dropped (I8, fail-closed).

PURE (§2.2): no environment reads (trip-wire enforced below), no filesystem.
"""

from __future__ import annotations

import contextlib
import inspect
from collections.abc import Callable

import pytest

from lsassist.sandbox import env as env_mod
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

KIMI_KEY_NAME = "LSASSIST_KIMI_API_KEY"
KIMI_KEY_VALUE = "sk-kimi-DEADBEEFdeadbeef0123456789"


# ---------------------------------------------------------------------------
# §8.3 allowlist projection
# ---------------------------------------------------------------------------


def test_allowlist_is_exactly_the_8_3_set() -> None:
    assert set(ENV_ALLOWLIST) == {"PATH", "HOME", "LANG", "LC_ALL", "TERM"}


def test_defaults_match_8_1_setenv_line() -> None:
    assert (DEFAULT_PATH, DEFAULT_HOME, DEFAULT_LANG) == (
        "/usr/bin:/bin",
        "/tmp/lsassist-home",
        "C.UTF-8",
    )


def test_minimal_projection_is_from_scratch() -> None:
    assert project_env() == {
        "PATH": DEFAULT_PATH,
        "HOME": DEFAULT_HOME,
        "LANG": DEFAULT_LANG,
    }


def test_optional_allowlist_keys_only_when_given() -> None:
    out = project_env(lc_all="C.UTF-8", term="dumb")
    assert out["LC_ALL"] == "C.UTF-8"
    assert out["TERM"] == "dumb"
    assert set(out) == {"PATH", "HOME", "LANG", "LC_ALL", "TERM"}


def test_returned_keys_are_subset_of_both_allowlists() -> None:
    out = project_env(lc_all="C", term="xterm", extra={"CI": "1"})
    assert set(out) <= ENV_ALLOWLIST | TOOL_ENV_ALLOWLIST


def test_tool_specific_addition_ci_is_admitted() -> None:
    assert project_env(extra={"CI": "1"})["CI"] == "1"


def test_path_parameter_drives_the_venv_prepend() -> None:
    out = project_env(path=f"/ws/.venv/bin:{DEFAULT_PATH}")
    assert out["PATH"] == f"/ws/.venv/bin:{DEFAULT_PATH}"


def test_returns_a_fresh_dict_each_call() -> None:
    a, b = project_env(), project_env()
    assert a == b and a is not b
    a["PATH"] = "/mutated"
    assert project_env()["PATH"] == DEFAULT_PATH


# ---------------------------------------------------------------------------
# I8 — parent-env leftovers and secret-shaped names are REJECTED
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        KIMI_KEY_NAME,
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "SSH_AUTH_SOCK",
        "GPG_TTY",
        "DBUS_SESSION_BUS_ADDRESS",
        "FOO",
        "LD_PRELOAD",
        "PYTHONPATH",
    ],
)
def test_non_allowlisted_key_is_rejected(key: str) -> None:
    with pytest.raises(EnvProjectionError):
        project_env(extra={key: "x"})


@pytest.mark.parametrize(
    "key",
    [
        KIMI_KEY_NAME,
        "MY_TOKEN",
        "SOME_SECRET",
        "DB_PASSWORD",
        "CI_PASSWD",
        "A_CREDENTIAL",
        "X_PRIVATE_KEY",
        "SESSION_ID",
        "A_COOKIE",
    ],
)
def test_secret_shaped_key_is_rejected(key: str) -> None:
    with pytest.raises(EnvProjectionError):
        project_env(extra={key: "x"})


def test_rejection_message_never_echoes_the_secret_value() -> None:
    with pytest.raises(EnvProjectionError) as exc:
        project_env(extra={KIMI_KEY_NAME: KIMI_KEY_VALUE})
    assert KIMI_KEY_VALUE not in str(exc.value)


def test_no_allowlisted_name_is_itself_secret_shaped() -> None:
    # The secret-marker guard runs on EVERY key, so an allowlist entry that
    # tripped it would be dead (or, worse, would tempt a future weakening).
    for key in ENV_ALLOWLIST | TOOL_ENV_ALLOWLIST:
        assert not any(marker in key.upper() for marker in SECRET_KEY_MARKERS)


def test_extra_may_not_override_a_base_allowlist_key() -> None:
    # PATH/HOME/LANG/LC_ALL/TERM have dedicated parameters; letting `extra`
    # override them would let a caller undo the §8.2 venv PATH computation.
    for key in ENV_ALLOWLIST:
        with pytest.raises(EnvProjectionError):
            project_env(extra={key: "/evil"})


@pytest.mark.parametrize("key", ["", "1BAD", "has-dash", "has space", "A=B", "A\x00B", "lower"])
def test_malformed_posix_name_rejected(key: str) -> None:
    with pytest.raises(EnvProjectionError):
        project_env(extra={key: "x"})


@pytest.mark.parametrize("value", ["a\x00b", 1, None])
def test_malformed_value_rejected(value: object) -> None:
    with pytest.raises(EnvProjectionError):
        project_env(extra={"CI": value})  # type: ignore[dict-item]


@pytest.mark.parametrize("value", ["a\x00b", 3])
def test_malformed_base_value_rejected(value: object) -> None:
    with pytest.raises(EnvProjectionError):
        project_env(path=value)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# S3 — VALUES land in /proc/<pid>/cmdline too, so they carry a shape guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",  # `=`: a smuggled assignment
        "C.UTF-8 --evil",  # whitespace
        "/etc/passwd",  # path separator
        "a$(id)b",  # shell metacharacters
        "line\nbreak",  # newline (splits `ps`/audit lines)
        "x" * 65,  # over the length cap
    ],
)
def test_value_outside_the_permitted_shape_is_rejected(value: str) -> None:
    with pytest.raises(EnvProjectionError):
        project_env(term=value)


def test_value_rejection_message_never_echoes_the_value() -> None:
    with pytest.raises(EnvProjectionError) as exc:
        project_env(lc_all="AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in str(exc.value)


@pytest.mark.parametrize("value", ["C.UTF-8", "en_US.UTF-8", "xterm-256color", "1", "1735689600"])
def test_realistic_locale_terminfo_and_flag_values_pass(value: str) -> None:
    assert project_env(term=value)["TERM"] == value


def test_pathlike_values_may_contain_slashes_and_spaces() -> None:
    # PATH/HOME are exempt from the charset guard: they are `/`-bearing (and
    # PATH `:`-bearing) paths, and a workspace name may legally contain spaces.
    out = project_env(path="/my ws/.venv/bin:/usr/bin:/bin", home="/tmp/lsassist-home")
    assert out["PATH"] == "/my ws/.venv/bin:/usr/bin:/bin"


# ---------------------------------------------------------------------------
# C5 — a non-Mapping `extra` gets the typed error, not AttributeError
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("extra", [["CI=1"], "CI=1", 42, {"CI"}, object()])
def test_non_mapping_extra_raises_the_typed_error(extra: object) -> None:
    with pytest.raises(EnvProjectionError, match="Mapping"):
        project_env(extra=extra)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# PURITY — os.environ is never touched
# ---------------------------------------------------------------------------


def test_project_env_never_reads_the_process_environment(
    tripwired_environ: Callable[[], contextlib.AbstractContextManager[None]],
) -> None:
    caught: Exception | None = None
    with tripwired_environ():
        projected = project_env(extra={"CI": "1"})
        try:
            project_env(extra={KIMI_KEY_NAME: KIMI_KEY_VALUE})
        except EnvProjectionError as exc:
            caught = exc
    assert projected["CI"] == "1"
    assert isinstance(caught, EnvProjectionError)


def test_module_source_contains_no_io_primitives() -> None:
    src = inspect.getsource(env_mod)
    for forbidden in ("subprocess", "os.environ", "getenv", "os.path.exists", "open("):
        assert forbidden not in src, f"{forbidden} in a PURE module"


def test_module_imports_only_stdlib() -> None:
    src = inspect.getsource(env_mod)
    for forbidden in ("lsassist.policy", "lsassist.kernel", "lsassist.providers",
                      "lsassist.cli", "lsassist.tools"):
        assert forbidden not in src
