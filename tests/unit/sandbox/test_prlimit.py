"""T2.06 RED: the pure ``prlimit`` prefix builder (SPEC §8.1, §4.3; T-14).

The prefix is five literal argv elements, so the first test is an exact
SNAPSHOT: content AND order. The rest pin the two things a snapshot cannot —

1. **The ``4G`` suffix trap.** SPEC §8.1 writes ``--as=4G``, but util-linux
   ``prlimit`` (2.39.3, host-verified) has NO size-suffix parser: it reads
   ``4G`` as the integer ``4``, i.e. a FOUR BYTE address-space limit, and every
   ``execve`` under it dies with ``E2BIG`` ("Argument list too long"). A build
   that regresses to the literal SPEC text therefore breaks every sandboxed
   exec. ``test_as_limit_is_plain_bytes_not_a_suffix`` and
   ``test_no_limit_value_carries_a_size_suffix`` exist solely to make that
   regression impossible.
2. **Fail-closed input validation.** ``timeout_s`` outside ``1..600`` (§6.4's
   largest per-exec timeout, ``test.run``; §4.3's 30-min ``max_wall_clock`` is a
   per-TASK budget, so 1800 must be REJECTED here), a non-``int``, or a ``bool``
   (``isinstance(True, int)`` is True in Python) must RAISE — never clamp, never
   coerce.
3. **Program pinning.** ``prlimit_path`` defaults to the §8.1 bare name but the
   exec path passes an absolute one, so a writable early ``PATH`` entry cannot
   substitute a shim that drops the limits.

PURE (§2.2): no filesystem, no environment, no child processes; the
``tripwired_environ`` fixture proves the environment is not read.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import Any

import pytest

from lsassist.sandbox.prlimit import (
    AS_LIMIT_BYTES,
    CPU_GRACE_S,
    MAX_TIMEOUT_S,
    NOFILE_LIMIT,
    NPROC_LIMIT,
    PrlimitError,
    prlimit_prefix,
)

# The exact prefix for the §6.4 `proc.exec` default timeout's neighbour, 30 s.
EXPECTED_30 = [
    "prlimit",
    "--nproc=256",
    "--nofile=1024",
    "--as=4294967296",
    "--cpu=40",
]


def limit_values(prefix: list[str]) -> dict[str, str]:
    """Return ``{flag: value}`` for every ``--flag=value`` element of ``prefix``."""
    return dict(element.split("=", 1) for element in prefix if "=" in element)


# ---------------------------------------------------------------------------
# SNAPSHOT — the complete prefix, pinning content AND order
# ---------------------------------------------------------------------------


def test_snapshot_timeout_30() -> None:
    assert prlimit_prefix(30) == EXPECTED_30


def test_prefix_is_the_program_then_four_limits() -> None:
    prefix = prlimit_prefix(30)
    assert prefix[0] == "prlimit"
    assert len(prefix) == 5
    assert sorted(limit_values(prefix)) == ["--as", "--cpu", "--nofile", "--nproc"]


def test_every_element_is_a_plain_str() -> None:
    assert all(type(element) is str for element in prlimit_prefix(120))


# ---------------------------------------------------------------------------
# THE `4G` TRAP — plain bytes only, no size suffixes anywhere
# ---------------------------------------------------------------------------


def test_as_limit_is_plain_bytes_not_a_suffix() -> None:
    """`--as=4G` would be parsed as FOUR BYTES → E2BIG on every execve."""
    value = limit_values(prlimit_prefix(30))["--as"]
    assert value.isdigit(), f"--as must be plain bytes, got {value!r}"
    assert not any(char.isalpha() for char in value)
    assert int(value) == 4 * 1024**3 == 4294967296


def test_no_limit_value_carries_a_size_suffix() -> None:
    for timeout_s in (1, 30, 599, 600):
        for flag, value in limit_values(prlimit_prefix(timeout_s)).items():
            assert value.isdigit(), f"{flag} must be a plain integer, got {value!r}"


def test_the_spec_literal_4g_never_appears() -> None:
    assert "--as=4G" not in prlimit_prefix(30)
    assert not any("4G" in element for element in prlimit_prefix(30))


def test_as_limit_bytes_constant_is_four_gibibytes() -> None:
    assert AS_LIMIT_BYTES == 4 * 1024**3 == 4294967296


def test_nproc_and_nofile_match_the_spec_template() -> None:
    assert (NPROC_LIMIT, NOFILE_LIMIT) == (256, 1024)
    values = limit_values(prlimit_prefix(30))
    assert values["--nproc"] == "256"
    assert values["--nofile"] == "1024"


# ---------------------------------------------------------------------------
# CPU = timeout + grace
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("timeout_s", [1, 5, 30, 120, 300, 599, 600])
def test_cpu_is_timeout_plus_ten(timeout_s: int) -> None:
    assert limit_values(prlimit_prefix(timeout_s))["--cpu"] == str(timeout_s + 10)


def test_cpu_grace_constant() -> None:
    assert CPU_GRACE_S == 10


def test_only_the_cpu_limit_varies_with_timeout() -> None:
    short = prlimit_prefix(5)
    long = prlimit_prefix(600)
    assert short[:4] == long[:4]
    assert (short[4], long[4]) == ("--cpu=15", "--cpu=610")


# ---------------------------------------------------------------------------
# PROGRAM PATH — the §8.1 bare name by default, an absolute path on the exec path
# ---------------------------------------------------------------------------


def test_default_program_is_the_spec_bare_name() -> None:
    assert prlimit_prefix(30)[0] == "prlimit"


def test_absolute_program_path_is_rendered_verbatim() -> None:
    """The exec path pins the binary so no PATH lookup happens at spawn time."""
    prefix = prlimit_prefix(30, prlimit_path="/usr/bin/prlimit")
    assert prefix[0] == "/usr/bin/prlimit"
    assert prefix[1:] == EXPECTED_30[1:]


def test_program_path_does_not_disturb_the_limits() -> None:
    assert prlimit_prefix(30, prlimit_path="/bin/prlimit")[1:] == EXPECTED_30[1:]


@pytest.mark.parametrize("bad", ["", None, 0, b"/usr/bin/prlimit", ["/usr/bin/prlimit"]])
def test_rejects_a_non_string_or_empty_program_path(bad: Any) -> None:
    with pytest.raises(PrlimitError):
        prlimit_prefix(30, prlimit_path=bad)


def test_rejects_a_nul_bearing_program_path() -> None:
    with pytest.raises(PrlimitError):
        prlimit_prefix(30, prlimit_path="/usr/bin/prlimit\x00evil")


def test_program_path_is_keyword_only() -> None:
    with pytest.raises(TypeError):
        prlimit_prefix(30, "/usr/bin/prlimit")  # type: ignore[misc]


# ---------------------------------------------------------------------------
# FAIL-CLOSED validation — raise, never clamp
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("timeout_s", [0, -1, -30, -1800])
def test_rejects_non_positive(timeout_s: int) -> None:
    with pytest.raises(PrlimitError):
        prlimit_prefix(timeout_s)


@pytest.mark.parametrize("timeout_s", [601, 1800, 3600, 100_000, 2**63])
def test_rejects_above_the_per_exec_ceiling(timeout_s: int) -> None:
    """§6.4: 600 s (`test.run`) is the largest per-exec timeout in the catalog.

    §4.3's `max_wall_clock` (1800 s) is a per-TASK budget summed over up to 25
    tool calls — not a ceiling for a single exec, and 1800 must be REJECTED.
    """
    with pytest.raises(PrlimitError):
        prlimit_prefix(timeout_s)


def test_boundaries_are_inclusive_1_and_600() -> None:
    assert MAX_TIMEOUT_S == 600
    assert prlimit_prefix(1)[4] == "--cpu=11"
    assert prlimit_prefix(MAX_TIMEOUT_S)[4] == "--cpu=610"
    with pytest.raises(PrlimitError):
        prlimit_prefix(MAX_TIMEOUT_S + 1)


@pytest.mark.parametrize(
    "timeout_s",
    ["30", 30.0, 29.5, None, b"30", [30], object()],
)
def test_rejects_non_int(timeout_s: Any) -> None:
    with pytest.raises(PrlimitError):
        prlimit_prefix(timeout_s)


@pytest.mark.parametrize("timeout_s", [True, False])
def test_rejects_bool(timeout_s: bool) -> None:
    """`isinstance(True, int)` is True — `--cpu=11` from `True` is a caller bug."""
    with pytest.raises(PrlimitError):
        prlimit_prefix(timeout_s)


def test_error_is_typed_and_a_value_error() -> None:
    assert issubclass(PrlimitError, ValueError)
    with pytest.raises(PrlimitError):
        prlimit_prefix(0)


# ---------------------------------------------------------------------------
# PURITY / determinism
# ---------------------------------------------------------------------------


def test_deterministic() -> None:
    assert prlimit_prefix(42) == prlimit_prefix(42)


def test_returns_a_fresh_list_each_call() -> None:
    first = prlimit_prefix(30)
    first.append("--injected")
    assert prlimit_prefix(30) == EXPECTED_30


def test_reads_no_environment(
    tripwired_environ: Callable[[], contextlib.AbstractContextManager[None]],
) -> None:
    with tripwired_environ():
        built = prlimit_prefix(30)
        with contextlib.suppress(PrlimitError):
            prlimit_prefix(0)
    assert built == EXPECTED_30
