"""``sys.info`` — §6.4's host-facts tool: a fixed argv table and nothing else.

This tool has no path argument and no free text. Its entire security story is
that the argv is SELECTED from a table by an enum-valued key, never ASSEMBLED
from anything the caller typed — so there is no string for a metacharacter to
live in and no branch where a name becomes a command.

**MEASURED: `os-release` must name `/usr/lib/os-release`, not `/etc/os-release`.**
§6.4 says "os-release read", and the obvious spelling is the `/etc` one. But §8.1
binds `/usr`, `/bin`, `/lib`, `/lib64`, `/etc/ld.so.cache` and `/etc/alternatives`
— it does NOT bind `/etc` itself, so `/etc/os-release` simply does not exist in
the sandbox's mount view and the tool would ENOENT on every host. Measured here:
`/etc/os-release` is a symlink to `/usr/lib/os-release`, which the `--ro-bind
/usr` already exposes. systemd specifies `/usr/lib/os-release` as the standard
location with `/etc/os-release` as the (optional) symlink to it, so this is the
portable choice, not a local one.

NAMED RESIDUAL: a host that ships `/etc/os-release` as a REAL file with no
`/usr/lib/os-release` cannot answer this query inside the `ro` profile. It fails
closed — an ENOENT and a non-zero exit — rather than silently reading something
else.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from lsassist.tools.handlers import READ_FAILED, HandlerRefused
from lsassist.tools.result import ExecObservation

__all__ = ["ALLOWED_QUERIES", "build_argv", "result_of"]

#: §6.4's fixed allowlist, keyed by the manifest's `query` enum. Absolute paths:
#: a bare name is re-resolved against `PATH` at spawn time, and `availability.py`
#: records the measurement behind that rule — an early writable `PATH` entry is a
#: shim, and a shimmed program is not the program that was approved.
ALLOWED_QUERIES: Final[Mapping[str, tuple[str, ...]]] = {
    "uname": ("/usr/bin/uname", "-a"),
    "lscpu": ("/usr/bin/lscpu",),
    "free": ("/usr/bin/free", "-h"),
    "df": ("/usr/bin/df", "-h"),
    "os_release": ("/usr/bin/cat", "/usr/lib/os-release"),
}


def build_argv(args: Mapping[str, Any]) -> tuple[str, ...]:
    """Select the §6.4 argv for ``args['query']``, or refuse."""
    query = args.get("query")
    if not isinstance(query, str) or query not in ALLOWED_QUERIES:
        raise HandlerRefused(
            READ_FAILED,
            f"sys.info query {query!r} is not one of {sorted(ALLOWED_QUERIES)}",
        )
    return ALLOWED_QUERIES[query]


def result_of(observation: ExecObservation) -> dict[str, Any]:
    """Render the child's stdout into the §6.5 ``result`` payload.

    ``errors="replace"`` because the subject decides these bytes: a tool that
    raised on undecodable output would be killable by whatever it was reporting
    on, and a crash in step 8 loses the journal entry for a child that already ran.
    """
    return {
        "stdout": observation.stdout.decode("utf-8", errors="replace"),
        "exit_code": observation.exit_code,
    }
