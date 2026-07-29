"""``pkg.query`` — §6.4's package-query tool: fixed argv, one validated slot.

§6.4 gives three forms — ``dpkg-query -W [pkg]``, ``apt-cache show [pkg]`` and
``pip list`` (venv) — plus one rule about the only caller-supplied token that may
reach an argv in this whole module: "name arg validated ``^[a-zA-Z0-9+._:-]+$``".

That regex is stated in TWO places on purpose. The manifest's ``input_schema``
carries it, so a malformed name is refused at §6.3 step 1 and never reaches a
handler; this module carries it again, so a manifest that drifted — or a caller
that reached the builder directly — still cannot put a shell metacharacter into
an argv. The tool never runs a shell (§7.6 rule 8), so a metacharacter would not
be interpreted anyway; the check exists because "argv exec" is a property of the
CURRENT call path, and a defence that depends on nothing downstream ever changing
is not a defence.

**NAMED RESIDUAL — §6.4's argv list is Debian-specific.** Measured on Garuda
Linux (Arch): ``dpkg-query``, ``apt-cache`` and a host ``pip`` are all ABSENT, so
two of these three forms cannot execute at all there. This is the same class of
finding as HARDEN-05's ``/etc/alternatives``: SPEC §6.4 was authored on Zorin OS
18.1 and encodes its package manager. Adding a ``pacman -Q`` form would be a §6.4
change and is deliberately NOT done here. The failure is loud — the sandbox exec
ENOENTs and the non-zero exit is reported — never a silently wrong answer.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping
from typing import Any, Final

from lsassist.tools.handlers import READ_FAILED, HandlerRefused
from lsassist.tools.result import ExecObservation

__all__ = ["ALLOWED_ACTIONS", "NAME_PATTERN", "build_argv", "result_of"]

#: §6.4 verbatim. Anchored at both ends: an unanchored pattern would accept
#: `bash;reboot` because it CONTAINS a legal run of characters.
NAME_PATTERN: Final = re.compile(r"\A[a-zA-Z0-9+._:-]+\Z")

#: The three §6.4 forms. `pip` is resolved against the WORKSPACE venv, because
#: §6.4 says "pip list (venv)" — the host's `pip` would report the host's
#: packages, which is a different question than the one the user asked.
ALLOWED_ACTIONS: Final[frozenset[str]] = frozenset(
    {"dpkg_query", "apt_cache_show", "pip_list"}
)

_NAME_REQUIRED: Final[frozenset[str]] = frozenset({"apt_cache_show"})


def _checked_name(args: Mapping[str, Any], action: str) -> str | None:
    name = args.get("name")
    if name is None:
        if action in _NAME_REQUIRED:
            raise HandlerRefused(READ_FAILED, f"pkg.query {action} requires a name")
        return None
    if not isinstance(name, str) or not NAME_PATTERN.match(name):
        raise HandlerRefused(
            READ_FAILED,
            f"pkg.query name {name!r} does not match the §6.4 pattern",
        )
    return name


def build_argv(args: Mapping[str, Any], *, workspace_root: str = "") -> tuple[str, ...]:
    """Build the §6.4 argv for ``args['action']``, or refuse."""
    action = args.get("action")
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        raise HandlerRefused(
            READ_FAILED,
            f"pkg.query action {action!r} is not one of {sorted(ALLOWED_ACTIONS)}",
        )
    name = _checked_name(args, action)
    if action == "pip_list":
        if not workspace_root:
            raise HandlerRefused(READ_FAILED, "pkg.query pip_list needs a workspace root")
        return (posixpath.join(workspace_root, ".venv", "bin", "pip"), "list")
    if action == "dpkg_query":
        base = ("/usr/bin/dpkg-query", "-W")
    else:
        base = ("/usr/bin/apt-cache", "show")
    # The name is APPENDED as its own argv element. It is never interpolated into
    # a string, so there is no token for a separator to split.
    return base if name is None else (*base, name)


def result_of(observation: ExecObservation) -> dict[str, Any]:
    """Render the child's stdout into the §6.5 ``result`` payload."""
    return {
        "stdout": observation.stdout.decode("utf-8", errors="replace"),
        "exit_code": observation.exit_code,
    }
