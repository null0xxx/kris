"""Exact-path ``proc.exec`` argv admission for T3.06."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

from lsassist.tools.handlers import EXECUTABLE_REFUSED, HandlerRefused
from lsassist.tools.result import ExecObservation

__all__ = ["build_argv", "make_proc_exec_handler", "result_of"]


def _validated_allowlist(allowed_executables: frozenset[str]) -> frozenset[str]:
    if not isinstance(allowed_executables, frozenset):
        raise TypeError("proc.exec allowlist must be an immutable frozenset")
    if any(not isinstance(path, str) or not os.path.isabs(path) for path in allowed_executables):
        raise ValueError("proc.exec allowlist entries must be exact absolute paths")
    return allowed_executables


def build_argv(args: Mapping[str, Any], *, allowed_executables: frozenset[str]) -> tuple[str, ...]:
    """Return the approved argv byte-for-byte; never resolve or rewrite it."""
    allowed = _validated_allowlist(allowed_executables)
    argv = args.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(t, str) for t in argv):
        raise HandlerRefused(EXECUTABLE_REFUSED, "proc.exec argv must be a non-empty string list")
    if any(not token or "\x00" in token for token in argv):
        raise HandlerRefused(EXECUTABLE_REFUSED, "proc.exec argv has an empty or NUL token")
    if argv[0] not in allowed:
        raise HandlerRefused(
            EXECUTABLE_REFUSED,
            f"proc.exec executable {argv[0]!r} is not an exact configured allowlist entry",
        )
    return tuple(argv)


def make_proc_exec_handler(
    allowed_executables: frozenset[str],
) -> Callable[[Mapping[str, Any]], tuple[str, ...]]:
    """Inject the immutable executable set without widening dispatcher context."""
    allowed = _validated_allowlist(allowed_executables)

    def handler(args: Mapping[str, Any]) -> tuple[str, ...]:
        return build_argv(args, allowed_executables=allowed)

    return handler


def result_of(observation: ExecObservation) -> dict[str, Any]:
    return {
        "stdout": observation.stdout.decode("utf-8", errors="replace"),
        "exit_code": observation.exit_code,
    }
