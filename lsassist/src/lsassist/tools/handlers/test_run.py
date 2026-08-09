"""Detected, fixed-head test runner argv construction for T3.06."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Final

from lsassist.tools.handlers import RUNNER_AMBIGUOUS, RUNNER_MISSING, HandlerRefused
from lsassist.tools.result import ExecObservation

__all__ = ["build_argv", "detect_runner", "make_test_run_handler", "result_of"]

_FORBIDDEN: Final = (";", "&&", "`")


def _has_pytest(root: Path) -> bool:
    if (root / "pytest.ini").is_file():
        return True
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file() or pyproject.stat().st_size > 1024 * 1024:
        return False
    return "[tool.pytest." in pyproject.read_text(encoding="utf-8", errors="replace")


def _has_npm_test(root: Path) -> bool:
    package = root / "package.json"
    if not package.is_file() or package.stat().st_size > 1024 * 1024:
        return False
    try:
        document = json.loads(package.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    scripts = document.get("scripts") if isinstance(document, dict) else None
    return isinstance(scripts, dict) and isinstance(scripts.get("test"), str)


def detect_runner(workspace_root: str) -> str:
    """Detect exactly one supported project runner, otherwise fail closed."""
    root = Path(workspace_root)
    detected = [
        name
        for name, present in (
            ("pytest", _has_pytest(root)),
            ("npm", _has_npm_test(root)),
            ("cargo", (root / "Cargo.toml").is_file()),
        )
        if present
    ]
    if not detected:
        raise HandlerRefused(RUNNER_MISSING, "no pytest, npm test, or cargo test runner detected")
    if len(detected) != 1:
        raise HandlerRefused(RUNNER_AMBIGUOUS, f"multiple test runners detected: {detected}")
    return detected[0]


def _extra_args(args: Mapping[str, Any]) -> tuple[str, ...]:
    extra = args.get("extra_args", [])
    if not isinstance(extra, list) or not all(isinstance(token, str) for token in extra):
        raise HandlerRefused(RUNNER_AMBIGUOUS, "test.run extra_args must be a string list")
    if any(
        not token or "\x00" in token or any(mark in token for mark in _FORBIDDEN) for token in extra
    ):
        raise HandlerRefused(
            RUNNER_AMBIGUOUS,
            "test.run extra_args contain an empty, NUL, or plan-forbidden metacharacter token",
        )
    return tuple(extra)


def build_argv(args: Mapping[str, Any], *, workspace_root: str) -> tuple[str, ...]:
    runner = detect_runner(workspace_root)
    head = {
        "pytest": (os.path.join(workspace_root, ".venv", "bin", "pytest"),),
        "npm": ("/usr/bin/npm", "test", "--"),
        "cargo": ("/usr/bin/cargo", "test", "--"),
    }[runner]
    if runner == "pytest" and not os.path.isfile(head[0]):
        raise HandlerRefused(
            RUNNER_MISSING,
            "pytest was detected but workspace .venv/bin/pytest is not available to the sandbox",
        )
    return (*head, *_extra_args(args))


def make_test_run_handler(
    workspace_root: str,
) -> Callable[[Mapping[str, Any]], tuple[str, ...]]:
    root = os.path.realpath(workspace_root)

    def handler(args: Mapping[str, Any]) -> tuple[str, ...]:
        return build_argv(args, workspace_root=root)

    return handler


def result_of(observation: ExecObservation) -> dict[str, Any]:
    return {
        "stdout": observation.stdout.decode("utf-8", errors="replace"),
        "exit_code": observation.exit_code,
    }
