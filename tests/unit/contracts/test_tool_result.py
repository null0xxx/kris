"""T1.04 RED: ToolResult contract model (SPEC §6.5).

§6.5: every tool execution yields ``{tool, status, exit_code, duration_ms,
stdout_digest, stderr_digest, result, evidence?, error?}``; ``result`` is
validated against the manifest's ``output_schema`` by the dispatcher (Phase 3),
and all result text is handled as untrusted in the kernel (§4.6). The model
here pins the structural contract: digest fields carry a ``sha256:`` prefix,
``status="error"`` requires ``error.kind``, and ``exit_code`` is a bounded
integer (0..255, the standard process exit-code range).
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from lsassist.contracts.tool_result import ToolError, ToolResult

_HEX64 = "a" * 64
_ZERO64 = "0" * 64


def _valid_result() -> dict[str, Any]:
    """The §6.5 example with concrete digests."""
    return {
        "tool": "fs.read",
        "status": "ok",
        "exit_code": 0,
        "duration_ms": 12,
        "stdout_digest": f"sha256:{_HEX64}",
        "stderr_digest": f"sha256:{_ZERO64}",
        "result": {"path": "src/x.py", "bytes": 128},
        "evidence": {
            "type": "file_snapshot",
            "path": "src/x.py",
            "sha256": _HEX64,
            "inode": 12345,
        },
    }


# --- (1) valid ToolResult round-trip (§6.5 example) -----------------------------


def test_valid_tool_result_round_trip() -> None:
    result = ToolResult.model_validate(_valid_result())
    assert result.tool == "fs.read"
    assert result.status == "ok"
    assert result.error is None
    assert result.evidence is not None
    assert result.evidence.inode == 12345
    restored = ToolResult.model_validate(result.model_dump(mode="json"))
    assert restored == result


def test_error_result_with_kind_ok() -> None:
    data = _valid_result()
    data["status"] = "error"
    data["exit_code"] = 1
    data["error"] = {"kind": "deny_path", "message_redacted": "path outside scope"}
    result = ToolResult.model_validate(data)
    assert result.error is not None
    assert result.error.kind == "deny_path"


# --- (2) status="error" requires error.kind --------------------------------------


def test_error_status_without_error_object_rejected() -> None:
    data = _valid_result()
    data["status"] = "error"
    data["exit_code"] = 1
    with pytest.raises(ValidationError):
        ToolResult.model_validate(data)


def test_error_object_requires_nonempty_kind() -> None:
    with pytest.raises(ValidationError):
        ToolError(kind="", message_redacted="boom")


# --- (3) digest fields validated with sha256: prefix -----------------------------


@pytest.mark.parametrize("field", ["stdout_digest", "stderr_digest"])
@pytest.mark.parametrize(
    "bad_digest",
    [
        _HEX64,  # missing sha256: prefix
        f"sha256:{_HEX64.upper()}",  # uppercase hex not allowed
        "sha256:abc",  # too short
        f"sha256:{'g' * 64}",  # non-hex characters
        f"md5:{_HEX64}",  # wrong algorithm tag
    ],
)
def test_digest_fields_require_sha256_prefix(field: str, bad_digest: str) -> None:
    data = _valid_result()
    data[field] = bad_digest
    with pytest.raises(ValidationError):
        ToolResult.model_validate(data)


# --- (4) exit_code integer bounds -------------------------------------------------


@pytest.mark.parametrize("ok_code", [0, 1, 127, 255])
def test_exit_code_within_bounds_accepted(ok_code: int) -> None:
    data = _valid_result()
    data["exit_code"] = ok_code
    ToolResult.model_validate(data)


@pytest.mark.parametrize("bad_code", [-1, 256])
def test_exit_code_out_of_bounds_rejected(bad_code: int) -> None:
    data = _valid_result()
    data["exit_code"] = bad_code
    with pytest.raises(ValidationError):
        ToolResult.model_validate(data)
