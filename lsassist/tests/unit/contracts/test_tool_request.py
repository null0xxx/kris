"""T1.11 RED: ToolRequest contract model (SPEC §6.2 name pattern, §6.3 step 1).

A ``ToolRequest`` is the model's request to call a tool: ``{call_id, tool,
args}``. The ``tool`` name must match the §6.2 manifest name pattern
(``^[a-z][a-z0-9_.]{1,31}$``), ``args`` defaults to an empty object, and
unknown fields are rejected (``extra="forbid"``) so a malformed model output
fails closed at the schema-validation stage (§6.3 step 1).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from lsassist.contracts.tool_request import ToolRequest

# --- (1) valid ToolRequest parses -------------------------------------------------


def test_valid_tool_request_parses() -> None:
    request = ToolRequest.model_validate(
        {"call_id": "call-1", "tool": "fs.read", "args": {"path": "src/x.py"}}
    )
    assert request.call_id == "call-1"
    assert request.tool == "fs.read"
    assert request.args == {"path": "src/x.py"}


def test_valid_tool_request_round_trip() -> None:
    request = ToolRequest(call_id="call-2", tool="proc.exec", args={"argv": ["ls", "-l"]})
    restored = ToolRequest.model_validate(request.model_dump(mode="json"))
    assert restored == request


# --- (2) tool name pattern violations (§6.2) --------------------------------------


@pytest.mark.parametrize(
    "bad_tool",
    [
        "Fs.Read",  # uppercase not allowed
        "1bad",  # must start with a lowercase letter
        "",  # empty
        "fs read",  # space not allowed
        "-fs.read",  # leading dash
    ],
)
def test_tool_name_pattern_violations_rejected(bad_tool: str) -> None:
    with pytest.raises(ValidationError):
        ToolRequest(call_id="call-1", tool=bad_tool, args={})


@pytest.mark.parametrize("good_tool", ["fs.read", "proc.exec", "net.fetch", "fs_read.v2"])
def test_tool_name_pattern_accepts_spec_names(good_tool: str) -> None:
    request = ToolRequest(call_id="call-1", tool=good_tool, args={})
    assert request.tool == good_tool


# --- (3) args defaults to empty object ---------------------------------------------


def test_args_defaults_to_empty_dict() -> None:
    request = ToolRequest(call_id="call-1", tool="fs.read")
    assert request.args == {}


# --- (4) unknown fields forbidden ---------------------------------------------------


def test_unknown_field_rejected() -> None:
    with pytest.raises(ValidationError):
        ToolRequest.model_validate(
            {"call_id": "call-1", "tool": "fs.read", "args": {}, "extra_field": 1}
        )


def test_frozen_model_rejects_mutation() -> None:
    request = ToolRequest(call_id="call-1", tool="fs.read", args={})
    with pytest.raises(ValidationError):
        request.tool = "fs.write"  # type: ignore[misc]
