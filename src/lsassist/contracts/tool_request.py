"""ToolRequest contract model — the model's request to call a tool (SPEC §6.2, §6.3).

A provider turn yields zero or more tool call requests; each is validated into
a :class:`ToolRequest` before entering the §6.3 dispatch pipeline. ``tool``
must match the §6.2 manifest name pattern, and unknown fields are forbidden
(``extra="forbid"``) so malformed model output fails closed at §6.3 step 1
(``malformed_tool_request``) instead of silently dropping data.

§2.2: stdlib + pydantic only; no I/O, no child processes, no network.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from lsassist.contracts.manifest import TOOL_NAME_PATTERN


class ToolRequest(BaseModel):
    """One model tool call request: ``{call_id, tool, args}``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    call_id: str = Field(min_length=1)
    tool: str = Field(pattern=TOOL_NAME_PATTERN)
    args: dict[str, Any] = Field(default_factory=dict)
