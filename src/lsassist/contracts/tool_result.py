"""ToolResult contract model (SPEC §6.5).

Every tool execution yields one ToolResult: ``{tool, status, exit_code,
duration_ms, stdout_digest, stderr_digest, result, evidence?, error?}``.
``result`` is validated against the manifest's ``output_schema`` by the
dispatcher (§6.3 step 8, Phase 3); all result text is untrusted in the kernel
(§4.6). Digest fields carry the ``sha256:`` algorithm prefix; ``exit_code`` is
bounded to the standard process exit-code range 0..255.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from lsassist.contracts.enums import EvidenceType
from lsassist.contracts.manifest import TOOL_NAME_PATTERN

Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]


class ToolResultStatus(StrEnum):
    """§6.5 status enum."""

    OK = "ok"
    ERROR = "error"
    TRUNCATED = "truncated"


class ToolError(BaseModel):
    """§6.5 error object; ``message_redacted`` is already redaction-applied."""

    model_config = ConfigDict(frozen=True)

    kind: str = Field(min_length=1)
    message_redacted: str = ""


class ToolResultEvidence(BaseModel):
    """§6.5 evidence object, e.g. a file snapshot taken during execution.

    ``sha256`` is the bare 64-char hex digest (the field name already carries
    the algorithm), unlike the ``*_digest`` fields which are prefixed.
    """

    model_config = ConfigDict(frozen=True)

    type: EvidenceType
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inode: int = Field(ge=0)


class ToolResult(BaseModel):
    """§6.5 tool result record; every execution and audit ``tool_result`` event."""

    model_config = ConfigDict(frozen=True)

    tool: str = Field(pattern=TOOL_NAME_PATTERN)
    status: ToolResultStatus
    exit_code: int = Field(ge=0, le=255)
    duration_ms: int = Field(ge=0)
    stdout_digest: Sha256Digest
    stderr_digest: Sha256Digest
    result: dict[str, Any] = Field(default_factory=dict)
    evidence: ToolResultEvidence | None = None
    error: ToolError | None = None

    @model_validator(mode="after")
    def _error_status_requires_error(self) -> Self:
        if self.status is ToolResultStatus.ERROR and self.error is None:
            raise ValueError("status=error requires an error object with error.kind")
        return self
