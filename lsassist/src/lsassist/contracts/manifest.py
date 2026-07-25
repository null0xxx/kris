"""ToolManifest contract model + JSON Schema export (SPEC §6.2, invariant I4).

I4 (§1.2): every action carries scope, normalized args, timeout, output limit,
policy class, audit event, failure behavior — the §6.2 tool manifest schema is
the contract and every listed field is required. The model below is the single
source from which ``schemas/tool-manifest.schema.json`` is generated
(:func:`export_manifest_schema`); the unit test compares the generated schema
against the verbatim §6.2 text after a documented canonicalization.

Semantic-equivalence notes (pinned in ``tests/unit/contracts/test_manifest.py``):
- ``path_scope`` is optional in §6.2; here it defaults to ``"workspace"`` (the
  most restrictive value) and rejects an explicit ``null``, exactly like the
  SPEC schema whose enum contains no null.
- ``capabilities`` / ``output_limits`` carry no ``additionalProperties`` in
  §6.2, so these sub-models use pydantic's default config (extras ignored);
  only the root model forbids extras.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from lsassist.contracts.enums import PermissionClass

TOOL_NAME_PATTERN = r"^[a-z][a-z0-9_.]{1,31}$"
VERSION_PATTERN = r"^\d+\.\d+\.\d+$"


class FsCapability(StrEnum):
    """§6.2 capabilities.fs enum."""

    NONE = "none"
    READ_SCOPED = "read_scoped"
    WRITE_SCOPED = "write_scoped"


class NetCapability(StrEnum):
    """§6.2 capabilities.net enum."""

    NONE = "none"
    FETCH_ALLOWLIST = "fetch_allowlist"


class ProcCapability(StrEnum):
    """§6.2 capabilities.proc enum."""

    NONE = "none"
    SPAWN_ARGV = "spawn_argv"


class Concurrency(StrEnum):
    """§6.2 concurrency enum."""

    EXCLUSIVE = "exclusive"
    SHARED_READ = "shared_read"
    UNRESTRICTED = "unrestricted"


class Rollback(StrEnum):
    """§6.2 rollback enum."""

    NONE = "none"
    CHECKPOINT = "checkpoint"
    MANUAL_STEPS = "manual_steps"


class Redaction(StrEnum):
    """§6.2 redaction item enum."""

    PATHS = "paths"
    SECRETS = "secrets"
    ENV = "env"
    FULL_BODY = "full_body"


class PathScope(StrEnum):
    """§6.2 path_scope enum (ordered most → least restrictive by declaration)."""

    WORKSPACE = "workspace"
    SYSTEM_READ = "system_read"
    CONFIG_OWN = "config_own"
    ANY_READ = "any_read"


class Capabilities(BaseModel):
    """§6.2 capabilities object — all three dimensions required."""

    fs: FsCapability
    net: NetCapability
    proc: ProcCapability


class OutputLimits(BaseModel):
    """§6.2 output_limits object — kernel-enforced per-tool ceilings."""

    max_stdout_bytes: int = Field(le=1_048_576)
    max_stderr_bytes: int = Field(le=262_144)
    max_result_chars: int = Field(le=200_000)


class ToolManifest(BaseModel):
    """Tool manifest per SPEC §6.2 — root object, additionalProperties: false."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=TOOL_NAME_PATTERN)
    version: str = Field(pattern=VERSION_PATTERN)
    purpose: str = Field(max_length=300)
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    permission_class: PermissionClass
    capabilities: Capabilities
    timeout_s: int = Field(ge=1, le=1800)
    output_limits: OutputLimits
    concurrency: Concurrency
    idempotent: bool
    dry_run: bool
    rollback: Rollback
    redaction: list[Redaction]
    path_scope: PathScope = PathScope.WORKSPACE
    tests: list[str]


def export_manifest_schema(path: Path | str) -> Path:
    """Write ``ToolManifest.model_json_schema()`` to ``path`` deterministically.

    Sorted keys + fixed indent make regeneration byte-stable; the unit test
    asserts two runs produce identical bytes and match the committed artifact
    ``schemas/tool-manifest.schema.json``.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    schema = ToolManifest.model_json_schema()
    out.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out
