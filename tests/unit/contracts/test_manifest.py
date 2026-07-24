"""T1.04 RED: ToolManifest model + SPEC §6.2 JSON Schema export (invariant I4).

I4 / §1.2: every action carries scope, normalized args, timeout, output limit,
policy class, audit event, failure behavior — the tool manifest JSON Schema
(§6.2) is the contract, and every field is required.

Schema-vs-SPEC comparison (test_generated_schema_matches_spec_62): the §6.2
schema from SPEC.md is embedded VERBATIM below as
``SPEC_TOOL_MANIFEST_SCHEMA_JSON`` and is the canonical expected value. The
generated schema (``ToolManifest.model_json_schema()``) is compared against it
after a canonicalization step (``_canonicalize``), because pydantic and the
SPEC text express the same schema with different *surface* details. The exact
mapping, item by item:

1. pydantic emits nested models (Capabilities, OutputLimits) and enums via
   ``$defs`` + ``$ref``; SPEC §6.2 inlines them. Canonicalization resolves
   ``$ref`` against ``$defs`` and drops the ``$defs`` block.
2. pydantic emits ``"type": "string"`` alongside every ``"enum"``; SPEC §6.2
   omits the redundant type on enum subschemas. Canonicalization drops
   ``"type"`` on any subschema that carries ``"enum"``.
3. pydantic emits ``"title"`` annotations everywhere, and ``"description"``
   from model docstrings; SPEC has neither. Both dropped.
4. ``$schema`` (draft marker) exists only in the SPEC text. Dropped.
5. ``path_scope``: SPEC marks it optional (absent from ``required``). The
   model gives it a default of ``"workspace"`` — the most restrictive value —
   so absence is accepted and an explicit ``null`` is REJECTED, exactly like
   the SPEC schema (whose enum contains no null). The emitted ``"default"``
   annotation is dropped by canonicalization.
6. pydantic emits ``"additionalProperties": true`` for ``dict[str, Any]``
   fields; JSON Schema treats an absent ``additionalProperties`` as ``true``,
   so the explicit ``true`` is dropped. The meaningful ``false`` on the root
   object is kept.
7. ``required`` lists and object key order are normalized (sorted): field
   ORDER never matters, content does.

The invariant (stated in T1.04): anything the SPEC schema rejects, the model
also rejects, and vice versa. The structural tests below pin the reject side
(missing fields, pattern violations, unknown fields, cap violations, bad
enum items); the canonical diff pins the accept side wholesale.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from lsassist.contracts.manifest import ToolManifest, export_manifest_schema

REPO_ROOT = Path(__file__).resolve().parents[3]
GENERATED_SCHEMA_PATH = REPO_ROOT / "schemas" / "tool-manifest.schema.json"

# --- SPEC §6.2, copied verbatim from SPEC.md (source of truth, I4) -----------

SPEC_TOOL_MANIFEST_SCHEMA_JSON = r"""
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["name", "version", "purpose", "input_schema", "output_schema",
               "permission_class", "capabilities", "timeout_s", "output_limits",
               "concurrency", "idempotent", "dry_run", "rollback", "redaction", "tests"],
  "properties": {
    "name": {"type": "string", "pattern": "^[a-z][a-z0-9_.]{1,31}$"},
    "version": {"type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$"},
    "purpose": {"type": "string", "maxLength": 300},
    "input_schema": {"type": "object"},
    "output_schema": {"type": "object"},
    "permission_class": {
        "enum": ["AUTO_READ", "AUTO_SCOPED_WRITE", "CONFIRM_ONCE", "CONFIRM_EXACT", "DENY_ALWAYS"]
    },
    "capabilities": {
      "type": "object",
      "required": ["fs", "net", "proc"],
      "properties": {
        "fs": {"enum": ["none", "read_scoped", "write_scoped"]},
        "net": {"enum": ["none", "fetch_allowlist"]},
        "proc": {"enum": ["none", "spawn_argv"]}
      }
    },
    "timeout_s": {"type": "integer", "minimum": 1, "maximum": 1800},
    "output_limits": {
      "type": "object",
      "required": ["max_stdout_bytes", "max_stderr_bytes", "max_result_chars"],
      "properties": {
        "max_stdout_bytes": {"type": "integer", "maximum": 1048576},
        "max_stderr_bytes": {"type": "integer", "maximum": 262144},
        "max_result_chars": {"type": "integer", "maximum": 200000}
      }
    },
    "concurrency": {"enum": ["exclusive", "shared_read", "unrestricted"]},
    "idempotent": {"type": "boolean"},
    "dry_run": {"type": "boolean"},
    "rollback": {"enum": ["none", "checkpoint", "manual_steps"]},
    "redaction": {"type": "array", "items": {"enum": ["paths", "secrets", "env", "full_body"]}},
    "path_scope": {"enum": ["workspace", "system_read", "config_own", "any_read"]},
    "tests": {"type": "array", "items": {"type": "string"}}
  },
  "additionalProperties": false
}
"""

SPEC_SCHEMA: dict[str, Any] = json.loads(SPEC_TOOL_MANIFEST_SCHEMA_JSON)
SPEC_REQUIRED: list[str] = SPEC_SCHEMA["required"]

_ANNOTATION_KEYS = frozenset({"title", "description", "$schema", "default"})


def _canonicalize(node: Any, defs: dict[str, Any] | None = None) -> Any:
    """Normalize a JSON Schema for content comparison (see module docstring)."""
    if defs is None:
        defs = node.get("$defs", {}) if isinstance(node, dict) else {}
    if isinstance(node, dict):
        if "$ref" in node:
            ref_name = node["$ref"].rsplit("/", 1)[-1]
            return _canonicalize(defs[ref_name], defs)
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key in _ANNOTATION_KEYS or key == "$defs":
                continue
            if key == "type" and "enum" in node:
                continue  # SPEC §6.2 omits the redundant type on enum subschemas
            if key == "additionalProperties" and value is True:
                continue  # JSON Schema default; absent == true
            out[key] = sorted(value) if key == "required" else _canonicalize(value, defs)
        return out
    if isinstance(node, list):
        return [_canonicalize(item, defs) for item in node]
    return node


def _valid_manifest() -> dict[str, Any]:
    """A minimal manifest carrying every §6.2 required field with valid values."""
    return {
        "name": "fs.read",
        "version": "1.0.0",
        "purpose": "Read a file inside the declared path scope.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        "output_schema": {"type": "object"},
        "permission_class": "AUTO_READ",
        "capabilities": {"fs": "read_scoped", "net": "none", "proc": "none"},
        "timeout_s": 10,
        "output_limits": {
            "max_stdout_bytes": 0,
            "max_stderr_bytes": 0,
            "max_result_chars": 200_000,
        },
        "concurrency": "shared_read",
        "idempotent": True,
        "dry_run": False,
        "rollback": "none",
        "redaction": ["paths", "secrets"],
        "tests": ["tests/unit/tools/test_fs_read.py"],
    }


# --- (1) minimal valid manifest parses ----------------------------------------


def test_minimal_valid_manifest_parses() -> None:
    manifest = ToolManifest.model_validate(_valid_manifest())
    assert manifest.name == "fs.read"
    assert manifest.permission_class == "AUTO_READ"
    assert manifest.capabilities.fs == "read_scoped"
    assert manifest.output_limits.max_result_chars == 200_000
    assert manifest.path_scope == "workspace"  # §6.2-optional, restrictive default


def test_spec_required_list_has_15_fields() -> None:
    # Guards the SPEC verbatim copy itself: §6.2 requires exactly 15 fields.
    assert len(SPEC_REQUIRED) == 15


# --- (2) every required field missing → ValidationError (15 cases) ------------


@pytest.mark.parametrize("field", SPEC_REQUIRED)
def test_missing_required_field_rejected(field: str) -> None:
    data = _valid_manifest()
    del data[field]
    with pytest.raises(ValidationError):
        ToolManifest.model_validate(data)


# --- (3) name pattern violations ------------------------------------------------


@pytest.mark.parametrize("bad_name", ["Fs.Read", "1bad"])
def test_name_pattern_violation_rejected(bad_name: str) -> None:
    data = _valid_manifest()
    data["name"] = bad_name
    with pytest.raises(ValidationError):
        ToolManifest.model_validate(data)


# --- (4) additionalProperties: false ---------------------------------------------


def test_unknown_field_rejected() -> None:
    data = _valid_manifest()
    data["sandbox_profile"] = "ws"  # not a §6.2 property
    with pytest.raises(ValidationError):
        ToolManifest.model_validate(data)


# --- (5) output_limits caps (§6.2) ----------------------------------------------


@pytest.mark.parametrize(
    ("field", "over_cap"),
    [
        ("max_stdout_bytes", 1_048_577),
        ("max_stderr_bytes", 262_145),
        ("max_result_chars", 200_001),
    ],
)
def test_output_limits_over_cap_rejected(field: str, over_cap: int) -> None:
    data = _valid_manifest()
    data["output_limits"][field] = over_cap
    with pytest.raises(ValidationError):
        ToolManifest.model_validate(data)


@pytest.mark.parametrize(
    ("field", "at_cap"),
    [
        ("max_stdout_bytes", 1_048_576),
        ("max_stderr_bytes", 262_144),
        ("max_result_chars", 200_000),
    ],
)
def test_output_limits_at_cap_accepted(field: str, at_cap: int) -> None:
    data = _valid_manifest()
    data["output_limits"][field] = at_cap
    ToolManifest.model_validate(data)


def test_timeout_s_out_of_range_rejected() -> None:
    for bad_timeout in (0, 1801):
        data = _valid_manifest()
        data["timeout_s"] = bad_timeout
        with pytest.raises(ValidationError):
            ToolManifest.model_validate(data)


# --- (6) generated schema == SPEC §6.2 (canonical diff, I4) ---------------------


def test_generated_schema_matches_spec_62() -> None:
    generated = json.loads(GENERATED_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert _canonicalize(generated) == _canonicalize(SPEC_SCHEMA)


def test_export_is_deterministic_and_current(tmp_path: Path) -> None:
    first = tmp_path / "first.schema.json"
    second = tmp_path / "second.schema.json"
    export_manifest_schema(first)
    export_manifest_schema(second)
    assert first.read_bytes() == second.read_bytes()  # deterministic
    # The committed artifact is exactly what the exporter produces today.
    assert first.read_bytes() == GENERATED_SCHEMA_PATH.read_bytes()


# --- (7) redaction items only from the allowed enum -----------------------------


@pytest.mark.parametrize("allowed", ["paths", "secrets", "env", "full_body"])
def test_redaction_accepts_allowed_items(allowed: str) -> None:
    data = _valid_manifest()
    data["redaction"] = [allowed]
    manifest = ToolManifest.model_validate(data)
    assert manifest.redaction == [allowed]


def test_redaction_rejects_unknown_item() -> None:
    data = _valid_manifest()
    data["redaction"] = ["everything"]
    with pytest.raises(ValidationError):
        ToolManifest.model_validate(data)
