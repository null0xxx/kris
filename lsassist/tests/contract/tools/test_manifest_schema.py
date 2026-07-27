"""T3.01 RED (contract): ``tools/manifest_schema.json`` IS SPEC §6.2 (I3, I4).

Two independent encodings of §6.2 now exist in this repository, on purpose:

* ``src/lsassist/tools/manifest_schema.json`` — the DATA the registry loader
  validates against, a verbatim transcription of the §6.2 block.
* ``contracts/manifest.py::ToolManifest`` — the typed model, whose generated
  schema T1.04 already diffs against §6.2 after a documented canonicalization.

Keeping two is not duplication, it is the I4 check: a drift in either one is
caught by the other, whereas generating the loader's schema from the model
would make a model bug indistinguishable from correct behaviour. The tests
below pin the loader's copy against the SPEC text (exactly — it is a
transcription, so no canonicalization is permitted), prove the copy is a valid
JSON Schema in its own right, and then assert that both encodings accept and
reject the same manifests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from lsassist.contracts.enums import PermissionClass
from lsassist.contracts.manifest import ToolManifest
from lsassist.tools.registry import MANIFEST_SCHEMA_PATH, load_manifest_schema

# --- SPEC §6.2, copied verbatim from SPEC.md (source of truth, I4) -----------
#
# One whitespace-only reflow: the `permission_class` line is 117 characters in
# SPEC.md and the repository's line limit is 100, so its enum is wrapped. JSON
# whitespace is insignificant, so the parsed object is byte-for-byte the SPEC's;
# `tests/unit/contracts/test_manifest.py` wraps the same line the same way.
# The SHIPPED artifact (src/lsassist/tools/manifest_schema.json) is not linted
# and carries the SPEC text with no reflow at all.

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


def valid_manifest(**overrides: Any) -> dict[str, Any]:
    """A §6.4 ``fs.read``-shaped manifest that satisfies every §6.2 constraint."""
    manifest: dict[str, Any] = {
        "name": "fs.read",
        "version": "1.0.0",
        "purpose": "Read a UTF-8 text file inside the workspace.",
        "input_schema": {"type": "object", "additionalProperties": False},
        "output_schema": {"type": "object", "additionalProperties": False},
        "permission_class": "AUTO_READ",
        "capabilities": {"fs": "read_scoped", "net": "none", "proc": "none"},
        "timeout_s": 10,
        "output_limits": {
            "max_stdout_bytes": 204800,
            "max_stderr_bytes": 65536,
            "max_result_chars": 200000,
        },
        "concurrency": "shared_read",
        "idempotent": True,
        "dry_run": False,
        "rollback": "none",
        "redaction": ["paths", "secrets"],
        "path_scope": "workspace",
        "tests": ["tests/unit/tools/test_readonly_tools.py"],
    }
    manifest.update(overrides)
    return manifest


# ==========================================================================
# 1. the shipped copy IS the SPEC text
# ==========================================================================
def test_shipped_schema_equals_spec_62_exactly() -> None:
    """A transcription, not a derivation: no canonicalization is permitted here."""
    shipped = json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert shipped == SPEC_SCHEMA


def test_shipped_schema_declares_the_2020_12_dialect() -> None:
    assert SPEC_SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert load_manifest_schema()["$schema"] == SPEC_SCHEMA["$schema"]


def test_shipped_schema_is_itself_a_valid_json_schema() -> None:
    """§6.2 validated against the 2020-12 meta-schema."""
    Draft202012Validator.check_schema(load_manifest_schema())


def test_spec_62_required_list_is_the_frozen_fifteen() -> None:
    """Guards the verbatim copy above: §6.2 requires exactly 15 fields (I4)."""
    assert len(SPEC_SCHEMA["required"]) == 15
    assert "path_scope" not in SPEC_SCHEMA["required"]  # the one optional property
    assert sorted(SPEC_SCHEMA["properties"]) == sorted([*SPEC_SCHEMA["required"], "path_scope"])


def test_root_object_forbids_unknown_properties() -> None:
    """The whole point of a manifest contract (§6.2, I4)."""
    assert SPEC_SCHEMA["additionalProperties"] is False
    assert SPEC_SCHEMA["type"] == "object"


def test_permission_class_enum_is_the_contracts_enum() -> None:
    """The manifest class is a CEILING (§7.1); its domain is the kernel's enum."""
    schema_classes = set(SPEC_SCHEMA["properties"]["permission_class"]["enum"])
    assert schema_classes == {member.value for member in PermissionClass}


def test_capability_enums_match_spec_62() -> None:
    capabilities = SPEC_SCHEMA["properties"]["capabilities"]
    assert capabilities["required"] == ["fs", "net", "proc"]
    assert capabilities["properties"]["fs"]["enum"] == ["none", "read_scoped", "write_scoped"]
    assert capabilities["properties"]["net"]["enum"] == ["none", "fetch_allowlist"]
    assert capabilities["properties"]["proc"]["enum"] == ["none", "spawn_argv"]


def test_output_limit_ceilings_match_spec_62() -> None:
    limits = SPEC_SCHEMA["properties"]["output_limits"]["properties"]
    assert limits["max_stdout_bytes"]["maximum"] == 1048576
    assert limits["max_stderr_bytes"]["maximum"] == 262144
    assert limits["max_result_chars"]["maximum"] == 200000
    assert SPEC_SCHEMA["properties"]["timeout_s"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 1800,
    }


# ==========================================================================
# 2. the two encodings agree (I4)
# ==========================================================================
def _schema_accepts(manifest: dict[str, Any]) -> bool:
    return Draft202012Validator(load_manifest_schema()).is_valid(manifest)


def _model_accepts(manifest: dict[str, Any]) -> bool:
    try:
        ToolManifest.model_validate(manifest)
    except ValidationError:
        return False
    return True


def test_both_encodings_accept_a_valid_manifest() -> None:
    manifest = valid_manifest()
    assert _schema_accepts(manifest)
    assert _model_accepts(manifest)


REJECTION_VECTORS: list[tuple[str, dict[str, Any]]] = [
    ("bad name pattern", {"name": "FS.read"}),
    ("name too long", {"name": "a" * 33}),
    ("bad version pattern", {"version": "1.0"}),
    ("purpose over 300", {"purpose": "x" * 301}),
    ("class outside the enum", {"permission_class": "AUTO_EVERYTHING"}),
    ("timeout below 1", {"timeout_s": 0}),
    ("timeout above 1800", {"timeout_s": 1801}),
    ("concurrency outside the enum", {"concurrency": "parallel"}),
    ("rollback outside the enum", {"rollback": "undo"}),
    ("redaction item outside the enum", {"redaction": ["everything"]}),
    ("path_scope outside the enum", {"path_scope": "anywhere"}),
    ("unknown property", {"sandbox_profile": "ws"}),
    (
        "fs capability outside the enum",
        {"capabilities": {"fs": "rw", "net": "none", "proc": "none"}},
    ),
    (
        "stdout cap over 1 MiB",
        {
            "output_limits": {
                "max_stdout_bytes": 1048577,
                "max_stderr_bytes": 1,
                "max_result_chars": 1,
            }
        },
    ),
    (
        "stderr cap over 256 KiB",
        {
            "output_limits": {
                "max_stdout_bytes": 1,
                "max_stderr_bytes": 262145,
                "max_result_chars": 1,
            }
        },
    ),
    (
        "result cap over 200k",
        {
            "output_limits": {
                "max_stdout_bytes": 1,
                "max_stderr_bytes": 1,
                "max_result_chars": 200001,
            }
        },
    ),
]


@pytest.mark.parametrize(
    ("label", "patch"), REJECTION_VECTORS, ids=[label for label, _ in REJECTION_VECTORS]
)
def test_both_encodings_reject_the_same_vectors(label: str, patch: dict[str, Any]) -> None:
    """I4: anything the SPEC schema rejects, the model rejects — and vice versa."""
    manifest = valid_manifest(**patch)
    assert not _schema_accepts(manifest), f"JSON Schema accepted {label}"
    assert not _model_accepts(manifest), f"ToolManifest accepted {label}"


@pytest.mark.parametrize("field", SPEC_SCHEMA["required"])
def test_both_encodings_require_every_field(field: str) -> None:
    manifest = valid_manifest()
    del manifest[field]
    assert not _schema_accepts(manifest), f"JSON Schema accepted a manifest without {field}"
    assert not _model_accepts(manifest), f"ToolManifest accepted a manifest without {field}"


def test_path_scope_is_optional_in_both_encodings() -> None:
    """The one §6.2-optional property; the model defaults it to the strictest value."""
    manifest = valid_manifest()
    del manifest["path_scope"]
    assert _schema_accepts(manifest)
    assert ToolManifest.model_validate(manifest).path_scope == "workspace"


# ==========================================================================
# 3. the MEASURED asymmetry between the two encodings — and its containment
# ==========================================================================
#: Documents §6.2 rejects and ``ToolManifest`` alone ACCEPTS, because pydantic
#: validates in lax mode by default and coerces each of these. T1.04's docstring
#: states the invariant "anything the SPEC schema rejects, the model also
#: rejects"; for these five vectors that is FALSE. Recorded here rather than
#: hidden, because the registry's schema-first order is what contains it, and an
#: invariant nobody has measured is an invariant nobody is enforcing.
LAX_COERCION_VECTORS: list[tuple[str, dict[str, Any]]] = [
    ("idempotent as the string yes", {"idempotent": "yes"}),
    ("idempotent as the string no", {"idempotent": "no"}),
    ("dry_run as the integer 1", {"dry_run": 1}),
    ("timeout_s as a numeric string", {"timeout_s": "10"}),
    (
        "output cap as a numeric string",
        {
            "output_limits": {
                "max_stdout_bytes": "5",
                "max_stderr_bytes": 1,
                "max_result_chars": 1,
            }
        },
    ),
]


@pytest.mark.parametrize(
    ("label", "patch"), LAX_COERCION_VECTORS, ids=[label for label, _ in LAX_COERCION_VECTORS]
)
def test_the_model_alone_is_weaker_than_spec_62(label: str, patch: dict[str, Any]) -> None:
    """The asymmetry itself. If this test starts FAILING, the model got stricter
    (welcome) — update the list and the registry docstring together."""
    manifest = valid_manifest(**patch)
    assert not _schema_accepts(manifest), f"§6.2 should reject {label}"
    assert _model_accepts(manifest), f"the model is expected to coerce {label} today"


def test_lax_mode_normalizes_instead_of_rejecting() -> None:
    """Why the asymmetry matters, concretely.

    Lax mode does not corrupt the value — ``"no"`` becomes ``False``, which is
    what the author meant. The problem is that it ACCEPTS at all: §6.2 says
    these fields are JSON booleans and integers, a manifest is a security
    contract, and a contract that quietly repairs its own violations reports
    conformance it never had. The registry therefore never relies on the model
    to police the document's SHAPE — only its TYPES, after §6.2 has passed.
    """
    assert ToolManifest.model_validate(valid_manifest(idempotent="no")).idempotent is False
    assert ToolManifest.model_validate(valid_manifest(dry_run=1)).dry_run is True
    assert ToolManifest.model_validate(valid_manifest(timeout_s="10")).timeout_s == 10


@pytest.mark.parametrize(
    ("label", "patch"), LAX_COERCION_VECTORS, ids=[label for label, _ in LAX_COERCION_VECTORS]
)
def test_the_loader_rejects_every_lax_vector_anyway(
    label: str, patch: dict[str, Any], tmp_path: Path
) -> None:
    """Containment: ``load_registry`` runs the §6.2 schema BEFORE the model."""
    from lsassist.tools.registry import ToolRegistryError, load_registry

    directory = tmp_path / "manifests"
    directory.mkdir()
    (directory / "fs_read.json").write_text(
        json.dumps(valid_manifest(**patch)), encoding="utf-8"
    )
    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(directory)
    assert "fs_read.json" in str(excinfo.value), label


def test_the_generated_artifact_is_not_the_loader_schema() -> None:
    """Two encodings, two files — never one generated from the other."""
    generated = Path(__file__).resolve().parents[3] / "schemas" / "tool-manifest.schema.json"
    assert generated.is_file()
    assert generated != MANIFEST_SCHEMA_PATH
    assert json.loads(generated.read_text(encoding="utf-8")) != SPEC_SCHEMA
