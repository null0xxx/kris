"""Frozen V1 tool-surface contract (SPEC §6.4, ADR-010, I2/I3/I14)."""

from __future__ import annotations

import copy
import json
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from lsassist.tools.registry import DEFAULT_MANIFEST_DIR, ToolRegistry, load_registry

V1_TOOLS = frozenset(
    {
        "fs.read", "fs.list", "fs.find", "sys.info",
        "pkg.query", "git.read", "git.worktree",
        "fs.write", "fs.patch", "test.run", "proc.exec", "net.fetch",
    }
)
FORBIDDEN_NAME_PREFIXES = {
    "shell": ("shell",),
    "privileged/sudo execution": ("sudo", "proc.sudo", "privileged"),
    "package mutation": ("pkg.install", "pkg.remove"),
    "destructive Git": ("git.destructive",),
    "service mutation": ("service",),
    "firewall mutation": ("firewall",),
    "credential access": ("credentials",),
    "external send": ("send",),
    "scheduled execution": ("cron",),
}
SHELL_STRING_FIELDS = frozenset({"shell", "command", "cmd", "command_line", "script"})
SCHEMA_MAPS = ("properties", "patternProperties", "dependentSchemas", "$defs")
SCHEMA_LISTS = ("allOf", "anyOf", "oneOf", "prefixItems")
SCHEMA_SINGLES = ("additionalProperties", "items", "contains", "if", "then", "else", "not", "propertyNames", "unevaluatedProperties", "unevaluatedItems", "contentSchema")  # noqa: E501
V1_AUTHORITY = {
    ("AUTO_READ", "read_scoped", "none", "none"): {"fs.find", "fs.list", "fs.read"}, ("AUTO_SCOPED_WRITE", "write_scoped", "none", "none"): {"fs.patch", "fs.write"},  # noqa: E501
    ("AUTO_READ", "read_scoped", "none", "spawn_argv"): {"git.read"}, ("AUTO_SCOPED_WRITE", "write_scoped", "none", "spawn_argv"): {"git.worktree"},  # noqa: E501
    ("CONFIRM_ONCE", "none", "fetch_allowlist", "none"): {"net.fetch"}, ("AUTO_READ", "none", "none", "spawn_argv"): {"pkg.query", "sys.info"},  # noqa: E501
    ("CONFIRM_ONCE", "write_scoped", "none", "spawn_argv"): {"proc.exec", "test.run"},
}


def _assert_frozen_catalog(registry: ToolRegistry) -> None:
    assert set(registry.names) == V1_TOOLS
    actual: dict[tuple[str, ...], set[str]] = {}
    for name, manifest in registry.items():
        key = (manifest.permission_class.value, manifest.capabilities.fs.value, manifest.capabilities.net.value, manifest.capabilities.proc.value)  # noqa: E501
        actual.setdefault(key, set()).add(name)
    assert actual == V1_AUTHORITY


def _schema_children(schema: Mapping[str, Any]) -> tuple[tuple[str, Mapping[str, Any]], ...]:
    assert not {"$ref", "$dynamicRef"}.intersection(schema), "schema reference is forbidden"
    maps = ((f"{key}.{name}", child) for key in SCHEMA_MAPS for name, child in schema.get(key, {}).items())  # noqa: E501
    lists = ((f"{key}[{index}]", child) for key in SCHEMA_LISTS for index, child in enumerate(schema.get(key, ())))  # noqa: E501
    singles = ((key, child) for key in SCHEMA_SINGLES if isinstance(child := schema.get(key), Mapping) or child is True)  # noqa: E501
    return (*maps, *lists, *singles)


def _assert_explicit_types(schema: Mapping[str, Any], path: str = "input_schema") -> None:
    assert "type" in schema, f"{path} has no explicit type"
    types = (schema["type"],) if isinstance(schema["type"], str) else schema["type"]
    assert "array" not in types or "items" in schema or "prefixItems" in schema, f"{path} array has no typed items"  # noqa: E501
    for name, child in _schema_children(schema):
        _assert_explicit_types(child, f"{path}.{name}")


def _assert_no_shell_fields(schema: Mapping[str, Any], path: str = "input_schema") -> None:
    types = (schema.get("type"),) if isinstance(schema.get("type"), str) else schema.get("type", ())
    if "object" in types:
        assert schema.get("additionalProperties") is False and not schema.get("patternProperties"), f"{path} accepts a shell string"  # noqa: E501
    for field in schema.get("properties", {}):
        lower = field.casefold()
        assert not (lower.startswith(tuple(SHELL_STRING_FIELDS)) or any(f"_{word}" in lower or f"-{word}" in lower or word.title() in field for word in SHELL_STRING_FIELDS)), f"{path} accepts a shell string"  # noqa: E501
    for name, child in _schema_children(schema):
        _assert_no_shell_fields(child, f"{path}.{name}")


def test_registry_is_exactly_the_bidirectional_frozen_v1_catalog() -> None:
    _assert_frozen_catalog(load_registry())


@pytest.mark.parametrize(("capability", "prefixes"), FORBIDDEN_NAME_PREFIXES.items())
def test_registry_excludes_every_privileged_or_absent_family(
    capability: str, prefixes: tuple[str, ...]
) -> None:
    names = load_registry().names
    assert not {
        name
        for name in names
        if any(name == prefix or name.startswith(f"{prefix}.") for prefix in prefixes)
    }, capability


def test_every_input_schema_is_recursively_typed_and_has_no_shell_string_field() -> None:
    for name, manifest in load_registry().items():
        _assert_explicit_types(manifest.input_schema, name)
        _assert_no_shell_fields(manifest.input_schema, name)


def test_exec_argument_surfaces_are_arrays_of_strings() -> None:
    registry = load_registry()
    for tool, field in (("proc.exec", "argv"), ("test.run", "extra_args")):
        schema = registry[tool].input_schema["properties"][field]
        assert schema["type"] == "array"
        assert schema["items"]["type"] == "string"


def test_valid_temporary_shell_manifest_breaks_the_frozen_catalog(
    tmp_path: Path,
) -> None:
    manifests = tmp_path / "manifests"
    shutil.copytree(DEFAULT_MANIFEST_DIR, manifests)
    shell = json.loads((manifests / "sys_info.json").read_text(encoding="utf-8"))
    shell.update(name="shell", purpose="Forbidden shell mutation fixture.")
    (manifests / "shell.json").write_text(json.dumps(shell), encoding="utf-8")
    with pytest.raises(AssertionError):
        _assert_frozen_catalog(load_registry(manifests))


def test_nested_missing_type_and_generic_command_mutations_are_killed() -> None:
    schema = copy.deepcopy(load_registry()["fs.patch"].input_schema)
    del schema["properties"]["blocks"]["items"]["properties"]["replace"]["type"]
    with pytest.raises(AssertionError, match="replace has no explicit type"):
        _assert_explicit_types(schema)
    schema["properties"]["command"] = {"type": "string"}
    with pytest.raises(AssertionError, match="accepts a shell string"):
        _assert_no_shell_fields(schema)


@pytest.mark.parametrize(("keyword", "field"), tuple((key, field) for key in (*SCHEMA_MAPS, *SCHEMA_LISTS, *SCHEMA_SINGLES, "$ref") for field in (None, "shell_command", "command_text", "commandLine")))  # noqa: E501
def test_every_schema_position_and_compound_shell_carrier_is_checked(keyword: str, field: str | None) -> None:  # noqa: E501
    child: dict[str, Any] = {} if field is None else {"type": ["object", "null"], "properties": {field: {"type": "string"}}, "additionalProperties": False}  # noqa: E501
    schema = {"type": "object", "additionalProperties": False, keyword: "#/$defs/x" if keyword == "$ref" else {"x": child} if keyword in SCHEMA_MAPS else [child] if keyword in SCHEMA_LISTS else child}  # noqa: E501
    with pytest.raises(AssertionError, match=r"no explicit type|accepts a shell string|reference"):
        _assert_explicit_types(schema)
        _assert_no_shell_fields(schema)
