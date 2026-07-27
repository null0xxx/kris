"""T3.01 RED: tool registry — immutable §6.2 manifest catalog (SPEC §6.1, I3, I4).

SPEC §6.1: "ყოველი tool = manifest (declarative) + handler (code). Registry =
manifest-ების immutable catalog loaded at startup; cross-tool name shadowing
rejected; runtime re-registration V1-ში არ არსებობს."

Three properties are pinned here, each with its own section:

1. **Fail-closed load.** Every way a manifest directory can be wrong — absent,
   unreadable, malformed JSON, schema-invalid, duplicated name — raises one
   typed :class:`ToolRegistryError` naming the offending file. There is no
   partial catalog and no "skip the bad one and carry on": SPEC §6.3's
   fail-closed rule applies to the startup load, so a broken manifest BLOCKS
   kernel startup rather than silently shipping a smaller tool set. A smaller
   tool set looks benign, which is exactly why it must not be reachable by
   accident.

2. **Immutability + no re-registration.** The catalog is a read-only mapping and
   :class:`ToolRegistry` has no public constructor, so the only way to obtain
   one is :func:`load_registry` reading files off disk. This is the direct
   enforcement of §6.1's "runtime re-registration V1-ში არ არსებობს": a public
   constructor taking a dict IS runtime registration, only spelled differently.

3. **Name shadowing rejected.** Two manifests declaring the same ``name`` is an
   error naming BOTH files, never last-wins or first-wins. A shadowed tool is a
   permission-class ceiling (§6.2) replaced by one an attacker chose.
"""

from __future__ import annotations

import json
import stat
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from lsassist.contracts.manifest import ToolManifest
from lsassist.tools.registry import (
    DEFAULT_MANIFEST_DIR,
    MANIFEST_SCHEMA_PATH,
    ToolRegistry,
    ToolRegistryError,
    load_manifest_schema,
    load_registry,
)

# --- fixtures ----------------------------------------------------------------


def valid_manifest(name: str = "fs.read") -> dict[str, Any]:
    """A minimal manifest that satisfies every §6.2 constraint.

    Modelled on the §6.4 catalog row for ``fs.read`` (AUTO_READ, read_scoped /
    none / none, 10 s, 200 KB result) so the fixture cannot drift into a shape
    the real tools never take.
    """
    return {
        "name": name,
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


def write_manifest(directory: Path, filename: str, manifest: object) -> Path:
    """Serialize ``manifest`` into ``directory/filename`` and return the path."""
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / filename
    target.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return target


REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def manifests_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "manifests"
    directory.mkdir()
    return directory


# ==========================================================================
# 1. the shipped schema artifact
# ==========================================================================
def test_manifest_schema_ships_inside_the_package() -> None:
    """The loader validates against DATA that travels with the code."""
    assert MANIFEST_SCHEMA_PATH.is_file(), f"{MANIFEST_SCHEMA_PATH} missing"
    assert MANIFEST_SCHEMA_PATH.parent.name == "tools"


def test_the_schema_is_declared_as_package_data() -> None:
    """Reproduced: a wheel built from this tree contained ZERO non-.py files.

    ``MANIFEST_SCHEMA_PATH.is_file()`` above passes under the ADR-005 editable
    install no matter what, because an editable install resolves back to the
    source tree — so does ``importlib.resources``. Only the packaging
    declaration itself distinguishes "ships with the code" from "happens to be
    next to the code here". Without it, every non-editable install raised
    ``ToolRegistryError`` from ``load_manifest_schema`` and kernel startup was
    permanently BLOCKED.
    """
    pyproject = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    package_data = pyproject["tool"]["setuptools"]["package-data"]
    globs = package_data["lsassist.tools"]
    assert any(
        MANIFEST_SCHEMA_PATH.match(pattern.split("/")[-1]) for pattern in globs
    ), f"{MANIFEST_SCHEMA_PATH.name} is not covered by {globs}"
    assert "manifests/*.json" in globs, (
        "src/lsassist/tools/manifests/ has no __init__.py, so packages.find never sees it "
        "and a bare *.json glob does not recurse — T3.04's manifests need their own entry"
    )


def test_load_manifest_schema_returns_the_spec_62_object() -> None:
    schema = load_manifest_schema()
    assert schema["additionalProperties"] is False
    assert len(schema["required"]) == 15
    assert schema["properties"]["name"]["pattern"] == r"^[a-z][a-z0-9_.]{1,31}$"


def test_load_manifest_schema_is_fail_closed_on_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ToolRegistryError) as excinfo:
        load_manifest_schema(tmp_path / "nope.json")
    assert "nope.json" in str(excinfo.value)


def test_load_manifest_schema_is_fail_closed_on_malformed_json(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(ToolRegistryError) as excinfo:
        load_manifest_schema(broken)
    assert "broken.json" in str(excinfo.value)


def test_load_manifest_schema_rejects_a_schema_the_metaschema_refuses(tmp_path: Path) -> None:
    """A corrupt schema must not become a permissive schema."""
    bad = tmp_path / "bad-schema.json"
    bad.write_text(json.dumps({"type": "not-a-json-schema-type"}), encoding="utf-8")
    with pytest.raises(ToolRegistryError) as excinfo:
        load_manifest_schema(bad)
    assert "bad-schema.json" in str(excinfo.value)


# ==========================================================================
# 2. happy path
# ==========================================================================
def test_empty_directory_yields_an_empty_catalog(manifests_dir: Path) -> None:
    """§6.4's tools arrive in T3.04+; until then the catalog is legitimately 0."""
    registry = load_registry(manifests_dir)
    assert len(registry) == 0
    assert registry.names == ()


def test_loads_every_manifest_as_a_typed_model(manifests_dir: Path) -> None:
    write_manifest(manifests_dir, "fs_read.json", valid_manifest("fs.read"))
    write_manifest(manifests_dir, "fs_list.json", valid_manifest("fs.list"))

    registry = load_registry(manifests_dir)

    assert registry.names == ("fs.list", "fs.read")  # sorted, deterministic
    assert set(registry) == {"fs.read", "fs.list"}
    assert isinstance(registry["fs.read"], ToolManifest)
    assert registry["fs.read"].permission_class == "AUTO_READ"
    assert registry["fs.read"].timeout_s == 10


def test_registry_is_a_mapping(manifests_dir: Path) -> None:
    write_manifest(manifests_dir, "fs_read.json", valid_manifest("fs.read"))
    registry = load_registry(manifests_dir)

    assert isinstance(registry, Mapping)
    assert "fs.read" in registry
    assert "shell" not in registry
    assert registry.get("shell") is None
    assert [name for name in registry] == ["fs.read"]
    assert list(registry.keys()) == ["fs.read"]


def test_non_json_files_are_ignored(manifests_dir: Path) -> None:
    write_manifest(manifests_dir, "fs_read.json", valid_manifest("fs.read"))
    (manifests_dir / "README.md").write_text("not a manifest\n", encoding="utf-8")
    (manifests_dir / "fs_read.json.bak").write_text("{broken", encoding="utf-8")

    assert load_registry(manifests_dir).names == ("fs.read",)


def test_load_is_deterministic(manifests_dir: Path) -> None:
    for index in range(5):
        write_manifest(manifests_dir, f"tool_{index}.json", valid_manifest(f"t.{index}"))
    first = load_registry(manifests_dir)
    second = load_registry(manifests_dir)
    assert first.names == second.names
    assert first == second


def test_default_manifest_dir_points_inside_the_package() -> None:
    """T3.04+ populates it; T3.01 only fixes where the loader will look."""
    assert DEFAULT_MANIFEST_DIR.name == "manifests"
    assert DEFAULT_MANIFEST_DIR.parent.name == "tools"


# ==========================================================================
# 3. fail-closed load — every rejection names the offending file
# ==========================================================================
def test_missing_directory_is_an_error_not_an_empty_catalog(tmp_path: Path) -> None:
    """A typo'd path yielding 0 tools is a deployment bug that LOOKS safe."""
    absent = tmp_path / "not-here"
    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(absent)
    assert "not-here" in str(excinfo.value)


def test_directory_that_is_actually_a_file_is_an_error(tmp_path: Path) -> None:
    impostor = tmp_path / "manifests"
    impostor.write_text("{}", encoding="utf-8")
    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(impostor)
    assert "manifests" in str(excinfo.value)


@pytest.mark.parametrize(
    "field",
    [
        "name",
        "version",
        "purpose",
        "input_schema",
        "output_schema",
        "permission_class",
        "capabilities",
        "timeout_s",
        "output_limits",
        "concurrency",
        "idempotent",
        "dry_run",
        "rollback",
        "redaction",
        "tests",
    ],
)
def test_missing_required_field_is_rejected(manifests_dir: Path, field: str) -> None:
    manifest = valid_manifest()
    del manifest[field]
    write_manifest(manifests_dir, "fs_read.json", manifest)

    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "fs_read.json" in str(excinfo.value)


def test_unknown_property_is_rejected(manifests_dir: Path) -> None:
    """§6.2 sets additionalProperties: false — an unknown key is a contract break."""
    manifest = valid_manifest()
    manifest["sandbox_profile"] = "ws"
    write_manifest(manifests_dir, "fs_read.json", manifest)

    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "fs_read.json" in str(excinfo.value)


@pytest.mark.parametrize(
    "bad_name",
    [
        "FS.read",  # uppercase
        "1fs.read",  # leading digit
        "f",  # shorter than the 2-char minimum
        "fs read",  # space
        "fs/read",  # path separator
        "fs-read",  # hyphen not in the class
        "a" * 33,  # longer than 32
        "",
    ],
)
def test_name_pattern_is_enforced(manifests_dir: Path, bad_name: str) -> None:
    write_manifest(manifests_dir, "tool.json", valid_manifest(bad_name))
    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "tool.json" in str(excinfo.value)


def test_permission_class_outside_the_enum_is_rejected(manifests_dir: Path) -> None:
    """The manifest class is the CEILING (§6.2/§7.1); an unknown one has no ceiling."""
    manifest = valid_manifest()
    manifest["permission_class"] = "AUTO_ANYTHING"
    write_manifest(manifests_dir, "fs_read.json", manifest)

    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "fs_read.json" in str(excinfo.value)


@pytest.mark.parametrize(
    ("patch", "label"),
    [
        ({"version": "1.0"}, "two-component version"),
        ({"version": "v1.0.0"}, "prefixed version"),
        ({"timeout_s": 0}, "timeout below 1"),
        ({"timeout_s": 1801}, "timeout above 1800"),
        ({"timeout_s": 10.5}, "non-integer timeout"),
        ({"purpose": "x" * 301}, "purpose over 300 chars"),
        ({"concurrency": "parallel"}, "concurrency outside the enum"),
        ({"rollback": "undo"}, "rollback outside the enum"),
        ({"redaction": ["everything"]}, "redaction item outside the enum"),
        ({"path_scope": "anywhere"}, "path_scope outside the enum"),
        ({"idempotent": "yes"}, "non-boolean idempotent"),
        ({"input_schema": "object"}, "non-object input_schema"),
        ({"capabilities": {"fs": "read_scoped", "net": "none"}}, "capabilities missing proc"),
        ({"capabilities": {"fs": "rw", "net": "none", "proc": "none"}}, "fs outside the enum"),
        ({"capabilities": {"fs": "none", "net": "any", "proc": "none"}}, "net outside the enum"),
        ({"capabilities": {"fs": "none", "net": "none", "proc": "shell"}}, "proc outside the enum"),
        (
            {
                "output_limits": {
                    "max_stdout_bytes": 1048577,
                    "max_stderr_bytes": 1,
                    "max_result_chars": 1,
                }
            },
            "stdout cap over 1 MiB",
        ),
        (
            {
                "output_limits": {
                    "max_stdout_bytes": 1,
                    "max_stderr_bytes": 262145,
                    "max_result_chars": 1,
                }
            },
            "stderr cap over 256 KiB",
        ),
        (
            {
                "output_limits": {
                    "max_stdout_bytes": 1,
                    "max_stderr_bytes": 1,
                    "max_result_chars": 200001,
                }
            },
            "result cap over 200k chars",
        ),
        ({"output_limits": {"max_stdout_bytes": 1}}, "output_limits missing keys"),
    ],
)
def test_schema_constraints_are_enforced(
    manifests_dir: Path, patch: dict[str, Any], label: str
) -> None:
    manifest = valid_manifest()
    manifest.update(patch)
    write_manifest(manifests_dir, "fs_read.json", manifest)

    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "fs_read.json" in str(excinfo.value), label


def test_malformed_json_is_rejected(manifests_dir: Path) -> None:
    (manifests_dir / "fs_read.json").write_text('{"name": "fs.read",', encoding="utf-8")
    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "fs_read.json" in str(excinfo.value)


@pytest.mark.parametrize("payload", ["[]", '"fs.read"', "42", "null", "true"])
def test_non_object_manifest_is_rejected(manifests_dir: Path, payload: str) -> None:
    (manifests_dir / "fs_read.json").write_text(payload, encoding="utf-8")
    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "fs_read.json" in str(excinfo.value)


def test_undecodable_bytes_are_rejected(manifests_dir: Path) -> None:
    (manifests_dir / "fs_read.json").write_bytes(b"\xff\xfe not utf-8")
    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "fs_read.json" in str(excinfo.value)


def test_a_symlinked_manifest_is_refused(manifests_dir: Path, tmp_path: Path) -> None:
    """O_NOFOLLOW on the manifest read (the sanctioned §7.5 pattern).

    Defense in depth, not the boundary: anyone who can write into the package's
    manifests directory can also edit ``registry.py``. It costs one open flag
    and closes the one route that does NOT require write access to the code.
    """
    outside = tmp_path / "elsewhere.json"
    outside.write_text(json.dumps(valid_manifest("fs.read")), encoding="utf-8")
    (manifests_dir / "fs_read.json").symlink_to(outside)

    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "fs_read.json" in str(excinfo.value)


def test_a_fifo_named_like_a_manifest_is_refused(manifests_dir: Path) -> None:
    """A non-regular file would make the loader block on open (§7.5 discipline)."""
    import os

    fifo = manifests_dir / "fs_read.json"
    os.mkfifo(fifo)
    assert stat.S_ISFIFO(fifo.lstat().st_mode)

    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "fs_read.json" in str(excinfo.value)


def test_a_directory_named_like_a_manifest_is_refused(manifests_dir: Path) -> None:
    (manifests_dir / "fs_read.json").mkdir()
    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "fs_read.json" in str(excinfo.value)


def test_one_bad_manifest_blocks_the_whole_load(manifests_dir: Path) -> None:
    """No partial catalog: a smaller tool set must not be reachable by accident."""
    write_manifest(manifests_dir, "a_good.json", valid_manifest("a.good"))
    write_manifest(manifests_dir, "b_good.json", valid_manifest("b.good"))
    (manifests_dir / "c_bad.json").write_text("{", encoding="utf-8")

    with pytest.raises(ToolRegistryError):
        load_registry(manifests_dir)


def test_an_unreadable_schema_blocks_the_load(
    manifests_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without §6.2 there is nothing to validate against — refuse, never skip."""
    from lsassist.tools import registry as registry_module

    monkeypatch.setattr(registry_module, "MANIFEST_SCHEMA_PATH", tmp_path / "gone.json")
    write_manifest(manifests_dir, "fs_read.json", valid_manifest("fs.read"))

    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "gone.json" in str(excinfo.value)


# ==========================================================================
# 4. name shadowing (§6.1)
# ==========================================================================
def test_duplicate_name_across_files_is_rejected(manifests_dir: Path) -> None:
    first = write_manifest(manifests_dir, "a_fs_read.json", valid_manifest("fs.read"))
    second = write_manifest(manifests_dir, "z_fs_read.json", valid_manifest("fs.read"))

    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)

    message = str(excinfo.value)
    assert first.name in message, "the error must name the manifest that was shadowed"
    assert second.name in message, "the error must name the shadowing manifest"


def test_shadowing_is_not_resolved_by_load_order(manifests_dir: Path) -> None:
    """Neither first-wins nor last-wins: both orders raise the same way."""
    shadow = valid_manifest("fs.read")
    shadow["permission_class"] = "AUTO_SCOPED_WRITE"  # a raised ceiling
    write_manifest(manifests_dir, "aaa.json", valid_manifest("fs.read"))
    write_manifest(manifests_dir, "zzz.json", shadow)

    with pytest.raises(ToolRegistryError):
        load_registry(manifests_dir)


# ==========================================================================
# 5. immutability and the absence of a re-registration path (§6.1)
# ==========================================================================
def test_registry_has_no_public_constructor() -> None:
    """A constructor taking a mapping IS runtime registration, differently spelled."""
    with pytest.raises(ToolRegistryError):
        ToolRegistry({"shell": valid_manifest("shell")})  # type: ignore[arg-type]


def test_registry_has_no_public_constructor_even_when_empty() -> None:
    with pytest.raises(ToolRegistryError):
        ToolRegistry()  # type: ignore[call-arg]


def test_catalog_rejects_item_assignment(manifests_dir: Path) -> None:
    registry = load_registry(manifests_dir)
    with pytest.raises(TypeError):
        registry["shell"] = valid_manifest("shell")  # type: ignore[index]


def test_catalog_rejects_deletion(manifests_dir: Path) -> None:
    write_manifest(manifests_dir, "fs_read.json", valid_manifest("fs.read"))
    registry = load_registry(manifests_dir)
    with pytest.raises(TypeError):
        del registry["fs.read"]  # type: ignore[attr-defined]


def test_registry_exposes_no_mutation_api() -> None:
    """Grep-style ownership check, mirroring the project's other ownership gates."""
    forbidden = {
        "register",
        "add",
        "add_tool",
        "update",
        "unregister",
        "remove",
        "pop",
        "popitem",
        "clear",
        "setdefault",
        "__setitem__",
        "__delitem__",
    }
    exposed = {name for name in dir(ToolRegistry) if not name.startswith("_")} | {
        name for name in dir(ToolRegistry) if name.startswith("__")
    }
    assert not (forbidden & exposed), f"re-registration surface: {sorted(forbidden & exposed)}"


def test_module_exports_no_registration_function() -> None:
    from lsassist.tools import registry as registry_module

    for exported in registry_module.__all__:
        assert not exported.startswith(("register", "add_", "install_")), exported


# ==========================================================================
# 6. REGRESSION PINS — defects the adversarial critic round reproduced
# ==========================================================================
def test_a_duplicate_json_key_is_rejected(manifests_dir: Path) -> None:
    """Reproduced: ``json.loads`` is last-wins, so a manifest declaring
    ``permission_class`` TWICE loaded silently with whichever copy the parser
    kept — the §6.2/§7.1 permission CEILING decided by parser trivia. Neither
    the JSON Schema nor the model can see the value that was discarded."""
    raw = json.dumps(valid_manifest())
    doubled = raw[:-1] + ', "permission_class": "DENY_ALWAYS"}'
    (manifests_dir / "fs_read.json").write_text(doubled, encoding="utf-8")

    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "duplicate" in str(excinfo.value)
    assert "permission_class" in str(excinfo.value)


def test_a_duplicate_key_in_a_nested_object_is_also_rejected(manifests_dir: Path) -> None:
    raw = json.dumps(valid_manifest())
    doubled = raw.replace('"proc": "none"}', '"proc": "none", "fs": "write_scoped"}', 1)
    (manifests_dir / "fs_read.json").write_text(doubled, encoding="utf-8")
    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert "duplicate" in str(excinfo.value)


def test_a_symlinked_manifests_directory_is_refused(tmp_path: Path) -> None:
    """Reproduced: the per-file ``O_NOFOLLOW`` defends the leaves, so a
    redirected DIRECTORY walked straight past the module's stated discipline."""
    real = tmp_path / "elsewhere"
    real.mkdir()
    write_manifest(real, "fs_read.json", valid_manifest("fs.read"))
    link = tmp_path / "manifests"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(link)
    assert "symlink" in str(excinfo.value)


def test_a_validation_error_message_is_bounded(manifests_dir: Path) -> None:
    """Reproduced: ``jsonschema`` inlines the offending INSTANCE, so a 200 KB
    manifest field produced a 200,000-character exception string."""
    manifest = valid_manifest()
    manifest["purpose"] = "x" * 200_000
    write_manifest(manifests_dir, "fs_read.json", manifest)

    with pytest.raises(ToolRegistryError) as excinfo:
        load_registry(manifests_dir)
    assert len(str(excinfo.value)) < 1000, "the diagnostic must stay readable"
    assert "fs_read.json" in str(excinfo.value)


def test_the_registry_carries_no_unread_issuance_state() -> None:
    """Reproduced: an earlier draft copied the sandbox receipt's issuance
    sentinel, wrote it in ``_issue`` and never read it anywhere — a docstring
    claiming a defense that did not exist. Removed rather than decorated."""
    assert "_issuance" not in ToolRegistry.__slots__


def test_mutating_the_source_directory_does_not_mutate_a_loaded_catalog(
    manifests_dir: Path,
) -> None:
    """"loaded at startup" means the catalog is a snapshot, not a live view."""
    write_manifest(manifests_dir, "fs_read.json", valid_manifest("fs.read"))
    registry = load_registry(manifests_dir)

    write_manifest(manifests_dir, "shell.json", valid_manifest("shell"))

    assert registry.names == ("fs.read",)
    assert "shell" not in registry
