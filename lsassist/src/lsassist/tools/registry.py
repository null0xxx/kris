"""Tool registry — the immutable §6.2 manifest catalog (SPEC §6.1, I3, I4).

SPEC §6.1: "ყოველი tool = manifest (declarative) + handler (code). Registry =
manifest-ების immutable catalog loaded at startup; cross-tool name shadowing
rejected; runtime re-registration V1-ში არ არსებობს."

**THIS MODULE IS NOT A DECIDER.** It answers "which tools exist and what does
each one declare", nothing more. The permission CLASS a manifest carries is a
CEILING (§6.2/§7.1) that :mod:`lsassist.policy.rules` may only raise; the
registry neither interprets nor enforces it. Handlers, dispatch and sandboxing
live elsewhere (T3.02+). Consequently ``tools/`` stays outside the TCB
(``scripts/tcb-loc-manifest.txt``), and only the future ``tools/dispatcher.py``
joins it.

**TWO ENCODINGS OF §6.2, DELIBERATELY.** ``manifest_schema.json`` beside this
module is a VERBATIM transcription of the SPEC §6.2 block, and
:class:`~lsassist.contracts.manifest.ToolManifest` is the typed model whose
generated schema T1.04 already diffs against the same text. Every manifest is
validated by BOTH, in that order. Generating one from the other would collapse
them into a single point of failure where a model bug and correct behaviour are
indistinguishable; ``tests/contract/tools/test_manifest_schema.py`` asserts the
two agree on every accept/reject vector, which is the I4 check.

**FAIL-CLOSED LOAD (§6.3's rule, applied at startup).** Every way the load can
go wrong — directory absent or not a directory, a manifest that is a symlink, a
FIFO or a directory, undecodable bytes, malformed JSON, a non-object document,
a schema violation, a duplicate name, or a missing/invalid §6.2 schema itself —
raises one typed :class:`ToolRegistryError`. There is no partial catalog and no
"skip the broken one": a startup that silently ships a SMALLER tool set looks
benign and reads as success, so it must not be reachable by accident. The kernel
treats the exception as BLOCKED startup.

**NAME SHADOWING IS AN ERROR, NOT A PRECEDENCE RULE.** Two manifests declaring
the same ``name`` raise, naming both files. Neither first-wins nor last-wins is
acceptable: a shadowed tool is a §6.2 permission ceiling replaced by one
somebody else chose, and a precedence rule would make that outcome legal.

**THERE IS NO RE-REGISTRATION PATH.** :class:`ToolRegistry` has no public
constructor — a constructor taking a mapping IS runtime registration, only
spelled differently — and the catalog it wraps is a read-only view.
:func:`load_registry` reading files off disk is the only route to an instance.

This is a MISUSE gate, not a forgery gate, and the difference matters. The
``sandbox`` package's probe receipt carries an issuance sentinel that
``compose_exec_argv`` re-checks, so a token built by ``object.__new__`` is
REFUSED at the point of use. Nothing here consumes such a sentinel — a registry
has no single choke point to re-check it at — so an earlier draft of this module
carried one that was written and never read, and the docstring claimed a defense
that did not exist. It has been removed rather than left as decoration. What
remains is real: no public constructor and no mutable view, which closes the
accidental and API-misuse routes. Code that can call ``object.__new__`` in this
process could also have edited this file.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, final

# `jsonschema` 4.26.0 ships no `py.typed`, and `types-jsonschema` is not in the
# §13.1 allowlist (adding it would need an ADR, as `coverage` did in ADR-011).
# The ignores are INLINE rather than a `[[tool.mypy.overrides]]` entry on
# purpose: a config-level `ignore_missing_imports` would apply tree-wide, so a
# TCB module importing jsonschema later would silently receive `Any`-typed
# symbols under `--strict`. Confined here, the hole cannot spread. With
# `warn_unused_ignores = true` these lines self-expire the day stubs land.
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import (  # type: ignore[import-untyped]
    SchemaError,
)
from jsonschema.exceptions import (
    ValidationError as JsonSchemaValidationError,
)
from pydantic import ValidationError as PydanticValidationError

from lsassist.contracts.manifest import ToolManifest

__all__ = [
    "DEFAULT_MANIFEST_DIR",
    "MANIFEST_SCHEMA_PATH",
    "ToolRegistry",
    "ToolRegistryError",
    "load_manifest_schema",
    "load_registry",
]

#: The §6.2 schema, shipped as DATA beside the code so the loader validates
#: against the SPEC text rather than against a model's opinion of it.
MANIFEST_SCHEMA_PATH: Final[Path] = Path(__file__).resolve().parent / "manifest_schema.json"

#: Where the §6.4 tool manifests live. Populated from T3.04 onwards; today it
#: does not exist, which is why "absent directory" is a first-class, tested
#: outcome rather than an assumption.
DEFAULT_MANIFEST_DIR: Final[Path] = Path(__file__).resolve().parent / "manifests"

#: Only ``*.json`` is a manifest. A README or an editor backup beside them is
#: not a load failure — but anything ending in ``.json`` is, so a broken file
#: cannot hide behind a filter.
_MANIFEST_SUFFIX: Final = ".json"

#: Longest validation message echoed into a :class:`ToolRegistryError`.
#: ``jsonschema`` inlines the offending instance, so an oversized manifest field
#: would otherwise become an oversized exception string.
_MAX_ERROR_CHARS: Final = 400

#: Largest manifest accepted. §6.2 documents are a few hundred bytes; the cap
#: exists so a hostile or corrupt file cannot be read into memory unbounded.
_MAX_MANIFEST_BYTES: Final = 256 * 1024

class ToolRegistryError(Exception):
    """A tool catalog could not be loaded — kernel startup is BLOCKED (§6.1/§6.3).

    Raised for every load failure and by :class:`ToolRegistry`'s blocked
    constructor. Callers must let it propagate: catching it and continuing with
    whatever loaded is the partial catalog this module exists to prevent.
    """


@final
class ToolRegistry(Mapping[str, ToolManifest]):
    """An immutable, name-keyed catalog of validated §6.2 manifests.

    A ``Mapping``, so ``registry["fs.read"]``, ``in``, ``len``, iteration and
    ``.get`` all work — but backed by a :class:`~types.MappingProxyType`, so
    item assignment and deletion raise :exc:`TypeError`. The catalog is a
    SNAPSHOT: writing another manifest into the source directory afterwards does
    not change a loaded registry, which is what "loaded at startup" means.

    Construction raises unconditionally; :func:`load_registry` mints instances
    through :func:`_issue`, which bypasses ``__init__``.
    """

    __slots__ = ("_by_name", "_source")

    _by_name: Mapping[str, ToolManifest]
    _source: Path

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise ToolRegistryError(
            "ToolRegistry has no public constructor; only load_registry() builds one "
            "(SPEC §6.1: no runtime re-registration)"
        )

    def __getitem__(self, name: str) -> ToolManifest:
        return self._by_name[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._by_name)

    def __len__(self) -> int:
        return len(self._by_name)

    def __repr__(self) -> str:
        return f"ToolRegistry({list(self._by_name)!r} from {str(self._source)!r})"

    @property
    def names(self) -> tuple[str, ...]:
        """Every tool name, sorted — the enumeration T3.07 pins against §6.4."""
        return tuple(self._by_name)

    @property
    def source(self) -> Path:
        """The directory this catalog was loaded from (diagnostics only)."""
        return self._source


def _issue(by_name: dict[str, ToolManifest], source: Path) -> ToolRegistry:
    """Mint a catalog WITHOUT running ``__init__`` (the only issuance path)."""
    registry = object.__new__(ToolRegistry)
    object.__setattr__(registry, "_by_name", MappingProxyType(dict(by_name)))
    object.__setattr__(registry, "_source", source)
    return registry


def _read_regular_file(path: Path, *, limit: int) -> bytes:
    """Read ``path`` with ``O_NOFOLLOW`` + an ``fstat`` regular-file re-check.

    The sanctioned filesystem-read pattern of this repository (``§7.5``, and the
    HARDEN-01 fix to ``config/secrets.py``): open the path itself, never follow
    a final-component symlink, and confirm on the OPEN DESCRIPTOR — not on the
    name — that what was opened is a regular file. ``O_NONBLOCK`` keeps a FIFO
    planted under a manifest name from blocking the open forever instead of
    failing.

    Defense in depth here rather than the boundary: the manifests directory sits
    inside the installed package, so an attacker able to write into it could
    equally edit this module. It costs two open flags and closes the one route
    that does not require write access to the code.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise ToolRegistryError(f"{path.name}: cannot be opened ({exc.strerror})") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ToolRegistryError(f"{path.name}: not a regular file")
        if info.st_size > limit:
            raise ToolRegistryError(f"{path.name}: {info.st_size} bytes exceeds the {limit} cap")
        return os.read(fd, limit)
    except OSError as exc:
        raise ToolRegistryError(f"{path.name}: cannot be read ({exc.strerror})") from exc
    finally:
        os.close(fd)


class _DuplicateKey(ValueError):
    """A JSON object declared the same key twice (see :func:`_reject_duplicate_keys`)."""

    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse a JSON object that declares any key twice.

    ``json.loads`` is last-wins by default, and neither the §6.2 JSON Schema nor
    the pydantic model ever sees the discarded value. Measured on the first draft
    of this loader: a manifest carrying BOTH ``"permission_class": "AUTO_READ"``
    and ``"permission_class": "DENY_ALWAYS"`` loaded without complaint as
    ``DENY_ALWAYS``. The permission CEILING (§6.2/§7.1) must never be decided by
    which copy the parser happened to keep — in the other direction that is a
    ceiling silently RAISED, which is what §7.2 forbids the rules from doing.
    """
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise _DuplicateKey(key)
        seen[key] = value
    return seen


def _load_json_document(path: Path) -> dict[str, Any]:
    """Read one UTF-8 JSON object, or raise :class:`ToolRegistryError`."""
    raw = _read_regular_file(path, limit=_MAX_MANIFEST_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ToolRegistryError(f"{path.name}: not valid UTF-8 ({exc})") from exc
    try:
        document = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ToolRegistryError(f"{path.name}: not valid JSON ({exc})") from exc
    except _DuplicateKey as exc:
        raise ToolRegistryError(f"{path.name}: duplicate JSON key {exc.key!r}") from exc
    if not isinstance(document, dict):
        raise ToolRegistryError(
            f"{path.name}: top level is {type(document).__name__}, expected a JSON object"
        )
    return document


def load_manifest_schema(path: Path | str | None = None) -> dict[str, Any]:
    """Load the §6.2 JSON Schema, fail-closed.

    :param path: override, for tests. Defaults to :data:`MANIFEST_SCHEMA_PATH`
        read at call time, so the constant can be monkeypatched.
    :raises ToolRegistryError: the file is missing, unreadable, not UTF-8, not
        JSON, not an object, or not a valid 2020-12 JSON Schema. A schema that
        cannot be validated must never degrade into a permissive one — without
        §6.2 there is nothing to check a manifest against.
    """
    target = Path(path) if path is not None else MANIFEST_SCHEMA_PATH
    schema = _load_json_document(target)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ToolRegistryError(f"{target.name}: not a valid JSON Schema ({exc.message})") from exc
    return schema


def _validate(
    path: Path, document: dict[str, Any], validator: Draft202012Validator
) -> ToolManifest:
    """Check one manifest against BOTH §6.2 encodings (see the module docstring).

    **THE ORDER IS LOAD-BEARING, and this is measured, not assumed.** The JSON
    Schema runs FIRST because the two encodings are not equally strict: pydantic
    validates in lax mode by default, so ``ToolManifest`` alone ACCEPTS five
    documents §6.2 rejects — ``idempotent: "yes"``, ``idempotent: "no"``,
    ``dry_run: 1``, ``timeout_s: "10"``, ``max_stdout_bytes: "5"`` — coercing
    each to the typed value it resembles. The coercion is not WRONG (``"no"``
    becomes ``False``, as the author meant); the problem is that it accepts at
    all. A manifest is a security contract carrying a permission ceiling, and a
    contract that quietly repairs its own violations reports a conformance it
    never had — so §6.2, not the model, decides the document's shape here.

    T1.04 states the invariant as "anything the SPEC schema rejects, the model
    also rejects". For these five vectors that is FALSE; the asymmetry is
    measured and pinned in ``tests/contract/tools/test_manifest_schema.py``.
    Tightening ``ToolManifest`` (``ConfigDict(strict=True)``) would close it at
    the source, but that edits a TCB contract from a non-TCB task, so it is
    recorded as a named residual instead of made silently.
    """
    try:
        validator.validate(document)
    except JsonSchemaValidationError as exc:
        location = "/".join(str(part) for part in exc.absolute_path) or "<root>"
        # jsonschema inlines the offending INSTANCE in `message`, so a manifest
        # with a 200 KB field produced a 200 KB exception string. Bounded here:
        # a diagnostic nobody can read is not a better diagnostic.
        detail = exc.message if len(exc.message) <= _MAX_ERROR_CHARS else (
            exc.message[:_MAX_ERROR_CHARS] + "... (truncated)"
        )
        raise ToolRegistryError(f"{path.name}: §6.2 violation at {location}: {detail}") from exc
    try:
        return ToolManifest.model_validate(document)
    except PydanticValidationError as exc:
        # Reaching this means the two encodings disagree — the contract test
        # exists to keep that impossible, so say so rather than papering over it.
        raise ToolRegistryError(
            f"{path.name}: passed the §6.2 schema but failed the ToolManifest model "
            f"({exc.error_count()} error(s)); the two encodings of §6.2 disagree"
        ) from exc


def _manifest_files(directory: Path) -> list[Path]:
    """Every ``*.json`` entry in ``directory``, sorted, or raise."""
    if directory.is_symlink():
        raise ToolRegistryError(
            f"{directory}: the manifests directory is a symlink; the per-file O_NOFOLLOW "
            "read defends the leaves, so a redirected DIRECTORY would walk straight past it"
        )
    if not directory.is_dir():
        raise ToolRegistryError(
            f"{directory}: manifest directory is absent or not a directory; an empty "
            "catalog is a legitimate state but a missing directory is a deployment error"
        )
    try:
        entries = sorted(directory.iterdir())
    except OSError as exc:
        raise ToolRegistryError(f"{directory}: cannot be listed ({exc.strerror})") from exc
    return [entry for entry in entries if entry.name.endswith(_MANIFEST_SUFFIX)]


def load_registry(directory: Path | str = DEFAULT_MANIFEST_DIR) -> ToolRegistry:
    """Load, validate and freeze the tool catalog (SPEC §6.1) — or raise.

    :param directory: the manifests directory. Must exist; an EMPTY directory
        yields an empty catalog (0 tools is legitimate before T3.04), an ABSENT
        one is an error.
    :returns: an immutable :class:`ToolRegistry` keyed by ``manifest.name``,
        sorted, with no re-registration path.
    :raises ToolRegistryError: for every failure mode listed in the module
        docstring. The catalog is all-or-nothing: no partial registry is ever
        returned, and no manifest is ever skipped.
    """
    source = Path(directory)
    files = _manifest_files(source)
    validator = Draft202012Validator(load_manifest_schema())

    by_name: dict[str, ToolManifest] = {}
    origin: dict[str, Path] = {}
    for path in files:
        manifest = _validate(path, _load_json_document(path), validator)
        if manifest.name in by_name:
            raise ToolRegistryError(
                f"duplicate tool name {manifest.name!r}: declared by both "
                f"{origin[manifest.name].name} and {path.name}; cross-tool name "
                "shadowing is rejected (SPEC §6.1) — it would silently replace one "
                "tool's §6.2 permission ceiling with another's"
            )
        by_name[manifest.name] = manifest
        origin[manifest.name] = path

    return _issue({name: by_name[name] for name in sorted(by_name)}, source)
