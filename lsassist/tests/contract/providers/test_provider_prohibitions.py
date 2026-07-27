"""T3.08 RED (contract): the §2.2/§5.1 adapter prohibitions, enforced by AST.

SPEC §2.2, ``providers/`` row — may import: ``contracts`` (httpx);
**forbidden: subprocess, fs writes, tools, kernel**. SPEC §5.1 adds:
"Adapter-ში აკრძალულია: subprocess, fs writes, tool execution,
credential-ების logging."

**WHY AST AND NOT GREP.** ``providers/base.py`` must itself contain the strings
``"subprocess"``, ``"open"`` and ``"logging"`` — they are the prohibition data
the checker consumes. A grep-based gate would flag its own rule list, and the
usual way that gets "fixed" is by exempting the file that carries the rules.
Parsing the tree instead means a name is only a violation when it is an actual
``import`` or ``Call`` node, so the list can live beside the code it governs.
This mirrors HARDEN-02's AST-verified purity check on ``contracts/``.

The scan covers EVERY module under ``src/lsassist/providers/``, not just
``base.py``: the invariant is a property of the package, and T3.09/T3.11 add the
adapters that actually make a network call. A gate that only looks at today's
file is a gate that expires at the next commit.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from lsassist.providers.base import (
    ADAPTER_PROHIBITED_CALLS,
    ADAPTER_PROHIBITED_METHODS,
    ADAPTER_PROHIBITED_MODULES,
    ADAPTER_PROHIBITED_PACKAGES,
    ADAPTER_PROHIBITED_SYMBOLS,
)

SRC_ROOT = Path(__file__).resolve().parents[3] / "src"
PROVIDERS_DIR = SRC_ROOT / "lsassist" / "providers"

#: The one method name below that a legitimate provider WILL want. ``httpx``
#: responses expose ``.read()``, not ``.write()``, so nothing in the §13.1
#: allowlist needs a prohibited method today; this stays empty on purpose, and
#: a future adapter that needs an entry should have to argue for it here.
METHOD_EXEMPTIONS: frozenset[str] = frozenset()


def provider_modules() -> list[Path]:
    return sorted(PROVIDERS_DIR.rglob("*.py"))


def parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _package_of(path: Path) -> list[str]:
    """The dotted package parts of ``path``'s directory, e.g. lsassist.providers."""
    try:
        relative = path.resolve().relative_to(SRC_ROOT)
    except ValueError:  # a planted file outside src/ (the harness's own guards)
        return []
    return list(relative.parts[:-1])


def imported_modules(tree: ast.Module, path: Path | None = None) -> set[str]:
    """Every module this file imports, with RELATIVE imports resolved.

    ``from ..kernel import decide`` carries ``module="kernel"`` and ``level=2``.
    Reading ``node.module`` alone reports ``kernel``, which matches no entry in
    :data:`ADAPTER_PROHIBITED_PACKAGES` — a two-character change that walked
    through the §2.2 dependency-direction gate. The level is resolved against
    the file's own package so the absolute name is what gets checked.
    """
    package = _package_of(path) if path is not None else []
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level and package:
                base = package[: len(package) - node.level + 1]
                absolute = ".".join([*base, node.module] if node.module else base)
            elif node.module:
                absolute = node.module
            else:
                continue
            names.add(absolute)
            names.add(absolute.split(".")[0])
    return names


def imported_symbols(tree: ast.Module) -> set[str]:
    """Every NAME pulled out of a module by ``from X import name``.

    ``from os import system`` imports ``os``, which is not prohibited (reading
    ``os.environ`` is legitimate), and then calls a bare ``system(...)``. The
    capability travels with the symbol, so the symbol is what gets checked.
    """
    return {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }


def called_names(tree: ast.Module) -> set[str]:
    """Bare function calls (``open(...)``) — not attribute calls."""
    return {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }


def called_methods(tree: ast.Module) -> set[str]:
    """Every attribute CALLED, receiver-independent (``.write_text``).

    Matching ``owner.attr`` instead — ``os.open``, ``Path.write_text`` — only
    catches the unbound form nobody writes. ``Path(p).write_text(t)`` has a
    ``Call`` as its receiver and ``p.write_text(t)`` has a local variable; both
    passed. The METHOD is the capability, and the receiver is only how you spell
    reaching it, so the receiver is deliberately not part of the match.
    """
    return {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }


# ==========================================================================
# 1. the package exists and is being scanned
# ==========================================================================
def test_the_scan_actually_covers_files() -> None:
    """A gate over an empty file list passes vacuously — assert it does not."""
    modules = provider_modules()
    assert modules, f"no provider modules found under {PROVIDERS_DIR}"
    assert (PROVIDERS_DIR / "base.py") in modules


# ==========================================================================
# 2. §2.2 / §5.1 prohibitions
# ==========================================================================
@pytest.mark.parametrize("path", provider_modules(), ids=lambda p: p.name)
def test_no_prohibited_module_import(path: Path) -> None:
    """subprocess (§2.2, §5.1) and logging (no credential can reach a log sink)."""
    violations = imported_modules(parse(path)) & ADAPTER_PROHIBITED_MODULES
    assert not violations, f"{path.name} imports {sorted(violations)} (SPEC §2.2/§5.1)"


@pytest.mark.parametrize("path", provider_modules(), ids=lambda p: p.name)
def test_no_prohibited_symbol_import(path: Path) -> None:
    """``from os import system`` names no prohibited module and no prohibited call."""
    violations = imported_symbols(parse(path)) & ADAPTER_PROHIBITED_SYMBOLS
    assert not violations, f"{path.name} imports {sorted(violations)} (SPEC §2.2/§5.1)"


@pytest.mark.parametrize("path", provider_modules(), ids=lambda p: p.name)
def test_no_inward_package_import(path: Path) -> None:
    """§2.2 dependency direction: providers may reach contracts, nothing deeper."""
    imported = imported_modules(parse(path), path)
    violations = {
        name
        for name in imported
        for forbidden in ADAPTER_PROHIBITED_PACKAGES
        if name == forbidden or name.startswith(forbidden + ".")
    }
    assert not violations, f"{path.name} imports {sorted(violations)} (SPEC §2.2)"


@pytest.mark.parametrize("path", provider_modules(), ids=lambda p: p.name)
def test_no_prohibited_bare_call(path: Path) -> None:
    """``open`` is an fs write vector; ``print`` is an unaudited output sink."""
    violations = called_names(parse(path)) & ADAPTER_PROHIBITED_CALLS
    assert not violations, f"{path.name} calls {sorted(violations)} (SPEC §2.2/§5.1)"


@pytest.mark.parametrize("path", provider_modules(), ids=lambda p: p.name)
def test_no_filesystem_or_process_method_call(path: Path) -> None:
    violations = called_methods(parse(path)) & ADAPTER_PROHIBITED_METHODS - METHOD_EXEMPTIONS
    assert not violations, f"{path.name} calls .{sorted(violations)} (SPEC §2.2/§5.1)"


@pytest.mark.parametrize("path", provider_modules(), ids=lambda p: p.name)
def test_only_the_allowed_lsassist_package_is_imported(path: Path) -> None:
    """The positive form of §2.2: contracts is the ONLY inward edge permitted."""
    internal = {n for n in imported_modules(parse(path), path) if n.startswith("lsassist.")}
    allowed = {"lsassist.contracts", "lsassist.providers"}
    unexpected = {
        name
        for name in internal
        if not any(name == root or name.startswith(root + ".") for root in allowed)
    }
    assert not unexpected, f"{path.name} imports {sorted(unexpected)}; §2.2 allows contracts only"


# ==========================================================================
# 3. the checker cannot pass vacuously (mutation guards on the harness itself)
# ==========================================================================
def test_the_import_detector_finds_a_planted_violation(tmp_path: Path) -> None:
    planted = tmp_path / "bad.py"
    planted.write_text("import subprocess\n", encoding="utf-8")
    assert "subprocess" in imported_modules(parse(planted))


def test_the_import_detector_sees_a_from_import(tmp_path: Path) -> None:
    planted = tmp_path / "bad.py"
    planted.write_text("from subprocess import run\n", encoding="utf-8")
    assert "subprocess" in imported_modules(parse(planted))


def test_the_import_detector_sees_a_dotted_package(tmp_path: Path) -> None:
    planted = tmp_path / "bad.py"
    planted.write_text("from lsassist.tools.registry import load_registry\n", encoding="utf-8")
    assert "lsassist.tools.registry" in imported_modules(parse(planted))


def test_the_call_detector_finds_open_and_print(tmp_path: Path) -> None:
    planted = tmp_path / "bad.py"
    planted.write_text("def f():\n    print(open('/etc/passwd').read())\n", encoding="utf-8")
    calls = called_names(parse(planted))
    assert {"open", "print"} <= calls


def test_the_method_detector_finds_os_open(tmp_path: Path) -> None:
    planted = tmp_path / "bad.py"
    planted.write_text("import os\ndef f():\n    os.open('/tmp/x', 0)\n", encoding="utf-8")
    assert "open" in called_methods(parse(planted))


# --- the six bypasses an adversarial critic round reproduced on the first draft
def test_the_gate_sees_a_symbol_imported_out_of_an_allowed_module(tmp_path: Path) -> None:
    """`from os import system` names neither a prohibited module nor a prohibited
    call site — the two-word change that bypassed the whole gate."""
    planted = tmp_path / "bad.py"
    planted.write_text("from os import system\ndef f():\n    system('id')\n", encoding="utf-8")
    tree = parse(planted)
    assert imported_symbols(tree) & ADAPTER_PROHIBITED_SYMBOLS
    assert called_names(tree) & ADAPTER_PROHIBITED_CALLS


@pytest.mark.parametrize(
    "source",
    [
        "from pathlib import Path\ndef f(p, t):\n    Path(p).write_text(t)\n",
        "def f(p, t):\n    p.write_text(t)\n",
        "import sys\ndef f(m):\n    sys.stderr.write(m)\n",
        "import importlib\ndef f():\n    importlib.import_module('subprocess')\n",
    ],
    ids=["Path(p).write_text", "var.write_text", "sys.stderr.write", "importlib"],
)
def test_the_method_detector_is_receiver_independent(tmp_path: Path, source: str) -> None:
    """All four were MISSED when the match was on ``receiver.attr``."""
    planted = tmp_path / "bad.py"
    planted.write_text(source, encoding="utf-8")
    assert called_methods(parse(planted)) & ADAPTER_PROHIBITED_METHODS


def test_a_relative_inward_import_is_resolved_to_its_absolute_name(tmp_path: Path) -> None:
    """`from ..kernel import decide` reported `kernel`, which matches no §2.2 entry."""
    planted = SRC_ROOT / "lsassist" / "providers" / "__init__.py"
    tree = ast.parse("from ..kernel import decide\n")
    resolved = imported_modules(tree, planted)
    assert "lsassist.kernel" in resolved, resolved


def test_a_prohibited_name_inside_a_string_is_not_a_violation() -> None:
    """The reason this gate parses instead of grepping (see the module docstring)."""
    source = ast.parse('BANNED = frozenset({"subprocess", "logging", "open", "print"})\n')
    assert not imported_modules(source) & ADAPTER_PROHIBITED_MODULES
    assert not called_names(source) & ADAPTER_PROHIBITED_CALLS


# ==========================================================================
# 4. I16 — reasoning_opaque never becomes serializable from this package
# ==========================================================================
@pytest.mark.parametrize("path", provider_modules(), ids=lambda p: p.name)
def test_no_module_reads_reasoning_opaque_into_a_dump(path: Path) -> None:
    """An adapter may CARRY the blob; it may never move it into a dict/dump.

    ``AssistantTurn.reasoning_opaque`` is ``Field(exclude=True)``, so the only
    way it reaches a serializable structure is if code copies it out by hand.
    """
    tree = parse(path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "reasoning_opaque":
            parent_is_construction = isinstance(node.ctx, ast.Store)
            assert parent_is_construction, (
                f"{path.name} READS .reasoning_opaque; the blob is RAM-only (I16) and "
                "reading it is how it escapes into a dump"
            )
