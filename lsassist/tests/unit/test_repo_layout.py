"""T1.02 RED test: repository layout per SPEC §22 and packaging bootstrap.

Asserts:
1. Every SPEC §22 package directory exists with an ``__init__.py``.
2. ``pyproject.toml`` parses and declares ``requires-python = ">=3.12"``.
3. ``scripts/loc-count`` is executable and reports 0 TCB LOC on an empty tree.
4. ``.github/workflows/ci.yml`` exists, is valid YAML, and defines the three
   gate jobs: ``ruff``, ``unit``, ``loc-count``.
"""

from __future__ import annotations

import json
import os
import subprocess
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# SPEC §22 src/lsassist package tree.
PACKAGES = [
    "contracts",
    "kernel",
    "policy",
    "tools",
    "sandbox",
    "providers",
    "memory",
    "skills",
    "audit",
    "recovery",
    "config",
    "tutor",
    "coding",
    "cli",
]

# SPEC §22 test layers.
TEST_LAYERS = ["unit", "property", "contract", "integration", "e2e", "redteam", "evals"]


def test_spec22_package_tree_exists() -> None:
    src = REPO_ROOT / "src" / "lsassist"
    assert (src / "__init__.py").is_file(), "src/lsassist/__init__.py missing"
    assert (src / "__main__.py").is_file(), "src/lsassist/__main__.py missing"
    for pkg in PACKAGES:
        pkg_dir = src / pkg
        assert pkg_dir.is_dir(), f"missing package dir: {pkg_dir}"
        assert (pkg_dir / "__init__.py").is_file(), f"missing {pkg_dir}/__init__.py"


def test_spec22_test_layers_exist() -> None:
    tests = REPO_ROOT / "tests"
    for layer in TEST_LAYERS:
        layer_dir = tests / layer
        assert layer_dir.is_dir(), f"missing test layer: {layer_dir}"
        assert (layer_dir / "__init__.py").is_file(), f"missing {layer_dir}/__init__.py"


def test_pyproject_requires_python() -> None:
    pyproject = REPO_ROOT / "pyproject.toml"
    assert pyproject.is_file(), "pyproject.toml missing"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    assert data["project"]["requires-python"] == ">=3.12"


def test_loc_count_executable_and_empty_tree_zero(tmp_path: Path) -> None:
    script = REPO_ROOT / "scripts" / "loc-count"
    assert script.is_file(), "scripts/loc-count missing"
    assert os.access(script, os.X_OK), "scripts/loc-count is not executable"

    # Empty tree: all TCB package dirs present but containing no code.
    empty_root = tmp_path / "empty-tree"
    for pkg in ["kernel", "policy", "sandbox", "audit", "recovery", "config", "contracts"]:
        (empty_root / "src" / "lsassist" / pkg).mkdir(parents=True)
    result = subprocess.run(
        [str(script), "--root", str(empty_root)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"loc-count failed: {result.stderr}"
    assert "TCB LOC: 0" in result.stdout, f"unexpected output: {result.stdout!r}"


def _load_ci_workflow(path: Path) -> dict:
    """Parse the CI workflow.

    The workflow file is written in the JSON subset of YAML 1.2 (JSON is
    valid YAML), so ``json.loads`` doubles as a YAML validity proof without
    adding PyYAML to the §13.1 dependency allowlist.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def test_ci_workflow_skeleton() -> None:
    ci = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert ci.is_file(), ".github/workflows/ci.yml missing"
    workflow = _load_ci_workflow(ci)  # raises if not valid YAML(JSON subset)
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict), "ci.yml has no jobs mapping"
    for job in ("ruff", "unit", "loc-count"):
        assert job in jobs, f"ci.yml missing job: {job}"
