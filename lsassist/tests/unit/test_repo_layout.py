"""T1.02 RED test: repository layout per SPEC §22 and packaging bootstrap.

Asserts:
1. Every SPEC §22 package directory exists with an ``__init__.py``.
2. ``pyproject.toml`` parses and declares ``requires-python = ">=3.12"``.
3. ``scripts/loc-count`` is executable and reports 0 TCB LOC on an empty tree.
4. ``.github/workflows/ci.yml`` exists **at the git root**, is valid YAML, and
   defines the three gate jobs: ``ruff``, ``unit``, ``loc-count``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The git root, one level ABOVE the Python project root. The repository was
#: re-rooted here on 2026-07-26 (`chore: re-root repository at project top
#: level`), so `lsassist/` is now a subdirectory of the checkout rather than the
#: checkout itself. GitHub Actions only executes workflows found at the
#: repository root, which is why `.github/` may not live beside `pyproject.toml`.
GIT_ROOT = REPO_ROOT.parent

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

    # Empty tree: every unit the manifest declares as counted-and-must-exist is
    # present but contains no code. Derived FROM the manifest rather than
    # hard-coded, so adding a TCB unit (T3.02 added the file-level
    # `src/lsassist/tools/dispatcher.py` row) does not silently redden a T1.02
    # test that was only ever asserting "no code means no LOC".
    empty_root = tmp_path / "empty-tree"
    manifest = (REPO_ROOT / "scripts" / "tcb-loc-manifest.txt").read_text(encoding="utf-8")
    for line in manifest.splitlines():
        stripped = line.split("#", 1)[0].split()
        if len(stripped) != 2 or stripped[0] not in {"tcb", "tcb-partial"}:
            continue
        target = empty_root / stripped[1]
        if target.suffix == ".py":
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("", encoding="utf-8")
        else:
            target.mkdir(parents=True, exist_ok=True)
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
    ci = GIT_ROOT / ".github" / "workflows" / "ci.yml"
    assert ci.is_file(), ".github/workflows/ci.yml missing at the git root"
    workflow = _load_ci_workflow(ci)  # raises if not valid YAML(JSON subset)
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict), "ci.yml has no jobs mapping"
    for job in ("ruff", "unit", "loc-count"):
        assert job in jobs, f"ci.yml missing job: {job}"


def test_ci_workflow_is_at_the_git_root_not_the_project_root() -> None:
    """A workflow below the repository root is INERT — Actions never runs it.

    Regression pin for the 2026-07-26 re-root: `.github/` stayed inside
    `lsassist/` while the checkout root moved one level up, so all five gate
    jobs silently stopped running on push while the file still looked correct.
    A gate that does not execute is indistinguishable from a passing gate, so
    the location is asserted in both directions.
    """
    assert not (REPO_ROOT / ".github").exists(), (
        f"{REPO_ROOT / '.github'} exists: a workflow below the repository root is "
        "never executed by GitHub Actions"
    )


def test_ci_run_steps_resolve_against_the_project_root() -> None:
    """`actions/checkout` lands at the git root, one level above `pyproject.toml`.

    Every `run:` step is written relative to `lsassist/` (`scripts/loc-count`,
    `-r requirements.lock`, `tests/unit`), so the workflow-level `defaults`
    is what keeps them resolvable after the re-root.
    """
    workflow = _load_ci_workflow(GIT_ROOT / ".github" / "workflows" / "ci.yml")
    working_directory = workflow.get("defaults", {}).get("run", {}).get("working-directory")
    assert working_directory == "lsassist", (
        f"defaults.run.working-directory={working_directory!r}; every run: step in this "
        "workflow is relative to the project root, not the checkout root"
    )


def test_ci_hashfiles_paths_are_checkout_relative() -> None:
    """`hashFiles()` resolves against GITHUB_WORKSPACE, NOT `working-directory`.

    `defaults.run` only governs `run:` steps. A `hashFiles('requirements.lock')`
    left project-relative silently returns the empty string after the re-root,
    collapsing the pip cache key to a constant that no longer tracks the locks.
    """
    raw = (GIT_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for match in re.finditer(r"hashFiles\(([^)]*)\)", raw):
        for argument in re.findall(r"'([^']*)'", match.group(1)):
            assert argument.startswith("lsassist/"), (
                f"hashFiles argument {argument!r} is project-relative; it resolves "
                "against the checkout root and will match nothing"
            )
            assert (GIT_ROOT / argument).is_file(), f"hashFiles references a missing {argument!r}"
