"""T2.12 RED tests: the TCB LOC checkpoint gate (SPEC §2.3 size budget).

``scripts/loc-count`` is an extensionless executable script, not an importable
module, so every test here drives it as a **subprocess** — the same way CI and
a developer invoke it. No refactor into an importable module was made.

Exit-code contract under test (SPEC §2.3: ≤6,000 target, 8,000 hard stop,
"crossing the ceiling = feature freeze, NOT relaxing the budget"):

===============================================  ====  ==========================
input                                            exit  stderr
===============================================  ====  ==========================
count ≤ target                                   0     (silent)
target < count ≤ hard stop                       0     feature-freeze WARNING
count > hard stop                                1     hard-stop ERROR
manifest entry (TCB) not on disk                 1     manifest drift ERROR
TCB path on disk not covered by the manifest     1     manifest drift ERROR
``tcb-planned`` unit has appeared on disk        1     manifest drift ERROR
manifest missing / unreadable / malformed        2     manifest ERROR
a counted ``*.py`` file cannot be parsed         2     parse ERROR
===============================================  ====  ==========================

Counting semantics under test: **tokei-style** — blank lines, ``#`` comments and
module/class/function docstrings are NOT code (SPEC §2.3 mandates a "``tokei``-ის
ექვივალენტი count job", and ``tokei`` classifies Python docstrings as comments).
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "loc-count"
REAL_MANIFEST = REPO_ROOT / "scripts" / "tcb-loc-manifest.txt"

EXIT_OK = 0
EXIT_BUDGET_OR_DRIFT = 1
EXIT_TOOLING = 2


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _code(n: int) -> str:
    """``n`` lines of trivially valid, non-blank, non-comment Python."""
    return "".join(f"x{i} = {i}\n" for i in range(n))


def _tree(tmp_path: Path, name: str = "tree") -> Path:
    root = tmp_path / name
    (root / "src" / "lsassist").mkdir(parents=True)
    return root


def _manifest(root: Path, lines: Iterable[str]) -> Path:
    path = root / "scripts" / "tcb-loc-manifest.txt"
    _write(path, "\n".join(lines) + "\n")
    return path


def _run(
    root: Path | None = None,
    manifest: Path | None = None,
    target: int | None = None,
    hard_stop: int | None = None,
    extra: Sequence[str] = (),
    direct: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd: list[str] = [str(SCRIPT)] if direct else [sys.executable, str(SCRIPT)]
    if root is not None:
        cmd += ["--root", str(root)]
    if manifest is not None:
        cmd += ["--manifest", str(manifest)]
    if target is not None:
        cmd += ["--target", str(target)]
    if hard_stop is not None:
        cmd += ["--hard-stop", str(hard_stop)]
    cmd += list(extra)
    return subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=REPO_ROOT)


def _minimal_fixture(
    tmp_path: Path, kernel_body: str, *, extra_manifest: Sequence[str] = ()
) -> Path:
    """A synthetic repo: one TCB package (``kernel``) + one non-TCB package."""
    root = _tree(tmp_path)
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", kernel_body)
    _write(root / "src" / "lsassist" / "cli" / "__init__.py", _code(500))
    _manifest(
        root,
        [
            "# fixture manifest",
            "tcb      src/lsassist/kernel",
            "non-tcb  src/lsassist/cli",
            *extra_manifest,
        ],
    )
    return root


# --------------------------------------------------------------------------
# exit contract row 1: count ≤ target → exit 0
# --------------------------------------------------------------------------
def test_under_target_exits_zero(tmp_path: Path) -> None:
    root = _minimal_fixture(tmp_path, _code(100))
    res = _run(root, manifest=root / "scripts" / "tcb-loc-manifest.txt")
    assert res.returncode == EXIT_OK, res.stderr
    assert "TCB LOC: 100 / 6000" in res.stdout, res.stdout
    assert "hard stop 8000" in res.stdout, res.stdout
    assert "WARNING" not in res.stderr


def test_non_tcb_package_is_not_counted(tmp_path: Path) -> None:
    """The 500-line non-TCB ``cli`` package must not appear in the total."""
    root = _minimal_fixture(tmp_path, _code(7))
    res = _run(root, manifest=root / "scripts" / "tcb-loc-manifest.txt")
    assert res.returncode == EXIT_OK, res.stderr
    assert "TCB LOC: 7 /" in res.stdout, res.stdout


# --------------------------------------------------------------------------
# exit contract row 2: target < count ≤ hard stop → exit 0 + stderr notice
# --------------------------------------------------------------------------
def test_between_target_and_hard_stop_warns_but_passes(tmp_path: Path) -> None:
    root = _minimal_fixture(tmp_path, _code(6500))
    res = _run(root, manifest=root / "scripts" / "tcb-loc-manifest.txt")
    assert res.returncode == EXIT_OK, res.stderr
    assert "TCB LOC: 6500 / 6000" in res.stdout, res.stdout
    assert "WARNING" in res.stderr, res.stderr
    assert "freeze" in res.stderr.lower(), res.stderr


def test_exactly_at_target_does_not_warn(tmp_path: Path) -> None:
    root = _minimal_fixture(tmp_path, _code(20))
    res = _run(root, manifest=root / "scripts" / "tcb-loc-manifest.txt", target=20, hard_stop=30)
    assert res.returncode == EXIT_OK, res.stderr
    assert res.stderr.strip() == "", res.stderr


def test_exactly_at_hard_stop_warns_but_passes(tmp_path: Path) -> None:
    root = _minimal_fixture(tmp_path, _code(30))
    res = _run(root, manifest=root / "scripts" / "tcb-loc-manifest.txt", target=20, hard_stop=30)
    assert res.returncode == EXIT_OK, res.stderr
    assert "WARNING" in res.stderr, res.stderr


# --------------------------------------------------------------------------
# exit contract row 3: count > hard stop → exit 1
# --------------------------------------------------------------------------
def test_over_hard_stop_exits_one(tmp_path: Path) -> None:
    root = _minimal_fixture(tmp_path, _code(8001))
    res = _run(root, manifest=root / "scripts" / "tcb-loc-manifest.txt")
    assert res.returncode == EXIT_BUDGET_OR_DRIFT, (res.returncode, res.stdout, res.stderr)
    assert "TCB LOC: 8001 / 6000" in res.stdout, res.stdout
    assert "hard stop" in res.stderr.lower(), res.stderr


def test_over_hard_stop_with_custom_thresholds_exits_one(tmp_path: Path) -> None:
    root = _minimal_fixture(tmp_path, _code(31))
    res = _run(root, manifest=root / "scripts" / "tcb-loc-manifest.txt", target=20, hard_stop=30)
    assert res.returncode == EXIT_BUDGET_OR_DRIFT, (res.returncode, res.stdout, res.stderr)


# --------------------------------------------------------------------------
# exit contract row 4: manifest entry missing from disk → exit 1 (drift)
# --------------------------------------------------------------------------
def test_manifest_entry_missing_from_disk_is_drift(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", _code(10))
    manifest = _manifest(
        root,
        [
            "tcb  src/lsassist/kernel",
            "tcb  src/lsassist/policy",  # never created on disk
        ],
    )
    res = _run(root, manifest=manifest)
    assert res.returncode == EXIT_BUDGET_OR_DRIFT, (res.returncode, res.stdout, res.stderr)
    assert "drift" in res.stderr.lower(), res.stderr
    assert "src/lsassist/policy" in res.stderr, res.stderr


def test_renaming_a_tcb_directory_is_drift(tmp_path: Path) -> None:
    """Anti-Goodhart: a rename must not silently zero out a package's LOC."""
    root = _tree(tmp_path)
    # manifest says `policy`; disk says `policy_engine`.
    _write(root / "src" / "lsassist" / "policy_engine" / "__init__.py", _code(400))
    manifest = _manifest(root, ["tcb  src/lsassist/policy"])
    res = _run(root, manifest=manifest)
    assert res.returncode == EXIT_BUDGET_OR_DRIFT, (res.returncode, res.stdout, res.stderr)
    assert "drift" in res.stderr.lower(), res.stderr


# --------------------------------------------------------------------------
# exit contract row 5: TCB path on disk not covered by manifest → exit 1
# --------------------------------------------------------------------------
def test_package_on_disk_absent_from_manifest_is_drift(tmp_path: Path) -> None:
    root = _minimal_fixture(tmp_path, _code(10))
    _write(root / "src" / "lsassist" / "broker" / "__init__.py", _code(900))
    res = _run(root, manifest=root / "scripts" / "tcb-loc-manifest.txt")
    assert res.returncode == EXIT_BUDGET_OR_DRIFT, (res.returncode, res.stdout, res.stderr)
    assert "broker" in res.stderr, res.stderr
    assert "drift" in res.stderr.lower(), res.stderr


def test_toplevel_module_on_disk_absent_from_manifest_is_drift(tmp_path: Path) -> None:
    root = _minimal_fixture(tmp_path, _code(10))
    _write(root / "src" / "lsassist" / "__init__.py", _code(3))
    res = _run(root, manifest=root / "scripts" / "tcb-loc-manifest.txt")
    assert res.returncode == EXIT_BUDGET_OR_DRIFT, (res.returncode, res.stdout, res.stderr)
    assert "__init__.py" in res.stderr, res.stderr


def test_dropping_a_package_from_the_manifest_is_drift(tmp_path: Path) -> None:
    """Anti-Goodhart 2(a): you cannot shrink the number by editing the manifest."""
    root = _tree(tmp_path)
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", _code(10))
    _write(root / "src" / "lsassist" / "policy" / "__init__.py", _code(5000))
    full = _manifest(root, ["tcb  src/lsassist/kernel", "tcb  src/lsassist/policy"])
    assert _run(root, manifest=full).returncode == EXIT_OK

    trimmed = root / "scripts" / "trimmed.txt"
    _write(trimmed, "tcb  src/lsassist/kernel\n")
    res = _run(root, manifest=trimmed)
    assert res.returncode == EXIT_BUDGET_OR_DRIFT, (res.returncode, res.stdout, res.stderr)
    assert "src/lsassist/policy" in res.stderr, res.stderr


# --------------------------------------------------------------------------
# `tcb-planned`: TCB per §2.3 but not yet built
# --------------------------------------------------------------------------
def test_planned_entry_absent_from_disk_is_ok(tmp_path: Path) -> None:
    root = _minimal_fixture(
        tmp_path, _code(10), extra_manifest=["tcb-planned  src/lsassist/cli/dispatcher.py"]
    )
    res = _run(root, manifest=root / "scripts" / "tcb-loc-manifest.txt")
    assert res.returncode == EXIT_OK, res.stderr


def test_planned_entry_that_appeared_is_drift_and_is_still_counted(tmp_path: Path) -> None:
    """A not-yet-built TCB unit cannot arrive uncounted."""
    root = _minimal_fixture(
        tmp_path, _code(10), extra_manifest=["tcb-planned  src/lsassist/cli/dispatcher.py"]
    )
    _write(root / "src" / "lsassist" / "cli" / "dispatcher.py", _code(40))
    res = _run(root, manifest=root / "scripts" / "tcb-loc-manifest.txt")
    assert res.returncode == EXIT_BUDGET_OR_DRIFT, (res.returncode, res.stdout, res.stderr)
    assert "drift" in res.stderr.lower(), res.stderr
    # counted anyway: 10 (kernel) + 40 (the arrived planned unit)
    assert "TCB LOC: 50 /" in res.stdout, res.stdout


def test_partial_package_is_counted_whole(tmp_path: Path) -> None:
    """`tcb-partial` (e.g. config/, TCB only for the secrets resolver) over-counts."""
    root = _tree(tmp_path)
    _write(root / "src" / "lsassist" / "config" / "__init__.py", _code(3))
    _write(root / "src" / "lsassist" / "config" / "secrets.py", _code(7))
    _write(root / "src" / "lsassist" / "config" / "xdg.py", _code(11))
    manifest = _manifest(root, ["tcb-partial  src/lsassist/config"])
    res = _run(root, manifest=manifest)
    assert res.returncode == EXIT_OK, res.stderr
    assert "TCB LOC: 21 /" in res.stdout, res.stdout


# --------------------------------------------------------------------------
# exit contract rows 6-7: fail closed on tooling failure
# --------------------------------------------------------------------------
def test_missing_manifest_is_nonzero(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", _code(10))
    res = _run(root, manifest=root / "scripts" / "does-not-exist.txt")
    assert res.returncode == EXIT_TOOLING, (res.returncode, res.stdout, res.stderr)
    assert "TCB LOC:" not in res.stdout, "must not report a passing number"


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file mode bits")
def test_unreadable_manifest_is_nonzero(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", _code(10))
    manifest = _manifest(root, ["tcb  src/lsassist/kernel"])
    manifest.chmod(0o000)
    try:
        res = _run(root, manifest=manifest)
    finally:
        manifest.chmod(0o644)
    assert res.returncode != EXIT_OK, (res.returncode, res.stdout)
    assert "TCB LOC:" not in res.stdout, "must not report a passing number"


def test_malformed_manifest_line_is_nonzero(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", _code(10))
    manifest = _manifest(root, ["tcb  src/lsassist/kernel", "banana  src/lsassist/policy"])
    res = _run(root, manifest=manifest)
    assert res.returncode == EXIT_TOOLING, (res.returncode, res.stdout, res.stderr)
    assert "banana" in res.stderr, res.stderr


def test_duplicate_manifest_path_is_nonzero(tmp_path: Path) -> None:
    root = _minimal_fixture(tmp_path, _code(10), extra_manifest=["tcb  src/lsassist/kernel"])
    res = _run(root, manifest=root / "scripts" / "tcb-loc-manifest.txt")
    assert res.returncode == EXIT_TOOLING, (res.returncode, res.stdout, res.stderr)
    assert "duplicate path" in res.stderr.lower(), res.stderr


def test_unparseable_python_file_fails_closed(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", "def broken(:\n")
    manifest = _manifest(root, ["tcb  src/lsassist/kernel"])
    res = _run(root, manifest=manifest)
    assert res.returncode == EXIT_TOOLING, (res.returncode, res.stdout, res.stderr)
    assert "TCB LOC:" not in res.stdout, "must not report a passing number"


def test_undecodable_python_file_fails_closed(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    path = root / "src" / "lsassist" / "kernel" / "__init__.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x = 1\n\xff\xfe\x00 not utf-8\n")
    manifest = _manifest(root, ["tcb  src/lsassist/kernel"])
    res = _run(root, manifest=manifest)
    assert res.returncode == EXIT_TOOLING, (res.returncode, res.stdout, res.stderr)


# --------------------------------------------------------------------------
# tokei-style counting semantics
# --------------------------------------------------------------------------
DOCSTRING_HEAVY = '''"""Module docstring line 1.

line 3
line 4
line 5
line 6
line 7
line 8
line 9
line 10
"""


def f():
    """Function docstring.

    more
    more
    more
    more
    more
    more
    """
    return 1


class C:
    """Class docstring.

    more
    more
    more
    """

    x = 1
'''


def test_docstrings_count_as_comments_not_code(tmp_path: Path) -> None:
    """A ~90%-docstring file counts only its code lines (tokei semantics)."""
    root = _tree(tmp_path)
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", DOCSTRING_HEAVY)
    manifest = _manifest(root, ["tcb  src/lsassist/kernel"])
    res = _run(root, manifest=manifest)
    assert res.returncode == EXIT_OK, res.stderr
    # code lines: `def f():`, `return 1`, `class C:`, `x = 1` == 4
    assert "TCB LOC: 4 /" in res.stdout, res.stdout


def test_both_numbers_are_reported(tmp_path: Path) -> None:
    """The measurement correction must be auditable: code AND docstring counts."""
    root = _tree(tmp_path)
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", DOCSTRING_HEAVY)
    manifest = _manifest(root, ["tcb  src/lsassist/kernel"])
    res = _run(root, manifest=manifest)
    assert res.returncode == EXIT_OK, res.stderr
    # 23 non-blank docstring lines are excluded from the code count.
    assert "+23 docstring lines not counted" in res.stdout, res.stdout


def test_blank_and_hash_comment_lines_are_not_code(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    body = "\n".join(
        ["# a comment", "", "   ", "x = 1", "   # indented comment", "y = 2  # trailing"]
    )
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", body + "\n")
    manifest = _manifest(root, ["tcb  src/lsassist/kernel"])
    res = _run(root, manifest=manifest)
    assert res.returncode == EXIT_OK, res.stderr
    assert "TCB LOC: 2 /" in res.stdout, res.stdout


def test_non_docstring_string_literals_are_code(tmp_path: Path) -> None:
    """Stricter than tokei on purpose: a data triple-quote is code, not a comment."""
    root = _tree(tmp_path)
    body = 'BANNER = """\nline\nline\n"""\n'
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", body)
    manifest = _manifest(root, ["tcb  src/lsassist/kernel"])
    res = _run(root, manifest=manifest)
    assert res.returncode == EXIT_OK, res.stderr
    assert "TCB LOC: 4 /" in res.stdout, res.stdout


def test_docstring_sharing_a_line_with_code_still_counts_that_line(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", 'def f(): """doc"""\n')
    manifest = _manifest(root, ["tcb  src/lsassist/kernel"])
    res = _run(root, manifest=manifest)
    assert res.returncode == EXIT_OK, res.stderr
    assert "TCB LOC: 1 /" in res.stdout, res.stdout


def test_nested_packages_are_counted_recursively(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    _write(root / "src" / "lsassist" / "kernel" / "__init__.py", _code(2))
    _write(root / "src" / "lsassist" / "kernel" / "sub" / "deep.py", _code(3))
    manifest = _manifest(root, ["tcb  src/lsassist/kernel"])
    res = _run(root, manifest=manifest)
    assert res.returncode == EXIT_OK, res.stderr
    assert "TCB LOC: 5 /" in res.stdout, res.stdout


# --------------------------------------------------------------------------
# the real repository + backwards compatibility
# --------------------------------------------------------------------------
def test_real_manifest_exists_and_repo_passes_the_gate() -> None:
    assert REAL_MANIFEST.is_file(), f"missing {REAL_MANIFEST}"
    res = _run(manifest=REAL_MANIFEST, target=6000, hard_stop=8000)
    assert res.returncode == EXIT_OK, (res.returncode, res.stdout, res.stderr)
    assert "TCB LOC:" in res.stdout, res.stdout


def test_no_arg_invocation_still_works() -> None:
    """The ledger and other tasks call `./scripts/loc-count` with no flags."""
    res = _run(direct=True)
    assert res.returncode == EXIT_OK, (res.returncode, res.stdout, res.stderr)
    assert "TCB LOC:" in res.stdout, res.stdout
    assert "/ 6000 (hard stop 8000)" in res.stdout, res.stdout


def test_defaults_match_spec_2_3() -> None:
    res = _run()
    assert "/ 6000 (hard stop 8000)" in res.stdout, res.stdout


def test_real_manifest_covers_every_toplevel_src_entry() -> None:
    """The shipped manifest must classify every top-level src/lsassist entry."""
    src = REPO_ROOT / "src" / "lsassist"
    listed = {
        line.split("#", 1)[0].split()[1]
        for line in REAL_MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.split("#", 1)[0].split()
    }
    for entry in sorted(src.iterdir()):
        if entry.name == "__pycache__" or entry.name.startswith("."):
            continue
        if not entry.is_dir() and entry.suffix != ".py":
            continue
        rel = entry.relative_to(REPO_ROOT).as_posix()
        assert rel in listed, f"{rel} is not classified in {REAL_MANIFEST.name}"


def test_real_manifest_lists_every_spec_2_3_tcb_unit() -> None:
    """SPEC §2.3 TCB units must be counted, not merely mentioned."""
    text = REAL_MANIFEST.read_text(encoding="utf-8")
    counted = {
        parts[1]
        for line in text.splitlines()
        if (parts := line.split("#", 1)[0].split())
        and parts[0] in {"tcb", "tcb-partial", "tcb-planned"}
    }
    for pkg in ("kernel", "policy", "sandbox", "audit", "recovery", "config", "contracts"):
        assert f"src/lsassist/{pkg}" in counted, f"{pkg} is TCB per §2.3 but not counted"
    assert any("tools" in path for path in counted), "tools dispatcher core (§2.3) not tracked"
