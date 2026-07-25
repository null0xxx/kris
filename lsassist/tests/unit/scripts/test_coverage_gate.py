"""T2.13 RED tests: the 100%-branch coverage gate (SPEC §23.1, ADR-011).

This file is **the gate's own gate**. The thing under test is not application
code — it is the *configuration* (``[tool.coverage.*]`` in ``pyproject.toml``)
and the *CI wiring* (``.github/workflows/ci.yml``) that together enforce
SPEC §23.1's floor: ``kernel``/``policy``/``sandbox`` at **100% branch**.

Why a gate needs its own tests
------------------------------
ADR-011's "Named limitation" says it plainly: **coverage measures EXECUTION,
not ASSERTION**. A gate that only checks "did the number say 100" is theatre —
the number can be driven to 100 by weakening the measurement rather than by
covering code. So every test below is an *attack* on the gate, and the gate
must survive it:

===================================  ==========================================
attack                               blocked by
===================================  ==========================================
widen ``exclude_lines``              ``test_exclude_list_does_not_match_real_code``
                                     ``test_pragma_no_cover_cannot_hide_a_line``
                                     ``test_type_checking_guard_is_not_excluded``
                                     ``test_raise_not_implemented_is_not_excluded``
append via ``exclude_also``          ``test_exclude_also_and_partial_also_are_empty``
lower ``fail_under``                 ``test_fail_under_is_exactly_100``
shrink ``source``                    ``test_source_names_every_tcb_package``
                                     ``test_ci_measurement_source_matches_config``
``omit`` / ``include`` carve-out     ``test_no_omit_carve_out`` / ``…_include_…``
turn off branch mode                 ``test_branch_mode_is_on``
                                     ``test_line_only_coverage_would_have_passed``
``# pragma: no branch``              ``test_pragma_no_branch_cannot_hide_an_arc``
**empty both partial lists**         ``test_partial_regex_is_never_match_everything``
drop the pragma grep                 ``test_ci_has_a_pragma_grep_step`` (+ firing)
grep fails open on a rename          ``test_pragma_grep_fails_closed_on_missing_pkg``
make the job non-blocking            ``test_coverage_job_is_blocking``
genuine coverage regression          ``test_gate_fails_on_an_uncovered_branch``
===================================  ==========================================

The ``join_regex("")`` footgun (the reason this file exists)
-----------------------------------------------------------
``coverage.misc.join_regex([])`` returns ``""``, and ``re.finditer("", text)``
matches at **every** position. ``exclude_lines`` is safe from this because
``PythonParser._raw_parse`` guards with ``if self.exclude:`` — but
``PythonFileReporter.no_branch_lines()`` has **no such guard**. So writing::

    partial_branches = []
    partial_branches_always = []

puts *every line in the file* into ``no_branch``, which silently discards every
missing branch arc and reports **100% branch on a suite with no branch tests at
all**. That config change is invisible in a diff review and turns the entire
§23.1 floor into a no-op. ``test_partial_regex_is_never_match_everything`` and
``test_emptying_both_partial_lists_makes_the_gate_vacuous`` exist solely to make
that mutation impossible to land quietly.

Style follows T2.12's ``test_loc_gate.py``: the gate is exercised as a
**subprocess**, the same way CI and a developer invoke it, and ``ci.yml`` is
parsed with ``json.load`` (PyYAML is deliberately not a dependency; the workflow
is written in the JSON subset of YAML).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PYPROJECT = REPO_ROOT / "pyproject.toml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DEV_LOCK = REPO_ROOT / "requirements-dev.lock"

#: SPEC §23.1's floor applies to these three packages at this phase.
#: ``audit``/``recovery`` join the same gate in Phase 4.
TCB_PACKAGES = (
    "src/lsassist/kernel",
    "src/lsassist/policy",
    "src/lsassist/sandbox",
)

#: ``coverage report`` exits 2 when the total is below ``fail_under``.
EXIT_OK = 0

#: Lines that are ordinary, behaviour-carrying Python. None of them may ever be
#: excluded from measurement — if a widened ``exclude_lines`` starts matching one
#: of these, real code has become invisible to the §23.1 floor.
REAL_CODE_LINES = (
    "x = 1",
    "return canonical",
    "if verdict is None:",
    "elif request.tool == 'fs.write':",
    "else:",
    "for entry in entries:",
    "while pending:",
    "raise PolicyError('denied')",
    "raise NotImplementedError",
    "raise NotImplementedError('later')",
    "assert token is not None",
    "import os",
    "from typing import TYPE_CHECKING",
    "if TYPE_CHECKING:",
    "if typing.TYPE_CHECKING:",
    "def classify(self, request):",
    "async def run(self):",
    "return 0  # pragma: no cover",
    "continue",
    "break",
    "pass",
)


# --------------------------------------------------------------------------
# reading the two artifacts under test
# --------------------------------------------------------------------------
def _pyproject() -> dict[str, object]:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)


def _coverage_table() -> dict[str, dict[str, object]]:
    """The raw ``[tool.coverage.*]`` table. Absent → the gate does not exist."""
    tool = _pyproject().get("tool")
    assert isinstance(tool, dict), "pyproject.toml has no [tool] table"
    coverage_table = tool.get("coverage")
    assert isinstance(coverage_table, dict), (
        "pyproject.toml declares no [tool.coverage.*] config — SPEC §23.1's "
        "coverage floor is unenforced (ADR-011)"
    )
    return coverage_table


def _run_table() -> dict[str, object]:
    table = _coverage_table().get("run")
    assert isinstance(table, dict), "missing [tool.coverage.run]"
    return table


def _report_table() -> dict[str, object]:
    table = _coverage_table().get("report")
    assert isinstance(table, dict), "missing [tool.coverage.report]"
    return table


def _ci() -> dict[str, object]:
    """``ci.yml`` is the JSON subset of YAML on purpose — PyYAML is not a dep."""
    with CI_WORKFLOW.open("rb") as handle:
        return json.load(handle)


def _jobs() -> dict[str, dict[str, object]]:
    jobs = _ci()["jobs"]
    assert isinstance(jobs, dict)
    return jobs


def _coverage_job() -> dict[str, object]:
    jobs = _jobs()
    assert "coverage" in jobs, f"ci.yml has no `coverage` job; jobs={sorted(jobs)}"
    return jobs["coverage"]


def _steps(job: dict[str, object]) -> list[dict[str, object]]:
    steps = job["steps"]
    assert isinstance(steps, list)
    return steps


def _run_scripts(job: dict[str, object]) -> list[str]:
    return [str(step["run"]) for step in _steps(job) if "run" in step]


def _step_containing(job: dict[str, object], needle: str) -> str:
    matches = [script for script in _run_scripts(job) if needle in script]
    assert matches, f"no step in the coverage job runs {needle!r}"
    assert len(matches) == 1, f"{needle!r} appears in {len(matches)} steps; expected exactly 1"
    return matches[0]


# --------------------------------------------------------------------------
# fixture harness: drive the REAL config against a throwaway package
# --------------------------------------------------------------------------
#: The config's ``source`` line, rewritten to point at the fixture package. The
#: substitution is asserted to fire exactly once, so a reformat of pyproject.toml
#: makes these tests error loudly rather than silently testing nothing.
_SOURCE_LINE = re.compile(r"^source = \[[^\]]*\]$", re.MULTILINE)


def _fixture_repo(
    tmp_path: Path,
    modules: dict[str, str],
    driver: str,
    *,
    config_patch: tuple[str, str] | None = None,
) -> Path:
    """A throwaway repo whose coverage config IS the repo's, retargeted.

    Everything except ``source`` is copied verbatim from ``pyproject.toml``, so
    these tests exercise the shipped ``branch`` / ``fail_under`` /
    ``exclude_lines`` / ``partial_branches*`` settings rather than a restatement
    of them. ``config_patch`` applies one extra literal substitution, used only
    by the tests that deliberately mutate the config to show what it prevents.
    """
    root = tmp_path / "fixture"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    for name, body in modules.items():
        (root / "pkg" / f"{name}.py").write_text(body, encoding="utf-8")
    (root / "driver.py").write_text(driver, encoding="utf-8")

    config = PYPROJECT.read_text(encoding="utf-8")
    config, count = _SOURCE_LINE.subn('source = ["pkg"]', config)
    assert count == 1, (
        f"expected exactly one `source = [...]` line in pyproject.toml, found {count} — "
        "the fixture harness can no longer retarget the real config"
    )
    if config_patch is not None:
        old, new = config_patch
        assert old in config, f"config_patch anchor {old!r} not found in pyproject.toml"
        config = config.replace(old, new)
    (root / "pyproject.toml").write_text(config, encoding="utf-8")
    return root


def _env() -> dict[str, str]:
    """A clean environment: this suite may itself be running under ``coverage``."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("COVERAGE_")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _coverage(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "coverage", *args, "--rcfile=pyproject.toml"],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
        env=_env(),
    )


def _gate(root: Path) -> subprocess.CompletedProcess[str]:
    """Run the fixture, then apply the gate. Returns the *report* result."""
    measured = _coverage(root, "run", "driver.py")
    assert measured.returncode == EXIT_OK, (measured.stdout, measured.stderr)
    return _coverage(root, "report", "--show-missing")


def _gate_json(root: Path) -> dict[str, object]:
    """Per-file detail, notably ``excluded_lines`` — which the terminal report
    cannot show. ``coverage json`` honours ``fail_under`` too (exit 2) and
    appends its failure notice after the document, so both are tolerated here:
    this helper inspects the measurement, it is not the gate."""
    measured = _coverage(root, "run", "driver.py")
    assert measured.returncode == EXIT_OK, (measured.stdout, measured.stderr)
    reported = _coverage(root, "json", "-o", "-")
    assert reported.returncode in (0, 2), (reported.returncode, reported.stderr)
    document = reported.stdout[: reported.stdout.rindex("}") + 1]
    return json.loads(document)["files"]


# fixture modules ----------------------------------------------------------
#: All five lines execute, but the ``if`` never takes its false arc: **line**
#: coverage is 100%, **branch** coverage is not. This is the shape §23.1's word
#: "branch" exists for.
PARTIAL_BRANCH = """\
def f(x):
    y = 0
    if x:
        y = 1
    return y
"""

PARTIAL_BRANCH_WITH_PRAGMA = """\
def f(x):
    y = 0
    if x:  # pragma: no branch
        y = 1
    return y
"""

MISSING_LINE_WITH_PRAGMA = """\
def f(x):
    if x:
        return 1
    return 0  # pragma: no cover
"""

TYPE_CHECKING_GUARD = """\
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


def f(x):
    return x
"""

NOT_IMPLEMENTED = """\
def f(x):
    if x:
        return 1
    raise NotImplementedError
"""

FULLY_COVERED = """\
def f(x):
    y = 0
    if x:
        y = 1
    return y
"""

DRIVER_TRUE_ONLY = "from pkg.m import f\n\nassert f(True) == 1\n"
DRIVER_BOTH = "from pkg.m import f\n\nassert f(True) == 1\nassert f(False) == 0\n"


# ==========================================================================
# 1. the config exists and says what §23.1 says
# ==========================================================================
def test_pyproject_declares_a_coverage_config() -> None:
    assert _coverage_table(), "no [tool.coverage.*] section"


def test_branch_mode_is_on() -> None:
    """§23.1 says *branch*; line-only coverage passes on untaken arcs."""
    assert _run_table().get("branch") is True, (
        "[tool.coverage.run] branch must be true — SPEC §23.1's floor is BRANCH coverage"
    )


def test_fail_under_is_exactly_100() -> None:
    """100 is special-cased in ``coverage.results.should_fail_under``: at exactly
    100 the total must *really* be 100.0, so rounding cannot buy a pass."""
    assert _report_table().get("fail_under") == 100, (
        "[tool.coverage.report] fail_under must be exactly 100 (SPEC §23.1)"
    )


def test_show_missing_is_on() -> None:
    """A red gate has to name the uncovered arc, or nobody can act on it."""
    assert _report_table().get("show_missing") is True


def test_source_names_every_tcb_package() -> None:
    """Scope shrinking: dropping a package trivially "achieves" the floor."""
    source = _run_table().get("source")
    assert isinstance(source, list), "[tool.coverage.run] source must be a list"
    normalised = {str(entry).rstrip("/") for entry in source}
    for package in TCB_PACKAGES:
        assert package in normalised, f"{package} dropped from the §23.1 coverage scope"
    assert normalised == set(TCB_PACKAGES), (
        f"unexpected extra scope entries: {sorted(normalised - set(TCB_PACKAGES))}"
    )


def test_no_omit_carve_out() -> None:
    """An ``omit`` pattern is a hole in the floor: the file stops being measured."""
    for table_name, table in (("run", _run_table()), ("report", _report_table())):
        omit = table.get("omit")
        assert not omit, f"[tool.coverage.{table_name}] omit={omit!r} carves TCB files out of §23.1"


def test_no_include_carve_out() -> None:
    """``include`` is an allowlist — narrower than ``source`` and easy to shrink."""
    for table_name, table in (("run", _run_table()), ("report", _report_table())):
        include = table.get("include")
        assert not include, (
            f"[tool.coverage.{table_name}] include={include!r} narrows the §23.1 scope; "
            "scope is declared by `source` alone"
        )


def test_ignore_errors_is_off() -> None:
    """``ignore_errors`` hides files coverage could not parse — fail open."""
    assert _report_table().get("ignore_errors") in (None, False)


def test_exclude_also_and_partial_also_are_empty() -> None:
    """``exclude_also``/``partial_also`` are *append* vectors: coverage merges them
    into ``exclude_lines``/``partial_branches`` in ``CoverageConfig.post_process``.
    Asserting only on ``exclude_lines`` would miss this door entirely."""
    report = _report_table()
    for key in ("exclude_also", "partial_also"):
        assert not report.get(key), (
            f"[tool.coverage.report] {key}={report.get(key)!r} widens the exclusion set "
            "behind `exclude_lines`' back (coverage appends it in post_process)"
        )


# ==========================================================================
# 2. the exclusion regexes cannot swallow real code
# ==========================================================================
def _matches(patterns: list[str], line: str) -> bool:
    return any(re.search(pattern, line) for pattern in patterns)


def test_exclude_list_does_not_match_real_code() -> None:
    """Whatever survives in ``exclude_lines`` must not match behaviour-carrying
    code. This is the test that fires if someone adds ``pragma: no cover``,
    ``if TYPE_CHECKING:`` or ``raise NotImplementedError`` back into the config."""
    patterns = [str(p) for p in _report_table().get("exclude_lines", [])]
    for line in REAL_CODE_LINES:
        assert not _matches(patterns, line), (
            f"exclude_lines matches real code: {line!r} would stop being measured"
        )


def test_exclude_list_admits_only_no_op_statements() -> None:
    """The one exclusion the config is allowed to carry is the ``...`` stub body
    of a ``typing.Protocol`` / ``@overload`` declaration. ``...`` is a no-op by
    language semantics, so it can never hide behaviour — unlike every other
    default coverage ships. If ``exclude_lines`` is empty that is also fine."""
    patterns = [str(p) for p in _report_table().get("exclude_lines", [])]
    for pattern in patterns:
        assert re.search(pattern, "    ...") or re.search(pattern, "..."), (
            f"exclude_lines carries {pattern!r}, which is not the `...` stub pattern; "
            "every exclusion must be a no-op statement (ADR-011 forbids weakening the floor)"
        )


def test_partial_regex_is_never_match_everything() -> None:
    """**The footgun.** ``no_branch_lines()`` joins ``partial_branches`` and
    ``partial_branches_always`` with ``join_regex`` and passes the result to
    ``lines_matching`` with *no* empty-string guard. Both lists empty →
    ``re.finditer("", text)`` matches every line → every missing branch arc is
    discarded → the §23.1 floor becomes vacuously green."""
    report = _report_table()
    partial = [str(p) for p in report.get("partial_branches", [])]
    always = [str(p) for p in report.get("partial_branches_always", [])]
    combined = partial + always
    assert combined, (
        "partial_branches and partial_branches_always are BOTH empty — "
        "coverage's join_regex([]) == '' matches every line, silently disabling "
        "branch checking entirely. Leave partial_branches_always non-empty."
    )
    for line in REAL_CODE_LINES:
        assert not _matches(combined, line), (
            f"the partial-branch regex matches real code: {line!r}; its branches "
            "would stop being checked"
        )


def test_partial_branches_admits_no_pragma_escape() -> None:
    """``# pragma: no branch`` must not be a way to bless an untaken arc."""
    patterns = [str(p) for p in _report_table().get("partial_branches", [])]
    for line in ("    if x:  # pragma: no branch", "    if x:  # pragma: no cover"):
        assert not _matches(patterns, line), (
            "partial_branches still honours a pragma escape; SPEC §23.1 forbids it"
        )


# ==========================================================================
# 3. behavioural proof: the gate turns red on real regressions
# ==========================================================================
def test_gate_is_green_on_a_fully_covered_fixture(tmp_path: Path) -> None:
    """Control. Without this, every red result below could be a broken harness."""
    root = _fixture_repo(tmp_path, {"m": FULLY_COVERED}, DRIVER_BOTH)
    result = _gate(root)
    assert result.returncode == EXIT_OK, (result.stdout, result.stderr)
    assert "100%" in result.stdout, result.stdout


def test_gate_fails_on_an_uncovered_branch(tmp_path: Path) -> None:
    """The honest end-to-end proof: a genuine branch regression is blocked."""
    root = _fixture_repo(tmp_path, {"m": PARTIAL_BRANCH}, DRIVER_TRUE_ONLY)
    result = _gate(root)
    assert result.returncode != EXIT_OK, f"gate passed an uncovered branch:\n{result.stdout}"
    assert "3->5" in result.stdout, result.stdout
    assert "fail-under=100" in result.stdout + result.stderr


def test_line_only_coverage_would_have_passed(tmp_path: Path) -> None:
    """Why ``branch = true`` is load-bearing: with branch mode off, the exact
    fixture that just failed reports a clean 100%."""
    root = _fixture_repo(
        tmp_path,
        {"m": PARTIAL_BRANCH},
        DRIVER_TRUE_ONLY,
        config_patch=("branch = true", "branch = false"),
    )
    result = _gate(root)
    assert result.returncode == EXIT_OK, result.stdout
    assert "100%" in result.stdout, result.stdout


def test_pragma_no_cover_cannot_hide_a_line(tmp_path: Path) -> None:
    root = _fixture_repo(tmp_path, {"m": MISSING_LINE_WITH_PRAGMA}, DRIVER_TRUE_ONLY)
    result = _gate(root)
    assert result.returncode != EXIT_OK, f"`# pragma: no cover` hid a line:\n{result.stdout}"
    measured = _gate_json(root)["pkg/m.py"]
    assert measured["excluded_lines"] == [], measured  # type: ignore[index,call-overload]
    assert measured["missing_lines"] == [4], measured  # type: ignore[index,call-overload]


def test_pragma_no_branch_cannot_hide_an_arc(tmp_path: Path) -> None:
    root = _fixture_repo(tmp_path, {"m": PARTIAL_BRANCH_WITH_PRAGMA}, DRIVER_TRUE_ONLY)
    result = _gate(root)
    assert result.returncode != EXIT_OK, f"`# pragma: no branch` hid an arc:\n{result.stdout}"
    assert "3->5" in result.stdout, result.stdout


def test_type_checking_guard_is_not_excluded(tmp_path: Path) -> None:
    """Coverage 7.x excludes ``if TYPE_CHECKING:`` **by default**. The gate must
    not inherit that default: the guard's true arc is genuinely never taken, and
    §23.1 wants that visible, not silently forgiven."""
    root = _fixture_repo(tmp_path, {"m": TYPE_CHECKING_GUARD}, DRIVER_TRUE_ONLY)
    result = _gate(root)
    assert result.returncode != EXIT_OK, f"`if TYPE_CHECKING:` was excluded:\n{result.stdout}"
    assert not _gate_json(root)["pkg/m.py"]["excluded_lines"]  # type: ignore[index,call-overload]


def test_raise_not_implemented_is_not_excluded(tmp_path: Path) -> None:
    root = _fixture_repo(tmp_path, {"m": NOT_IMPLEMENTED}, DRIVER_TRUE_ONLY)
    result = _gate(root)
    assert result.returncode != EXIT_OK, result.stdout


def test_a_never_imported_module_is_measured_not_omitted(tmp_path: Path) -> None:
    """``source`` (unlike ``include``) forces never-imported files into the
    report at 0%. Adding dead, untested code to the TCB must turn the gate red."""
    root = _fixture_repo(
        tmp_path, {"m": FULLY_COVERED, "orphan": PARTIAL_BRANCH}, DRIVER_BOTH
    )
    result = _gate(root)
    assert result.returncode != EXIT_OK, f"an unimported module passed:\n{result.stdout}"
    assert "pkg/orphan.py" in result.stdout, result.stdout


def test_widening_exclude_lines_would_have_let_it_pass(tmp_path: Path) -> None:
    """Attack 1, demonstrated rather than asserted: restore coverage's default
    pragma exclusion and the same uncovered line sails through at 100%."""
    root = _fixture_repo(
        tmp_path,
        {"m": MISSING_LINE_WITH_PRAGMA},
        DRIVER_TRUE_ONLY,
        config_patch=("exclude_lines = [", "exclude_lines = ['pragma: no cover',"),
    )
    result = _gate(root)
    assert result.returncode == EXIT_OK, result.stdout
    assert "100%" in result.stdout, result.stdout


def test_emptying_both_partial_lists_makes_the_gate_vacuous(tmp_path: Path) -> None:
    """The footgun, demonstrated. Same uncovered arc as
    ``test_gate_fails_on_an_uncovered_branch``; the only change is emptying
    ``partial_branches_always``. The gate reports a clean 100%.

    This test is the reason the shipped config pins that list explicitly instead
    of writing the tidier-looking ``[]``."""
    root = _fixture_repo(
        tmp_path,
        {"m": PARTIAL_BRANCH},
        DRIVER_TRUE_ONLY,
        config_patch=("partial_branches_always = [", "partial_branches_always = []  # ["),
    )
    result = _gate(root)
    assert result.returncode == EXIT_OK, result.stdout
    assert "100%" in result.stdout, result.stdout
    assert "3->5" not in result.stdout, result.stdout


# ==========================================================================
# 4. CI wiring
# ==========================================================================
def test_ci_yaml_is_json_with_five_jobs() -> None:
    """PyYAML is deliberately not a dependency (T2.12); the workflow is written
    in the JSON subset of YAML so it can be validated with the stdlib."""
    jobs = _jobs()
    assert len(jobs) == 5, f"expected 5 jobs, got {sorted(jobs)}"


def test_ci_keeps_the_four_pre_existing_jobs() -> None:
    """T2.13 adds one job; it must not disturb T1.02's and T2.12's."""
    jobs = _jobs()
    for name in ("ruff", "unit", "loc-count", "tcb-loc"):
        assert name in jobs, f"pre-existing job {name!r} disappeared"


def test_coverage_job_runs_measurement_then_report() -> None:
    job = _coverage_job()
    scripts = _run_scripts(job)
    measure = next(i for i, s in enumerate(scripts) if "coverage run" in s)
    report = next(i for i, s in enumerate(scripts) if "coverage report" in s)
    assert measure < report, "the report step must follow the measurement step"


def test_coverage_job_measurement_matches_adr_011() -> None:
    """ADR-011 chose ``coverage``, explicitly **not** ``pytest-cov``."""
    script = _step_containing(_coverage_job(), "coverage run")
    assert "--branch" in script, "the measurement must be a BRANCH measurement (§23.1)"
    assert "-m pytest" in script
    assert "--cov" not in script, "ADR-011 rejected pytest-cov; do not reintroduce it"
    for layer in ("tests/unit", "tests/property"):
        assert layer in script, f"{layer} missing from the measured test layers"


def test_ci_measurement_source_matches_config() -> None:
    """Scope shrinking, CLI edition: ``--source`` on the command line overrides
    the config, so it is a second place the scope can quietly lose a package."""
    script = _step_containing(_coverage_job(), "coverage run")
    match = re.search(r"--source=(\S+)", script)
    assert match, f"the measurement step passes no --source: {script!r}"
    cli_scope = {entry.rstrip("/") for entry in match.group(1).split(",")}
    assert cli_scope == set(TCB_PACKAGES), (
        f"CI --source={sorted(cli_scope)} disagrees with SPEC §23.1's scope {sorted(TCB_PACKAGES)}"
    )
    config_scope = {str(entry).rstrip("/") for entry in _run_table()["source"]}  # type: ignore[union-attr]
    assert cli_scope == config_scope, "CI --source and [tool.coverage.run] source disagree"


def test_coverage_job_report_does_not_override_fail_under() -> None:
    """``--fail-under`` on the CLI beats the config; if it is there it must be 100."""
    script = _step_containing(_coverage_job(), "coverage report")
    for match in re.finditer(r"--fail-under[= ](\S+)", script):
        assert float(match.group(1)) == 100.0, f"CI lowers the floor: {match.group(0)}"
    assert "-i" not in script.split(), "--ignore-errors hides unparseable files"
    assert "--ignore-errors" not in script


def test_coverage_job_is_blocking() -> None:
    """A gate that cannot fail the build is documentation, not a gate."""
    job = _coverage_job()
    assert "continue-on-error" not in job, "the coverage job is non-blocking"
    for step in _steps(job):
        assert "continue-on-error" not in step, f"non-blocking step: {step}"
    for script in _run_scripts(job):
        assert "|| true" not in script, f"failure swallowed: {script!r}"
        assert "|| exit 0" not in script, f"failure swallowed: {script!r}"


def test_coverage_job_installs_dev_dependencies() -> None:
    """Without the dev lock there is no ``coverage`` in CI and the job cannot run."""
    script = _step_containing(_coverage_job(), "pip install")
    assert "--require-hashes" in script, "ADR-005: hashes are enforced on install"
    assert "requirements-dev.lock" in script


def test_coverage_is_pinned_with_a_hash_in_the_dev_lock() -> None:
    """ADR-011 adds ``coverage`` to the §13.1 dev-only allowlist, pinned per ADR-005."""
    lock = DEV_LOCK.read_text(encoding="utf-8")
    match = re.search(r"^coverage==(\S+) \\\n\s+--hash=sha256:([0-9a-f]{64})", lock, re.MULTILINE)
    assert match, "coverage is not pinned-with-hash in requirements-dev.lock (ADR-011)"
    assert "pytest-cov" not in lock, "ADR-011 rejected pytest-cov"


# ==========================================================================
# 5. the `pragma: no cover` grep — T2.13's review checkpoint
# ==========================================================================
def _pragma_step() -> str:
    job = _coverage_job()
    matches = [script for script in _run_scripts(job) if "pragma" in script and "grep" in script]
    assert matches, "the coverage job has no `pragma: no cover` grep (T2.13 review checkpoint)"
    assert len(matches) == 1
    return matches[0]


def _run_pragma_step(cwd: Path) -> subprocess.CompletedProcess[str]:
    """Execute CI's grep step **verbatim**, so the test cannot drift from CI."""
    return subprocess.run(
        ["bash", "-c", _pragma_step()],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
        env=_env(),
    )


def _tcb_shaped_tree(tmp_path: Path, planted: dict[str, str], *, skip: str = "") -> Path:
    root = tmp_path / "tree"
    for package in TCB_PACKAGES:
        if package.endswith(skip) and skip:
            continue
        (root / package).mkdir(parents=True)
        (root / package / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    for rel, body in planted.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return root


def test_ci_has_a_pragma_grep_step() -> None:
    script = _pragma_step()
    for package in TCB_PACKAGES:
        assert package in script, f"the pragma grep does not scan {package}"


def test_pragma_grep_is_silent_on_a_clean_tree(tmp_path: Path) -> None:
    """Control: the step must not fail a TCB that carries no pragma."""
    result = _run_pragma_step(_tcb_shaped_tree(tmp_path, {}))
    assert result.returncode == EXIT_OK, (result.stdout, result.stderr)


@pytest.mark.parametrize(
    "pragma",
    [
        "# pragma: no cover",
        "#pragma: no cover",
        "# pragma: no branch",
        "# PRAGMA: NO COVER",
        "# pragma:no cover",
    ],
)
def test_pragma_grep_fires_on_a_planted_pragma(tmp_path: Path, pragma: str) -> None:
    """Proof the grep actually fires — and on every spelling coverage honours."""
    root = _tcb_shaped_tree(
        tmp_path, {"src/lsassist/policy/canonical.py": f"def f():\n    return 1  {pragma}\n"}
    )
    result = _run_pragma_step(root)
    assert result.returncode != EXIT_OK, (
        f"the grep did not fire on {pragma!r}:\n{result.stdout}\n{result.stderr}"
    )


def test_pragma_grep_fails_closed_when_a_tcb_package_is_missing(tmp_path: Path) -> None:
    """``grep`` exits 2 (not 1) when a path does not exist, so a naive
    ``if grep …; then exit 1; fi`` **passes** after a package rename. The step
    must check the directories exist first."""
    root = _tcb_shaped_tree(tmp_path, {}, skip="sandbox")
    result = _run_pragma_step(root)
    assert result.returncode != EXIT_OK, (
        "the pragma grep failed OPEN with a TCB package missing:\n"
        f"{result.stdout}\n{result.stderr}"
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_real_tcb_sources_carry_no_pragma() -> None:
    """The invariant itself, on the real repository (SPEC §23.1, ADR-011)."""
    result = _run_pragma_step(REPO_ROOT)
    assert result.returncode == EXIT_OK, (
        f"a coverage pragma is present in the TCB:\n{result.stdout}\n{result.stderr}"
    )


# ==========================================================================
# 6. the measurement's own droppings
# ==========================================================================
def test_coverage_data_files_are_gitignored() -> None:
    """``coverage run`` writes ``.coverage`` into the repo root."""
    for candidate in (".coverage", ".coverage.host.12345.678"):
        result = subprocess.run(
            ["git", "check-ignore", "-q", "--no-index", candidate],
            check=False,
            cwd=REPO_ROOT,
        )
        assert result.returncode == EXIT_OK, f"{candidate} is not gitignored"
