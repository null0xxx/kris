# LinuxSec — continuation handoff

> Resume from `/home/null/Desktop/LinuxSec`, the Git root. The public repository is
> [null0xxx/kris](https://github.com/null0xxx/kris). This handoff was refreshed on
> 2026-08-10 after T3.07 and its Atlas documentation were published.

## Quick path

1. Recover Engram memory using the exact project and topics below.
2. Run the complete fail-closed baseline block without skipping a command.
3. Read the frozen T3.09 plan block and its cited SPEC/ADR material.
4. If every guard passes, implement only T3.09 with strict TDD and one commit.

## 1. Recover Engram before continuing

**Use Engram before reading or editing implementation code. Do not continue from
this prompt alone.** Run these memory operations in order:

1. `mem_context(project="kris", scope="project")`.
2. `mem_search(project="kris", scope="project", query="implementation/t3-07-landed")`.
3. `mem_search(project="kris", scope="project", query="delivery/github-sync")`.
4. `mem_search(project="kris", scope="project", query="workflow/t3-06-handoff")`.
5. `mem_search(project="kris", scope="project", query="T3.09")`.
6. Call `mem_get_observation(id=<matching-id>)` for the full, untruncated results.

The first three query strings are stable topic keys. Current useful observations
are `#731` (latest session summary), `#723` (T3.07 landed), `#724` (GitHub sync),
and `#707` (resume-gate pattern). IDs are aids, not authority: if search returns a
newer revision, read the newer full observation. Treat any `needs_review` memory
as stale until current Git, frozen-plan, and native-receipt evidence confirms it.
Git and the frozen documents win over memory when they disagree.

## 2. Verify the baseline before editing

The repository was clean immediately before this handoff edit. At that point,
local `HEAD` and local `origin/main` were both `7b23f55`, with ahead=0 and behind=0.
A sole modification to this handoff file is therefore expected until it is handled
as its own documentation work unit; it does not authorize source drift.

Run the block exactly. `SPEC.md` and `IMPLEMENTATION_PLAN.md` are included in both
tracked and untracked hard-stop guards; this closes the former root
authority-document gap.

```bash
set -euo pipefail
cd /home/null/Desktop/LinuxSec
BASE=7b23f55

printf 'HEAD: '; git rev-parse --short=7 HEAD
printf 'origin/main: '; git rev-parse --short=7 origin/main
printf 'ahead behind: '; git rev-list --left-right --count HEAD...origin/main
git status --short

git merge-base --is-ancestor "$BASE" HEAD || {
  echo "STOP: HEAD is not 7b23f55 or a descendant" >&2
  exit 1
}
git diff --quiet "$BASE" -- SPEC.md IMPLEMENTATION_PLAN.md .github lsassist || {
  echo "STOP: frozen authority, source, or workflow bytes differ from 7b23f55" >&2
  exit 1
}
untracked="$(git ls-files --others --exclude-standard -- \
  SPEC.md IMPLEMENTATION_PLAN.md .github lsassist)" || {
  echo "STOP: unable to enumerate untracked authority/source/workflow paths" >&2
  exit 1
}
if test -n "$untracked"; then
  printf 'STOP: unreviewed authority/source/workflow paths:\n%s\n' "$untracked" >&2
  exit 1
fi

cd lsassist
V=~/.local/share/lsassist/venv/bin
$V/python -m pytest
$V/python -m ruff check src tests
$V/python -m mypy --strict \
  src/lsassist/contracts src/lsassist/config src/lsassist/policy \
  src/lsassist/sandbox src/lsassist/kernel src/lsassist/audit \
  src/lsassist/recovery src/lsassist/tools/dispatcher.py \
  src/lsassist/tools/result.py
./scripts/loc-count

$V/python -m coverage run --branch \
  --source=src/lsassist/kernel,src/lsassist/policy,src/lsassist/sandbox,src/lsassist/audit,src/lsassist/recovery \
  -m pytest tests/unit tests/property -q
$V/python -m coverage report --fail-under=100 --show-missing

$V/python -m coverage run --branch \
  --source=lsassist.tools.dispatcher,lsassist.tools.result \
  -m pytest tests/unit/tools -q
$V/python -m coverage report --fail-under=100 --show-missing

$V/python -m coverage run --branch \
  --source=lsassist.tools.handlers.test_run,lsassist.tools.handlers.proc_exec,lsassist.tools.handlers.net_fetch \
  -m pytest tests/unit/tools/test_exec_net_tools.py \
  tests/integration/tools/test_exec_net_sandbox.py -q
$V/python -m coverage report --fail-under=100 --show-missing

cd ..
gentle-ai review status --cwd /home/null/Desktop/LinuxSec | jq -e '
  def approved($id):
    ([.entries[] | select(.lineage_id == $id)] |
      length == 1 and .[0].state == "approved" and .[0].status == "approved");
  approved("review-22c0be57fd5434eb") and
  approved("review-4f7cd8abf4344ccc") and
  approved("review-0476b3ac39c6317d")
' >/dev/null
```

### Expected results

| Check | Expected result |
|---|---|
| source baseline | `7b23f55` or a documentation-only descendant; guarded paths identical to `7b23f55` |
| published baseline | before this edit: local `HEAD` = local `origin/main` = `7b23f55`; ahead 0, behind 0 |
| full pytest | **3285 passed** |
| Ruff / mypy | clean |
| §23.1 TCB coverage | **100%** |
| dispatcher + result coverage | **100%** |
| T3.06 handler coverage | **100%** |
| T3.07 exhaustive mutations | **27 / 27 killed** |
| T3.07 catalog mutations | **3 / 3 killed** |
| TCB LOC | **6031 / 6000**; feature freeze active; hard stop **8000** |

The tests, lint, typing, LOC, and three coverage commands are fresh gates. The
T3.07 mutation counts are immutable reviewed historical evidence, not a claim
that this block replays them: no durable exhaustive mutation harness shipped.
The exact-lineage status checks bind the approved evidence and documents:

- T3.06 `6729b4e` → `review-22c0be57fd5434eb`;
- T3.07 `2d0f6c2` → `review-4f7cd8abf4344ccc`;
- Atlas docs `5942450` and `7b23f55` → latest approved docs lineage
  `review-0476b3ac39c6317d`.

If any guard, fresh gate, or exact-lineage check fails, stop and report the
specific discrepancy. Do not reinterpret a failure as permission to continue.

## 3. Current project state

| Item | Current truth |
|---|---|
| repository | public `https://github.com/null0xxx/kris`, default branch `main` |
| completed tasks | **35 / 70 = 50.0%** |
| phase totals | **10/11, 13/13, 8/14, 4/12, 0/14, 0/6** |
| T3.06 | `6729b4e` — `test.run`, `proc.exec`, and `net.fetch` |
| T3.07 | `2d0f6c2` — exact registry/authority/schema contract |
| Atlas docs | `5942450` and `7b23f55` |
| next task | **T3.09**, dependency-ready |

This percentage measures frozen-plan task artifacts, not usable-product
completion. Phase 5 still owns CLI/session assembly, with T5.12 as the integration
point.

### Security boundaries and residuals

- **Feature freeze:** TCB is 6031, above the 6000 target. The 8000 hard stop is
  not feature capacity. Avoid TCB growth and never hide the warning.
- **`proc.exec`:** executable authority is identity-bound and rechecked, but a
  narrow stat-to-exec pathname race remains.
- **`net.fetch`:** an uncooperative transport worker may outlive a timed-out
  caller, but caller-side storage prevents that worker from storing a late body.
- **Resume authority:** the former guard gap for root `SPEC.md` and
  `IMPLEMENTATION_PLAN.md` is fixed by this prompt's tracked/untracked checks.

## 4. Next dependency-ready task — T3.09

Before editing, read the **exact frozen T3.09 block** in
`IMPLEMENTATION_PLAN.md` and its cited `SPEC.md` §5.2, ADR-003, and AC-03 material.
Do not rely on this summary as a substitute and do not edit either frozen file.

Direct grounding:

1. The frozen plan says T3.09 depends only on T3.08.
2. T3.08 is complete; `lsassist/src/lsassist/providers/base.py` exists.
3. All four T3.09 artifacts are absent:
   - `lsassist/src/lsassist/providers/kimi_coding.py`
   - `lsassist/tests/unit/providers/test_kimi_sse.py`
   - `lsassist/tests/unit/providers/test_kimi_errors.py`
   - `lsassist/tests/contract/providers/test_kimi_identity.py`

T3.09 owns the Kimi adapter core: OpenAI-compatible request construction,
streaming SSE parsing, strict tool definitions, the frozen §5.2 error mapping,
honest User-Agent identity, and credential-safe logs. Reuse T3.08 provider
contracts by identity; do not redefine them.

Start with the frozen RED command:

```bash
set -euo pipefail
cd /home/null/Desktop/LinuxSec/lsassist
V=~/.local/share/lsassist/venv/bin
$V/python -m pytest \
  tests/unit/providers/test_kimi_sse.py \
  tests/unit/providers/test_kimi_errors.py \
  tests/contract/providers/test_kimi_identity.py -q
```

The expected initial result is failure because the three test modules and adapter
are absent. Write the failing tests first, observe the correct RED, implement the
minimum GREEN, then refactor without weakening the assertions. Verification must
include the focused command and:

```bash
cd /home/null/Desktop/LinuxSec/lsassist
V=~/.local/share/lsassist/venv/bin
$V/python -m mypy --strict src/lsassist/providers/kimi_coding.py
```

Ground mutations against SSE framing, every §5.2 mapping row, honest identity,
and credential non-disclosure. Prove each substitution was applied exactly once.

## 5. Non-negotiable workflow

- Speak Georgian with the maintainer; keep repository artifacts in English.
- Strict TDD is mandatory: RED → GREEN → REFACTOR → focused gates → full gates.
- Implement one frozen task per conventional commit. Never add AI attribution or
  `Co-Authored-By` trailers.
- `SPEC.md` and `IMPLEMENTATION_PLAN.md` are frozen authority. Never change them
  to make implementation pass.
- Run every source-mutating normalizer before candidate freeze. Do not mutate
  reviewed bytes afterward.
- Gentle AI review is candidate-specific. Relay its consent request to the human;
  never infer consent from an earlier candidate. Use the resulting exact receipt
  for pre-commit, pre-push, and later delivery gates.
- Push only when the maintainer explicitly asks. The earlier publication request
  does not authorize future pushes.
- Do not resume `.atlas/session_3056019e-…`; it is the terminal Gate-3 session.
- A green suite alone is insufficient. Verify authority bindings, diagnostics,
  mutation application, and the native receipt.

If memory recovery, frozen grounding, baseline guards, or evidence gates disagree,
stop. Otherwise continue with T3.09 only.
