# LinuxSec — continuation handoff

> Resume from `/home/null/Desktop/LinuxSec`, the Git root. The public repository is
> [null0xxx/kris](https://github.com/null0xxx/kris). This handoff follows completed
> T3.09 commit `d7b28ac` and its **3393-passing-test** full-suite evidence.

## Quick path

1. Recover Engram memory using the exact project and topics below.
2. Run the complete fail-closed baseline block without skipping a command.
3. Read the frozen T3.10 plan block and its cited SPEC material.
4. If every guard passes, implement only T3.10 with strict TDD and one commit.

## 1. Recover Engram before continuing

**Use Engram before reading or editing implementation code. Do not continue from
this prompt alone.** Run these memory operations in order:

1. `mem_context(project="kris", scope="project")`.
2. `mem_search(project="kris", scope="project", query="delivery/t3-09-full-target-review")`.
3. `mem_search(project="kris", scope="project", query="delivery/github-sync")`.
4. `mem_search(project="kris", scope="project", query="T3.09")`.
5. `mem_search(project="kris", scope="project", query="T3.10")`.
6. Call `mem_get_observation(id=<matching-id>)` for the full, untruncated results.

The first two query strings are stable topic keys. Read the newest matching full
observation rather than relying on remembered IDs. Treat any `needs_review` memory
as stale until current Git, frozen-plan, and native-receipt evidence confirms it.
Git and the frozen documents win over memory when they disagree.

## 2. Verify the baseline before editing

Run this only after the T3.09 PR is merged and local `main` is synchronized. The
guard refreshes `origin/main`, requires a clean and exact local mirror, and anchors
frozen authority, workflow, and source bytes to T3.09 commit `d7b28ac`.

Run the block exactly. `SPEC.md` and `IMPLEMENTATION_PLAN.md` are included in both
tracked and untracked hard-stop guards; this closes the former root
authority-document gap.

```bash
set -euo pipefail
cd /home/null/Desktop/LinuxSec
BASE=d7b28ac6747f9c06f99f7e64845791fbf1c0191e

git fetch --prune origin
test "$(git branch --show-current)" = main || {
  echo "STOP: check out main" >&2
  exit 1
}
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" || {
  echo "STOP: local main is not synchronized with origin/main" >&2
  exit 1
}
status="$(git status --porcelain=v1 --untracked-files=all)"
test -z "$status" || {
  printf 'STOP: worktree is not clean:\n%s\n' "$status" >&2
  exit 1
}

git merge-base --is-ancestor "$BASE" HEAD || {
  echo "STOP: main does not contain T3.09 commit d7b28ac" >&2
  exit 1
}
git diff --quiet "$BASE" HEAD -- SPEC.md IMPLEMENTATION_PLAN.md .github lsassist || {
  echo "STOP: frozen authority, source, or workflow bytes differ from d7b28ac" >&2
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
$V/python -m mypy --strict src/lsassist/providers/kimi_coding.py
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
  approved("review-0476b3ac39c6317d") and
  approved("review-01a926ca35169642")
' >/dev/null
```

### Expected results

| Check | Expected result |
|---|---|
| source baseline | `d7b28ac` or a descendant; guarded paths identical to `d7b28ac` |
| published baseline | clean local `main` = refreshed `origin/main` |
| full pytest | **3393 passed** |
| Ruff / mypy | clean |
| §23.1 TCB coverage | **100%** |
| dispatcher + result coverage | **100%** |
| T3.06 handler coverage | **100%** |
| T3.07 exhaustive mutations | **27 / 27 killed** |
| T3.07 catalog mutations | **3 / 3 killed** |
| TCB LOC | fresh `scripts/loc-count` result; feature freeze active; hard stop **8000** |

The tests, lint, typing, LOC, and three coverage commands are fresh gates. The
T3.07 mutation counts are immutable reviewed historical evidence, not a claim
that this block replays them: no durable exhaustive mutation harness shipped.
The exact-lineage status checks bind the approved evidence and documents:

- T3.06 `6729b4e` → `review-22c0be57fd5434eb`;
- T3.07 `2d0f6c2` → `review-4f7cd8abf4344ccc`;
- Atlas docs `5942450` and `7b23f55` → latest approved docs lineage
  `review-0476b3ac39c6317d`;
- T3.09 `d7b28ac` and this six-path PR boundary → full-target lineage
  `review-01a926ca35169642` after its bounded correction is approved.

If any guard, fresh gate, or exact-lineage check fails, stop and report the
specific discrepancy. Do not reinterpret a failure as permission to continue.

## 3. Current project state

| Item | Current truth |
|---|---|
| repository | public `https://github.com/null0xxx/kris`, default branch `main` |
| completed tasks | **36 / 70 = 51.4%** |
| phase totals | **10/11, 13/13, 9/14, 4/12, 0/14, 0/6** |
| T3.06 | `6729b4e` — `test.run`, `proc.exec`, and `net.fetch` |
| T3.07 | `2d0f6c2` — exact registry/authority/schema contract |
| T3.09 | `d7b28ac` — Kimi adapter core; full suite **3393 passed** |
| Atlas docs | `5942450` and `7b23f55` |
| next task | **T3.10**, dependency-ready |

This percentage measures frozen-plan task artifacts, not usable-product
completion. Phase 5 still owns CLI/session assembly, with T5.12 as the integration
point.

### Security boundaries and residuals

- **Feature freeze:** TCB is above the 6000 target. The fresh LOC gate is
  authoritative; the 8000 hard stop is not feature capacity.
- **`proc.exec`:** executable authority is identity-bound and rechecked, but a
  narrow stat-to-exec pathname race remains.
- **`net.fetch`:** an uncooperative transport worker may outlive a timed-out
  caller, but caller-side storage prevents that worker from storing a late body.
- **Resume authority:** the former guard gap for root `SPEC.md` and
  `IMPLEMENTATION_PLAN.md` is fixed by this prompt's tracked/untracked checks.
- **Review warnings:** this correction resolves the former display-only/no-fetch
  baseline guard. Two informational adapter warnings remain outside T3.10:
  outbound non-JSON tool parameters may escape serialization as a raw error, and
  normalizing an unread streamed `httpx.Response` may raise `ResponseNotRead`.

## 4. Next dependency-ready task — T3.10

Before editing, read the **exact frozen T3.10 block** in
`IMPLEMENTATION_PLAN.md` and its cited `SPEC.md` §5.2 and §5.4 material.
Do not rely on this summary as a substitute and do not edit either frozen file.

Direct grounding:

1. The frozen plan says T3.10 depends only on T3.09.
2. T3.09 is complete at `d7b28ac`; do not reimplement or weaken it.
3. T3.10 owns only Kimi retry/backoff, the circuit breaker, and usage telemetry
   in `kimi_coding.py`, new `retry.py`, `test_kimi_retry.py`, and
   `test_circuit_breaker.py`.

Retry only `retryable=True` errors. Preserve the frozen 1s→2s→4s→8s jittered
backoff, overload ≤4 and transient ≤3 bounds, five-minute chain cap,
`Retry-After`, breaker thresholds, `provider_down`, rolling five-hour usage
counter, 80% warning, and no 429 quota-window retry storm.

Start with the frozen RED command:

```bash
set -euo pipefail
cd /home/null/Desktop/LinuxSec/lsassist
V=~/.local/share/lsassist/venv/bin
$V/python -m pytest \
  tests/unit/providers/test_kimi_retry.py \
  tests/unit/providers/test_circuit_breaker.py -q
```

The expected RED is missing retry/breaker behavior. Write failing tests first,
observe the behavioral failure, implement the minimum GREEN, then refactor without
weakening assertions. Verification includes the focused command and the frozen
property-style proof that arbitrary error sequences never retry terminal kinds.
Do not add T3.11+, fallback-flow behavior, or opportunistic fixes for the two
informational warnings.

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
stop. Otherwise continue with T3.10 only.
