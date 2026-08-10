# LinuxSec — next-session prompt

> Open the next session at `/home/null/Desktop/LinuxSec`, the Git root, and paste
> everything below the separator as one message. This handoff was updated on
> 2026-08-10 after T3.06 landed at `6729b4e`.

---

Work on `/home/null/Desktop/LinuxSec`. Speak Georgian with the maintainer; keep
repository artifacts in English.

## 1. Verify the baseline before editing

```bash
set -euo pipefail
cd /home/null/Desktop/LinuxSec
git log --oneline -4
git status --short
git diff --quiet 6729b4e -- .github lsassist || {
  echo "STOP: source/workflow bytes differ from approved T3.06 commit 6729b4e" >&2
  exit 1
}
untracked="$(git ls-files --others --exclude-standard -- .github lsassist)" || {
  echo "STOP: unable to enumerate untracked source/workflow paths" >&2
  exit 1
}
if test -n "$untracked"; then
  printf 'STOP: unreviewed source/workflow paths:\n%s\n' "$untracked" >&2
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
  -m pytest tests/unit tests/property -q && $V/python -m coverage report --show-missing
$V/python -m coverage run --branch \
  --source=lsassist.tools.dispatcher,lsassist.tools.result \
  -m pytest tests/unit/tools -q && $V/python -m coverage report --show-missing
$V/python -m coverage run --branch \
  --source=lsassist.tools.handlers.test_run,lsassist.tools.handlers.proc_exec,lsassist.tools.handlers.net_fetch \
  -m pytest tests/unit/tools/test_exec_net_tools.py tests/integration/tools/test_exec_net_sandbox.py -q \
  && $V/python -m coverage report --fail-under=90 --show-missing

cd ..
gentle-ai review status --cwd /home/null/Desktop/LinuxSec | jq -e \
  '[.entries[] | select(.lineage_id == "review-22c0be57fd5434eb")] |
   length == 1 and .[0].state == "approved" and .[0].status == "approved"' >/dev/null
```

Expected committed baseline:

| Check | Expected result |
|---|---|
| HEAD | `6729b4e` or a later documentation-only commit |
| full pytest | **3191 passed** |
| Ruff / mypy | clean |
| §23.1 TCB coverage | **100%** |
| dispatcher + result coverage | **100%** |
| T3.06 handler coverage | **100%** |
| T3.06 mutations | **18 / 18 killed** |
| TCB LOC | **6031 / 6000**, feature freeze active; hard stop **8000** |

The three coverage commands are fresh gates. The **18/18 mutation result is
immutable reviewed historical evidence**, not a replay claim: no durable mutation
script shipped. The final receipt binds that evidence to lineage
`review-22c0be57fd5434eb` and the approved T3.06 candidate. Proceed to T3.07 only
if the native status pipeline exits zero and confirms **approved** for that lineage.
If HEAD is not `6729b4e` or a documentation-only descendant, source bytes differ,
any fresh gate fails, or receipt validation fails, stop and report the discrepancy.
The virtual environment is the ADR-005 Python 3.12 environment, not a repository
`.venv`; do not rebuild it with Python 3.14.

## 2. Current project state

T3.06 landed at `6729b4e` with `test.run`, `proc.exec`, and `net.fetch`. Gentle AI
lineage `review-22c0be57fd5434eb` is approved, final evidence passed, and native
pre-commit validation returned allow for the committed candidate.

The important authority boundaries are:

- `test.run` binds the detected final runner argv into the approval.
- `proc.exec` uses an immutable exact absolute-path allowlist and binds
  `(realpath, device, inode, size, ctime_ns)` before rechecking it at execution.
- Only `test.run` and `proc.exec` may omit filesystem `path_args`; `git.worktree`
  remains path-bound.
- `PolicyStores.net_allowlist` is the single policy/runtime redirect authority.
- Redirects preserve the approved scheme and effective port.
- Fetch uses an absolute total deadline. The sync handler is safe inside an
  already-running event loop, and body storage occurs only after successful
  bounded completion.
- Accepted response types are `text/*`, exact `application/json`, and exact
  `application/xml`; GET bodies remain in RAM and are capped at 1 MiB.

### Security residuals

1. A narrow stat-to-exec race remains because the executable is ultimately
   opened by pathname after its final identity check.
2. An uncooperative HTTP transport may leave a daemon worker alive after the
   caller times out. It cannot store a body because storage is caller-side only.

Do not hide these residuals or treat the 8000 hard stop as permission to expand
the TCB. The 6000 feature freeze remains active.

## 3. Measured completion

**34 / 70 tasks = 48.6%.** Phase totals are:

| Phase | Built |
|---|---:|
| 1 | 10/11 |
| 2 | 13/13 |
| 3 | 7/14 |
| 4 | 4/12 |
| 5 | 0/14 |
| 6 | 0/6 |

This is task completion, not a usable-program percentage. Phase 5 still owns the
CLI/session assembly; T5.12 is the integration point.

## 4. Next recommended task — T3.07

Use the frozen T3.07 block in `IMPLEMENTATION_PLAN.md`. This recommendation is
based on direct evidence, not priority inference:

1. The frozen plan says T3.07 depends only on T3.06.
2. T3.06 is landed at `6729b4e`.
3. T3.07's sole artifact,
   `lsassist/tests/contract/tools/test_registry_enumeration.py`, is absent.

T3.07 is contract-only. Add no production behavior. Its test must assert:

- the registry contains exactly the twelve frozen V1 tools;
- the explicitly absent shell, privileged execution, destructive Git, package
  mutation, service, firewall, credential, send, and cron tool families remain
  absent;
- every manifest has a typed input schema; and
- no manifest accepts a shell command string.

Start RED-first with the frozen command:

```bash
cd /home/null/Desktop/LinuxSec/lsassist
V=~/.local/share/lsassist/venv/bin
$V/python -m pytest tests/contract/tools/test_registry_enumeration.py -q
```

The initial RED is the absent contract-test file. After implementation, run the
focused test, the relevant full gates, and the frozen mutation check that proves a
temporary `shell` manifest makes the exact enumeration fail.

## 5. Non-negotiable workflow

- `SPEC.md` and `IMPLEMENTATION_PLAN.md` are frozen. Do not edit them to make a
  test pass.
- Work RED → GREEN → focused gates → native review → mutations → commit.
- Freeze the candidate before `gentle-ai review start`; run every mutating
  normalizer before review, never after.
- Use the native review receipt and validate the same candidate at pre-commit.
- Push only when the maintainer asks separately.
- Do not resume `.atlas/session_3056019e-…`; it is the terminal Gate-3 session.
- `/tmp` is hidden by the sandbox profile. Real sandbox workspaces belong under
  `~/.cache/lsassist/<uuid>/ws`.
- A green suite is not sufficient evidence. Assert diagnostics and authority
  bindings, and prove every mutation was actually substituted exactly once.

Begin with the baseline verification in §1. If it matches, continue with T3.07.
