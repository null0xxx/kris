# LinuxSec — next-session prompt

> Open the next session at `/home/null/Desktop/LinuxSec`, the Git root, and paste
> everything below the separator as one message. This handoff was updated on
> 2026-08-10 after T3.07 landed at `2d0f6c2`.

---

Work on `/home/null/Desktop/LinuxSec`. Speak Georgian with the maintainer; keep
repository artifacts in English.

## 1. Verify the baseline before editing

```bash
set -euo pipefail
cd /home/null/Desktop/LinuxSec
git log --oneline -4
git status --short
git diff --quiet 2d0f6c2 -- .github lsassist || {
  echo "STOP: source/workflow bytes differ from approved T3.07 commit 2d0f6c2" >&2
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
  '[.entries[] | select(.lineage_id == "review-4f7cd8abf4344ccc")] |
   length == 1 and .[0].state == "approved" and .[0].status == "approved"' >/dev/null
```

Expected committed baseline:

| Check | Expected result |
|---|---|
| HEAD | `2d0f6c2` or a later documentation-only commit |
| full pytest | **3285 passed** |
| Ruff / mypy | clean |
| §23.1 TCB coverage | **100%** |
| dispatcher + result coverage | **100%** |
| T3.06 handler coverage | **100%** |
| T3.07 exhaustive mutations | **27 / 27 killed** |
| T3.07 grounded catalog mutations | **3 / 3 killed** |
| TCB LOC | **6031 / 6000**, T3.07 delta 0; feature freeze active; hard stop **8000** |

The three coverage commands are fresh gates. The **27/27** and **3/3** mutation
results are immutable reviewed historical evidence, not replay claims. The final
receipt binds that evidence to lineage `review-4f7cd8abf4344ccc` and the approved
T3.07 candidate. Proceed to T3.09 only if the native status pipeline exits zero
and confirms **approved** for that exact lineage. If HEAD is not `2d0f6c2` or a
documentation-only descendant, source bytes differ, any fresh gate fails, or
authority validation fails, stop and report the discrepancy.
The virtual environment is the ADR-005 Python 3.12 environment, not a repository
`.venv`; do not rebuild it with Python 3.14.

## 2. Current project state

T3.07 landed at `2d0f6c2` as a contract-only change. Gentle AI lineage
`review-4f7cd8abf4344ccc` is approved, final evidence passed, and native
pre-commit validation returned allow for the committed candidate. The contract
freezes both the exact twelve-name catalog and every name's exact permission and
`fs/net/proc` capability authority. Its fail-closed schema walk covers unions,
combinators, dynamic schema positions, and references, and rejects compound shell
carriers without rejecting `subcommand`.

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

**35 / 70 tasks = 50.0%.** Phase totals are:

| Phase | Built |
|---|---:|
| 1 | 10/11 |
| 2 | 13/13 |
| 3 | 8/14 |
| 4 | 4/12 |
| 5 | 0/14 |
| 6 | 0/6 |

This is task completion, not a usable-program percentage. Phase 5 still owns the
CLI/session assembly; T5.12 is the integration point.

## 4. Next recommended task — T3.09

Use the frozen T3.09 block in `IMPLEMENTATION_PLAN.md`. This recommendation is
based on direct evidence, not priority inference:

1. The frozen plan says T3.09 depends only on T3.08.
2. T3.08's `src/lsassist/providers/base.py` exists and the progress ledger
   records T3.08 as GREEN in the landed Phase-3/4 Wave 1.
3. All four T3.09 artifacts are absent: `providers/kimi_coding.py`,
   `test_kimi_sse.py`, `test_kimi_errors.py`, and `test_kimi_identity.py`.

T3.09 owns the Kimi adapter core: OpenAI-compatible request construction,
streaming SSE parsing, strict tool definitions, the frozen provider-error mapping,
honest User-Agent identity, and secret-safe logging. Keep provider contracts in
T3.08's base layer; do not redefine them in the adapter.

Start RED-first with the frozen command:

```bash
cd /home/null/Desktop/LinuxSec/lsassist
V=~/.local/share/lsassist/venv/bin
$V/python -m pytest \
  tests/unit/providers/test_kimi_sse.py \
  tests/unit/providers/test_kimi_errors.py \
  tests/contract/providers/test_kimi_identity.py -q
```

The initial RED is the three absent test modules. After implementation, run the
focused tests, strict mypy on `src/lsassist/providers/kimi_coding.py`, the relevant
full gates, and grounded mutation checks for SSE framing, every error-map row,
identity headers, and credential non-disclosure.

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

Begin with the baseline verification in §1. If it matches, continue with T3.09.
