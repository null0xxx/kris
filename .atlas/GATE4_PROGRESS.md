# LinuxSec — Gate 4 Progress Ledger (handoff)

> **What this file is:** a durable, human+agent-readable Gate-4 progress record so Kimi3 (or any
> elite agent) can resume implementation correctly. It is a HANDOFF DOC, **not** a Kimi atlas
> session ledger — it deliberately lives at `.atlas/` root (not in a `session_*/` dir) so it is
> **never** picked up by atlas's resume scanner (`newest .atlas/*/state.json with non-terminal
> current_state`).
>
> **⚠️ DO NOT resume `session_3056019e-…`.** That is the Gate-3 (plan-authoring) session; its
> `current_state` is `OUTPUT` (terminal) and it is correctly complete + hash-chained + critic-
> verified (70 tasks / 0 fails). Making it non-terminal to "continue" would corrupt the Gate-3
> record and mis-drive resume. Gate-4 progress is tracked by **git commits** (task-tagged) + this
> file, exactly as Kimi3 ran T1.07–T1.09.

- **Gate:** 4 (implementation) — IN PROGRESS
- **Source of truth for tasks:** `../IMPLEMENTATION_PLAN.md` (70 tasks, 6 phases)
- **Repo:** `../lsassist` (branch `main`)
- **Last updated:** 2026-07-24

---

## Environment (ADR-005) — REQUIRED to run gates

The venv already exists (Kimi3 provisioned it); it is NOT `.venv` in the repo — it is at the
ADR-005 path. `lsassist` is importable via a `.pth` in the venv site-packages (src-layout).

```bash
V=~/.local/share/lsassist/venv/bin
$V/python -m pytest -q                         # full suite
$V/python -m mypy --strict src/lsassist/config # TCB strict (per-package)
$V/python -m ruff check src tests              # lint (E,F,I,UP,B,SIM,RUF)
./scripts/loc-count                            # TCB LOC / 6000 (hard stop 8000)
./scripts/verify-env.sh                        # host re-verification (T1.01)
```
If the venv is ever missing: `python3 -m venv ~/.local/share/lsassist/venv && $V/python -m pip install --require-hashes -r requirements.lock -r requirements-dev.lock` then add a `.pth` pointing at `.../lsassist/src` (uv/setuptools not required for src-layout).

---

## Phase 1 — Foundation: ✅ COMPLETE (T1.01–T1.11)

| Task | Verdict | Commit | Note |
|---|---|---|---|
| T1.01–T1.06, T1.11 | GREEN | 6a91988…36bb6e4 | bootstrap + `contracts/` (I1/I4/I5/I6/I12/I16 structural) |
| T1.07 | GREEN | cb38f25 | `config/` XDG + canary honeyfiles |
| T1.08 | GREEN | 74e233a | `config/` versioned schema (unknown=warn+drop; version gate; Ollama localhost-only; lab.enabled=false) |
| T1.09 | GREEN | f00dd44 | `config/` secrets env→keyring→0600 (ADR-004); `Secret.reveal()`-only (I8); `kernel.secret` O_EXCL\|O_NOFOLLOW |
| — hygiene | — | 5a85567 | ruff-clean Phase-1 test files (UP031/RUF100/E501); green baseline restored |
| **T1.10** | **GREEN** | **1168065** | `config/redaction_patterns.py` §12.4 DATA-only; 53 tests; adversarial-critic refine (see below) |
| **HARDEN-01** | **GREEN** | **3c56f53** | TOCTOU-safe secret reads: `secrets._from_file` + `kernel_secret._load` now O_NOFOLLOW+fstat(fd)+O_NONBLOCK; race tests (symlink + FIFO swap) |
| **HARDEN-02** | **GREEN** | **3e8b9a9** | `contracts/PolicyContext` validator now PURE (os.path.isabs + normpath==value, AST-verified 0 I/O); realpath re-homed to dispatcher (T3.02); contract tests FS-independent |

**Gate state after Phase 1 + HARDEN-01/02:** pytest **384 passed** · mypy --strict clean · ruff clean · **TCB LOC 1829 / 6000** · ownership grep clean (redactor engine reserved for T4.01).

### T1.10 checkpoint detail (Claude Code atlas replication, 2026-07-24)
- Loop: ground → RED (elite-coder) → GREEN → deterministic floors (orchestrator) → 3 **isolated adversarial critics** (Opus: correctness/security/code-quality) → pure verdict → V7 refine ×1 → floors re-run.
- **Convergent critic finding (fixed):** `sk-[A-Za-z0-9]{…}` excluded `-`/`_` → modern keys (`sk-proj-…`, `sk-or-v1-…`) escaped redaction (I8 false-negative). Widened to `[A-Za-z0-9_-]` + left lookbehind `(?<![A-Za-z0-9])` (also kills `disk-`/`task-` false-positive). Empty exact-match rejected fail-closed. Empirically re-verified.
- Accepted/deferred (code-quality LOW, non-gating): `REDACTION_CLASSES` frozenset unused; `redaction_patterns` not re-exported in `config/__init__.py`; import-time `validate_patterns()` self-check.

---

## Phase 2 — Core TCB (T2.01–T2.13), order **policy → sandbox → kernel** — IN PROGRESS

| Task | Verdict | Commit | Note |
|---|---|---|---|
| **T2.01** | **GREEN** | **5293fab** | `policy/` classes + R1–R9 classifier. `classify(request, ctx, manifest, stores)` — base=manifest floor, rules only RAISE, DENY short-circuit, R3 post-fold, monotonic. **Hardened through 3 critic rounds / 2 refine passes** (fixed 2 CRITICAL: C1 R3-ordering, S1 XDG-store bypass; + HIGH audit-path/wrapper-peel/normpath). Fail-closed `PolicyStores` injection. 184 tests. |
| **T2.02** | **GREEN** | **a1f75f6** | `canonical.py` (sole I/O module: `canonicalize` realpath+lstat fail-closed, `CanonicalPath` NewType, `env_digest`/`action_hash` §7.4 binding) + `denylist.py` (pure `deny_match`, single §7.3 authority). Hypothesis property (300ex): canonical form invariant to path spelling. **2 critics + 1 refine** (fixed HIGH env_digest non-injective binding-forgery → canonical JSON; symlink-loop; bytes-guard). CanonicalPath = type-level S4 closure. |
| **T2.03** | **GREEN** | **bd202a3** | `token.py` HMAC approval-token service (I5/I6). `mint`=HMAC over `record.canonical_bytes()` **verbatim** (T-12 structurally impossible); `verify`→TokenVerdict fail-closed (timing-safe, material-change, TTL, uses, increment-only-on-VALID). Forgery property 7×300ex. **2 critics + 1 refine** (LOW non-ASCII compare hardened). |
| **T2.04** | **GREEN** | **d3f4b5f** | `recheck.py` §7.5 pre-exec re-canonicalization (I6). `recheck`→ DANGLING/PATH_RETARGETED/PARENT_SWAPPED/NODE_REPLACED (fail-closed); node-(dev,ino) catches rename-over swap; in-place content=VALID (handler's job). `FsView` Protocol keeps logic pure, `OsFsView`=sole I/O. **2 critics DISAGREED + 1 refine** (correctness lens won: HIGH file-swap gap → node-identity check). **⚠️ CROSS-PHASE FLAG:** §7.5 step-6 is write-only (SPEC:564) → T3.x read/exec handlers MUST fstat-pin the opened inode. **`policy/` package COMPLETE.** |

| **T2.05** | **GREEN** | **e04b586** | `sandbox/` pure `build_argv` (§8.1 `ro` / §8.2 `ws`) + `project_env` §8.3 allowlist-from-scratch. NOT-a-decider (§2.2: Profile is a param; contracts+stdlib only; zero I/O). **3 critics + 1 refine.** **HIGH (empirically reproduced on bwrap 0.9.0): bwrap does NOT clear env — `--setenv` overlays an INHERITED environ; the first draft leaked 81 parent vars incl. `LSASSIST_KIMI_API_KEY`/`SSH_AUTH_SOCK`.** FIX = `--clearenv` right after `--new-session`, BEFORE the `--setenv` block (placement load-bearing). Orchestrator-verified at commit: child env = exactly {HOME,LANG,PATH,PWD}, 0 canaries; same argv w/o the flag → 83 vars + key leaked. Also fixed: HIGH colon-in-workspace PATH corruption; `workspace="/"` → `--bind / /`; `//x` spelling drift; **no test pinned §8.1 mount ORDER (mutation-proven) → full-argv snapshots**; tmpfs masking; unguarded `--setenv` values; non-Mapping extra; `ro` silently ignoring `venv_exists`. |

| **T2.06** | **GREEN** | **b743737** | `prlimit.py` (pure caps) + `availability.py` (the package's ONLY I/O): `probe()` = version parse (≥0.9.0) **+ functional namespace spawn**, both program paths validated into `{/usr/bin,/bin,/usr/local/bin}` and pinned; `compose_exec_argv(available=…)` = the ONLY exported exec-argv producer. **2 critics + 1 refine.** **HIGH: probe discarded the resolved path and ran a BARE name → a planted `~/.local/bin/bwrap` (PATH #1, writable) was ACCEPTED and ran the tool fully unsandboxed with real `~/.ssh` visible** → paths now pinned+absolute (re-verified by planting the shim). Also: receipt gate was isinstance-only (6 forgery routes minted tokens) → `init=False` + private `_issue()` + compose re-validates paths; probe attested a *binary* not a *sandbox* → functional step; mutation-proven forwarding gap; `--cpu` rationale measurably false → corrected; `MAX_TIMEOUT_S` 1800→600 (§6.4). **`sandbox/` package COMPLETE.** |

**Gate state after T2.06 (sandbox/ COMPLETE):** pytest **1071 passed** · mypy --strict clean · ruff clean · **TCB LOC 3676 / 6000** · policy pure (canonical.py + recheck.OsFsView) · sandbox pure except `availability.py` (the documented §8.3 probe boundary).

| **HARDEN-03** | **GREEN** | **1b1c9f8** | **Human-gated decision APPLIED (option A):** the whole `prlimit` fragment moved INSIDE the sandbox (head of the inner command, right after the single `--`). Verified end-to-end: rc=0 with `nproc=256 nofile=1024 as=4194304 cpu=40` observed inside, hard limit 256, and `ulimit -u 4096` inside → "Operation not permitted". New guard: a pinned `prlimit_path` outside `SYSTEM_RO_BINDS` is refused (the caps now run inside). Also caught while reordering: with the fragment in front, `build_argv` validated *prlimit* as the program, so `argv=[]` composed into a sandbox running prlimit ALONE (silent success) → `checked_argv` now validates the tool argv at both ends. **New `tests/e2e/test_sandbox_exec.py` actually spawns the composed argv** — it FAILS on the pre-fix HEAD with the original EAGAIN, i.e. it reproduces an outage the unit suite could not see. **SPEC §8.1 updated to match (see below).** |

**Gate state after HARDEN-03:** pytest **1092 passed** (405 sandbox unit + 2 e2e) · mypy --strict clean · ruff clean · **TCB LOC 3752 / 6000**.

### ✅ RESOLVED (2026-07-25) — SPEC §8.1 revised with three measured corrections
`SPEC.md` §8.1 now carries a revision table (the normative command line changed):
1. `--as=4G` → `--as=4294967296` — prlimit has no suffix parser; `4G` = **4 bytes** → every `execve` dies `E2BIG`.
2. `--unsetenv LSASSIST_KIMI_API_KEY` → `--clearenv` (after `--new-session`, **before** the `--setenv` block) — bwrap does NOT clear env by default; without it the child inherited **81** vars incl. the API key and `SSH_AUTH_SOCK`. Placement is load-bearing.
3. `prlimit` **outer** → **inner** (after `--`) — `RLIMIT_NPROC` counts tasks per real UID, so the outer position enforced nothing and blocked every exec. ⚠️ Deleting the outer `--nproc` instead would silently remove the §18 T-14 fork-bomb control.
Programs are pinned absolute paths from `probe()` (bare names allowed a PATH shim to run tools fully unsandboxed).

<details><summary>Original open-decision text (kept for the record)</summary>

### 🔴 (RESOLVED) OPEN, HUMAN-GATED DECISION — `--nproc` placement (changes SPEC §8.1's literal command line)
`prlimit --nproc=256 bwrap …` **fails to start on a normal desktop session**: `RLIMIT_NPROC` counts **tasks per real UID** (2024 threads measured here) → `bwrap: Creating new namespace failed: Resource temporarily unavailable`. Verified end-to-end; the same argv minus the outer `--nproc` runs fine. Applied **inside** the sandbox all four caps work correctly (`--nproc=32` → spawned=29 refused=31); `/usr/bin/prlimit` is already in the mount view via `--ro-bind /usr /usr`, it `execve`s (pid/exit/signal transparent), and soft==hard blocks the tool raising it.
**⚠️ Trap:** simply DELETING the outer `--nproc` makes exec work and thereby *looks* like the fix, while silently removing the §18 T-14 fork-bomb control — a security regression disguised as a bug fix. A test now asserts `--nproc=` survives in the composed argv.
Code ships §8.1 **verbatim** and flags it (no silent reorder). Options: **(A) move the whole prlimit prefix inside** (`bwrap … -- prlimit … tool`) · (B) keep outer for nofile/as/cpu, move only `--nproc` inside · (C) raise the outer value (e.g. 4096) — weakest, still session-scoped. Recommended by the security lens with measurements: **inside**. → **CHOSEN: A (HARDEN-03, `1b1c9f8`).**

</details>

**Named residual (T2.06) — now CLOSED by HARDEN-03:** the functional probe was not wrapped in the prlimit prefix, so `probe()` passed while the composed argv died. With the caps moved inside, the probe and the real spawn share the same outer program (`bwrap` directly), so the shapes match.
**Named residual (T2.05, documented in `profiles.py`):** under `ws` + `venv_exists=True`, `<workspace>/.venv/bin` outranks system tools by design (§8.2) — approval binds a NAME (§7.4), so the T3.x renderer/dispatcher must surface which binary actually runs, or require an absolute `argv[0]`.

**⚠️ T2.06 RUNNER OBLIGATIONS (recorded in `profiles.py` docstring — MUST honor):** spawn with `env={}` (NEVER `env=None` or a parent copy — that hands the whole environ to bwrap itself; `--clearenv` is defense-in-depth, not a substitute) · exec the argv **LIST** directly, never via a shell string (§7.6 rule 8) · own the `prlimit` wrapper (§8.1 prefix, not in the builder) · own every filesystem check (`/lib64` absent on some distros; whether to degrade a missing bind is a runner decision) · bwrap unavailable → typed `sandbox_unavailable` → BLOCKED, **never unsandboxed fallback** (I11).

**Named residual (T2.05):** the `--setenv` value-shape guard (`[A-Za-z0-9._@:+-]{0,64}`) blocks `=`/whitespace/`/`/metachars/oversize, but is NOT a credential detector — a short hyphenated token still matches. Containment rests on: only 7 names settable, values caller-originated (not parent env), §14.3 redactor owning secret-bearing sinks.

**Named residual (T2.01):** R5 exec-wrapper detection is defense-in-depth over a KNOWN wrapper set — the load-bearing boundary is the bwrap sandbox + gated `proc.exec` (§2.1), not this heuristic. **Flag for review:** `classify` gained a 4th arg (`stores`) vs the SPEC's 2-arg sketch.

**Open for T3.02 (dispatcher):** construct `PolicyStores` from `XdgPaths` (resolved audit/policy/kernel-secret paths) and realpath + `//`-collapse the workspace_root / target path BEFORE calling `classify` — the pure policy layer no longer does I/O (HARDEN-02 + T2.01 injection).

| **T2.07–T2.11** | **GREEN** | **f86582c** | **`kernel/` package — built as a PARALLEL WAVE (5 isolated agents) + INTEGRATE sink.** states/machine (§4.1-4.2, EXECUTE = exactly 2 entry edges, checked AT IMPORT) · budgets/loopdetect (§4.3) · verdict (§4.4-4.5, I12 downgrade-not-raise) · idempotency (§4.7, injective HMAC + domain tag) · untrusted (§4.6/I7, sole delimiter producer). **Decoupled by construction:** `machine.py` imports ZERO siblings (AST-verified), 6 Protocol collaborators instead. **2 seam-critic rounds found 15 composition defects** that 5 green unit suites + mypy --strict + a 22-test seam suite all missed — 4 HIGH (stale-PolicyView untrusted bypass · permissive negated-field defaults · unreachable loop REPORT · wall-clock double-writer re-opening the EXECUTE gate). 684 new tests (1092→**1776**), 34 seam tests driving the machine with REAL collaborators. |

**Gate state after the kernel wave:** pytest **1776 passed** · mypy --strict clean (40 TCB files) · ruff clean · **TCB LOC 5850 / 6000** (see the measurement note below) · §2.2 + I7 verified.

### 📏 TCB MEASUREMENT — decide at T2.12 (evidence gathered, nothing changed yet)
`scripts/loc-count` counts **docstrings as code**: **5850 / 6000** (98% of the warn budget) with `audit/`, `recovery/` and the `tools/` dispatcher core — all TCB — still to build. Measured the same tree **tokei-style** (docstrings counted as comments, which is what SPEC §2.3's "`tokei`-ს ექვივალენტი count job" mandates): **3178** code lines, 2672 docstring lines (46%). So `loc-count` is **not** tokei-equivalent and over-counts by ~46%. Under it we breach 6000 immediately; under the SPEC's own stated measure we land near ~4400 with everything built. **This is a measurement correction to decide with evidence at T2.12 — NOT a budget relaxation (§2.3 forbids that).**

### 🔖 NAMED RESIDUALS from the kernel wave
- **§4.7 `PARTIAL_EXECUTION` human review has no §4.2 row.** Adding one would fabricate a cause or invent §4.1/§4.4 wire values, so the turn stalls fail-closed and `replay_block()` names the condition. **Needs a SPEC amendment.**
- **Runner obligations have ZERO callers in `src/`** (budget charge/settle, `LoopTracker.observe`, `IdempotencyLedger.begin/complete`, output caps, `compute_verdict`, `require_coherent_pair`). T5.12 owns them; they are now **NAMED as side-effect tags on the rows that incur them**, so an unowned obligation is greppable rather than invisible.
- **`BudgetState` mixes per-task and per-session scope** with no reset API — a runner cannot enforce the §4.3 200-call session cap without breaking the per-task cap. Needs a contracts addition (`next_task()`).
- **`(BLOCKED, budget_exhausted)` is not constructible** — `contracts.Verdict` requires a rule id or provider status for BLOCKED, and there is no field for the budget kind. `require_coherent_pair` accepts the pair so a runner can gate it, but emitting the record needs a contracts field.
- **Collaborator adapters live only in tests** — `RegistryView`/`PolicyView`/`ProviderView`/`VerdictView`/`ReplayView` have no `src/` implementation; `tests/integration/test_kernel_seams.py` is the worked example T5.12 must productionize.

### ⏭️ NEXT: **T2.12** (TCB LOC checkpoint gate — decide the tokei question above) → **T2.13** (100%-branch coverage gate; still blocked on the `pytest-cov` mini-ADR). That closes Phase 2 and the whole TCB. Then (T2.07 §4 state machine — EXECUTE only via AUTO or valid token I15/AC-07; T2.08 budgets/loop; T2.09 verdict I12; §4.6 untrusted wrap; T2.10/11). Close with **T2.12** TCB-LOC CI gate + **T2.13** 100%-branch coverage gate.

**`policy/` package DONE** (T2.01–T2.04): classify (R1–R9) · canonicalize+denylist (§7.3/§7.5) · HMAC token (mint/verify) · re-canonicalization (invalidation). = the §7 permission-engine core. Pure except the two §7.5 I/O boundaries (`canonical.canonicalize`, `recheck.OsFsView`).

**Open item before T2.13:** `pytest-cov` is NOT in the §13.1 allowlist but T2.13 needs `--cov-fail-under=100`. Log a mini-ADR (add pytest-cov dev-only, or stdlib `coverage`) before activating the coverage gate. Does not block T2.01.

## 🐛 Defects surfaced by the 18-agent audit
1. ~~**[HIGH] TOCTOU** in `config/secrets.py::_from_file`~~ — ✅ **FIXED (HARDEN-01, 3c56f53)**: O_NOFOLLOW+fstat(fd)+O_NONBLOCK on both `_from_file` and `kernel_secret._load`; symlink + FIFO race tests.
2. ~~**[MEDIUM] Contract purity** — `contracts/policy_context.py:43` `path.resolve()` I/O~~ — ✅ **FIXED (HARDEN-02)**: validator now pure (`os.path.isabs` + `os.path.normpath==value`, AST-verified zero I/O); realpath canonicalization re-homed to dispatcher (T3.02, §7.5). Contract tests now FS-independent. **Note for T3.02:** dispatcher must realpath the workspace_root before constructing PolicyContext (contract no longer does it); also collapse a leading `//` (POSIX normpath preserves it).
3. **[design-note, OPEN] Verdict I12** — contracts `Verdict` RAISES on evidence-less VERIFIED (good, construction-time). `compute_verdict` (T2.09) must DOWNGRADE→UNVERIFIED, never raise/swallow.

## Elite loop to follow per task (do NOT use low-tier agents)
freeze intent (9 fields verbatim) → read-only scout ground → pre-code human gate → **RED first** → elite-coder (Opus) in scope → deterministic floors at root (authoritative) → 3 isolated adversarial critics (Opus) → pure verdict (no LLM grades itself) → refine ≤2 (V7: any correctness/security defect forces 1 pass) → human Review checkpoint → commit `Tx.yy: …` → next. Weave/fan-out ONLY for ≥3-way file-disjoint splits.

See `../PROJECT_STATE_ANALYSIS.md` for the full spec/plan/methodology brief.
