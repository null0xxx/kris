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
- **Last updated:** 2026-07-28

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

| **T2.12+T2.13** | **GREEN** | **5baa9e9** | TCB LOC gate (tokei-style; **measurement correction**, not a budget relaxation) + 100% branch gate + **ADR-011** (`coverage`, not `pytest-cov`). T2.13's premise was FALSE — the tree was at 99% with a `# pragma: no cover` hiding two statements; closed with real tests. 5+16 mutations, all killed. **Phase 2 COMPLETE.** |

---

## Phase 3/4 — Wave 1 (T3.01 · T3.08 · T4.01), 2026-07-27

Three file-disjoint frontier tasks built as one wave, each RED-first, then put
through **16 isolated adversarial agents** (7 per-node lens critics + 8 refuters +
1 seam critic). They returned **37 findings**; the orchestrator reproduced the
material ones firsthand before acting on any of them, and two were REFUTED and
dropped. Everything below landed in a single refine pass.

| Task | Verdict | Note |
|---|---|---|
| **pre-flight** | **GREEN** (`f3b0212`) | `chore:` — CI restored to the git root. The 2026-07-26 re-root left `.github/workflows/ci.yml` inside `lsassist/`, so **all five gate jobs had been inert since `b79267c`** — nothing was red because nothing ran. `git mv` + `defaults.run.working-directory`, plus a second break the move alone would not have fixed: `hashFiles()` resolves against `GITHUB_WORKSPACE`, NOT `working-directory`, so all three pip cache keys had collapsed to a constant. 3 new location pins, both mutation-proven. |
| **T3.01** | **GREEN** | `tools/registry.py` + `manifest_schema.json` (§6.2 **verbatim**, extracted from SPEC.md rather than retyped). Immutable catalog, no public constructor, duplicate-name rejection naming BOTH files, fail-closed load. **TWO independent encodings of §6.2** (shipped JSON Schema + `contracts.ToolManifest`) validated in that ORDER — measured: pydantic's lax mode accepts 5 documents §6.2 rejects (`idempotent:"yes"`, `dry_run:1`, `timeout_s:"10"`, …), so schema-first is load-bearing. Non-TCB: TCB LOC unmoved. |
| **T3.08** | **GREEN** | `providers/base.py` — plumbing only. Contract types re-exported by **IDENTITY** (a parallel `ProviderError` would break the kernel's `except`). `UsageCounter` monotonic by construction (a negative delta would buy back §4.3 budget), `healthy`/`unhealthy`, `ensure_provider_profile`. The §2.2/§5.1 prohibition list lives in `base.py` as DATA and is enforced by an **AST** checker (grep would flag its own rule list). |
| **T4.01** | **GREEN** | `audit/redactor.py` — THE single redactor (I8). Consumes T1.10's DATA by reference. Ordered rules to a **fixpoint**, `[REDACTED:<class>]`, hits record class+count, fail-closed to digest-only with a payload-free `error_detail`. Corpus 100% on all 7 §12.4 classes; fuzz **10,000 secret-shaped examples, 0 leaks** (measured: 2500 passing / 0 invalid × 4 secret strategies). `audit` joined the §23.1 branch floor — **100% branch, 0 partial, 0 pragmas**. |

### 🔴 What the adversarial round found — every one reproduced firsthand

The three nodes were **not** committable as first drafted. Ordered by severity:

| Sev | Defect | Fix |
|---|---|---|
| **CRITICAL** | **OpenPGP armored private keys were not redacted at all.** T1.10's source ends `PRIVATE KEY-----`; PGP armor ends `PRIVATE KEY BLOCK-----`, so it matched nothing — while `~/.gnupg` is a §7.3 DENY_ALWAYS subtree. | engine-owned BEGIN form; **named residual: this is DATA and belongs in T1.10's table** |
| **HIGH** | **An injected `-----END … PRIVATE KEY-----` truncated the block** and published the real body verbatim. Tool and model output can contain such a line. | body is now GREEDY-to-last-END, TEMPERED so it cannot cross the next `BEGIN`. `<body>(?:<end>\|\Z)` is WRONG and was measured to be: `\Z` matches empty at EOF, so the greedy body ate the whole payload |
| **HIGH** | **A secret revealed by an earlier replacement was emitted verbatim.** `AKIA…sk-…`: the `sk-` rule's `(?<![A-Za-z0-9])` boundary failed while the AWS prefix was still there, and by the time AWS ran, `sk-` had already run. | ordered pass now iterates to a **fixpoint** (`MAX_PASSES`), non-convergence is an engine error |
| **HIGH** | **An empty or filtered pattern table built a NO-OP redactor reporting clean success** — the one degenerate input that failed **OPEN**. | a table missing any §12.4 class T1.10 declares is refused |
| **HIGH** | **`_fail_closed(digest, detail)` discarded `detail`.** Four call sites computed a reason; all four dropped it. The docstring said "the reason recorded". | `error_detail` on `AuditRedaction`, payload-free by construction (build-time keeps the message; substitution-time records the exception TYPE only, because an arbitrary `str(exc)` can quote the secret) |
| **HIGH** | **`tests/contract/` was executed by NO CI job.** Both new nodes ship their only enforcement gate there. Raising the shipped schema's `timeout_s` ceiling 1800→86400 left `pytest tests/unit` fully green. | `unit` job runs `tests/unit tests/contract`; a test now pins that every layer carrying a gate is named by some job |
| **HIGH** | **The §2.2/§5.1 prohibition gate was theatre.** Six spellings measured, six MISSED: `from os import system`, `Path(p).write_text(t)`, `p.write_text(t)`, `from ..kernel import decide`, `importlib.import_module(...)`, `sys.stderr.write(m)`. | symbol list + receiver-independent METHOD matching + relative-import resolution; each bypass is now its own harness guard |
| MEDIUM | `repr(text)` sat OUTSIDE the try, so a hostile `__repr__` made the "total function" raise at the caller. | moved inside |
| MEDIUM | `deny_paths` were silently DISCARDED when the table had no slot to place them in. | fail-closed; second lock kept and tested by disabling the first |
| MEDIUM | **JSON duplicate keys collapsed last-wins**: a manifest declaring `permission_class` as both `AUTO_READ` and `DENY_ALWAYS` loaded as `DENY_ALWAYS`. The §6.2/§7.1 permission CEILING decided by parser trivia. | `object_pairs_hook` refuses any repeated key |
| MEDIUM | **`manifest_schema.json` was not packaged.** A wheel built from this tree contained ZERO non-.py files, so `load_registry()` raised on every call for any non-editable install — kernel startup permanently BLOCKED. Hidden by ADR-005's editable install, which resolves back to the source tree. | `[tool.setuptools.package-data]` incl. `manifests/*.json` (that dir has no `__init__.py`, so a bare `*.json` glob does not reach it) |
| MEDIUM | `engine_canaries` escaped T1.10's AC-12 "every value is synthetic" guard, which parametrizes over `canaries` only. | mirrored guard over the new array |
| MEDIUM | The pragma-grep step's two package lists were unpinned **individually**: dropping `audit` from either failed open with the suite green. | both gate tests parametrized over every TCB package |
| LOW | `Redactor.rules` handed out compiled patterns — and a configured-secret rule's source is `re.escape(<the secret>)`. | returns `RuleInfo(name, class_label)` only |
| LOW | The registry's `_issuance` sentinel was **written and never read**; the docstring claimed a sandbox-style forgery defense that did not exist. | removed, and the docstring now says plainly that this is a MISUSE gate, not a forgery gate |
| — | REFUTED and dropped: the `NaN` cost guard, and "the default facade silently no-ops two classes" (documented, tested, and unavoidable — neither class is knowable statically). | — |

**Gate state after Wave 1 + HARDEN-04:** pytest **2249 passed, 0 failed, nothing deselected** · ruff clean · `mypy --strict` clean on all 6 TCB packages + `providers/base.py` · `mypy src` clean (54 files) · **TCB LOC 3756 / 6000** · **100% branch on kernel+policy+sandbox+audit**, 0 partial, 0 pragmas.

### ✅ RESOLVED (HARDEN-04) — a pre-existing kernel defect surfaced by Hypothesis

`tests/property/kernel/test_state_machine.py::test_wired_decision_states_never_park`
FAILS, and **reproduces at HEAD with this wave's changes stashed** — it is a
latent defect in already-committed TCB code (T2.07-T2.11, `f86582c`) that the
randomized property suite had simply never generated an input for.

Root cause, isolated: `machine.py` contains two functions that **disagree about
what `ReplayView.replay_verdict() -> None` means**.

- `replay_block()`: `None if seen is None or seen == REPLAY_ALLOWED else seen` → `None` is NOT a block.
- `_g_replay_allowed()`: `replay_verdict() == REPLAY_ALLOWED` → `None` is NOT allowed.

So with an `AUTO_READ` request, budget and provider fine, and a replay view that
returns no verdict, `POLICY_CHECK --POLICY_CLASSIFIED-->` has **no firing row**:
`_g_auto_class` false, `_g_needs_consent` false (not a CONFIRM class), no BLOCKED
guard true. `missing_measurements()` reports nothing (the collaborator is
present; only its ANSWER is absent) and `replay_block()` names nothing. The turn
parks with **no diagnosis at all** — precisely the outcome `replay_block`'s own
docstring says must not happen ("a silent stall would make the runner retry
forever").

Fail-CLOSED (safe direction) but undiagnosable. Treating `None` as ALLOWED would
have opened an I15 EXECUTE edge on an unconsulted ledger, so that direction was
never on the table.

**FIXED — HARDEN-04, human-gated, option B.** The `ReplayView` Protocol settles
what `None` means in its own words: *"the §4.7 verdict for the CURRENT action, or
`None` if **not consulted**"*, and *"every other value, **and `None`**, refuses"*.
So an absent verdict is an absent MEASUREMENT, not a state the guards can resolve
by waiting — `missing_measurements()` now reports `replay.replay_verdict` for
`POLICY_CHECK` and `APPROVAL` (`_g_valid_token` reads the same verdict, so
APPROVAL had the identical hole). Nothing was invented: the fix restates the
module's own contract, and `_REQUIRED_READINGS` generalises it so the next
collaborator-with-an-absent-answer is a table row rather than a rediscovery.

Hypothesis then moved to a SECOND counterexample, `ALREADY_EXECUTED`, which is
the kernel wave's own **already-recorded residual** (§4.7 has no §4.2 row; the
turn stalls fail-closed and `replay_block()` names it, pending a SPEC amendment).
That one is a TEST-side gap: `test_wired_decision_states_never_park` honoured
only ONE of the module's three documented stall kinds. Its exemption now covers
`replay_block()` too — and is not a blanket escape, because when it fires the
named condition is asserted to be a genuinely refusing verdict.

2 mutations, 2 killed: reverting the reading check, and making an absent verdict
count as ALLOWED (which the pre-existing N6 EXECUTE-edge test also caught —
proof the fail-open direction was already fenced).

### 🔖 Named residuals from Wave 1
- **`_ENGINE_PRIVATE_KEY_BEGINS` is pattern DATA living in the engine.** OpenPGP armor belongs in T1.10's table; it is in `audit/redactor.py` only because T4.01's scope forbids touching `config/`. A follow-up should move it and delete the constant.
- **`payload_digest` is a confirmation oracle.** It is sha256 of the PRE-redaction text, as T4.01 specifies. Anyone who can guess a secret can confirm it against a stored record. Inherent to digest-based evidence (§6.5 does the same for `stdout_digest`); recorded rather than silently changed.
- **`contracts.ToolManifest` is weaker than §6.2** in pydantic's lax mode (measured: at least 5 vectors). The registry contains it by validating schema-first. Tightening the model (`ConfigDict(strict=True)`) is a TCB `contracts/` change and was not made from a non-TCB task.
- **`AssistantTurn.reasoning_opaque` is excluded from `model_dump`/`model_dump_json`/`repr` but NOT from `dict(turn)`, `turn.__dict__` or `pickle`.** `contracts/provider.py`'s docstring says "every serialization form", which overstates it. T3.08 did not edit that TCB file; T4.02's writer must not reach the blob by those routes.
- **T4.02 must hold ONE `Redactor` built at startup.** The facade rebuilds and recompiles the rule set whenever runtime data is passed, and in production `configured_secrets` is never empty.
- **`MAX_PAYLOAD_CHARS` (1 MB) is an engine-invented DoS cap**, not a plan requirement. Documented; oversized payloads are stored digest-only.

### ⏭️ NEXT after this wave
Recomputing the closure over `Depends on`: **T3.02** (dispatcher — the `tcb-planned` file, which flips the LOC manifest to `tcb` the moment it appears) and **T4.02** (audit writer, which unblocks T3.03). Carry the cross-phase obligations already recorded for T3.02 (PolicyStores from XdgPaths, realpath + leading-`//` collapse, fstat-pinned read/exec handlers, `env={}`, argv LIST, never an unsandboxed fallback).

---

<details><summary>Superseded planning note (kept for the record)</summary>

### ⏭️ (SUPERSEDED) NEXT: **T2.12** (TCB LOC checkpoint gate — decide the tokei question above) → **T2.13** (100%-branch coverage gate; still blocked on the `pytest-cov` mini-ADR). That closes Phase 2 and the whole TCB. Then (T2.07 §4 state machine — EXECUTE only via AUTO or valid token I15/AC-07; T2.08 budgets/loop; T2.09 verdict I12; §4.6 untrusted wrap; T2.10/11). Close with **T2.12** TCB-LOC CI gate + **T2.13** 100%-branch coverage gate.

</details>

**`policy/` package DONE** (T2.01–T2.04): classify (R1–R9) · canonicalize+denylist (§7.3/§7.5) · HMAC token (mint/verify) · re-canonicalization (invalidation). = the §7 permission-engine core. Pure except the two §7.5 I/O boundaries (`canonical.canonicalize`, `recheck.OsFsView`).

**Open item before T2.13:** `pytest-cov` is NOT in the §13.1 allowlist but T2.13 needs `--cov-fail-under=100`. Log a mini-ADR (add pytest-cov dev-only, or stdlib `coverage`) before activating the coverage gate. Does not block T2.01.

## 🐛 Defects surfaced by the 18-agent audit
1. ~~**[HIGH] TOCTOU** in `config/secrets.py::_from_file`~~ — ✅ **FIXED (HARDEN-01, 3c56f53)**: O_NOFOLLOW+fstat(fd)+O_NONBLOCK on both `_from_file` and `kernel_secret._load`; symlink + FIFO race tests.
2. ~~**[MEDIUM] Contract purity** — `contracts/policy_context.py:43` `path.resolve()` I/O~~ — ✅ **FIXED (HARDEN-02)**: validator now pure (`os.path.isabs` + `os.path.normpath==value`, AST-verified zero I/O); realpath canonicalization re-homed to dispatcher (T3.02, §7.5). Contract tests now FS-independent. **Note for T3.02:** dispatcher must realpath the workspace_root before constructing PolicyContext (contract no longer does it); also collapse a leading `//` (POSIX normpath preserves it).
3. **[design-note, OPEN] Verdict I12** — contracts `Verdict` RAISES on evidence-less VERIFIED (good, construction-time). `compute_verdict` (T2.09) must DOWNGRADE→UNVERIFIED, never raise/swallow.

## Elite loop to follow per task (do NOT use low-tier agents)
freeze intent (9 fields verbatim) → read-only scout ground → pre-code human gate → **RED first** → elite-coder (Opus) in scope → deterministic floors at root (authoritative) → 3 isolated adversarial critics (Opus) → pure verdict (no LLM grades itself) → refine ≤2 (V7: any correctness/security defect forces 1 pass) → human Review checkpoint → commit `Tx.yy: …` → next. Weave/fan-out ONLY for ≥3-way file-disjoint splits.

See `../PROJECT_STATE_ANALYSIS.md` for the full spec/plan/methodology brief.

---

## Phase 3/4 — Wave 2 (T3.02, T4.02), 2026-07-27/28

Continued from the recomputed frontier, one task at a time, each RED-first and
each put through an isolated adversarial round before commit.

| Task | Verdict | Note |
|---|---|---|
| **T3.02** | **GREEN** (`b87dad3`) | `tools/dispatcher.py` — §6.3 steps 1-4. The FIRST TCB file inside `tools/`; the LOC manifest's `tcb-planned` row went RED the moment the file appeared, exactly as designed, and was flipped to `tcb`. The dispatcher decides nothing itself: `classify` owns the class, `canonicalize` the §7.5 boundary, `project_env` the child env, `TokenService` the token. |
| **T4.02** | **GREEN** (`2ac1c0a`) | `audit/schema.py` + `audit/writer.py` — §14.1 append-only JSONL, hash chain, fsync policy, 50 MB/10-file rotation. Append-only is a DESCRIPTOR property (`O_APPEND`, asserted off the live fd); the chain continues across both rotation and writer restart; `verify_chain` never raises and names the broken record. |

### 🔴 T3.02 — four isolated lenses converged INDEPENDENTLY on one CRITICAL

**Step 3 classified the RAW request, not the normalized one.** §6.3 orders step 2
(realpath, symlink-chain resolution) before step 3 precisely so policy judges the
path that will be opened. `normalize()` canonicalized into a COPY and `dispatch()`
then handed `classify()` the original. Measured:

```
control: fs.read ~/.ssh/id_rsa            -> BLOCKED / DENY_ALWAYS
attack:  <ws>/notes.txt -> ~/.ssh/id_rsa  -> PROCEED / AUTO_READ
         handler receives args={'path': '<home>/.ssh/id_rsa'}
stronger, nothing outside the workspace needed:
         <ws>/readme.md -> <ws>/.env      -> PROCEED / AUTO_READ
```

A symlink already present in a cloned repository is sufficient — no model action,
no prompt. §7.3's DENY_ALWAYS is specified as absolute ("no approval can grant
it") and degraded to AUTO with an audit entry naming AUTO_READ. This was recorded
cross-phase obligation 1 left half-done: `workspace_root` was resolved, the TARGET
was not — which made `rules.py`'s own docstring claim factually false.

Also confirmed and fixed: a real approval token could NEVER verify (the rebuilt
record re-stamped `issued_at`, which is inside `canonical_bytes()`, so the HMAC
matched only in the second of minting — the whole §7.1 CONFIRM flow was unusable
and `TokenVerdict.EXPIRED` was unreachable) · `ToolError.message_redacted` echoed
the model-supplied argument verbatim via jsonschema (I8) · `env_digest` bound an
environment no child ever gets · the model/wiring split was a SUBSTRING match on
model-controlled text · `policy_rule_id` named the first rule that FIRED rather
than the one that DENIED · plus five more MEDIUMs. **Two mutations survived the
first attempt and were the most valuable of the run**: one showed a fix was
INCOMPLETE, the other that a test was WEAK.

### 🔴 T4.02 — the fuzz found a framing defect, and a test HUNG rather than failed

**`str.splitlines()` breaks on more than `\n`.** U+0085, U+2028 and U+2029 are
line boundaries, and `ensure_ascii=False` leaves exactly those three raw (measured
— `json.dumps` already escapes every ASCII control character). One record
containing U+2028 became TWO journal lines, the chain read MALFORMED, and one
payload had silently become two. U+2028 is common in JavaScript-derived text and
tool output is attacker-influenced.

**A FIFO at a journal path hung the CONSTRUCTOR.** Resuming the chain reads the
previous record first, and `_resume` used `Path.read_text()`: the WRITE path had
been hardened and the READ path, which runs earlier, had not. Journal reads now
use HARDEN-01's full pattern (`O_NOFOLLOW` + `O_NONBLOCK` + `fstat` + a size
bound).

### 🔖 Named residuals from Wave 2
- **T3.02:** `create_if_missing` requires `fs=write_scoped`, but the manifest cannot tell `fs.write` (creates) from `fs.patch` (does not) — T3.04's boundary. A dangling path from the model propagates as a WIRING-class error; T3.03/T3.04 own the tool-level error kind. The token check is a PRE-FILTER: of `machine._g_valid_token`'s four conditions it checks the two it can see, and consent liveness plus the §4.7 replay verdict stay the kernel's.
- **T4.02:** the chain is tamper-EVIDENT, not tamper-PROOF (no secret in the link; a full rewrite from the edit to the end is consistent). `payload_digest` binds the PRE-redaction payload — the same confirmation-oracle residual the redactor carries.
- **Gate shape:** §23.1's 100% floor names PACKAGES and `tools/` is not one, so `tools/dispatcher.py` is measured by its own blocking `dispatcher-coverage` job; the `coverage` job keeps its "exactly one measurement" property, which is itself a gate.

**Gate state after Wave 2:** pytest **2557 passed** · ruff clean · `mypy --strict` clean on 6 TCB packages + `tools/dispatcher.py` · **TCB LOC 4720 / 6000** · **100% branch on kernel+policy+sandbox+audit**, 0 partial, 0 pragmas · CI: 6 jobs.

### ⏭️ (SUPERSEDED) NEXT frontier after Wave 2
`T3.03` (dispatch steps 5-9 — now unblocked by T4.02) and `T4.03` (audit reader).
T3.03 carries the recorded runner obligations from T2.06: `env={}` (never `None`),
the argv LIST (never a shell string), the `prlimit` prefix, and bwrap missing →
`sandbox_unavailable` → BLOCKED, never an unsandboxed fallback.

---

## Phase 3 — T3.03, 2026-07-28

| Task | Verdict | Note |
|---|---|---|
| **T3.03** | **GREEN** (`d4f12c7`) | `tools/dispatcher.py` §6.3 steps 5-9 + the new **TCB** file `tools/result.py` (§6.5 assembly, pure). Both joined the LOC manifest, `mypy --strict` and the `dispatcher-coverage` job. RED first on both new layers (ImportError). |

**Frontier note.** The recomputed closure at this point had **seven** ready tasks,
not the two Wave 2 recorded: `T3.03`, `T3.09`, `T3.11`, `T4.03`, `T4.04`, `T4.07`,
`T4.10`. T3.03 was taken because it unlocks the deepest chain (T3.04→T3.07 plus
T5.05).

### 🔴 §7.5 steps 2-3 did not exist

Step 3's pre-exec re-canonicalization has nothing to compare against without an
approval-time snapshot, and T3.02 stopped at the decision. `normalize()` now
captures `path_snapshots`; a create-intent target snapshots its **parent**, which
makes `recheck` work unchanged. It is deliberately **not** in `action_hash` — a
snapshot measures the world, and folding it into the binding would break an
approval the moment anything on disk moved.

### 🔴 What the four isolated lenses found — four CRITICAL, every one reproduced

The lenses ran with only {frozen intent, one diff, one lens, floors}. The risk and
readability lenses converged **independently** on the same argv-parsing defect.

| Sev | Defect | Fix |
|---|---|---|
| **CRITICAL** | **The wall-clock timeout was defeated by a child that closes both pipes and keeps running.** The selector loop ended on EOF, the deadline was only ever checked *inside* it, and `wait()` then blocked unbounded. Measured: `timeout_s=1` → returned after **20.00 s** with `timed_out=False`. `prlimit --cpu` cannot cover it (a sleeping process burns no CPU). A **HANG**, not a red test. | the deadline now outlives the read loop (`wait(timeout=…)` → kill → `wait()`) |
| **CRITICAL** | **`_check_env_binding` scanned the whole composed argv**, including the model-supplied tool argv after `--`. `["/bin/echo","--setenv"]` ran off the end with a bare `IndexError` — neither `SandboxUnavailable` nor `ExecRefused`, so it escaped `run()` and the refusal was never journalled; two tokens later the same parse produced a **false** `ENV_REBOUND` on an approved call. | parse only the bwrap prefix (`takewhile(… != "--")`), short pairs dropped fail-closed |
| **CRITICAL** | **A post-exec `RecheckError` escaped `run()`** after the tool had run and before step 9 — a completed action with no §14.1 record. Only the *pre*-exec `recheck` had a handler. | → `UNVERIFIED`, still journalled (I12: downgrade, never disappear) |
| **CRITICAL** | **A spawn failure was never audited.** `Popen` raising `EAGAIN` under `RLIMIT_NPROC` (the limit HARDEN-03 already watched break this host) surfaced as a `DispatchError` no `except` caught. | §8.3 names it: `sandbox_unavailable` → BLOCKED, journalled like every other refusal |
| **HIGH** | **The `spawn_capped` call-site contract test was THEATRE.** It grepped `src/` for `spawn_capped(`, and the only occurrence is the `def` line — the real invocation is spelled `runner(...)`. It passed on the definition alone, would have passed with **zero** callers, and could not see a second module using the same injected-default idiom. | AST walk: no other module *names* it, nothing *calls* it directly |
| **HIGH** | "a schema-rejected result is never published" had **no assertion** — mutating it to `result=capped` left the whole suite green. | assertion added |
| MEDIUM | **`output_schema` does not catch a non-serializable payload.** jsonschema validates only constrained properties, so `{"stdout": {1,2}}` passed and `json.dumps` raised *after* the tool ran. | typed, journalled `malformed_tool_result`; the message names the exception TYPE only (I8) |
| MEDIUM | `_file_snapshot` bounded `st_size` once instead of the bytes read; a growing target under `ws` defeated its own documented cap. | bound moved into the read loop |
| — | **REFUTED by measurement:** "bwrap's `--new-session` `setsid()`s away from the killed group, so the timeout cannot reach the workload". 3 sleepers inside a real sandbox, `timeout_s=2` → returned in **2.00 s**, rc 137, **zero survivors**. `--unshare-all` gives the sandbox its own PID namespace, so killing bwrap (its PID 1) reaps everything; `killpg` never needs to reach past it. | — |

**7 mutations, 7 killed** — one per fix above.

`audit` is now a **required** keyword on `run()`. An optional audit sink makes
"every execution is recorded" a property of whoever remembered to pass one.

**Gate state after T3.03:** pytest **2632 passed** · ruff clean · `mypy --strict`
clean on 6 TCB packages + `tools/dispatcher.py` + `tools/result.py` · **TCB LOC
5359 / 6000** · **100% branch, 0 partial, 0 pragmas** on kernel+policy+sandbox+audit
**and** on both `tools/` TCB files · CI **7 jobs**.

### 🧪 CI — a second layer that no job ran

`tests/integration` and `tests/e2e` were executed by **no** CI job — the same
defect the Wave-1 seam critic found in `tests/contract/`. The new `integration`
job runs both, **installs bubblewrap** (a suite that skips is not a gate) and is
bounded by `timeout-minutes` (a hang is now a proven failure mode in this code).

### 🔖 Named residuals from T3.03
- **§7.2 R2 admits an APPROVED out-of-workspace write and no V1 profile can
  express one** (§8.2 binds the workspace and nothing else rw). Step 5 refuses it
  as `workspace_scope` rather than leaving it to die as `EROFS`. Closing it is a
  §7.2 or §8 SPEC change, not a dispatcher change.
- **§6.4's `test.run` cannot be dispatched as catalogued** — it is `write_scoped`
  with an argv and NO path argument, exactly the shape T3.02's guard refuses.
  T3.06's boundary.
- §7.5 step 6 stays **write-only** (SPEC:564), so read/exec tools report
  `NOT_APPLICABLE` and their handlers must fstat-pin the opened inode (T3.04/T3.06).
- §6.5 carries **one** `evidence` object, so a multi-path write tool can publish
  only the first target's snapshot.
- §6.5 has **no representation for "no process ran"**: a BLOCKED outcome reports
  `exit_code=0` and lets `status=error` carry the meaning.
- The child gets no `LC_ALL`/`TERM` even though §8.3 allows them, because T3.02
  bound an `env_digest` computed without them.
- §6.2 carries one `fs` capability per **tool**, so `_check_write_scope` cannot
  tell a read path from a write path and refuses every out-of-workspace declared
  path.

### ⏭️ NEXT frontier
Recompute the closure yourself. At `d4f12c7` the ready set is **T3.04** (read-only
tool batch — the first task with real handlers, and the owner of the fstat-pinning
obligation above), **T3.09**/**T3.11** (provider adapters), **T4.03** (audit
reader), **T4.04**, **T4.07**, **T4.10**.
