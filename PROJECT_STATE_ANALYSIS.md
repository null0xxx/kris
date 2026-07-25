# LinuxSec Assistant — Project State & Elite-Continuation Brief

- **Version:** 1.0
- **Date:** 2026-07-24
- **Author:** Claude Code (Opus 4.8, 1M) — 18-agent workflow audit
- **Scope:** სრული, გადამოწმებული ანალიზი (SPEC + PLAN + code + `.atlas` session + `kimi-atlas` plugin), Gate 4-ის ელიტარულ გაგრძელებამდე
- **Method:** ATLAS-WEAVE-style fan-out (14 deep readers → 3 synthesis critics), ყველა finding firsthand grounded

> **ენის წესი (SPEC §0.3):** prose = ქართული+English; ყველა code identifier / path / command = English. ეს დოკუმენტიც ამ წესს იცავს.

---

## 0. Executive verdict (რა დონეზეა პროექტი)

| განზომილება | დონე | მტკიცებულება |
|---|---|---|
| **მეთოდი (`atlas` plugin)** | **ელიტარული ✦** | dამტკიცებადი halting (gas bound, `dispatches ≤ 173`), determinism fence (მხოლოდ 2 LLM structural decision), anti-false-green backstops, opus re-audit-ით ნაპოვნი+გასწორებული 7 დეფექტი, honest §10 residuals |
| **SPEC (Gate 2)** | **ელიტარული ✦** | 16 enforceable invariant (mechanism+verification თითო), ADR-ები weighted matrix-ით + host-verified facts + dated citations, threat model + 5 catastrophic scenario + 20 measurable AC |
| **PLAN (Gate 3)** | **ძალიან მაღალი** | 70 test-first task, topological, თითო 9-label template-ით; `verify_plan.py` = 70 tasks / 0 fails |
| **Code (რაც არის)** | **მაღალი, დისციპლინირებული** | contracts+config high-fidelity TDD build; მაგრამ gates ვერ გაეშვა (იხ. §3 blocker) → 3 confirmed defect |
| **სიმწიფე (progress)** | **ადრეული** | 70 task-იდან **10 done** (≈14%); 7 TCB module-იდან **2 populated** |

**დასკვნა:** *რელსები ელიტარულია; მატარებელი ახლახან გავიდა სადგურიდან.* ყველაზე რთული ფენა (foundation + verification methodology) გაკეთდა სწორად. რისკი აღარაა "ცუდი დიზაინი" — რისკია **invariant-ების შენარჩუნება** ახალი კოდის წერისას (§5).

---

## 1. რა არის LinuxSec Assistant

ნულიდან აგებული, security-first, sandboxed პერსონალური Linux AI-ასისტენტი. **არა** OpenClaw/Kimi/Hermes fork ან wrapper — საკუთარი:
deterministic agent **kernel** (state machine), provider abstraction (`kimi-coding` + `ollama-local`), typed **tool runtime** (12 tool), capability-based **permission engine** (HMAC approval tokens), **sandbox** (bubblewrap `ro`/`ws` profiles + prlimit), **skills** (data-only, no code V1), **memory** (SQLite+FTS5), **audit/recovery** (hash-chained JSONL + shadow-git), Coding Mode, Linux Tutor Mode, human-gated self-improvement **LAB** (default-OFF).

**Trust model:** ერთადერთი load-bearing boundary = (1) kernel dispatch pipeline + (2) OS isolation (bwrap+rlimits+Unix perms). Prompt-level delimiters = **signal layer, არა boundary** — დიზაინი ვარაუდობს რომ ისინი ჩაიშლება, ამიტომ untrusted turn-ზე tool capability იკვეცება.

**TCB budget:** ≤ 6,000 LOC (warn) / hard-stop **8,000** (feature freeze, არა budget relaxation). იზომება `scripts/loc-count`-ით CI-ში.

---

## 2. სად ვართ ზუსტად (state vs plan)

- **git:** `lsassist/` @ commit `f00dd44` "T1.09", branch `main`, **working tree clean**, 9 commits.
- **Phase 1 (Foundation): 10/11 done.** დარჩა **მხოლოდ T1.10**.
- **TCB modules populated: 2/7** — `contracts/` (~1086 LOC, 12 module) + `config/` (~933 LOC, 6 module). ორივე high-fidelity TDD (213 unit test).
- **ცარიელი 0-byte `__init__.py` stub-ები (12 package):** `kernel`, `policy`, `sandbox`, `audit`, `recovery`, `tools`, `providers`, `memory`, `skills`, `tutor`, `cli`, `coding`.

### 2.1 რა გაკეთდა (T1.01–T1.09, T1.11)

| Task | რა | commit |
|---|---|---|
| T1.01 | Host re-verification (`docs/env-verification-gate3.md`, `verify-env.sh` = OK) | folded → T1.02 |
| T1.02 | Repo+packaging bootstrap: §22 tree, `pyproject.toml` (mypy --strict scoped to 7 TCB modules), `requirements.lock`+`-dev.lock` (pins+hashes), `scripts/loc-count`, `ci.yml` | 6a91988 |
| T1.03 | `contracts/` enums + `Verdict`/`Evidence` **I12 validator** (evidence-less VERIFIED = unconstructable) | 08bdd38 |
| T1.04 | `contracts/` `ToolManifest` (`extra='forbid'`, 15 req fields) + `schemas/tool-manifest.schema.json` diffed vs §6.2 (**I4**); `ToolResult` | 2b9af93 |
| T1.05 | `contracts/` `ApprovalRecord` + **`canonical_json()`** = single HMAC-binding serializer (**I5/I6**); `BudgetState` | 5db66ca |
| T1.06 | `contracts/` provider-neutral layer; `reasoning_opaque` `Field(exclude=True)` (**I16**), no subprocess in providers surface (**I1**) | df78b2f |
| T1.11 | `contracts/` `ToolRequest`, `PolicyContext`, `IntentRecord`, sandbox `Profile` enum (ro/ws, ws-net absent) | 36bb6e4 |
| T1.07 | `config/` XDG §12.1 (dir 0700/file 0600, lstat symlink defense, ownership==euid) + canary honeyfiles (`O_CREAT\|O_EXCL\|O_NOFOLLOW`) | cb38f25 |
| T1.08 | `config/` versioned config schema §12.2 (version gate, unknown→drop, Ollama localhost-only regex) | 74e233a |
| T1.09 | `config/` secrets resolution (env→keyring→0600 file, ADR-004) + `kernel_secret.py` (32-byte `O_EXCL\|O_NOFOLLOW`, fstat TOCTOU-hardened) | f00dd44 |

### 2.2 TCB LOC budget
**1,580 / 6,000** (loc-count, T1.09) — ~26% of soft target. Headroom = 4,420 → soft, 6,420 → hard-stop. **⚠️ მაგრამ მხოლოდ 2/7 TCB module ითვლება** — kernel/policy/sandbox/audit/recovery + tools dispatcher ჯერ არაა. ეს 5 module ყველაზე მძიმეა; budget-ს დააკვირდი Phase 2-ში.

---

## 3. 🔴 HARD BLOCKER — gates ვერ გაეშვა

**venv არ არსებობს.** ყველა gate სისტემურ `python3 3.12.3`-ზე გაეშვა, რომელსაც აკლია `pydantic`, `ruff`, `mypy`.

| Gate | სტატუსი |
|---|---|
| **pytest** | 🔴 **0 executed** — 16 collection error (9× `No module named pydantic`, 7× `No module named lsassist`). exit 2. |
| **ruff** | 🔴 ABSENT (pinned `0.16.0`, არ დაინსტალდა) |
| **mypy** | 🔴 ABSENT (pinned `2.3.0`) |
| **loc-count** | ✅ PASS (1580/6000) |
| **verify-env.sh** | ✅ PASS (RESULT: OK) |

**შედეგი:** RED→GREEN TDD **შეუძლებელია** სანამ venv არ დაინსტალდება. test/mypy/ruff სტატუსი = **UNKNOWN, არა passing.**

**FIX (ADR-005 — uv absent, stdlib venv):**
```bash
python3 -m venv ~/.local/share/lsassist/venv
V=~/.local/share/lsassist/venv/bin
$V/pip install --require-hashes -r lsassist/requirements.lock -r lsassist/requirements-dev.lock
$V/pip install -e lsassist --no-deps
# შემდეგ: $V/python -m pytest -q  /  $V/python -m ruff check  /  $V/python -m mypy src
```

**+ open ADR:** `pytest-cov` არაა §13.1 allowlist-ში, მაგრამ T2.13 მოითხოვს `--cov-fail-under=100`. საჭიროა mini-ADR (დაამატე pytest-cov dev-only allowlist-ში, justification-ით) **Phase 2 close-მდე**.

---

## 4. 🐛 Confirmed real defects (firsthand, source-grounded)

ეს **ნამდვილი** დეფექტებია არსებულ კოდში (არა hypothetical). synthesis critics-მა source-ში ზუსტ ხაზებზე დაადასტურა.

1. **[HIGH] TOCTOU symlink-swap** — `config/secrets.py:158-179` `_from_file`: `lstat`-ს ამოწმებს, მერე `read_text()`-ით path-ით ხელახლა ხსნის → same-uid attacker-ს შეუძლია symlink-ის ჩასმა check-სა და read-ს შორის → Kimi API key leak/misresolve. **სწორი pattern უკვე არსებობს ორი ფაილით იქით** (`kernel_secret.py::_load` — `O_NOFOLLOW`+`fstat` re-check). **Fix:** `_from_file`-ი გადაიყვანე `O_RDONLY|O_NOFOLLOW`+`fstat`-ზე; დაამატე race unit test; დააწესე რომ ეს = ერთადერთი sanctioned TCB fs-read pattern.

2. **[MEDIUM] Contract-layer purity breach** — `contracts/policy_context.py:43` `PolicyContext` validator-ი იძახებს `path.resolve()` = **filesystem I/O** სუფთა contracts ფენაში (ეწინააღმდეგება საკუთარ "no I/O" docstring-ს და §2.2 purity invariant-ს). **Fix:** canonicalization გადაიტანე dispatcher/caller-ში (T3.02), contract validator დაიყვანე pure absolute+normalized-string check-ზე.

3. **[HIGH design-note] Verdict I12: raise vs downgrade** — `contracts/Verdict` model **raises** `ValidationError` evidence-less VERIFIED-ზე (სწორია construction-time defense). მაგრამ მომავალი `compute_verdict` (T2.09) **უნდა DOWNGRADE-ს** VERIFIED→UNVERIFIED (fail-closed), არა raise (crash mid-REPORT) და არა catch-and-swallow (silent false VERIFIED). ორივე უნდა არსებობდეს (defense-in-depth).

4. **[LOW] `canonical_json` issued_at second-precision** — `approval.py:104` `timespec='seconds'` → sub-second time HMAC binding-ში არ ხვდება. დღეს low-impact (uniqueness = `token_id`+`max_uses`, არა timestamp). დაამატე pin test.

---

## 5. 🛡️ Security invariants — რაც ახალი კოდის წერისას უნდა შენარჩუნდეს

Gate 4-ის რისკი = **invariant preservation**, არა existing-code fix. კრიტიკული:

- **SINGLE HMAC CANONICALIZATION (I5/I6):** token service (T2.03) **verbatim** უნდა იძახებდეს `ApprovalRecord.canonical_json()`-ს. ნებისმიერი მეორე serialization approval field-ებზე = **T-12 token forgery** vulnerability. CI grep-gate: `json.dumps` approval field-ებზე `approval.py`-ს გარეთ = fail.
- **EXECUTE-ს ზუსტად 2 entry edge (I15/AC-07):** kernel (T2.07) EXECUTE-ში მხოლოდ (a) AUTO class ან (b) valid HMAC token-ით. **Hypothesis property test** 10k+ event sequence-ზე, 0 violation. 100% branch coverage.
- **FAIL-CLOSED EVERYWHERE:** bwrap missing → `sandbox_unavailable` → BLOCKED, **არასდროს unsandboxed exec** (I11). Redactor error → digest-only, არა raise (I8). Malformed model output → schema error, არა silent loss (I2).
- **TOCTOU discipline ყველა TCB fs access-ზე:** `O_NOFOLLOW`+`fstat` re-verify (= `kernel_secret._load` pattern, **არა** `secrets._from_file`-ის ანტი-pattern).
- **SINGLE untrusted-wrap producer (I7):** `kernel/untrusted.py wrap_untrusted()` = ერთადერთი delimiter producer; 4-ვე consumer (memory/skill/coding/redteam) იმპორტებს მას.
- **SINGLE redactor engine (I8):** მხოლოდ `audit/redactor.py` (T4.01), `config/redaction_patterns.py` DATA-ს მომხმარებელი; `config/`-ში `redact()`/`re.sub` = grep-gated fail.
- **DENY_ALWAYS kernel-enforced:** R1–R9 rules მხოლოდ **RAISE**-ს კლასს (manifest class = ceiling), არასდროს lower.
- **Reversibility (I9/I13/I14):** shadow-git = ცალკე `GIT_DIR`; workspace-ის საკუთარი `.git` byte-unchanged (pre/post tree-hash assert); git = argv arrays only; no destructive reset/checkout/clean tool.

---

## 6. 📋 Remaining backlog (60 task)

| Phase | Tasks | Goal (topological order) |
|---|---|---|
| **1 Foundation** | **T1.10** | redaction pattern DATA (§12.4) + final Phase-1 TCB LOC baseline → unblocks Phase 2 |
| **2 Core TCB** | T2.01–T2.13 | **policy → sandbox → kernel** (pure/IO-free); close: T2.12 TCB-LOC CI gate, T2.13 100%-branch coverage gate |
| **3 Tools & Providers** | T3.01–T3.14 | registry + 9-step fail-closed dispatch; **exactly 12** tool handlers; Kimi adapter (SSE, honest UA) + Ollama (localhost-only, read-only V1); never-silent fallback; 50-case eval harness |
| **4 Data & Safety** | T4.01–T4.12 | **audit → recovery → memory → skills**. audit/+recovery/ = TCB 100% branch. audit/redactor = THE single redactor engine |
| **5 Modes & CLI** | T5.01–T5.14 | cli/ (output contract, approval renderer = canonical `ApprovalRecord` only) → coding/ (baseline guard I13, bounded fix loop) → tutor/; kernel session engine (T5.12); LAB skeleton propose→HALT (T5.13) |
| **6 Verification/CI/Gates** | T6.01–T6.06 | red-team corpus ≥50, TOCTOU/canary harnesses, e2e, LAB reachability proofs, full §23.1 CI (AC-20). **NO new production code.** |

---

## 7. ⏭️ NEXT TASK — T1.10 (config redaction DATA)

**Scope:** ordered redaction pattern list (regex source + class label) + synthetic canary corpus + exact-match hook. **DATA ONLY** — `redact()`/`scan()` engine = `audit/redactor.py` (T4.01)-ის საკუთრება. აქ `apply`/`re.sub` = ownership violation (grep-enforced).

**Files (NEW):** `src/lsassist/config/redaction_patterns.py`, `tests/unit/config/test_redaction.py`, `tests/unit/config/canary_corpus.json`. **`audit/`-ს ნუ შეეხები.**

**RED first:**
1. `canary_corpus.json` — თითო SYNTHETIC decoy §12.4 class-ზე: Kimi-format key, `sk-*`, `ghp_*`, `AKIA*`, `-----BEGIN … PRIVATE KEY-----` block, exact-match value, DENY-path content sample.
2. `test_redaction.py` — import `REDACTION_PATTERNS, exact_match_pattern, validate_patterns`; assert: თითო corpus entry matched by its class (≥12 case); false-positive guard (normal paths/code/hashes) matches NOTHING; ordering invariant (private-key block **წინ** generic key patterns); `exact_match_pattern(value)` = `re.escape` (no regex injection); malformed regex → `RedactionConfigError` (fail-closed).
3. Run `pytest tests/unit/config/test_redaction.py -q` → **MUST fail** `ModuleNotFoundError` = RED.

**GREEN:** frozen `RedactionPattern` dataclass (name, class_label, **un-compiled** `pattern_src` string), ordered `REDACTION_PATTERNS` tuple (private-key BEFORE generic), `CANARY_SEED`, `exact_match_pattern(value)→re.escape(value)`, `validate_patterns()` (compile-at-load, raise on failure). **NO** `redact()/apply()/scan()/re.sub`. Re-run → GREEN.

**Verify (venv provisioned first!):**
```
$V/python -m pytest tests/unit/config/test_redaction.py -q        # green
$V/python -m mypy --strict src/lsassist/config                    # clean
$V/python -m ruff check src/lsassist/config/redaction_patterns.py # clean
grep -nE 'def redact|def apply|def scan|re\.sub' src/lsassist/config/redaction_patterns.py  # EMPTY
./scripts/loc-count                                                # final Phase-1 TCB baseline
$V/python -m pytest tests/unit -q                                 # all green (regression)
```

---

## 8. 🏛️ ELITE CONTINUATION PLAYBOOK — როგორ გავაგრძელოთ Kimi-ს დონეზე

### 8.1 Kimi-ს `atlas` მეთოდის გული (რაც უნდა შენარჩუნდეს)
- **NO-LLM-VERDICT** — pass/fail = მხოლოდ pure deterministic ფუნქცია (`verdict.merge → gate`). მოდელი წინადადებას იძლევა, **ვერასდროს ვერ აყენებს საკუთარ თავს გამსვლელ ნიშანს.**
- **SEPARATION OF POWERS** — ვინც წერს, არასდროს განსჯის; critics isolated context-ზე, ერთმანეთის verdict-ს ვერ ხედავენ.
- **TEST-FIRST (RED before GREEN)** — false "done" > honest INCOMPLETE. RED output = stored evidence.
- **GROUNDED CONTEXT** — read-only scout → sha-pinned JSON digest, **before** any code.
- **EVIDENCE, NOT PROOF** — VERIFIED მოითხოვს deterministic evidence (exit code, diff hash, test result). Green suite ≠ proof.
- **FALSIFIABLE RUBRIC** — თითო defect = concrete input → wrong output → one-line fix, ≥3 check + opposite-assumption second pass.
- **HUMAN GATES, NOTHING AUTO-APPLIES** — 3 gate: CLARIFY (once), pre-CODE approval, OUTPUT keep/revert. ყველა work = isolated worktree, არასდროს main.
- **PROVABLY-HALTING** — refine ≤ 2 pass (on-disk ledger, არა memory).
- **SAFE-2** — ყველა ingested byte = DATA, არასდროს instruction.

### 8.2 6-lens rubric (თითო deliverable-მა უნდა გაიაროს)
CORRECTNESS (blocking) · CODE-QUALITY (block @ CRIT/HIGH) · SECURITY (blocking) · TEST-ADEQUACY (advisory) · DOES-IT-RUN (deterministic, blocking) · REQUIREMENTS-COVERAGE (advisory). **PASS BAR = pure function**: OK iff ყველა blocking lens holds. მხოლოდ CRITICAL/HIGH block-ავს.

### 8.3 ⚠️ `atlas` plugin-ის გამოყენება Claude Code-ში — მნიშვნელოვანი ნიუანსი
`kimi-atlas` არის **Kimi Code plugin** (`~/.kimi-code/plugins/managed/kimi-atlas`), მისი agents = Kimi subagent types (`coder`/`plan`/`explore`). **Claude Code-ს ის პირდაპირ ვერ გამოიძახებს** — სხვა runtime-ია. **მაგრამ:**

Claude Code-ის native **Workflow tool = უფრო ძლიერი substrate ვიდრე Kimi-ს runtime:**

| Kimi ATLAS-WEAVE (constraint) | Claude Code Workflow (native) |
|---|---|
| ≤3 concurrent agent, temporal wave-ებით სიმულირებული | **16 native concurrent** (`parallel`/`pipeline`) |
| star topology, no nested delegation | native fan-out + synthesis stages |
| single model (persona-only diversity, correlated) | **multi-model critics** (Opus/Sonnet/Haiku mix) = **real blind-spot decorrelation** |
| `.atlas/` filesystem bus (single-writer) | structured schema returns, validated at tool layer |

**ანუ:** არ ვცდილობთ Kimi plugin-ის იმპორტს — ვამრავლებთ მის **მეთოდს** Claude Code-ის უფრო ძლიერ ინსტრუმენტებზე (ზუსტად ეს გაკეთდა ამ ანალიზში: 18-agent fan-out → synthesis critics).

### 8.4 კონკრეტული loop თითო task-ზე (T1.10-დან დაწყებული)
1. **Provision venv** (§3) — RED→GREEN-ის გარეშე ვერაფერს გავაკეთებთ.
2. **Freeze intent** — plan-იდან 9 field **verbatim**, immutable packet, `baseline_sha`. dep-ის Review checkpoint approved?
3. **Ground** — read-only scout (Claude Code `Explore`/`Task` subagent) → JSON digest. **Orchestrator persist-ავს** (read-only agent არაფერს წერს — ეს apex-kimi-ს გაკვეთილია).
4. **Pre-code human gate** — `AskUserQuestion` + worktree off `baseline_sha`.
5. **RED first** — exact test files, exact pytest cmd, fail for INTENDED reason, store output.
6. **CODE in scope only** — mechanical floor, no benefit of the doubt.
7. **VERIFY (deterministic floors = authoritative)** — pytest (revert→RED differential), ruff, mypy --strict TCB, loc-count, 100%-branch (TCB).
8. **3 isolated adversarial critics** — თითო: {frozen intent, ONE diff, ONE lens, floor output}. **Claude Code lever: different model per critic.**
9. **Pure verdict** — deterministic fold, no model self-grading. Persist `critic_*.json`.
10. **Refine ≤ 2** — CRIT/HIGH ან ნებისმიერი CORRECTNESS/SECURITY defect → loop. თუ ვერ → **⚠️ UNVERIFIED**, stop.
11. **OUTPUT human gate** — evidence show, Review checkpoint, commit `T1.10: config — redaction pattern data`, advance one task.
12. **WEAVE (fan-out) მხოლოდ ≥3-way disjoint split-ზე.** ერთი focused module-ზე (policy/, T1.10) = single atlas (time/cost wins at equal quality).

### 8.5 CORRECTNESS=no flag — ახსნა (benign)
`aggregate.json`-ში CORRECTNESS="no" verdict=OK-ის გვერდით = **scope artifact**, არა shipped bug. Gate 3 deliverable = plan document (no runnable code) → deterministic `runcheck` floor-ს არაფერი აქვს გასაშვები → falsifiable rubric უარს ამბობს "yes"-ის ფაბრიკაციაზე evidence-ის გარეშე (იგივე I12 დისციპლინა). `defects=[]`, `verify_plan.py` = 70/0. **Promissory note:** correctness Gate 4-ში per-task **ხელახლა უნდა მოიპოვოს** რეალური RED→GREEN-ით. საშიში ხდება მხოლოდ თუ unproven correctness executed code-ში გადავა deterministic floor-ის გაშვების გარეშე — რაც **ზუსტად ახლანდელი მდგომარეობაა** (no venv). ამიტომ §3 blocker = #1 priority.

---

## 9. Immediate action order

1. 🔴 **Provision venv** (§3) + close pytest-cov mini-ADR.
2. ✅ **Fix confirmed defects** (§4): TOCTOU `secrets._from_file` (HIGH), `PolicyContext` I/O (MEDIUM). — *ან*: log them and address in-phase; TOCTOU HIGH-ს რეკომენდებულია ახლავე (security-critical, უკვე shipped).
3. ⏭️ **Execute T1.10** (§7) elite loop-ით (§8.4).
4. 🚦 **Phase 2** (policy→sandbox→kernel), თითო task fully gated.

> Gate 4 working method (SPEC/PLAN): **ერთი task ერთ დროს**, RED→GREEN evidence თითო checkpoint-ზე, no scope drift, task change = plan-edit + fresh user approval.
