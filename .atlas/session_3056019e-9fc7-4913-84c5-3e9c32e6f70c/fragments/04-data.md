## Phase 4 — Data & Safety (memory, skills, audit, recovery)

ამ ფაზის მიზანი: ოთხი TCB/მონაცემთა პაკეტი test-first რიგით — ჯერ `audit/` (ყველა სხვა პაკეტი მისით logs-ავს, ამიტომ redactor და writer პირველია), შემდეგ `recovery/` (shadow-git checkpoints, rollback, resume/replay), შემდეგ `memory/` (SQLite + FTS5 + write gates), ბოლოს `skills/` (manifest, tiers, lifecycle, injection wiring). ყველა write path გადის redactor-ზე (§12.4) და audit event-ზე (§14.1); `audit/` და `recovery/` TCB-ია — 100% branch coverage სავალდებულოა (§23.1).

### T4.01 — audit/: redactor engine — ერთადერთი მოდული `audit/redactor.py` (T1.10 pattern data-ს მომხმარებელი) + canary/fuzz suite

**Scope:** redactor engine-ის იმპლემენტაცია როგორც ერთადერთი redactor module მთელს codebase-ში — `audit/redactor.py` (§2.2, §14.3, §12.4) — ordered-rule, fail-closed, audit-facing facade-ით; engine მოიხმარს T1.10-ის pattern data-ს (`config/redaction_patterns.py`: `REDACTION_PATTERNS`, `exact_match_pattern`, `validate_patterns`) import-ით — `config/`-ში არანაირი engine კოდი არ იწერება (T1.10 მხოლოდ data-ს აწვდის, არა engine-ს). Sink integration (writer/reader/memory) შემდგომი task-ების საგანია.

**Files:** `lsassist/src/lsassist/audit/__init__.py`, `lsassist/src/lsassist/audit/redactor.py`, `lsassist/tests/unit/audit/test_redactor.py`, `lsassist/tests/unit/config/canary_corpus.json` (გაფართოება), `lsassist/tests/property/test_redactor_fuzz.py`

**Depends on:** T1.10 (redaction pattern data — `REDACTION_PATTERNS`/`exact_match_pattern`/`validate_patterns`; engine აქ იწერება, T1.10-ში არა)

**RED (tests first):** (1) `test_redactor.py`: `redact_for_audit(text)` — T1.10-ის pattern data-ს ყველა rule + ახალი path-based rule (DENY paths-ის content class, §12.4) → `[REDACTED:<class>]`; (2) rule ordering test: უფრო სპეციფიური rule (private key block) მუშაობს generic-მდე — შეცვლილი output არ შეიცავს ნაწილობრივ შეუცვლელ ფრაგმენტს; (3) fail-closed: pattern engine error (injected broken rule ან T1.10 `validate_patterns()`-ის `RedactionConfigError`) → `redact_for_audit` აბრუნებს digest-only placeholder-ს (`payload` ცარიელი, მხოლოდ `payload_digest`) და არა exception-ს ზედა ფენისთვის, ხოლო შეცდომის ფაქტი ინიშნება hits-ში (§14.3); (4) extended `canary_corpus.json`: თითო entry თითო §12.4 class-ზე (Kimi-format key, `sk-*`, `ghp_*`, `AKIA*`, RSA/EC/OpenSSH private key blocks, configured exact-match, DENY-path content) — corpus-driven parameterized test, 100% redaction; (5) false-positive guard განახლებული corpus-ით (normal paths, code snippets, hash strings — unchanged); (6) `test_redactor_fuzz.py` (hypothesis): 10,000 random secret-shaped string (თითო class-ის generator-ით) → 100% redacted, 0 leak; random benign text → redaction count == 0 tolerance-ში. Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/audit/test_redactor.py tests/unit/config/test_redaction.py tests/property/test_redactor_fuzz.py -q` — მარცხდება `ModuleNotFoundError`-ით (`lsassist.audit.redactor` არ არსებობს).

**GREEN (implementation):** `audit/redactor.py` — ერთადერთი redactor engine module (§2.2): T1.10-ის `config/redaction_patterns.py`-დან `REDACTION_PATTERNS`-ის import და compile (`validate_patterns()` load time-ზე), ordered rule application + ახალი path-based rule (DENY paths-ის canonical list T2.02-დან input-ად, content match → `[REDACTED:deny_path_content]`); `redact_for_audit(text) -> AuditRedaction` — engine-ის audit-facing facade: წარმატებაზე `(redacted_text, hits)`; `RedactorError`/`RedactionConfigError`-ზე fail-closed branch — აბრუნებს digest-only შედეგს (`text=""`, `digest_only=True`, `payload_digest=sha256(original)`), hits-ში `engine_error` ჩანაწერი; redaction-ის ყოველი ფაქტი hits-ში class/count-ით (§12.4 "audit records the fact of redaction"). `config/`-ში არანაირი ცვლილება — pattern data T1.10-ის საკუთრებაა.

**Expected results:** corpus 100% redaction rate ყველა class-ზე; fuzz 10,000 case → 0 leak; ≥24 test case green.

**Verification:** ზედა pytest command green; `~/.local/share/lsassist/venv/bin/python -m mypy --strict src/lsassist/audit` clean; `~/.local/share/lsassist/venv/bin/python -m pytest --cov=src/lsassist/audit --cov-branch --cov-fail-under=100 tests/unit/audit -q` — 100% branch. Pass criteria: ყველა command exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) rule list ფარავს §12.4-ის ყველა class-ს, ordering დოკუმენტირებულია; (2) fail-closed branch მართლა digest-only-ს აბრუნებს (არა ნაწილობრივ redacted text-ს); (3) canary corpus მხოლოდ synthetic მნიშვნელობებს შეიცავს; (4) ownership boundary დაცულია — engine მხოლოდ `audit/redactor.py`-შია, `config/`-ში მხოლოდ T1.10-ის data.

**Rollback:** `git checkout -- tests/unit/config/canary_corpus.json && git rm -r --cached src/lsassist/audit tests/unit/audit tests/property/test_redactor_fuzz.py 2>/dev/null; rm -rf src/lsassist/audit tests/unit/audit tests/property/test_redactor_fuzz.py` (uncommitted ფაილებზე `rm` საკმარისია; T1.10-ის `config/redaction_patterns.py` უხრწნელი რჩება).

(SPEC §14.3, §12.4, I8)

### T4.02 — audit/: append-only JSONL writer + hash-chain + fsync policy + rotation

**Scope:** audit writer-ის იმპლემენტაცია §14.1-ით — session JSONL + global index, `prev_hash` hash-chain, fsync policy event class-ებით, 50 MB / 10 files rotation, record schema validation; reader შემდგომი task-ის საგანია.

**Files:** `lsassist/src/lsassist/audit/schema.py`, `lsassist/src/lsassist/audit/writer.py`, `lsassist/tests/unit/audit/test_schema.py`, `lsassist/tests/unit/audit/test_writer.py`, `lsassist/tests/unit/audit/test_hash_chain.py`, `lsassist/tests/unit/audit/test_rotation.py`, `lsassist/tests/contract/test_audit_schema.py`

**Depends on:** T4.01, T1.07

**RED (tests first):** (1) `test_schema.py`: record schema (§14.1) — required fields (`seq`, `ts`, `session_id`, `task_id`, `event`, `payload`, `payload_digest`, `prev_hash`, `model`, `provider`); `event` enum ზუსტად §14.1 list-ია (`intent`…`config_change`, `lab_*` pattern-ით); unknown event → validation error; (2) `test_hash_chain.py`: N sequential event → თითო `prev_hash` == წინა record-ის sha256 (canonical serialization-ზე); chain-ის შუა record-ის byte mutation / truncation / rewrite → `verify_chain()` აღმოაჩენს და ზუსტ position-ს ანგარიშობს; (3) `test_writer.py`: append-only (write არ ხსნის ფაილს `r+`/`w` mode-ში — fd flags assertion); fsync policy: `approval`, `verdict`, `policy_decision(deny)` event-ზე `os.fsync` იძახება ყოველ write-ზე (mock assert), სხვა event-ზე batched (flush threshold-მდე fsync არ არის); file permissions `0600`, dir `0700` (§12.1); თითო write გადის `redact_for_audit`-ზე — payload-ში canary secret → stored record შეიცავს `[REDACTED:<class>]`-ს და redaction hit-ის ფაქტს; `digest_only` შედეგზე record ინახება payload-ის გარეშე, მხოლოდ digest-ით; **negative tests (§14.1 never recorded):** payload-ში `reasoning_content` key → write refused (`AuditRefusedError`); secret value plain-ად (redactor bypass-ის მცდელობა non-string field-ით) → refused ან redacted; raw prompt field (`raw_prompt`/`prompt_body`) → refused; (4) `test_rotation.py`: 50 MB threshold-ზე rotate ახალ file-ში, chain გრძელდება გადატანილი `prev_hash`-ით; 10 file-ის ზღვარზე უძველესი იშლება; rotation-ის შემდეგ `verify_chain()` active files-ზე valid რჩება; (5) `test_audit_schema.py` (contract): fuzzed session-ების (hypothesis-generated event sequences) ყველა record schema-valid (AC-17-ის წინაპირობა). Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/audit tests/contract/test_audit_schema.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `schema.py`: pydantic `AuditRecord` model + event enum; canonical serialization helper (sorted keys, UTF-8, separators fixed) hash-ისთვის; `writer.py`: `AuditWriter` class — open `O_APPEND|O_CREAT|O_WRONLY|O_NOFOLLOW`, mode `0600`; `write(event, payload, ctx)` → redact → schema validate → `prev_hash` chain-იდან → append + fsync policy dict `{approval, verdict, policy_decision_deny}` vs batched flush; never-recorded key blocklist (`reasoning_content`, `raw_prompt`, `prompt_body`, `secret`, `api_key` values plain) → refuse pre-write; rotation helper size check write-მდე; `verify_chain(path)` reader-მხარესაც ხელმისაწვდომი util.

**Expected results:** hash-chain tamper detection 3/3 vector-ზე; fsync policy assertions 100%; never-recorded negative tests 100% refused; ≥30 test case.

**Verification:** pytest command green; `mypy --strict src/lsassist/audit` clean; `pytest --cov=src/lsassist/audit --cov-branch --cov-fail-under=100 tests/unit/audit -q` — 100% branch (audit = TCB, §23.1); `scripts/loc-count` — TCB LOC budget-ში (§2.3). Pass criteria: ყველა exit 0, coverage gate green.

**Review checkpoint:** ადამიანი ამოწმებს: (1) never-recorded blocklist ფარავს §14.1-ის სამივე კატეგორიას (secrets, CoT/`reasoning_content`, raw prompts) და negative test თითოეულზე არსებობს; (2) fsync policy ზუსტად §14.1 list-ს ემთხვევა; (3) rotation-ში chain integrity არ იკარგება (test მტკიცებულებით).

**Rollback:** `git rm -r --cached src/lsassist/audit/schema.py src/lsassist/audit/writer.py tests/unit/audit/test_schema.py tests/unit/audit/test_writer.py tests/unit/audit/test_hash_chain.py tests/unit/audit/test_rotation.py tests/contract/test_audit_schema.py 2>/dev/null; rm -f <იგივე paths>`; T4.01-ის `audit/redactor.py` უვნებელი რჩება.

(SPEC §14.1, §14.3, I8, I16)

### T4.03 — audit/: reader + on-read redaction + session stats

**Scope:** audit reader (filter, chain verify report, on-read redaction defense-in-depth) და session stats aggregation (§14.2) — მხოლოდ backend API; CLI surface (`lsassist audit show`) ამ task-ში არ იწერება — მისი ერთადერთი მფლობელია T5.04 (`cli/commands_*.py` adapters), რომელიც ამ backend-ს wire-ს; writer-ის შეცვლა გარეშე.

**Files:** `lsassist/src/lsassist/audit/reader.py`, `lsassist/src/lsassist/audit/stats.py`, `lsassist/tests/unit/audit/test_reader.py`, `lsassist/tests/unit/audit/test_stats.py`, `lsassist/tests/integration/audit/test_audit_read.py`

**Depends on:** T4.02

**RED (tests first):** (1) `test_reader.py`: filter by `session_id` / `event` type / seq range; corrupted line (invalid JSON) → skip + report, არა crash; on-read redaction: ფაილში ხელით ჩაწერილი record, რომელიც შეიცავს canary secret-ს (writer bypass scenario) → reader-ის output-ში `[REDACTED:<class>]` (§14.1 "redaction applied on read too"); `verify_chain()` report: valid chain → ok; broken → exact seq + მიზეზი; (2) `test_stats.py`: tool-call counts by class, verdict distribution, budget usage, provider usage/fallback events aggregation fixture journal-იდან; repair-rate metric (malformed output rate) ცალკე field (§14.2); (3) `test_audit_read.py` (integration, backend API only): fixture journal → `reader.read(session_id=N, event_type="verdict")` და `stats.aggregate()` პირდაპირი call-ებით (CLI invocation-ის გარეშე) — შედეგი შეიცავს მხოლოდ შესაბამის record-ებს, redacted; არავალიდური filter value → typed `AuditQueryError`; chain-broken journal → chain verify report-ში warning entry. Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/audit/test_reader.py tests/unit/audit/test_stats.py tests/integration/audit -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `reader.py`: streaming JSONL reader (არ იტვირთება მთლიანად RAM-ში), filter pipeline, on-read `redact_for_audit` გამოყენება rendering-მდე, chain verify reusing writer-ის util; `stats.py`: pure aggregation functions journal records-ზე. CLI surface აქ არ იწერება — `cli/commands_*.py` adapter-ების ერთადერთი მფლობელია T5.04, რომელიც ამ backend API-ებს (`audit.reader`, `audit.stats`) wire-ს.

**Expected results:** on-read redaction test green (writer bypass scenario დაფარული); stats fields 6/6 §14.2 list-იდან; backend integration test green; ≥18 test case.

**Verification:** pytest command green; `mypy --strict src/lsassist/audit` clean; `pytest --cov=src/lsassist/audit --cov-branch --cov-fail-under=100 tests/unit/audit tests/integration/audit -q` — 100% branch მთელ `audit/` package-ზე. Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) on-read redaction ნამდვილად მეორე ფენაა (writer-ის გარეშე, reader-ში); (2) reader-ის rendered output არ შეიცავს digest-ების გარდა არავითარ payload secret material-ს fixture-ზე; (3) `audit/` package TCB coverage gate 100%-ზეა — Phase 4-ის audit ბლოკი დასრულებულია.

**Rollback:** `git rm --cached src/lsassist/audit/reader.py src/lsassist/audit/stats.py tests/unit/audit/test_reader.py tests/unit/audit/test_stats.py tests/integration/audit/test_audit_read.py 2>/dev/null; rm -f <იგივე paths>`.

(SPEC §14.1, §14.2, I16)

### T4.04 — recovery/: shadow-git checkpoint store (§14.4)

**Scope:** content-addressed shadow-git checkpoint store — ცალკე `GIT_DIR`, per-workspace index/work-tree, snapshot API pre-mutation trigger-ებისთვის, retention (50/workspace, 2 GB, LRU), >50MB binary exclusion; rollback flow შემდგომი task-ის საგანია.

**Files:** `lsassist/src/lsassist/recovery/__init__.py`, `lsassist/src/lsassist/recovery/manifest.py`, `lsassist/src/lsassist/recovery/checkpoints.py`, `lsassist/tests/unit/recovery/test_manifest.py`, `lsassist/tests/unit/recovery/test_checkpoints.py`, `lsassist/tests/integration/recovery/test_checkpoint_store.py`

**Depends on:** T4.02, T2.02

**RED (tests first):** (1) `test_manifest.py`: snapshot manifest schema (workspace canonical path, file list + sha256 + mtime + size, trigger kind, timestamp); (2) `test_checkpoints.py`: `create_checkpoint(workspace, paths, trigger)` → git env (`GIT_DIR=$XDG_STATE_HOME/lsassist/checkpoints/objects`, `GIT_INDEX_FILE` per-workspace, `GIT_WORK_TREE`=workspace canonical) — subprocess env assertion; workspace-ის საკუთარი `.git` არ იცვლება (tree hash pre/post identical, `.git/index` mtime unchanged); >50MB binary file → excluded + manifest-ში `excluded` marker; retention: 51-ე checkpoint-ზე უძველესი LRU prune; store size >2 GB → prune ველურს ჯერ; prune არასდროს ეხება active checkpoint-ს; (3) `test_checkpoint_store.py` (integration): tmp workspace-ში files → checkpoint → files modified/deleted → stored objects აღდგენადია (restore materialization tmp dir-ში byte-identical, AC-06-ის წინაპირობა); checkpoint create → `recovery` audit event ჩაიწერა (writer-დან T4.02). Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/recovery tests/integration/recovery -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `manifest.py`: pydantic `CheckpointManifest` + canonical serialization; `checkpoints.py`: `CheckpointStore` — git plumbing calls (`git --git-dir=... hash-object`, `update-index`, `write-tree`, `commit-tree`) env-ით, არა shell string-ით (argv array, I2); `create_checkpoint()` trigger kinds (`pre_write`, `pre_patch`, `pre_test` lightweight mtime-manifest, `manual`); retention pruner (count + size, LRU by manifest timestamp); exclusion rule (size >50MB ან binary detection); audit emit `recovery` event ყოველ create/prune-ზე.

**Expected results:** workspace `.git` untouched (hash equality); restore materialization byte-identical; retention rules 3/3; ≥20 test case.

**Verification:** pytest command green; `mypy --strict src/lsassist/recovery` clean; `pytest --cov=src/lsassist/recovery --cov-branch --cov-fail-under=100 tests/unit/recovery tests/integration/recovery -q` — 100% branch (recovery = TCB, §23.1). Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) git invocations მხოლოდ argv array-ითაა, shell არსად; (2) `GIT_DIR`/`GIT_INDEX_FILE`/`GIT_WORK_TREE` env isolation სწორია — test-ი ადასტურებს, რომ workspace `.git` უხრწნელია; (3) exclusion/LRU წესები §14.4-ის რიცხვებს ემთხვევა (50, 2 GB, 50 MB).

**Rollback:** `git rm -r --cached src/lsassist/recovery tests/unit/recovery tests/integration/recovery 2>/dev/null; rm -rf src/lsassist/recovery tests/unit/recovery tests/integration/recovery`.

(SPEC §14.4, §12.1, I2, I9)

### T4.05 — recovery/: rollback flow (preview diff → confirm → atomic restore)

**Scope:** rollback backend flow (`recovery.rollback`) — preview diff, user confirm (confirm callback injection-ით automation API-სთვის), manifest-driven atomic restore; CLI surface (`lsassist rollback`) ამ task-ში არ იწერება — მისი ერთადერთი მფლობელია T5.04 (`cli/commands_*.py` adapters), რომელიც ამ backend-ს wire-ს.

**Files:** `lsassist/src/lsassist/recovery/rollback.py`, `lsassist/tests/unit/recovery/test_rollback.py`, `lsassist/tests/integration/recovery/test_rollback_flow.py`

**Depends on:** T4.04

**RED (tests first):** (1) `test_rollback.py`: `plan_rollback(checkpoint_id)` → diff preview (changed/added/deleted files list + unified diff text); manifest-driven restore set — მხოლოდ manifest-ის ფაილები, unrelated workspace files restore plan-გარეშე (I13); (2) `test_rollback_flow.py` (integration): tmp workspace: files A,B → checkpoint → modify A, delete B, modify unrelated C (user edit post-checkpoint) → rollback confirm=yes → A,B byte-identical checkpoint state-თან (sha256 equality, AC-06), C უცვლელი; confirm=no → 0 side effects (tree hash unchanged, AC-08-ის ნაწილი); atomic restore: restore-ს შუაში injected failure (mock write error) → target file ან სრული ძველია ან სრული ახალი, partial არასდროს (tmp+rename protocol); restore → `recovery` audit event (`rollback`, checkpoint ref, file list). Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/recovery/test_rollback.py tests/integration/recovery/test_rollback_flow.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `rollback.py`: `plan_rollback()` — manifest read → current state diff vs stored tree (git diff plumbing); `execute_rollback(plan, confirm_fn)` — confirm callback (CLI-ში user prompt, test-ში injected); restore თითო ფაილზე: write tmp in same dir → fsync → `os.rename` (atomic, §14.5 crash mid-write row); deleted file restore; parent dirs `os.makedirs` `0700`-გარეშე (workspace perms შენარჩუნებული); never touch files outside manifest; audit emit. CLI surface აქ არ იწერება — T5.04-ის `cli/commands_*.py` adapter-ი ამ `plan_rollback`/`execute_rollback` API-ებს wire-ს (preview render, `CONFIRM` prompt, result summary).

**Expected results:** AC-06 restore hash equality integration test green; unrelated-file preservation test green; atomicity failure-injection test green; ≥14 test case.

**Verification:** pytest command green; `mypy --strict src/lsassist/recovery` clean; `pytest --cov=src/lsassist/recovery --cov-branch --cov-fail-under=100 tests/unit/recovery tests/integration/recovery -q` — 100% branch. Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) restore მხოლოდ manifest-driven-ია — code review-ით ვერ პოულობს path-ს manifest-ს გარეთ; (2) atomic write protocol (tmp+fsync+rename) თითო restore write-ზე; (3) preview diff user-facing-ია confirm-მდე — backend flow ხელით ერთხელ გაშვებული tmp workspace-ზე injected `confirm_fn`-ით.

**Rollback:** `git rm --cached src/lsassist/recovery/rollback.py tests/unit/recovery/test_rollback.py tests/integration/recovery/test_rollback_flow.py 2>/dev/null; rm -f <იგივე paths>`.

(SPEC §14.4, §14.5, I9, I13)

### T4.06 — recovery/: journal resume + idempotency replay + crash-recovery tests

**Scope:** `lsassist resume` — journal-დან ბოლო `seq`-ის აღდგენა, §4.7 replay წესებით (executed seq არასდროს მეორდება; completed non-idempotent → fresh token; partial exec → human review), SIGINT handler semantics და §14.5 crash-row tests (`kill -9` mid-write/mid-task, stale tmp discard, disk watermark).

**Files:** `lsassist/src/lsassist/recovery/resume.py`, `lsassist/src/lsassist/recovery/signals.py`, `lsassist/src/lsassist/recovery/watermark.py`, `lsassist/tests/unit/recovery/test_resume.py`, `lsassist/tests/unit/recovery/test_signals.py`, `lsassist/tests/unit/recovery/test_watermark.py`, `lsassist/tests/integration/recovery/test_crash_recovery.py`

**Depends on:** T4.05, T2.10, T2.07

**RED (tests first):** (1) `test_resume.py`: fixture journal (tool_request/tool_result seq 1..N) → `build_resume_plan()` — already-executed seq-ები plan-ში `replay=never`; completed non-idempotent action (fs.write result recorded) → `fresh_token_required`; crash mid-exec (request without result) → `human_review` marker ("unknown side effects, inspect checkpoint diff" — §4.7); (2) `test_signals.py`: SIGINT handler → child process group-ზე SIGKILL call (mock), journal-ში checkpoint entry, verdict `CANCELLED` event; მეორე SIGINT grace window-ში → hard exit path, journal append მაინც ხდება; (3) `test_watermark.py`: free space <500 MB → `check_disk_watermark()` → `HaltWrites` (§14.5 disk full row); audit headroom check: reserved 10 MB journal space შენარჩუნებული; (4) `test_crash_recovery.py` (integration, AC-11): subprocess-ში writer/restore შუა write-ზე `kill -9` → restart → 0 partial target files (tmp file without rename discarded as stale), checkpoint pre-state intact; `kill -9` mid-task → resume → 0 action replays (idempotency keys T2.10-დან, journal seq-თან შედარება); stale tmp detection: orphaned `.lsassist-tmp-*` → discarded + report. Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/recovery tests/integration/recovery -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `resume.py`: journal scan (reader reuse) → last `seq` per task → replay classification (§4.7 rules, table-driven); `signals.py`: SIGINT handler registration — first: kill process group (`os.killpg`), journal checkpoint + `CANCELLED` verdict event, second: hard exit journaled; `watermark.py`: `shutil.disk_usage` check pre-write hook API (`raise HaltWrites` <500 MB), 10 MB reserved journal headroom pre-allocation helper.

**Expected results:** AC-11 integration tests green (0 partial files, 0 action replays); resume replay classification 3/3 rule; §14.5 table-ის recovery-relevant rows (Ctrl+C, crash mid-write, crash mid-task, disk full) ყველა test-ით დაფარული; ≥20 test case.

**Verification:** pytest command green (integration `kill -9` test-ები `pytest -k crash` ცალკეც); `mypy --strict src/lsassist/recovery` clean; `pytest --cov=src/lsassist/recovery --cov-branch --cov-fail-under=100 tests/unit/recovery tests/integration/recovery -q` — 100% branch მთელ `recovery/` package-ზე. Pass criteria: ყველა exit 0, AC-11 markers green.

**Review checkpoint:** ადამიანი ამოწმებს: (1) replay rules ზუსტად §4.7-ის სამ შემთხვევას ემთხვევა (executed-never / completed→fresh token / partial→human review); (2) `kill -9` test-ები რეალურად subprocess-ს კლავს (არა mock-ს); (3) SIGINT double-press flow documented და journaled; recovery/ ბლოკი დასრულებულია.

**Rollback:** `git rm --cached src/lsassist/recovery/resume.py src/lsassist/recovery/signals.py src/lsassist/recovery/watermark.py tests/unit/recovery/test_resume.py tests/unit/recovery/test_signals.py tests/unit/recovery/test_watermark.py tests/integration/recovery/test_crash_recovery.py 2>/dev/null; rm -f <იგივე paths>`.

(SPEC §4.7, §14.5, I9)

### T4.07 — memory/: SQLite store — DDL, WAL, migrations, startup integrity check

**Scope:** `memory.db` store — §10.2 DDL verbatim, WAL mode, schema migrations runner, file permissions, startup `PRAGMA integrity_check` (§14.5 corrupted state row); retrieval და write gates შემდგომი task-ების საგანია.

**Files:** `lsassist/src/lsassist/memory/__init__.py`, `lsassist/src/lsassist/memory/schema.sql`, `lsassist/src/lsassist/memory/store.py`, `lsassist/src/lsassist/memory/migrations.py`, `lsassist/tests/unit/memory/test_store.py`, `lsassist/tests/unit/memory/test_migrations.py`

**Depends on:** T4.02, T1.07

**RED (tests first):** (1) `test_store.py`: `open_memory(path)` → `PRAGMA journal_mode` returns `wal`; `PRAGMA foreign_keys` == 1; tables `prefs`, `episodic`, `sessions` + virtual `episodic_fts` არსებობს §10.2 columns/constraints-ით (`provenance CHECK`, `sensitivity CHECK`, `UNIQUE(key)` — constraint violation tests); file mode `0600` (§12.1); corrupted db (flipped bytes fixture) → `integrity_check` fails → `MemoryCorruptedError` with restore-path message (§14.5: restore from latest session checkpoint, rebuild from episodic archive, user informed); (2) `test_migrations.py`: `schema_migrations` table; migrate 0→1 applies §10.2 DDL; migration runner idempotent (second run no-op); unknown newer version → refuse to start with exact message (fail-closed). Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/memory -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `schema.sql`: §10.2 DDL verbatim + `schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT)`; `store.py`: `open_memory()` — XDG path resolution (T1.07), `O_NOFOLLOW`-style checks reuse, pragmas, `0600` chmod create-ზე, startup `integrity_check`; `migrations.py`: ordered migration list `(version, sql)`, transaction-ში apply, version guard.

**Expected results:** DDL §10.2-ის ყველა table/constraint reflection test-ით დაფარული; WAL active; corruption → fail-closed clear error; ≥16 test case.

**Verification:** pytest command green; `~/.local/share/lsassist/venv/bin/python -m mypy src/lsassist/memory` clean (memory/ არ არის TCB §2.3 list-ში — strict არა, მაგრამ type-clean). Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) `schema.sql` სიტყვასიტყვით ემთხვევა §10.2-ს (diff ხელით); (2) corruption path-ის error message ადამიანისთვის გასაგებია და restore ნაბიჯებს ასახელებს; (3) permissions `0600` fixture-ზე დადასტურებული.

**Rollback:** `git rm -r --cached src/lsassist/memory tests/unit/memory 2>/dev/null; rm -rf src/lsassist/memory tests/unit/memory`; `$XDG_DATA_HOME/lsassist/memory.db` test fixture-ები tmp-ში იყო — production path უხრწნელი.

(SPEC §10.2, §12.1, §14.5)

### T4.08 — memory/: FTS5 retrieval — bm25 + recency + confidence, top-k ≤ 8, delimited injection

**Scope:** retrieval pipeline §10.3-ით — FTS5 query, `bm25 + recency_decay + confidence` ranking, top-k ≤ 8 cap, sensitive exclusion, §4.6 delimiter wrap provenance label-ით; write path შემდგომი task-ის საგანია.

**Files:** `lsassist/src/lsassist/memory/retrieval.py`, `lsassist/tests/unit/memory/test_retrieval.py`, `lsassist/tests/property/test_retrieval_ranking.py`

**Depends on:** T4.07, T2.11

**RED (tests first):** (1) `test_retrieval.py`: seeded episodic rows → FTS5 match-only rows დაბრუნდება; ranking deterministic: იგივე query ორჯერ → იგივე order; recency decay: equal bm25-ზე უახლესი წინ; confidence tie-break §10.3 formula-ით; **top-k ≤ 8** — 20 matching row → ზუსტად 8 (ან ნაკლები requested-ზე); `sensitivity='sensitive'` rows retrieval-დან გამორიცხული default-ად; explicit-require path მხოლოდ policy allow callback=True-ზე (CONFIRM gate hook, T2.01); output თითო item იფუთება `<<<UNTRUSTED_DATA … provenance="…">>` block-ად (T2.11 wrap helper reuse) — never plain text; (2) `test_retrieval_ranking.py` (hypothesis): random row sets → top-k invariant ≤ 8 ყოველთვის; order stable under input permutation. Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/memory/test_retrieval.py tests/property/test_retrieval_ranking.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `retrieval.py`: `retrieve(query, k=8, policy_allow_sensitive)` — parameterized FTS5 MATCH (no string interpolation — SQL injection guard); score = `bm25(episodic_fts) * recency_decay(created_at) * confidence` single SQL expression-ში; sensitive filter default `sensitivity='normal'`; result items dataclass `(id, summary, provenance, score)`; wrap helper T2.11-დან delimiter injection-ით; no embeddings (ADR-007).

**Expected results:** top-k cap property test green 1,000 generated case-ზე; ranking determinism 100%; sensitive exclusion 0 leak; ≥14 test case.

**Verification:** pytest command green; mypy clean; property test seed CI-ში ფიქსირებული (reproducible). Pass criteria: ყველა exit 0, top-k invariant 0 violation.

**Review checkpoint:** ადამიანი ამოწმებს: (1) ranking formula §10.3-ის სამივე კომპონენტს შეიცავს; (2) SQL მხოლოდ parameterized-ია; (3) retrieval output ყოველთვის delimited + provenance-labeled (§4.6 step 1/3).

**Rollback:** `git rm --cached src/lsassist/memory/retrieval.py tests/unit/memory/test_retrieval.py tests/property/test_retrieval_ranking.py 2>/dev/null; rm -f <იგივე paths>`.

(SPEC §10.3, §4.6, ADR-007, I7)

### T4.09 — memory/: write gates + forget/correct/archive + caps + disk watermark

**Scope:** მთელი write path §10.4-ით — model-initiated pref write → pending buffer → review → `CONFIRM_ONCE` (R8), provenance immutability, redactor-on-write refusal, auto-write მხოლოდ episodic-ში, `forget`/`correct` lifecycle operations, per-table caps და disk watermark pre-write — ყველა მხოლოდ backend API-ად; CLI surface (`memory review/forget/correct` subcommands) ამ task-ში არ იწერება — მისი ერთადერთი მფლობელია T5.04 (`cli/commands_*.py` adapters), რომელიც ამ backend-ს wire-ს.

**Files:** `lsassist/src/lsassist/memory/gates.py`, `lsassist/src/lsassist/memory/lifecycle.py`, `lsassist/tests/unit/memory/test_gates.py`, `lsassist/tests/unit/memory/test_lifecycle.py`, `lsassist/tests/integration/memory/test_memory_write_flow.py`

**Depends on:** T4.08, T4.01, T2.01

**RED (tests first):** (1) `test_gates.py`: model-initiated pref write → pending buffer-ში ჯდება, db-ში არა; `memory review` list → per-item approve (`CONFIRM_ONCE` token R8-ით, T2.01) → write; reject → discard + audit; **provenance immutability:** model write ვერასდროს იღებს `provenance='user'`-ს — direct call `provenance='user'` model context-ით → `ProvenanceViolation`; auto-write მხოლოდ `episodic`-ში (kernel writer); **redactor on write:** task_summary-ში canary secret → write refused, audit event `memory_write` (refused, class) — 0 row db-ში; (2) `test_lifecycle.py`: `forget <id>` → hard delete + FTS rebuild (row absent, MATCH აღარ აბრუნებს); `correct <id>` → ახალი revision, ძველი `archived=1` (FTS-დან გარეთ); user-origin rows auto-archive/auto-delete-ის ყველა path-ზე გამორიცხული; caps: prefs 501-ე row → უძველესი model_confirmed auto-archive (user rows უხრწნელი), episodic 10k cap იგივე წესით; disk watermark (T4.06 `check_disk_watermark` reuse) pre-write — `HaltWrites` → write paused, audit appendable; (3) `test_memory_write_flow.py` (integration, backend API only): pending buffer review (approve/reject) / `forget()` / `correct()` round-trip store functions-ის პირდაპირი call-ებით, CLI invocation-ის გარეშე (AC-18); ყოველი mutation → `memory_write` audit event. Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/memory tests/integration/memory -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `gates.py`: `PendingBuffer` (in-memory + journal-backed, approval token bind R8), `gated_write_pref()`, `auto_write_episodic()` — ორივე redactor pass-ით write-მდე, refusal → audit; provenance enforcement table-driven (writer context → allowed provenance set); `lifecycle.py`: `forget()` (delete + `INSERT INTO episodic_fts(episodic_fts) VALUES('rebuild')`), `correct()` (revision insert + archive), caps enforcement trigger pre-insert (count check → archive oldest non-user), watermark hook T4.06-დან. CLI surface აქ არ იწერება — T5.04-ის `cli/commands_*.py` adapter-ი ამ `gates`/`lifecycle` API-ებს wire-ს (`review/forget/correct` subcommands, item display redacted).

**Expected results:** AC-18 round-trip green; provenance violation 100% blocked; redactor refusal → 0 partial rows; caps: user-origin rows 0 auto-deleted across all tests; ≥22 test case.

**Verification:** pytest command green; mypy clean; integration test-ში audit journal assertion — ყოველი mutation-ის `memory_write` event არსებობს (§14.1 event list). Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) write path-ის ორი შესასვლელი (model pending / kernel auto) ორივე redactor-ზე გადის — code path tracing-ით; (2) provenance matrix table-driven-ია და user tier model write-ზე მიუწვდომელი; (3) cap/archive logic user rows-ს არასდროს ეხება (test მტკიცებულებით); memory/ ბლოკი დასრულებულია.

**Rollback:** `git rm --cached src/lsassist/memory/gates.py src/lsassist/memory/lifecycle.py tests/unit/memory/test_gates.py tests/unit/memory/test_lifecycle.py tests/integration/memory/test_memory_write_flow.py 2>/dev/null; rm -f <იგივე paths>`.

(SPEC §10.4, §14.1, §14.3, R8, I8)

### T4.10 — skills/: manifest schema + loader + content-hash verification + trust tiers + static inspection

**Scope:** skill package loading §9.1/§9.2-ით — `manifest.json` schema validation, content-hash verification, trust tier assignment და tier-ის enable gate-ები (`builtin` default, `user` explicit, `community` static inspection + `CONFIRM_EXACT` + hash pinned); lifecycle transitions შემდგომი task-ის საგანია.

**Files:** `lsassist/src/lsassist/skills/__init__.py`, `lsassist/src/lsassist/skills/manifest.py`, `lsassist/src/lsassist/skills/loader.py`, `lsassist/src/lsassist/skills/inspection.py`, `lsassist/tests/unit/skills/test_manifest.py`, `lsassist/tests/unit/skills/test_loader.py`, `lsassist/tests/unit/skills/test_inspection.py`, `lsassist/tests/unit/skills/fixtures/` (sample skill dirs per tier)

**Depends on:** T4.02, T2.01

**RED (tests first):** (1) `test_manifest.py`: schema required fields (§9.1: `schema_version`, `name` regex `^[a-z][a-z0-9-]{1,63}$`, semver `version`, `description` ≤1024, `required_tools` ⊆ registry, `permission_class_max`, `provenance`, `content_hash`, `risk_class`, `dependencies`, `compatibility`) — missing/invalid თითოეულზე validation error; **forbidden V1 keys:** `scripts`, `hooks`, `code`, executable entry points manifest-ში ან dir-ში → hard reject; (2) `test_loader.py`: `content_hash` = SHA-256 over canonical serialization of SKILL.md+manifest — match → load; mismatch → refuse (tamper); `required_tools` registry-ს გარეთ → refuse; auto-install command-ის მცდელობა SKILL.md-ში → loader მხოლოდ parse-ს აკეთებს, არავითარი exec (§9.1 "წაკითხვა ≠ შესრულება"); (3) `test_inspection.py`: tier detection (builtin path / user path / community path); enable gates: `user` → explicit enable required (default disabled); `community` → static inspection report generated (pattern scan: exec-ზე მიმთითებელი ინსტრუქციები — "run", "curl | bash", credential paths `~/.ssh`, `.env`, URLs) + enable მოითხოვს `CONFIRM_EXACT` + hash pin; report fixture-ზე 3/3 suspicious pattern ნაპოვნია; (4) enable/disable/load ყოველი → `skill_lifecycle` audit event (T4.02). Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/skills -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `manifest.py`: pydantic `SkillManifest` + forbidden-keys validator; canonical serialization helper hash-ისთვის; `loader.py`: dir scan → manifest validate → hash verify → registry check (`required_tools ⊆ registry`, `permission_class_max` vs policy ceiling T2.01) → `LoadedSkill` (SKILL.md text as untrusted data, no exec path); `inspection.py`: tier resolver (XDG paths), pattern scanner (ordered regex list, report dataclass `(pattern, line, excerpt)`), gate policy table §9.2 row-ებით.

**Expected results:** manifest schema 12/12 field test; hash mismatch 100% refused; forbidden keys 100% rejected; community report fixture 3/3 detection; ≥22 test case.

**Verification:** pytest command green; `mypy --strict src/lsassist/skills` clean (skills/ TCB-ში არ არის §2.3-ით, მაგრამ loader TCB-adjacent — strict მაინც). Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) loader-ში არავითარი `exec`/`subprocess`/import path — static grep `grep -rn "subprocess\|os.system\|exec(" src/lsassist/skills/` ცარიელი; (2) §9.2-ის სამივე tier-ის gate ზუსტადაა (builtin default-enabled / user explicit / community CONFIRM_EXACT+hash pin); (3) inspection pattern list გასაგები და გაფართოებადია.

**Rollback:** `git rm -r --cached src/lsassist/skills tests/unit/skills 2>/dev/null; rm -rf src/lsassist/skills tests/unit/skills`.

(SPEC §9.1, §9.2, §12.1, ADR-008, I2)

### T4.11 — skills/: lifecycle state machine + audit events + hash-pinned update re-confirm

**Scope:** skill lifecycle state machine §9.3-ით — `installed → inspected → enabled → (update-available → re-inspected) → disabled → removed`, ყოველი transition-ის audit event, update = ახალი hash → mandatory re-confirm (no silent update), rollback to previous enabled hash; versioned storage layout.

**Files:** `lsassist/src/lsassist/skills/lifecycle.py`, `lsassist/src/lsassist/skills/registry_store.py`, `lsassist/tests/unit/skills/test_lifecycle.py`, `lsassist/tests/unit/skills/test_registry_store.py`, `lsassist/tests/property/test_skill_lifecycle.py`

**Depends on:** T4.10

**RED (tests first):** (1) `test_lifecycle.py`: legal transitions თითოეული §9.3-დან — transition table-driven test; illegal transition (installed→enabled skip inspected; removed→enabled; update without re-inspected) → `IllegalTransitionError`; enable flow: hash verify → registry check → injection eligibility order enforced; **update flow:** ახალი version (new `content_hash`) → state `update-available`, skill stays on old pinned hash სანამ `CONFIRM_EXACT` re-confirm არ მოხდება; silent update attempt (hash replace without re-confirm) → rejected + audit; rollback: `rollback` → previous enabled hash restore; (2) `test_registry_store.py`: versioned layout `$XDG_DATA_HOME/lsassist/skills/<name>/<hash>/` — ორი version parallel stored; active pointer file; removed → dir delete only after disabled; (3) `test_skill_lifecycle.py` (hypothesis): arbitrary transition sequences → state machine არასდროს აღწევს `enabled` state-ს hash verify + gate-ის გარეშე (state machine model test, I15-style); (4) ყოველი transition → `skill_lifecycle` audit event `(from, to, name, hash)` — assertion over journal. Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/skills tests/property/test_skill_lifecycle.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `lifecycle.py`: `SkillLifecycle` — state enum, transition table (dict-of-dicts), guard functions (hash verify T4.10 loader reuse, gate check per tier T4.10, re-confirm callback injection); update detector (registry scan: new hash dir present ≠ active pointer → `update-available`); rollback (pointer switch to previous enabled hash); `registry_store.py`: filesystem layout manager (create `<name>/<hash>/`, active pointer, prune on removed); audit emit ყოველ transition-ზე.

**Expected results:** transition table 100% covered (legal + illegal); silent update 0 possible (property test); update re-confirm mandatory — test proof; ≥18 test case.

**Verification:** pytest command green; `mypy --strict src/lsassist/skills` clean; property test 2,000 sequence, 0 invariant violation. Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) transition table სიტყვასიტყვით §9.3-ს ემთხვევა; (2) "no silent update" property test-ით დამტკიცებულია, არა მხოლოდ code reading-ით; (3) versioned storage layout §9.3-ის rollback მოთხოვნას პასუხობს.

**Rollback:** `git rm --cached src/lsassist/skills/lifecycle.py src/lsassist/skills/registry_store.py tests/unit/skills/test_lifecycle.py tests/unit/skills/test_registry_store.py tests/property/test_skill_lifecycle.py 2>/dev/null; rm -f <იგივე paths>`.

(SPEC §9.3, §14.1, I15)

### T4.12 — skills/: injection rules wiring — delimited user-role injection + `permission_class_max` hook

**Scope:** enabled skill-ის ტექსტის context injection §9.4-ით — §4.6 delimiter wrap, provenance label, user-role block (never system), და wiring: loaded skill manifest-ის `permission_class_max` ჩაიწერება `PolicyContext.skill_ceiling` field-ში (contracts T1.11/T1.04-დან), რომელსაც T2.01-ის rule R9 მოიხმარს — enforcement თავად T2.01/R9-შია, აქ მხოლოდ wiring და contract; ახალი policy logic phase 4-ში არ იწერება; prompt assembly integration შემდგომი ფაზის საგანია.

**Files:** `lsassist/src/lsassist/skills/injection.py`, `lsassist/tests/unit/skills/test_injection.py`, `lsassist/tests/integration/skills/test_injection_policy.py`

**Depends on:** T4.11, T2.11, T2.01, T1.11

**RED (tests first):** (1) `test_injection.py`: `build_skill_context(skills)` → თითო skill text `<<<UNTRUSTED_DATA id="…" source="skill:<name>" provenance="<tier>">>` block-ში (T2.11 wrap reuse), provenance label tier-ით; delimiter-like strings SKILL.md content-ში → defanged insert-მდე (§4.6 step 1); output marked `role="user"` context block — system-role marker არსად (structural assertion on context message list); disabled/pending skills injection-ში არ ხვდება (lifecycle state filter T4.11); (2) `test_injection_policy.py` (integration): skill `permission_class_max=AUTO_READ` → injection wiring ავსებს `PolicyContext.skill_ceiling=AUTO_READ`-ს (contract T1.11/T1.04-დან) → skill-ის turn-ში წარმოშობილი simulated tool request `AUTO_WRITE` → T2.01-ის rule R9 raise → შედეგი მინიმუმ CONFIRM_EXACT (ceiling-ზე დაბალი კლასი აკრძალული); ceiling-ში ჯდება → normal flow; `skill_ceiling` absent (no skill) → ცვლილება არა; injection event → audit (skill context assembled, count). Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/skills/test_injection.py tests/integration/skills -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `injection.py`: `build_skill_context(active_skills) -> list[ContextBlock]` — wrap helper T2.11-დან (defang included), provenance label, user-role marker; `skill_ceiling(skills) -> PermissionClass` — min of enabled skills-ის `permission_class_max` (loaded manifest-ებიდან, T4.10) — შედეგი იწერება `PolicyContext.skill_ceiling` field-ში (contract T1.11/T1.04-დან), რომელსაც T2.01-ის rule R9 მოიხმარს classification-ზე (არსებული hook-ის consumption/wiring — ახალი policy logic phase 4-ში აკრძალულია); audit emit on assembly.

**Expected results:** delimiter wrap + defang 100% fixture-ზე; system-role leakage 0 (structural assertion); ceiling enforcement 2/2 (blocked above, allowed within); ≥12 test case.

**Verification:** pytest command green; `mypy --strict src/lsassist/skills` clean; `pytest -q tests/` სრული suite green (regression — phases 1–4); `scripts/loc-count` TCB budget-ში. Pass criteria: ყველა exit 0, full suite green → **Phase 4 done**.

**Review checkpoint:** ადამიანი ამოწმებს: (1) §9.4-ის სამივე წესი დაფარულია (delimited+provenance+user-role; ceiling enforcement; read≠execute — loader-ში exec არ არსებობს, T4.10 checkpoint-ის შედეგი); (2) ceiling hook მხოლოდ existing policy input-ს ავსებს — ახალი policy logic არ დაწერილა phase 4-ში; (3) Phase 4 სრულად: T4.01→T4.12 ჯაჭვი green, `audit/`+`recovery/` 100% branch coverage მტკიცებულებით → Phase 5 (providers/CLI integration) შეიძლება დაიწყოს.

**Rollback:** `git rm --cached src/lsassist/skills/injection.py tests/unit/skills/test_injection.py tests/integration/skills/test_injection_policy.py 2>/dev/null; rm -f <იგივე paths>`.

(SPEC §9.4, §4.6, ADR-008, I7)
