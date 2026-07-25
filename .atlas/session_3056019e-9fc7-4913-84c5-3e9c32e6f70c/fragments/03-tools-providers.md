## Phase 3 — Tools & Providers

ეს ფაზა ფარავს tool runtime-ის ბირთვს (registry, dispatch pipeline), SPEC §6.4-ის 12 tool-ის handler-ებსა და manifest-ებს, provider adapter-ებს (`kimi-coding`, `ollama-local`), fallback flow-ს და Ollama eval harness-ს. ყველა task test-first: RED precedes GREEN. Phase-1/2 dependency-ები: `T1.04`/`T1.11` (contracts package — pydantic models, JSON schemas), `T1.05` (`ApprovalRecord` contract), `T1.06` (provider contracts), `T1.07` (canary registry), `T2.01` (policy engine), `T2.03` (approval token service), `T2.05`/`T2.06` (sandbox profile builder + runner). Fragment 01 §0-ის მიხედვით execution order ტოპოლოგიურია, ამიტომ cross-phase forward edges T4 producer-ებზე (`T4.02` audit writer, `T4.04` checkpoint manager, `T4.07` memory store) ლეგიტიმურია.

### T3.01

- **Scope:** Tool registry და manifest-ების startup loading/validation §6.2 JSON Schema-ზე — immutable catalog, name shadowing rejection, runtime re-registration-ის არარსებობა.
- **Files:** `src/lsassist/tools/registry.py`, `src/lsassist/tools/manifest_schema.json`, `tests/unit/tools/test_registry.py`, `tests/contract/tools/test_manifest_schema.py`
- **Depends on:** `T1.04` (contracts package — `ToolManifest` model), `T1.02` (`jsonschema` dependency in requirements.lock)
- **RED (tests first):** `tests/unit/tools/test_registry.py` და `tests/contract/tools/test_manifest_schema.py`; ბრძანება: `pytest tests/unit/tools/test_registry.py tests/contract/tools/test_manifest_schema.py -q`. იღუპება: registry მოდული არ არსებობს (ImportError).
- **GREEN (implementation):** manifest schema როგორც მონაცემი (`manifest_schema.json`, verbatim §6.2: `additionalProperties:false`, `name` pattern `^[a-z][a-z0-9_.]{1,31}$`, `permission_class` enum — manifest class = ceiling, capabilities `fs/net/proc` enums, `timeout_s` 1–1800, `output_limits` caps); loader რომელიც კითხულობს `src/lsassist/tools/manifests/*.json`-ს startup-ზე, ამოწმებს schema-ზე, აგდებს duplicate name-ს (cross-tool shadowing), აბრუნებს immutable catalog-ს (frozen mapping); load failure → typed error, kernel startup BLOCKED (fail-closed).
- **Expected results:** ცარიელი manifests dir → 0 tool; არასწორი manifest (missing required field, unknown property, bad name pattern, class enum-ის გარეთ) → load error კონკრეტული ფაილის მითითებით; duplicate name → load error.
- **Verification:** `pytest tests/unit/tools/test_registry.py tests/contract/tools/test_manifest_schema.py -q` — ყველა მწვანე; schema-ს თავადი validation `jsonschema` meta-schema-ზე contract test-ში.
- **Review checkpoint:** ადამიანი ამოწმებს, რომ `manifest_schema.json` ზუსტად შეესაბამება SPEC §6.2-ს (field-by-field diff) და რომ loader-ში არ არის re-registration path.
- **Rollback:** `git checkout -- src/lsassist/tools/registry.py src/lsassist/tools/manifest_schema.json tests/unit/tools/test_registry.py tests/contract/tools/test_manifest_schema.py`
- (SPEC §6.1, §6.2, I3, I4)

### T3.02

- **Scope:** Dispatch pipeline-ის ნაბიჯები 1–4: schema validate → normalize/canonicalize → policy classify → approval — wired to phase-2 policy engine და token service, fail-closed ყოველ ეტაპზე.
- **Files:** `src/lsassist/tools/dispatcher.py`, `tests/unit/tools/test_dispatch_validate.py`, `tests/unit/tools/test_dispatch_policy.py`
- **Depends on:** T3.01, `T1.11` (`ToolRequest`/`PolicyContext` contracts — dispatch-ის input model), `T2.01` (policy engine R1–R9), `T2.03` (approval token service), `T1.05` (`ApprovalRecord` contract — `policy_note`/`rollback_hint` fields)
- **RED (tests first):** `tests/unit/tools/test_dispatch_validate.py` და `tests/unit/tools/test_dispatch_policy.py`; ბრძანება: `pytest tests/unit/tools/test_dispatch_validate.py tests/unit/tools/test_dispatch_policy.py -q`. იღუპება: dispatcher არ არსებობს.
- **GREEN (implementation):** ნაბიჯი 1 — args validation `input_schema`-ზე `additionalProperties:false`-ით, fail → `malformed_tool_request` (budget refund marker); ნაბიჯი 2 — path canonicalization `realpath` fail-closed (symlink chain resolution, dangling target → error `create_if_missing` tool-ის გარდა), argv = verbatim `list[str]` no interpolation, env = allowlist projection; ნაბიჯი 3 — phase-2 policy classify call ამ exact request-ზე, manifest class = ceiling, rules მხოლოდ აწიათებენ; classify time-ზე populate ხდება `ApprovalRecord`-ის `policy_note` და `rollback_hint` field-ები §7.1-ის class semantics-ის მიხედვით (`policy_note` = risk line + matched policy rule reference, მაგ. R2/R3/R5; `rollback_hint` = rollback path class-ის მიხედვით, მაგ. shadow-git checkpoint restore write tools-ზე) — რათა T5.03-ის approval renderer მათ user-facing prompt-ში გამოაჩინოს; ნაბიჯი 4 — AUTO → proceed, CONFIRM → token verify ან canonical record prompt-ის request, DENY → BLOCKED verdict. Handler-ს მიეწოდება მხოლოდ validated args + execution context — LLM context არა.
- **Expected results:** malformed args → `malformed_tool_request`; `..`-იანი ან DENY-path args → DENY_ALWAYS/BLOCKED; valid AUTO_READ call მიდის ნაბიჯ 5-მდე; policy rule-ით აწეული class (მაგ. R3 untrusted_turn) იძლევა CONFIRM_EXACT-ს.
- **Verification:** `pytest tests/unit/tools/test_dispatch_validate.py tests/unit/tools/test_dispatch_policy.py -q` — ყველა მწვანე; policy boundary-ები (ceiling-only-raise, DENY list hit) მოცემულია ცალკე case-ებით.
- **Review checkpoint:** ადამიანი ამოწმებს dispatch order-ს §6.3-თან და რომ handler signature-ში LLM context არ შემოდის (§6.1).
- **Rollback:** `git checkout -- src/lsassist/tools/dispatcher.py tests/unit/tools/test_dispatch_validate.py tests/unit/tools/test_dispatch_policy.py`
- (SPEC §6.3 steps 1–4, §7.1, §7.2, §7.5, I2, I5)

### T3.03

- **Scope:** Dispatch pipeline-ის ნაბიჯები 5–9: sandbox profile build → execute phase-2 sandbox runner-ით → observe → verify → audit-event hook.
- **Files:** `src/lsassist/tools/dispatcher.py`, `src/lsassist/tools/result.py`, `tests/unit/tools/test_dispatch_execute.py`, `tests/integration/tools/test_dispatch_sandbox.py`
- **Depends on:** T3.02, `T2.05` (sandbox profile builder), `T2.06` (bwrap runner), `T4.02` (audit writer)
- **RED (tests first):** `tests/unit/tools/test_dispatch_execute.py` (pure functions, mocked runner) და `tests/integration/tools/test_dispatch_sandbox.py` (real bwrap runner on host); ბრძანება: `pytest tests/unit/tools/test_dispatch_execute.py -q && pytest tests/integration/tools/test_dispatch_sandbox.py -q -m integration`. იღუპება: execution tail არ არსებობს.
- **GREEN (implementation):** ნაბიჯი 5 — pure function `(tool, args, policy) → bwrap argv` phase-2 profile builder-ის გამოძახებით (§8 `ro`/`ws`); ნაბიჯი 6 — execute runner-ით: `prlimit` + `bwrap`, `start_new_session`, timeout → `SIGKILL` process group, stdout/stderr caps, child env = allowlist only; bwrap spawn failure → typed `sandbox_unavailable` → BLOCKED (never unsandboxed fallback); ნაბიჯი 7 — observe: exit code, duration, output digests, truncated flags; ნაბიჯი 8 — verify: manifest postconditions, result-ის validation `output_schema`-ზე, workspace tree guard write tools-ზე; ნაბიჯი 9 — audit event (redacted) ყველა digest-ით. §6.5 result contract: `tool/status/exit_code/duration_ms/stdout_digest/stderr_digest/result/evidence/error`.
- **Expected results:** echo-style fixture tool sandbox-ში იძლევა §6.5 contract result-ს; timeout case → `SIGKILL` + verdict evidence `timeout`; spawn failure → BLOCKED, არა unsandboxed exec; oversized output → `truncated` + digest-only body.
- **Verification:** `pytest tests/unit/tools/test_dispatch_execute.py -q` და `pytest tests/integration/tools/test_dispatch_sandbox.py -q -m integration` — ყველა მწვანე; integration test ამოწმებს, რომ sandbox-ში workspace-გარეთ write → EROFS.
- **Review checkpoint:** ადამიანი ამოწმებს, რომ fail-closed behavior არის ყველგან (არანაირი degrade to direct exec) და result contract field-ები ემთხვევა §6.5-ს.
- **Rollback:** `git checkout -- src/lsassist/tools/dispatcher.py src/lsassist/tools/result.py tests/unit/tools/test_dispatch_execute.py tests/integration/tools/test_dispatch_sandbox.py`
- (SPEC §6.3 steps 5–9, §6.5, §8.3, I11, I12)

### T3.04

- **Scope:** Read-only tool batch — `fs.read`, `fs.list`, `fs.find`, `sys.info`, `pkg.query`, `git.read`: handler-ები + manifest-ები + unit/integration tests, თითოეული tool-ის §6.4 contract notes-ის დაცვით.
- **Files:** `src/lsassist/tools/manifests/fs_read.json`, `src/lsassist/tools/manifests/fs_list.json`, `src/lsassist/tools/manifests/fs_find.json`, `src/lsassist/tools/manifests/sys_info.json`, `src/lsassist/tools/manifests/pkg_query.json`, `src/lsassist/tools/manifests/git_read.json`, `src/lsassist/tools/handlers/fs_read.py`, `src/lsassist/tools/handlers/fs_list.py`, `src/lsassist/tools/handlers/fs_find.py`, `src/lsassist/tools/handlers/sys_info.py`, `src/lsassist/tools/handlers/pkg_query.py`, `src/lsassist/tools/handlers/git_read.py`, `tests/unit/tools/test_readonly_tools.py`, `tests/integration/tools/test_readonly_sandbox.py`
- **Depends on:** T3.03, `T1.07` (canary honeyfiles + `canary_registry()`)
- **RED (tests first):** `tests/unit/tools/test_readonly_tools.py` და `tests/integration/tools/test_readonly_sandbox.py`; ბრძანება: `pytest tests/unit/tools/test_readonly_tools.py -q`. იღუპება: handlers/manifests არ არსებობს. canary case (§19 scenario 1): `fs.read` honeyfile canonical path-ზე (T1.07 registry fixture) → `CANARY_TRIPPED` verdict, kernel freeze event, audit alert — content არ ბრუნდება.
- **GREEN (implementation):** `fs.read` — utf-8 errors=replace, binary → hex head 4 KB, §7.3 DENY paths handler-side double-check, fs access `os.open(..., O_NOFOLLOW, dir_fd=canonical_parent)` (§7.5 step 4); canary-read detection: requested canonical path-ები მოწმდება T1.07-ის `canary_registry()`-ის (path + sha256) წინააღმდეგ kernel watch-ის მეშვეობით — honeyfile-ზე read attempt-ზე handler-ი აგდებს `CANARY_TRIPPED`-ს, kernel-ი ყინავს session-ს და წერს audit alert-ს + user notice (§19 scenario 1), file content არასდროს ბრუნდება; `fs.list` — sorted output, depth ≤ 4 default; `fs.find` — name/glob/content modes, regex size-capped, `..` აკრძალული canonicalization-ის შემდეგ; `sys.info` — fixed argv allowlist (`uname -a`, `lscpu`, `free -h`, `df -h`, os-release read); `pkg.query` — fixed argv (`dpkg-query -W`, `apt-cache show`, venv `pip list`), name arg regex `^[a-zA-Z0-9+._:-]+$`; `git.read` — fixed subcommands მხოლოდ (`status --short --branch`, `diff [--cached] [path]`, `log --oneline -N`, `branch --show-current`, `worktree list`), repo = workspace. ყველა manifest: class `AUTO_READ`, caps და limits §6.4 ცხრილიდან.
- **Expected results:** ექვსი tool dispatch-ით მუშაობს `ro` profile-ში; DENY path (მაგ. `~/.ssh/id_rsa`) → BLOCKED/digest არ იბრუნება; honeyfile read attempt → session freeze + audit alert, content leak არ ხდება; binary file → hex head ≤ 4 KB; `git.read`-ზე არა-allowlisted subcommand → schema/policy error.
- **Verification:** `pytest tests/unit/tools/test_readonly_tools.py -q && pytest tests/integration/tools/test_readonly_sandbox.py -q -m integration` — ყველა მწვანე; handlers coverage ≥ 90% (`pytest --cov=src/lsassist/tools/handlers --cov-report=term-missing`).
- **Review checkpoint:** ადამიანი ამოწმებს manifest field-ებს §6.4 ცხრილთან (class ceiling, caps, timeout, output cap) და `O_NOFOLLOW`/dirfd pattern-ს `fs.read`-ში.
- **Rollback:** `git checkout -- src/lsassist/tools/manifests/ src/lsassist/tools/handlers/ tests/unit/tools/test_readonly_tools.py tests/integration/tools/test_readonly_sandbox.py`
- (SPEC §6.4, §7.3, §7.5, §8.1, §19 scenario 1, I8)

### T3.05

- **Scope:** Write tool batch — `fs.write`, `fs.patch`, `git.worktree`: atomic write semantics, all-or-nothing patch anchors, worktree path constraint, checkpoint hooks.
- **Files:** `src/lsassist/tools/manifests/fs_write.json`, `src/lsassist/tools/manifests/fs_patch.json`, `src/lsassist/tools/manifests/git_worktree.json`, `src/lsassist/tools/handlers/fs_write.py`, `src/lsassist/tools/handlers/fs_patch.py`, `src/lsassist/tools/handlers/git_worktree.py`, `tests/unit/tools/test_write_tools.py`, `tests/integration/tools/test_write_sandbox.py`
- **Depends on:** T3.04, `T4.04` (checkpoint manager — shadow-git)
- **RED (tests first):** `tests/unit/tools/test_write_tools.py` და `tests/integration/tools/test_write_sandbox.py`; ბრძანება: `pytest tests/unit/tools/test_write_tools.py -q`. იღუპება: handlers არ არსებობს.
- **GREEN (implementation):** `fs.write` — atomic: tmp file + `fsync` + `rename`; `O_NOFOLLOW` final component-ზე (§7.5); checkpoint pre-write call; overwrite მხოლოდ `intent=overwrite` flag-ით, create-only mode-ში existing file → error; `fs.patch` — search/replace blocks exact-match anchors-ით, all-or-nothing (ერთი anchor miss → no file touched), checkpoint pre-patch; `git.worktree` — მხოლოდ `git worktree add <path> -b <branch>`, path მხოლოდ workspace `.lsassist/worktrees/`-ში. Manifests: class `AUTO_SCOPED_WRITE`, `ws` profile, §6.4 limits.
- **Expected results:** partial patch → ფაილი უცვლელი (tree hash identical); overwrite without `intent=overwrite` → error; symlink target-ზე write → `O_NOFOLLOW` rejection; `git.worktree` path workspace-გარეთ → policy/classification error; post-exec verification (inode/hash compare) mismatch → UNVERIFIED + audit alert.
- **Verification:** `pytest tests/unit/tools/test_write_tools.py -q && pytest tests/integration/tools/test_write_sandbox.py -q -m integration` — ყველა მწვანე; integration test ამოწმებს checkpoint restore-ს წარუმატებელი write-ის შემდეგ.
- **Review checkpoint:** ადამიანი ამოწმებს atomicity sequence-ს (tmp+fsync+rename order), all-or-nothing guarantee-ს და `.lsassist/worktrees/` path constraint-ს.
- **Rollback:** `git checkout -- src/lsassist/tools/manifests/fs_write.json src/lsassist/tools/manifests/fs_patch.json src/lsassist/tools/manifests/git_worktree.json src/lsassist/tools/handlers/fs_write.py src/lsassist/tools/handlers/fs_patch.py src/lsassist/tools/handlers/git_worktree.py tests/unit/tools/test_write_tools.py tests/integration/tools/test_write_sandbox.py`
- (SPEC §6.4, §7.5, §8.2, I6, I9)

### T3.06

- **Scope:** Exec/network tool batch — `test.run`, `proc.exec`, `net.fetch`: argv allowlists, R5 class raising, domain/content-type allowlists, no body→disk.
- **Files:** `src/lsassist/tools/manifests/test_run.json`, `src/lsassist/tools/manifests/proc_exec.json`, `src/lsassist/tools/manifests/net_fetch.json`, `src/lsassist/tools/handlers/test_run.py`, `src/lsassist/tools/handlers/proc_exec.py`, `src/lsassist/tools/handlers/net_fetch.py`, `tests/unit/tools/test_exec_net_tools.py`, `tests/integration/tools/test_exec_net_sandbox.py`
- **Depends on:** T3.05, `T4.07` (memory store — `net.fetch` body→memory)
- **RED (tests first):** `tests/unit/tools/test_exec_net_tools.py` და `tests/integration/tools/test_exec_net_sandbox.py`; ბრძანება: `pytest tests/unit/tools/test_exec_net_tools.py -q`. იღუპება: handlers არ არსებობს.
- **GREEN (implementation):** `test.run` — detected runner (`pytest`, `npm test`, `cargo test`), argv fixed per runner + user-visible extra args validated (argv tokens only, `;`/`&&`/backtick rejection), bwrap `ws` profile, timeout 600 s; `proc.exec` — argv[0] ∈ allowlist (§7.4), policy R5: dangerous argv[0] → CONFIRM_EXACT, `sudo`/`doas`/`su` → DENY_ALWAYS, metachar data tokens → allowed მაგრამ CONFIRM_EXACT + token display; `net.fetch` — GET/HEAD only, domain allowlist config-დან (R6: off-allowlist → CONFIRM_EXACT with domain display), https only (localhost http excepted), redirects რჩება allowlist-ში, content-type allowlist (text/*, application/json, application/xml), body → memory store-ში (T4.07) only, არა disk write, 1 MB cap.
- **Expected results:** `proc.exec` `["sudo", ...]` → DENY_ALWAYS policy verdict; `["rm", "-rf", ...]` → CONFIRM_EXACT; `net.fetch` off-allowlist domain → CONFIRM_EXACT; non-allowlisted content-type → error; `test.run` extra args shell metachar-ებით → validation error; exec-ები `ws` profile-ში network-ის გარეშე (integration: net unreachable).
- **Verification:** `pytest tests/unit/tools/test_exec_net_tools.py -q && pytest tests/integration/tools/test_exec_net_sandbox.py -q -m integration` — ყველა მწვანე; handlers coverage ≥ 90%.
- **Review checkpoint:** ადამიანი ამოწმებს R5 allowlist/denylist table-ს §7.4-თან, `net.fetch` redirect-chain allowlist check-ს და რომ body არასდროს იწერება disk-ზე.
- **Rollback:** `git checkout -- src/lsassist/tools/manifests/test_run.json src/lsassist/tools/manifests/proc_exec.json src/lsassist/tools/manifests/net_fetch.json src/lsassist/tools/handlers/test_run.py src/lsassist/tools/handlers/proc_exec.py src/lsassist/tools/handlers/net_fetch.py tests/unit/tools/test_exec_net_tools.py tests/integration/tools/test_exec_net_sandbox.py`
- (SPEC §6.4, §7.2 R4–R6, §7.4, ADR-010, I2)

### T3.07

- **Scope:** Registry-enumeration test — SPEC §6.4-ის explicitly absent V1 tools (`shell`, `sudo`-capable exec, `pkg.install`/`pkg.remove`, `git.destructive`, `service.*`, `firewall.*`, `credentials.*`, `send.*`, `cron.*`) registry-ში არ არსებობს; registry შეიცავს ზუსტად 12 §6.4 tool-ს.
- **Files:** `tests/contract/tools/test_registry_enumeration.py`
- **Depends on:** T3.06
- **RED (tests first):** `tests/contract/tools/test_registry_enumeration.py`; ბრძანება: `pytest tests/contract/tools/test_registry_enumeration.py -q`. იღუპება: test ფაილი არ არსებობს (test-first; registry ამ წერტილში უკვე არსებობს, ამიტომ RED = ახალი contract assertions absent-catalog-ზე, რომლებიც enumeration list-ის შესაბამისობას SPEC §6.4-თან ამოწმებენ).
- **GREEN (implementation):** არა implementation — მხოლოდ contract test: registry name-ების set == frozen §6.4 list (`fs.read`, `fs.list`, `fs.find`, `sys.info`, `pkg.query`, `git.read`, `fs.write`, `fs.patch`, `git.worktree`, `test.run`, `proc.exec`, `net.fetch`); absent names list-ის თითოეულზე assertion `name not in registry`; ყველა manifest-ში `input_schema` typed (I2 check); არანაირი shell-string-მიმღები field.
- **Expected results:** 12-tool set exact match; თითოეული absent name → უარყოფითი assertion მწვანეა; მომავალში shell-like tool-ის დამატება ამ test-ს წითლებს.
- **Verification:** `pytest tests/contract/tools/test_registry_enumeration.py -q` — მწვანე; სახელდობით წარუმატებელი case: test-ში დროებით ჩასმული `shell` manifest fixture → test იღუპება (mutation check).
- **Review checkpoint:** ადამიანი ამოწმებს frozen list-ს SPEC §6.4-თან (ორივე მიმართულებით: present 12 + absent 9 ჯგუფი).
- **Rollback:** `git checkout -- tests/contract/tools/test_registry_enumeration.py`
- (SPEC §6.4, ADR-010, I2, I3, I14)

### T3.08

- **Scope:** Provider base plumbing — `providers/base.py` adapter plumbing T1.06-ის provider contract-ების ზემოთ (§5.1): `UsageAccounting`/`Health` helpers, `ProviderProfile` Protocol-ის re-export, adapter prohibition guard. Contract types-ის განსაზღვრა აქ არ ხდება — `contracts/provider.py` უკვე არსებობს T1.06-დან.
- **Files:** `src/lsassist/providers/base.py`, `tests/unit/providers/test_base_contract.py`, `tests/contract/providers/test_provider_prohibitions.py`
- **Depends on:** `T1.06` (provider contracts — `ProviderProfile` Protocol + models, pydantic)
- **RED (tests first):** `tests/unit/providers/test_base_contract.py` და `tests/contract/providers/test_provider_prohibitions.py`; ბრძანება: `pytest tests/unit/providers/test_base_contract.py tests/contract/providers/test_provider_prohibitions.py -q`. იღუპება: base module არ არსებობს.
- **GREEN (implementation):** `providers/base.py` მოიხმარს T1.06-ის contract-ებს (`ModelCapabilities`, `StreamEvent` enum, `AssistantTurn`, `ProviderError` `normalize_unmapped()`-ით, `ProviderProfile` runtime-checkable Protocol — import/re-export `contracts/provider.py`-დან, არა ხელახალი განსაზღვრა) და ამატებს მხოლოდ plumbing-ს: `UsageAccounting` და `Health` helpers adapter-ებისთვის; static guard test: `src/lsassist/providers/`-ში `subprocess`/`os.open` import-ების არარსებობა (I1); `reasoning_opaque` RAM-only marker — audit-serializable dump-ში field absent (I16).
- **Expected results:** T1.06 contract types round-trip base.py-ის re-export-ით; unmapped error normalization → `transient/retryable=True`; prohibition guard test მწვანე; `reasoning_opaque` audit-serializable models-ში არ ჩანს.
- **Verification:** `pytest tests/unit/providers/test_base_contract.py tests/contract/providers/test_provider_prohibitions.py -q` — ყველა მწვანე; `mypy --strict src/lsassist/providers/base.py` clean.
- **Review checkpoint:** ადამიანი ამოწმებს error kind enum-ს §5.1-თან და adapter prohibition list-ს (no subprocess, no fs writes, no credential logging hooks).
- **Rollback:** `git checkout -- src/lsassist/providers/base.py tests/unit/providers/test_base_contract.py tests/contract/providers/test_provider_prohibitions.py`
- (SPEC §5.1, I1, I16)

### T3.09

- **Scope:** Kimi adapter core — streaming SSE parse, OpenAI-compatible request build (base URL, auth header, model IDs, `strict: true` tools), error taxonomy mapping table, honest User-Agent.
- **Files:** `src/lsassist/providers/kimi_coding.py`, `tests/unit/providers/test_kimi_sse.py`, `tests/unit/providers/test_kimi_errors.py`, `tests/contract/providers/test_kimi_identity.py`
- **Depends on:** T3.08
- **RED (tests first):** `tests/unit/providers/test_kimi_sse.py`, `tests/unit/providers/test_kimi_errors.py`, `tests/contract/providers/test_kimi_identity.py`; ბრძანება: `pytest tests/unit/providers/test_kimi_sse.py tests/unit/providers/test_kimi_errors.py tests/contract/providers/test_kimi_identity.py -q`. იღუპება: adapter არ არსებობს.
- **GREEN (implementation):** `POST https://api.kimi.com/coding/v1/chat/completions`; header `Authorization: Bearer <key>` (key phase-1 secrets resolver-იდან, არა env-დან adapter-ში); model IDs (`kimi-for-coding` default, `k3`, `kimi-for-coding-highspeed`) startup cached catalog-ით; tool defs OpenAI format, `strict: true`, name regex `^[a-zA-Z_][a-zA-Z0-9-_]{2,63}$`; SSE parser → `StreamEvent` sequence (incl. `reasoning_delta` → `reasoning_opaque` RAM-only, tool-call assistant messages retain `reasoning_content` on resend); error mapping table verbatim §5.2 (401→auth terminal, 402→transient ≤3, 403→quota/terminated terminal, 429 window→quota wait no-retry-storm, 429 overload→rate_limit backoff ≤4, 500→transient ≤3, 499→client no, 400→client no + BLOCKED diagnostics); `User-Agent: lsassist/<semver> (+https://<repo>)` ყოველ request-ზე — contract test ამტკიცებს header-ს (AC-03).
- **Expected results:** recorded SSE fixture-ები სწორ event sequence-ად იშლება; თითოეული §5.2 table row → სწორი `ProviderError`; UA assertion მწვანე; credential არ ლოგირდება (log-capture test).
- **Verification:** `pytest tests/unit/providers/test_kimi_sse.py tests/unit/providers/test_kimi_errors.py tests/contract/providers/test_kimi_identity.py -q` — ყველა მწვანე; `mypy --strict src/lsassist/providers/kimi_coding.py` clean.
- **Review checkpoint:** ადამიანი ამოწმებს mapping table-ს §5.2-თან row-by-row და UA string format-ს (honest identity, ToS).
- **Rollback:** `git checkout -- src/lsassist/providers/kimi_coding.py tests/unit/providers/test_kimi_sse.py tests/unit/providers/test_kimi_errors.py tests/contract/providers/test_kimi_identity.py`
- (SPEC §5.2, ADR-003, AC-03)

### T3.10

- **Scope:** Kimi retry/backoff + circuit breaker — მხოლოდ retryable კლასები, 5 min chain cap, `Retry-After` honoring, breaker → `provider_down` trigger; usage telemetry counter.
- **Files:** `src/lsassist/providers/kimi_coding.py`, `src/lsassist/providers/retry.py`, `tests/unit/providers/test_kimi_retry.py`, `tests/unit/providers/test_circuit_breaker.py`
- **Depends on:** T3.09
- **RED (tests first):** `tests/unit/providers/test_kimi_retry.py` და `tests/unit/providers/test_circuit_breaker.py`; ბრძანება: `pytest tests/unit/providers/test_kimi_retry.py tests/unit/providers/test_circuit_breaker.py -q`. იღუპება: retry/breaker logic არ არსებობს.
- **GREEN (implementation):** retry მხოლოდ `retryable=True` kinds-ზე; backoff 1s→2s→4s→8s jitter-ით (overload ≤4; transient ≤3); total chain ≤ 5 min; `Retry-After` honored when present; circuit breaker: 5 consecutive retryable failures ან 1 terminal error → `provider_down` state (§5.4 flow-ს input); client-side usage counter per rolling 5h window + 80% warning threshold; 429 quota-window → reset expectation surface, no auto-retry storm.
- **Expected results:** terminal error (401/403) → 0 retries; 5 consecutive 500s → breaker open → `provider_down`; chain time cap enforced (monotonic clock mock); `Retry-After: 7` → next attempt ≥ 7 s; telemetry counter 80%-ზე warning event.
- **Verification:** `pytest tests/unit/providers/test_kimi_retry.py tests/unit/providers/test_circuit_breaker.py -q` — ყველა მწვანე; property-style test: arbitrary error sequences never retry terminal kinds.
- **Review checkpoint:** ადამიანი ამოწმებს breaker threshold-ებს (5 retryable / 1 terminal) §5.2-თან და რომ retry ლოგიკა არასდროს ეხება non-retryable kinds-ს.
- **Rollback:** `git checkout -- src/lsassist/providers/kimi_coding.py src/lsassist/providers/retry.py tests/unit/providers/test_kimi_retry.py tests/unit/providers/test_circuit_breaker.py`
- (SPEC §5.2, §5.4)

### T3.11

- **Scope:** Ollama adapter — endpoint allowlist enforcement, `num_ctx`/`keep_alive` settings, client-side request serialization, capability probe, malformed-call rate demote.
- **Files:** `src/lsassist/providers/ollama.py`, `tests/unit/providers/test_ollama_adapter.py`, `tests/unit/providers/test_ollama_demote.py`
- **Depends on:** T3.08
- **RED (tests first):** `tests/unit/providers/test_ollama_adapter.py` და `tests/unit/providers/test_ollama_demote.py`; ბრძანება: `pytest tests/unit/providers/test_ollama_adapter.py tests/unit/providers/test_ollama_demote.py -q`. იღუპება: adapter არ არსებობს.
- **GREEN (implementation):** endpoint config validation regex `^https?://(127\.0\.0\.1|\[::1\]|localhost)(:\d+)?$` — remote Ollama → config validation error; `POST /api/chat` tools param OpenAI-style, response `message.tool_calls` parse, tool results `{role:"tool", tool_name, content}`; `POST /api/show` capability probe (`tools` in `capabilities[]`); explicit `num_ctx` (default 32768, configurable, >65536 → VRAM warning on 8 GB); `keep_alive: "10m"` active session-ში, explicit unload on exit; client-side queue serialization (`OLLAMA_NUM_PARALLEL=1` assumption); eval-gated tool set (§5.3): `eval_results.json` load — absent/below threshold → read-only set only, pass → +`test.run`/`net.fetch`, `fs.write`/`fs.patch`/`proc.exec`/`git.worktree` never local in V1; malformed tool call counter → rolling rate > 5% → auto-demote EXPLAIN-only + user notification event.
- **Expected results:** remote endpoint config → validation error; queue guarantees sequential requests; eval gate unit tests: no eval → read-only set, pass → expanded set, never-write-set assertion; synthetic malformed stream 6/100 → demote trigger + notification.
- **Verification:** `pytest tests/unit/providers/test_ollama_adapter.py tests/unit/providers/test_ollama_demote.py -q` — ყველა მწვანე; `mypy --strict src/lsassist/providers/ollama.py` clean.
- **Review checkpoint:** ადამიანი ამოწმებს eval gate table-ს §5.3-თან (three rows verbatim) და demote threshold-ს (5% rolling).
- **Rollback:** `git checkout -- src/lsassist/providers/ollama.py tests/unit/providers/test_ollama_adapter.py tests/unit/providers/test_ollama_demote.py`
- (SPEC §5.3, §23.1 EV, R5)

### T3.12

- **Scope:** Fallback flow state machine (§5.4) — banner + consent + audit events, never mid-task switch-back, both-down → BLOCKED with checkpoint.
- **Files:** `src/lsassist/providers/fallback.py`, `tests/unit/providers/test_fallback_flow.py`, `tests/integration/providers/test_fallback_fault.py`
- **Depends on:** T3.10, T3.11
- **RED (tests first):** `tests/unit/providers/test_fallback_flow.py` და `tests/integration/providers/test_fallback_fault.py`; ბრძანება: `pytest tests/unit/providers/test_fallback_flow.py -q && pytest tests/integration/providers/test_fallback_fault.py -q -m integration`. იღუპება: fallback module არ არსებობს.
- **GREEN (implementation):** states `KIMI_OK → KIMI_DOWN → PROMPT → OLLAMA_RO | BLOCKED`, `OLLAMA_RO → KIMI_OK` მხოლოდ next turn + healthcheck ok + user confirmation; transition-ზე visible banner (provider, reason, capability delta) + audit events `provider_down`/`provider_fallback`/`provider_restored`; user decline → BLOCKED; mid-task switch-back attempt → rejected (state machine guard); both down → verdict BLOCKED + journal checkpoint + resume instructions; fault-injection integration test: provider stub raises terminal error → flow reaches PROMPT, consent mock → OLLAMA_RO.
- **Expected results:** ყველა §5.4 transition reachable და guarded; no silent fallback (banner+audit assertion ყოველ transition-ზე); mid-task switch-back → error; both-down → BLOCKED + checkpoint artifact.
- **Verification:** `pytest tests/unit/providers/test_fallback_flow.py -q && pytest tests/integration/providers/test_fallback_fault.py -q -m integration` — ყველა მწვანე; state machine reachability test: `OLLAMA_RO → OLLAMA_RO` self-loop (never mid-task switch) explicit.
- **Review checkpoint:** ადამიანი ამოწმებს state diagram-ს §5.4 mermaid-თან და audit event payload-ებს (never silent).
- **Rollback:** `git checkout -- src/lsassist/providers/fallback.py tests/unit/providers/test_fallback_flow.py tests/integration/providers/test_fallback_fault.py`
- (SPEC §5.4, §14.1)

### T3.13

- **Scope:** Provider contract tests — golden-stream replay ორივე adapter-ზე და manual live-smoke procedure documentation (§5.5).
- **Files:** `tests/contract/providers/test_kimi_golden.py`, `tests/contract/providers/test_ollama_golden.py`, `docs/provider-evidence/README.md`, `docs/provider-evidence/kimi/golden_001.sse.json`, `docs/provider-evidence/ollama/golden_001.json`
- **Depends on:** T3.09, T3.11
- **RED (tests first):** `tests/contract/providers/test_kimi_golden.py` და `tests/contract/providers/test_ollama_golden.py`; ბრძანება: `pytest tests/contract/providers/test_kimi_golden.py tests/contract/providers/test_ollama_golden.py -q`. იღუპება: golden fixtures არ არსებობს.
- **GREEN (implementation):** sanitized captured SSE sequences (`docs/provider-evidence/`) replayed adapter-ის parser-ში → parsed events byte-exact match expected `StreamEvent` sequences-თან (plain, tool-call, thinking/`reasoning_content`, error-path ვარიანტები); `docs/provider-evidence/README.md` — manual opt-in live smoke procedure: 3-call sequence (plain, tool-call, error-path) real endpoint-ებზე, archiving convention, refresh rule (provider contract change → adapter diff + golden refresh = reviewable change).
- **Expected results:** golden replay deterministically ემთხვევა; adapter parse-ის ცვლილება golden test-ს წითლებს (mutation check); smoke procedure document არსებობს და human-executableა.
- **Verification:** `pytest tests/contract/providers/test_kimi_golden.py tests/contract/providers/test_ollama_golden.py -q` — ყველა მწვანე; mutation check: golden file-ში ერთი event-ის შეცვლა → test fails.
- **Review checkpoint:** ადამიანი ამოწმებს, რომ goldens sanitizedა (no real credentials/user data) და smoke procedure-ი opt-inა (CI-ში არ გადის).
- **Rollback:** `git checkout -- tests/contract/providers/test_kimi_golden.py tests/contract/providers/test_ollama_golden.py docs/provider-evidence/`
- (SPEC §5.5, §23.1 CT)

### T3.14

- **Scope:** Ollama tool-use eval harness — 50-case suite (schema validity, correct tool selection, arg correctness) + §5.3 threshold gate, output `eval_results.json` per model digest.
- **Files:** `src/lsassist/evals/tool_use_suite.py`, `tests/evals/cases/tool_use_50.json`, `tests/evals/test_eval_harness.py`, `tests/evals/test_eval_gate.py`
- **Depends on:** T3.11, T3.04
- **RED (tests first):** `tests/evals/test_eval_harness.py` და `tests/evals/test_eval_gate.py`; ბრძანება: `pytest tests/evals/test_eval_harness.py tests/evals/test_eval_gate.py -q`. იღუპება: harness არ არსებობს.
- **GREEN (implementation):** case corpus `tests/evals/cases/tool_use_50.json` — 50 cases: natural-language task → expected tool (12-tool catalog-დან), expected args schema validity, arg correctness fields; harness იძახებს Ollama adapter-ს model digest-ით (offline mode-ში recorded stub responses determinism-ისთვის; live mode manual opt-in); metrics: `schema_valid_rate`, `correct_tool_selection`; gate: pass iff `schema_valid_rate ≥ 0.95` AND `correct_tool_selection ≥ 0.90`; output `$XDG_DATA_HOME/lsassist/evals/<model_digest>.json` (`eval_results.json` format: model digest, timestamp, per-case results, aggregate metrics, gate verdict); gate unit tests: synthetic scores 0.94/0.95/0.90/0.89 boundary cases.
- **Expected results:** harness synthetic stub-ზე deterministically იძლევა metrics-ს; gate boundary cases სწორია; output JSON schema-valid; T3.11 adapter gate ამ ფაილს კითხულობს (integration assertion).
- **Verification:** `pytest tests/evals/test_eval_harness.py tests/evals/test_eval_gate.py -q` — ყველა მწვანე; manual live run procedure documented `tests/evals/README`-ში (opt-in, archived in `docs/provider-evidence/`).
- **Review checkpoint:** ადამიანი ამოწმებს 50-case corpus-ის დაფარვას (ყველა read-only tool + selection-negative cases) და gate thresholds-ს §5.3-თან.
- **Rollback:** `git checkout -- src/lsassist/evals/ tests/evals/`
- (SPEC §5.3, §23.1 EV, R5)
