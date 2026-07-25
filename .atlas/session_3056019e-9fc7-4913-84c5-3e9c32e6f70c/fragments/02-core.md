## Phase 2 — Core TCB (kernel, policy, sandbox)

ეს ფაზა ფარავს TCB-ის სამ პაკეტს — `policy/`, `sandbox/`, `kernel/` — მკაცრად test-first წესით (RED → GREEN), სპეკ-ის §4, §7, §8 მიხედვით. დამოკიდებულება fragment 01-ზე (T1.*): repo bootstrap (`T1.02`, მათ შორის `scripts/loc-count` და pytest/hypothesis/ruff/mypy toolchain), `contracts/` pydantic მოდელები და `config/` XDG layout. Phase 1-ის ID-ები fragment 01-ის საკუთრებაა; აქ მხოლოდ მითითებულია როგორც წინაპირობა.

თანმიმდევრობა ნებითმიერ მომენტში არის: `policy/` → `sandbox/` → `kernel/` — რადგან kernel-ის guards იყენებენ policy-ს კლასიფიკატორს და token service-ს, ხოლო kernel-ის EXECUTE branch-ი იყენებს sandbox profile builder-ს. ყველა pure guard ტესტირდება I/O-ს გარეშე (in-memory registry/policy/budget ობიექტებით).

---

### T2.01 — Policy classes და classification rules R1–R9

- **Scope:** `policy/` პაკეტში ინარჩუნება `PolicyClass` enum-ის გამოყენება contracts-იდან და რეალიზდება დეტერმინისტული, დალაგებული კლასიფიკატორი `classify(request, context) -> PolicyClass` წესებით R1–R9 (first match wins, წესები მხოლოდ აწიათებენ კლასს), სადაც R9 არის §9.4-ის skill-ceiling raise.
- **Files:** `src/lsassist/policy/__init__.py`, `src/lsassist/policy/classes.py`, `src/lsassist/policy/rules.py`, `tests/unit/policy/test_rules.py`
- **Depends on:** T1.02 (bootstrap), T1.04 (contracts — `PolicyClass`, `ToolManifest`, `ToolResult` მოდელები), T1.11 (contracts — `ToolRequest`, `PolicyContext` მათ შორის `skill_ceiling` და `untrusted_turn` ველებით, `IntentRecord`, sandbox `Profile`)
- **RED (tests first):** `tests/unit/policy/test_rules.py` — ცხრილის ფორმის ტესტები თითო წესზე: R1 manifest ceiling (args-dependent წესი ვერ დაუწევებს კლასს); R2 workspace-გარე write → CONFIRM_EXACT; R3 `untrusted_turn=True` + non-AUTO_READ → CONFIRM_EXACT; R4 `proc.exec` argv მეტასიმბოლოიანი data token-ებით → CONFIRM_EXACT; R5 argv[0] `rm`/`systemctl`/`curl` → CONFIRM_EXACT, `sudo` → DENY_ALWAYS; R6 allowlist-გარე domain → CONFIRM_EXACT; R7 write `.git/` internals-ში → DENY_ALWAYS; R8 memory durable write provenance=model → CONFIRM_ONCE; R9 skill-ceiling raise (§9.4): `skill_provenance`-იანი request + `context.skill_ceiling=CONFIRM_EXACT` → შედეგი მინიმუმ CONFIRM_EXACT (ceiling-ზე დაბალი კლასი აკრძალული); ceiling-ში ჯდება → უცვლელი; `skill_ceiling` absent (skill-ის გარეშე) → ცვლილება არა. ბრძანება: `pytest tests/unit/policy/test_rules.py -q` — ჩავარდება, რადგან `lsassist.policy.rules` არ არსებობს (ImportError).
- **GREEN (implementation):** `classes.py` — class ordering helper (`AUTO_READ < AUTO_SCOPED_WRITE < CONFIRM_ONCE < CONFIRM_EXACT < DENY_ALWAYS`) და `raise_to(a, b)`; `rules.py` — ordered rule list, თითო წესი pure ფუნქცია `(request, context) -> PolicyClass | None`, კომპოზიცია `classify()`-ში first-match-wins სემანტიკით, monotonicity assert-ით (წესი ვერ დააბრუნებს manifest ceiling-ზე დაბალ კლასს). R9: request-ს აქვს `skill_provenance` და `context.skill_ceiling` set-ია → `raise_to(result, context.skill_ceiling)` enforcement path (skill manifest-ის `permission_class_max` აქედან აღემართება policy-ს — skill-ების მხარე, fragment 04 T4.12, ამ hook-ს მოიხმარს, ახალი policy logic იქ არ იწერება). არანაირი I/O — მხოლოდ contracts მოდელებზე ოპერაცია.
- **Expected results:** `pytest tests/unit/policy/test_rules.py -q` მწვანე; თითო R1–R9 წესზე მინიმუმ 3 პოზიტიური/ნეგატიური შემთხვევა; `mypy --strict src/lsassist/policy` სუფთა.
- **Verification:** `pytest tests/unit/policy -q`; `mypy --strict src/lsassist/policy`; `ruff check src/lsassist/policy`; coverage `src/lsassist/policy` = 100% branch (`pytest --cov=lsassist.policy --cov-branch --cov-report=term-missing`).
- **Review checkpoint:** ადამიანი ამოწმებს, რომ წესების რიგითობა და კლასების raise-only სემანტიკა ზუსტად ემთხვევა §7.2-ს — განსაკუთრებით R1 ceiling-ი, R3 untrusted-turn override-ი და R9 skill-ceiling raise-ი (§9.4: skill-ის turn-ში წარმოშობილი request ceiling-ს აღემატება → raise/BLOCKED).
- **Rollback:** `git rm -r src/lsassist/policy tests/unit/policy` (ან `git checkout -- .` თუ commit-მდეა); დამოკიდებული შემდგომი task-ები ჯერ არ დაწყებულა, შედეგებზე გავლენა არ აქვს. (SPEC §7.1–7.2, §9.4)

---

### T2.02 — DENY_ALWAYS list და canonicalization (realpath fail-closed, env digest, action_hash)

- **Scope:** რეალიზდება kernel-enforced DENY_ALWAYS path pattern-ების მატჩერი canonicalized path-ებზე და pure canonicalization მოდული: realpath + per-component lstat (fail-closed), env allowlist digest, `action_hash` გამოთვლა.
- **Files:** `src/lsassist/policy/denylist.py`, `src/lsassist/policy/canonical.py`, `tests/unit/policy/test_denylist.py`, `tests/unit/policy/test_canonical.py`, `tests/property/policy/test_canonicalization.py`
- **Depends on:** T2.01
- **RED (tests first):** `tests/unit/policy/test_denylist.py` — თითო §7.3 pattern-ზე მატჩის ტესტი (`~/.ssh/**`, `~/.gnupg/**`, `~/.kimi-code/**`, `**/.env`, `**/.env.*`, `~/.aws/**`, `~/.config/gh/**`, `/etc/shadow`, `/etc/sudoers*`, block devices, audit/policy store, kernel secret) + ნეგატიური შემთხვევები (`.env.example` task-scoped — ნებადართული). `tests/unit/policy/test_canonical.py` — symlink resolve, dangling path fail-closed (გარდა create-intent in-scope parent-ისა), `..` traversal, env digest დეტერმინისტულობა. `tests/property/policy/test_canonicalization.py` — **Hypothesis property: adversarial path inputs (symlink chains, unicode, `..`, long paths) არასდროს განსხვავდება კლასიფიკაციაში canonical form-გარეთ შეყვანილი ექვივალენტური path-ისგან** (§23.1 PT). ბრძანებები: `pytest tests/unit/policy/test_denylist.py tests/unit/policy/test_canonical.py -q` და `pytest tests/property/policy/test_canonicalization.py -q` — ჩავარდება ImportError-ით.
- **GREEN (implementation):** `canonical.py` — `canonicalize(path, intent) -> CanonicalPath` (os.path.realpath + per-component lstat loop, symlink resolve, dangling → typed error `canonicalization_failed` create-intent შემთხვევის გარდა), `env_digest(allowlist_env) -> str` (sorted key=value sha256), `action_hash(tool, args_normalized, canonical_paths, cwd_real, env_digest) -> str`. `denylist.py` — compiled pattern list §7.3-დან, `deny_match(canonical_path) -> bool`; მატჩი მხოლოდ canonicalized input-ზე (raw path-ზე მუშაობა type-level არ არის შესაძლებელი). ორივე მოდული pure-დან იწყებს API-ს; lstat გამოძახება მხოლოდ canonicalize-ში, რაც ტესტებში tmp_path-ით მოდელირდება — სხვა ლოგიკა pure.
- **Expected results:** ორივე unit ფაილი მწვანე; property test 200+ generated case-ზე მწვანე (`--hypothesis-profile=ci`); DENY_ALWAYS თითო pattern-ი მოცემულია ტესტით.
- **Verification:** `pytest tests/unit/policy tests/property/policy/test_canonicalization.py -q`; `mypy --strict src/lsassist/policy`; coverage 100% branch `canonical.py`/`denylist.py`-ზე.
- **Review checkpoint:** ადამიანი შეადარებს denylist pattern-ებს §7.3-ის სიას ერთი-ერთზე (გამოტოვებული pattern = blocking finding) და შეამოწმებს, რომ `classify()` R2/R7 გზები იყენებენ `canonicalize` + `deny_match`-ს fail-closed რეჟიმში.
- **Rollback:** `git rm src/lsassist/policy/denylist.py src/lsassist/policy/canonical.py tests/unit/policy/test_denylist.py tests/unit/policy/test_canonical.py tests/property/policy/test_canonicalization.py`; `rules.py`-ში canonicalization გამოძახება განვითარების ამ ეტაპზე მხოლოდ T2.02-ის integration line-ია — საჭიროებისამებრად revert. (SPEC §7.3, §7.5, §23.1)

---

### T2.03 — HMAC approval token service (mint/verify)

- **Scope:** რეალიზდება session-scoped HMAC token service: canonical record-ის აგება, mint (`HMAC_SHA256(kernel_secret, canonical_json(record))`), verify (TTL, uses, action_hash compare, use counter increment).
- **Files:** `src/lsassist/policy/token.py`, `tests/unit/policy/test_token.py`, `tests/property/policy/test_token_forgery.py`
- **Depends on:** T2.02 (საჭიროებს `canonicalize`, `env_digest`, `action_hash`), T1.05 (`contracts/approval.py` — `ApprovalRecord` და ერთადერთი `canonical_json()`)
- **RED (tests first):** `tests/unit/policy/test_token.py` — mint/verify roundtrip; TTL expiry → invalid; `max_uses` გადაჭარბება → invalid; args-ის ერთი ბაიტის შეცვლა → `action_hash` mismatch → invalid; `class` field-ის მუტაცია → invalid; canonical JSON დეტერმინისტულობა — token-ის HMAC input ზუსტად T1.05-ის `canonical_json(record)` bytes-ია (key order, separators მოდის contracts-იდან, აქ არაფერი სერიალიზდება თავისით). `tests/property/policy/test_token_forgery.py` — **Hypothesis property: token forgery/mutation rejection — არბიტრარული მუტაცია record-ის ნებისმიერ field-ში (hex corruption, field swap, TTL გაზრდა, uses reset) არასდროს verify-დება** (§23.1 PT). ბრძანებები: `pytest tests/unit/policy/test_token.py -q`, `pytest tests/property/policy/test_token_forgery.py -q` — ImportError.
- **GREEN (implementation):** `token.py` — `TokenService(kernel_secret: bytes)` კლასი: `mint(record: ApprovalRecord) -> ApprovalToken` (uuid4 token_id, `issued_at`, HMAC input = `canonical_json(record)` T1.05-იდან — **verbatim reuse, ამ task-ში საკუთარი serializer არ იწერება: მეორე canonical serialization path-ის არსებობა T-12 token forgery class-ია**, HMAC hex), `verify(token, recomputed_record, now) -> TokenVerdict` (recompute action_hash, compare digest `hmac.compare_digest`-ით, TTL check, uses check + increment kernel-side store-ში — in-memory dict V1-ში). Secret ფაილიდან მოდის `config/` resolver-იდან (T1.09 kernel_secret provisioning), token service იღებს მას როგორც bytes — fs წვდომა ამ პაკეტში არ არის.
- **Expected results:** ყველა ტესტი მწვანე; timing-საფრთხის გამო compare მხოლოდ `hmac.compare_digest`; property test 200+ case მწვანე.
- **Verification:** `pytest tests/unit/policy tests/property/policy -q`; `mypy --strict src/lsassist/policy`; coverage 100% branch `token.py`-ზე.
- **Review checkpoint:** ადამიანი ამოწმებს record schema-ს შესაბამისობას §7.4-სთან (ყველა field: token_id, session_id, tool, args_normalized, canonical_paths, cwd_real, env_digest, action_hash, max_uses, ttl_s, issued_at, class) და რომ display-renderer-ის input ეს record იქნება (CLI ფაზაში), არა მოდელის ტექსტი.
- **Rollback:** `git rm src/lsassist/policy/token.py tests/unit/policy/test_token.py tests/property/policy/test_token_forgery.py`; kernel task-ები ჯერ არ მოითხოვს token-ს, გავლენა არ აქვს. (SPEC §7.4, ADR-006, I5)

---

### T2.04 — Re-canonicalization და invalidation vectors (TOCTOU chain, policy მხარე)

- **Scope:** რეალიზდება pre-exec re-canonicalization ლოგიკა policy მხარეს: token-ში შენახული canonical paths + parent dir inode-ის ხელახლა resolve/compare, material change → token invalid (I6); session-scoped "remember" (`max_uses=∞`, ttl=session end) იგივე exact binding-ით.
- **Files:** `src/lsassist/policy/recheck.py`, `tests/unit/policy/test_recheck.py`, `tests/property/policy/test_invalidation.py`
- **Depends on:** T2.03
- **RED (tests first):** `tests/unit/policy/test_recheck.py` — tmp_path-ზე: approve → path-ის symlink retarget → re-check fail (invalid); approve → file content შეცვლა path ცვლილების გარეშე → path-level re-check OK (content change არ არის path-level invalidator; handler მხარე §7.5-4 არის tools ფაზა); parent dir inode swap (rename + recreate) → invalid; session-remember token ttl=session end სწორად იქცევა. `tests/property/policy/test_invalidation.py` — **Hypothesis property: არბიტრარული fs mutation sequence canonical path-ებზე (symlink swap, parent rename, dangling) — re-check-ის შედეგი ყოველთვის ან exact-match valid ან invalid; შუალედური "stale-but-valid" მდგომარეობა არ არსებობს**. ბრძანებები: `pytest tests/unit/policy/test_recheck.py -q`, `pytest tests/property/policy/test_invalidation.py -q` — ImportError.
- **GREEN (implementation):** `recheck.py` — `recheck_token(token, fs_view) -> RecheckVerdict`: თითო canonical path-ისთვის realpath + parent `os.stat` inode compare token-ის snapshot-თან; mismatch ან dangling (create-intent გარდა) → `TokenInvalid(reason)`; ყველა match → valid. `fs_view` არის thin protocol (exists/realpath/stat) — pure ლოგიკა ტესტირდება fake fs_view-თი I/O-ს გარეშე; რეალური adapter tmp_path ტესტებში.
- **Expected results:** invalidation ტესტები მწვანე; property test 200+ case; `max_uses=∞` მხოლოდ ttl=session end-თან ერთად დასაშვები (სხვა კომბინაცია → ტესტირებული უარყოფა).
- **Verification:** `pytest tests/unit/policy tests/property/policy -q`; `mypy --strict src/lsassist/policy`; coverage 100% branch `recheck.py`-ზე.
- **Review checkpoint:** ადამიანი ამოწმებს §7.5-ის 8-პუნქტიან ჯაჭვთან mapping-ს: რომელი პუნქტები ფარავს ეს task (1–3), რომელი tools/sandbox ფაზები (4–7) და რომელიც სტრუქტურულია (8 — no shell, უკვე გარანტირებული ADR-010-ით).
- **Rollback:** `git rm src/lsassist/policy/recheck.py tests/unit/policy/test_recheck.py tests/property/policy/test_invalidation.py`. (SPEC §7.5, I6, ADR-006)

---

### T2.05 — Pure bwrap profile builder (profiles `ro` და `ws`) + env allowlist projection

- **Scope:** რეალიზდება pure ფუნქცია `build_argv(tool, args, policy, profile) -> list[str]`, რომელიც აგენერირებს §8.1–8.2-ის ზუსტ bwrap argv-ს (`ro`/`ws` profile-ები) და child env-ის allowlist projection-ს §8.3-ის მიხედვით (env constructed from scratch, არასდროს inherited).
- **Files:** `src/lsassist/sandbox/__init__.py`, `src/lsassist/sandbox/profiles.py`, `src/lsassist/sandbox/env.py`, `tests/unit/sandbox/test_profiles.py`, `tests/unit/sandbox/test_env.py`
- **Depends on:** T1.02 (bootstrap), contracts tasks (fragment 01 — sandbox profile enums); policy T2.01 (profile choice input-ად policy class-იდან მოდის, მაგრამ builder-ი თავად გადაწყვეტილებას არ იღებს — §2.2)
- **RED (tests first):** `tests/unit/sandbox/test_profiles.py` — argv snapshot/structural assertions: `ro` შეიცავს `--unshare-all --die-with-parent --new-session`, `--ro-bind <workspace> <workspace>`, `--tmpfs /tmp`, `--proc /proc`, `--dev /dev`, network namespace off (არავითარი `--share-net`); `ws` განსხვავდება მხოლოდ `--bind <workspace> <workspace>`-ით და `.venv/bin` PATH-ით exists-check-ის დროს; cwd → `--chdir`; secret env name (`LSASSIST_KIMI_API_KEY`) ფიზიკურად არ ჩნდება argv-ში (assert not any). `tests/unit/sandbox/test_env.py` — env projection: მხოლოდ `PATH`, `HOME`, `LANG`, `LC_ALL`, `TERM` + tool-specific (`CI=1`); parent os.environ-ის არბიტრარული key არ გადაეცემა. ბრძანება: `pytest tests/unit/sandbox -q` — ImportError.
- **GREEN (implementation):** `profiles.py` — `Profile` dataclass + `build_argv()` pure builder: bind mount list §8.1-ის მიხედვით, workspace bind mode profile-ის მიხედვით, `.venv/bin` exists-check injection point-ით (pure core-ი იღებს `venv_exists: bool` პარამეტრს — fs check ხდება caller-ში, runner ფაზაში). `env.py` — `project_env(tool_env_spec) -> dict[str, str]` allowlist-იდან from scratch. არანაირი subprocess ამ task-ში.
- **Expected results:** ორივე test ფაილი მწვანე; argv §8.1–8.2-ის template-ებთან ერთი-ერთზე შესადარებელი; secret env არასდროს ჩნდება (canary assertion).
- **Verification:** `pytest tests/unit/sandbox -q`; `mypy --strict src/lsassist/sandbox`; coverage 100% branch `profiles.py`/`env.py`-ზე.
- **Review checkpoint:** ადამიანი შეადარებს გენერირებულ argv-ს §8.1/§8.2-ის ბლოკებს და დაადასტურებს, რომ builder-ი არ იღებს policy გადაწყვეტილებას (§2.2 sandbox-ის აკრძალვა).
- **Rollback:** `git rm -r src/lsassist/sandbox tests/unit/sandbox`. (SPEC §8.1–8.3, ADR-002)

---

### T2.06 — prlimit wrapper და fail-closed bwrap availability

- **Scope:** რეალიზდება prlimit prefix-ის აგება (nproc, nofile, as, cpu=timeout+10) pure builder-ად და bwrap availability probe fail-closed ქცევით: bwrap-ის არარსებობა → typed error `sandbox_unavailable`, არასდროს unsandboxed fallback.
- **Files:** `src/lsassist/sandbox/prlimit.py`, `src/lsassist/sandbox/availability.py`, `tests/unit/sandbox/test_prlimit.py`, `tests/unit/sandbox/test_availability.py`
- **Depends on:** T2.05
- **RED (tests first):** `tests/unit/sandbox/test_prlimit.py` — `prlimit_prefix(timeout_s) -> list[str]` snapshot: `--nproc=256 --nofile=1024 --as=4G --cpu=<timeout+10>`; cpu ყოველთვის timeout+10. `tests/unit/sandbox/test_availability.py` — fake `shutil.which`-ით: bwrap missing → `probe() -> SandboxUnavailable` (typed); bwrap present → Ok; version parse `0.9.0` → Ok, უფრო ძველი → typed error. ბრძანება: `pytest tests/unit/sandbox -q` — ImportError.
- **GREEN (implementation):** `prlimit.py` — pure prefix builder; `availability.py` — `probe(which_fn=shutil.which, run_fn=...)` injectable dependencies-ით, რომ ტესტი I/O-ს გარეშე მუშაობდეს; full argv composition helper `compose_exec_argv(profile, tool_argv, timeout_s) -> list[str]` = prlimit prefix + bwrap argv + `-- <argv>`.
- **Expected results:** ტესტები მწვანე; fail-closed გზა ტესტირებულია (არავითარი code path unsandboxed exec-კენ — ამის არარსებობა grep-ითაც მოწმდება: `grep -r "os.exec\\|subprocess" src/lsassist/sandbox` მხოლოდ availability probe-ში).
- **Verification:** `pytest tests/unit/sandbox -q`; `mypy --strict src/lsassist/sandbox`; coverage 100% branch; `grep -rn "fallback" src/lsassist/sandbox` — ცარიელი.
- **Review checkpoint:** ადამიანი ამოწმებს fail-closed კონტრაქტს §8.3-სთან და რომ runner (tools ფაზა) მიიღებს მხოლოდ `compose_exec_argv`-ის შედეგს.
- **Rollback:** `git rm src/lsassist/sandbox/prlimit.py src/lsassist/sandbox/availability.py tests/unit/sandbox/test_prlimit.py tests/unit/sandbox/test_availability.py`. (SPEC §8.3, ADR-002, I11)

---

### T2.07 — Kernel state machine pure guards-ით

- **Scope:** რეალიზდება §4.1–4.2-ის state machine: states/transitions enum, transition table pure guard ფუნქციებით `(state, request, registry, policy, budget) -> Transition | None`, EXECUTE-ზე შესვლა მხოლოდ AUTO კლასით ან valid token-ით (I15).
- **Files:** `src/lsassist/kernel/__init__.py`, `src/lsassist/kernel/states.py`, `src/lsassist/kernel/machine.py`, `tests/unit/kernel/test_machine.py`, `tests/property/kernel/test_state_machine.py`
- **Depends on:** T2.01 (classify), T2.03 (token verify), contracts tasks (fragment 01)
- **RED (tests first):** `tests/unit/kernel/test_machine.py` — §4.2 ცხრილის თითო row-ზე ტესტი: RECEIVE→CLASSIFY immutable intent_record; POLICY_CHECK→EXECUTE მხოლოდ AUTO კლასით; POLICY_CHECK→APPROVAL CONFIRM კლასებით; APPROVAL→EXECUTE valid token-ით; POLICY_CHECK→BLOCKED DENY_ALWAYS-ზე; VERIFY→PLAN/VERIFY→REPORT შტოები. `tests/property/kernel/test_state_machine.py` — **Hypothesis property (§23.1 PT): arbitrary tool-request sequence-ებზე state machine არასდროს აღწევს EXECUTE-ს POLICY_CHECK-ის გარეშე და არასდროს EXECUTE-ს non-AUTO კლასით valid token-ის გარეშე** (AC-07, I15). ბრძანებები: `pytest tests/unit/kernel/test_machine.py -q`, `pytest tests/property/kernel/test_state_machine.py -q` — ImportError.
- **GREEN (implementation):** `states.py` — `State` enum + terminal pseudo-states `BLOCKED`/`CANCELLED`; `machine.py` — transition table როგორც data (list of `(from, to, guard_fn, side_effect_tag)`), guard-ები pure ფუნქციები; `step(machine_state, event) -> MachineState` — I/O არაა, side effect-ები მხოლოდ tag-ებად ემატება emitted events list-ს (audit writer tools/audit ფაზაში მიაბამს). ყველა guard ტესტირდება in-memory ობიექტებით, I/O-ს გარეშე.
- **Expected results:** ცხრილის 100% row coverage ტესტებში; property test 300+ generated sequence-ზე მწვანე; EXECUTE-ზე შესასვლელი გზები ზუსტად ორი (AUTO, valid token) — სხვა გზა type/property დონეზე შეუძლებელი.
- **Verification:** `pytest tests/unit/kernel tests/property/kernel -q`; `mypy --strict src/lsassist/kernel`; coverage 100% branch `machine.py`-ზე.
- **Review checkpoint:** ადამიანი ადარებს transition table-ს §4.2-ს row-ებს ერთი-ერთზე; განსაკუთრებული ყურადღება POLICY_CHECK→EXECUTE და APPROVAL→EXECUTE guard-ებზე.
- **Rollback:** `git rm -r src/lsassist/kernel tests/unit/kernel tests/property/kernel`. (SPEC §4.1–4.2, I15, AC-07)

---

### T2.08 — Budgets, loop detection, refund rule

- **Scope:** რეალიზდება §4.3-ის per-task budget tracker: `max_tool_calls` (25), `max_plan_revisions` (8), `max_tokens_in+out` (180k), `max_wall_clock` (30 min), `max_output_per_tool` (50KB+20KB), `max_session_tool_calls` (200); action_hash-ზე დაფუძნებული loop detection (3× consecutive identical → halt) და refund rule (failed schema validation არ ხარჯავს tool call budget-ს).
- **Files:** `src/lsassist/kernel/budgets.py`, `src/lsassist/kernel/loopdetect.py`, `tests/unit/kernel/test_budgets.py`, `tests/unit/kernel/test_loopdetect.py`
- **Depends on:** T2.07
- **RED (tests first):** `tests/unit/kernel/test_budgets.py` — თითო budget-ის exhaustion → forced REPORT signal + verdict PARTIAL flag; schema-validation failure → `refund()` აღადგენს counter-ს; session cap → pause signal. `tests/unit/kernel/test_loopdetect.py` — 3× consecutive identical `action_hash` → `loop_detected`; 2× identical + განსხვავებული → reset; non-consecutive identical არ არის loop. ბრძანება: `pytest tests/unit/kernel -q` — ImportError.
- **GREEN (implementation):** `budgets.py` — `BudgetTracker` dataclass pure მეთოდებით (`consume_tool_call()`, `refund_tool_call()`, `consume_tokens(n)`, `tick(now)`, `exhausted() -> BudgetSignal | None`); `loopdetect.py` — `LoopDetector` deque(maxlen=3)-ით action_hash-ებზე, pure. ინტეგრაცია machine.py-ს VERIFY→REPORT guard-თან (budget exhausted → forced REPORT) — ერთი wiring ხაზი.
- **Expected results:** ტესტები მწვანე; exhaustion გზები ყველა 6 budget-ზე დაფარული; refund ტესტირებული.
- **Verification:** `pytest tests/unit/kernel tests/property/kernel -q` (T2.07-ის property test კვლავ მწვანე — wiring არ არღვევს I15); `mypy --strict src/lsassist/kernel`; coverage 100% branch `budgets.py`/`loopdetect.py`-ზე.
- **Review checkpoint:** ადამიანი ამოწმებს default რიცხვებს §4.3-ის ცხრილთან და refund-ის ზუსტ ტრიგერს (მხოლოდ model-side schema error, არა tool execution failure).
- **Rollback:** `git rm src/lsassist/kernel/budgets.py src/lsassist/kernel/loopdetect.py tests/unit/kernel/test_budgets.py tests/unit/kernel/test_loopdetect.py` + machine.py-ში wiring line-ის revert. (SPEC §4.3)

---

### T2.09 — Verdict computation, ExitReason, evidence requirement (I12)

- **Scope:** რეალიზდება §4.5-ის verdict computation pure ფუნქციით: sub-goal status map-იდან VERIFIED/PARTIAL/UNVERIFIED/BLOCKED/CANCELLED, I12 evidence requirement-ის enforcement (VERIFIED მოითხოვს ≥1 evidence ref, type ∈ allowed set), ყოველ REPORT-ზე `ExitReason` (§4.4).
- **Files:** `src/lsassist/kernel/verdict.py`, `tests/unit/kernel/test_verdict.py`
- **Depends on:** T2.08
- **RED (tests first):** `tests/unit/kernel/test_verdict.py` — VERIFIED without evidence → validation error (contracts `Verdict` model ან kernel-level assert); VERIFIED with evidence type ∉ {test_result, exit_code, diff_hash, file_snapshot, command_output_digest} → error; PARTIAL ≥1 sub-goal VERIFIED + explicit rest list; UNVERIFIED missing-evidence list; BLOCKED carries rule id / provider status; თითო `ExitReason` enum value-ზე mapping test (budget_exhausted:tool_calls, loop_detected, policy_blocked:<rule_id>, …). ბრძანება: `pytest tests/unit/kernel/test_verdict.py -q` — ImportError.
- **GREEN (implementation):** `verdict.py` — `compute_verdict(subgoal_statuses, evidence_store, exit_reason) -> Verdict` pure ფუნქცია; I12 guard: თუ computed verdict == VERIFIED და evidence refs არ აკმაყოფილებს → downgrade UNVERIFIED missing-evidence list-ით (fail-closed, არა exception); ExitReason passthrough contracts enum-იდან. REPORT transition-ში wiring (verdict emitted with evidence refs).
- **Expected results:** ტესტები მწვანე; VERIFIED-ზე evidence-less გზა შეუძლებელი property-დონეზე (unit + contracts validation ორივე).
- **Verification:** `pytest tests/unit/kernel -q`; `mypy --strict src/lsassist/kernel`; coverage 100% branch `verdict.py`-ზე.
- **Review checkpoint:** ადამიანი ამოწმებს §4.5-ის ცხრილთან შესაბამისობას და downgrade-ქცევას (VERIFIED→UNVERIFIED fail-closed) — ეს არის I12-ის ერთადერთი დასაშვები განხორციელება.
- **Rollback:** `git rm src/lsassist/kernel/verdict.py tests/unit/kernel/test_verdict.py` + REPORT wiring revert. (SPEC §4.4, §4.5, I12, AC-13)

---

### T2.10 — Idempotency keys და replay protection

- **Scope:** რეალიზდება §4.7: `idempotency_key = HMAC(session_id, task_id, action_hash, seq)` თითო tool request-ზე და replay guard — already-executed `seq` არასდროს მეორდება; partial execution marker-ი (crash mid-exec → human review state).
- **Files:** `src/lsassist/kernel/idempotency.py`, `tests/unit/kernel/test_idempotency.py`, `tests/property/kernel/test_replay.py`
- **Depends on:** T2.09
- **RED (tests first):** `tests/unit/kernel/test_idempotency.py` — key დეტერმინისტულობა იგივე input-ზე, განსხვავება seq-ის ცვლილებაზე; executed seq-ის ხელახლა წარდგენა → `ReplayRejected`; unknown seq resume → fresh action PLAN-დან; non-idempotent tool completed → EXECUTE მოითხოვს fresh token-ს; partial marker → `HumanReviewRequired` state tag. `tests/property/kernel/test_replay.py` — **Hypothesis property: არბიტრარული (seq, key) replay/interleave sequence-ზე ერთი და იგივე seq არასდროს სრულდება ორჯერ; key forgery (wrong HMAC) → reject**. ბრძანებები: `pytest tests/unit/kernel/test_idempotency.py -q`, `pytest tests/property/kernel/test_replay.py -q` — ImportError.
- **GREEN (implementation):** `idempotency.py` — `IdempotencyLedger` (in-memory + journal-backed resume hook — journal integration recovery ფაზაში): `issue_key(session, task, action_hash, seq)`, `register_execution(key, status: pending|completed|partial)`, `check(key, seq) -> ReplayVerdict`. Pure ლოგიკა; persistence contract მხოლოდ `last_seq()` interface-ით.
- **Expected results:** ტესტები მწვანე; property test 200+ case; double-execute შეუძლებელი ledger დონეზე.
- **Verification:** `pytest tests/unit/kernel tests/property/kernel -q`; `mypy --strict src/lsassist/kernel`; coverage 100% branch `idempotency.py`-ზე.
- **Review checkpoint:** ადამიანი ამოწმებს §4.7-ის სამ რეჟიმს (already-executed skip, fresh from PLAN, partial → human review) და non-idempotent fresh-token მოთხოვნას.
- **Rollback:** `git rm src/lsassist/kernel/idempotency.py tests/unit/kernel/test_idempotency.py tests/property/kernel/test_replay.py`. (SPEC §4.7)

---

### T2.11 — Untrusted wrap/defang helper (§4.6 step 1) + untrusted-turn flag propagation (§4.6 step 2)

- **Scope:** რეალიზდება `kernel/untrusted.py` pure მოდული ორი მექანიზმით: (1) §4.6 step 1-ის ერთადერთი wrap/defang helper — `wrap_untrusted(text, source, provenance) -> str` და `defang(text) -> str` — რომელსაც შემდგომი ფაზების producer-ები (T4.08 memory retrieval, T4.12 skill injection, T5.05 coding pipeline, T6.01 redteam runner) მოიხმარენ import-ით; (2) §4.6 step 2-ის capability reduction — `untrusted_turn=True` flag-ის დაყენება ახალი untrusted injection-ის აღმოჩენაზე და გავრცელება POLICY_CHECK-მდე (R3).
- **Files:** `src/lsassist/kernel/untrusted.py`, `tests/unit/kernel/test_untrusted.py`, `tests/unit/kernel/test_wrap_untrusted.py`, `tests/property/kernel/test_untrusted_capability.py`, `tests/property/kernel/test_wrap_defang.py`
- **Depends on:** T1.11 (`PolicyContext.untrusted_turn` ველი), T2.09 (R3-ის integration-ი policy rules-თან უკვე T2.01-შია; ეს task აკავშირებს flag-ის source-ს)
- **RED (tests first):** `tests/unit/kernel/test_wrap_untrusted.py` — `wrap_untrusted("body", "tool:fs.read", "model")` აბრუნებს `<<<UNTRUSTED_DATA id="<16 hex>" source="…" provenance="…">>` … `<<<END_UNTRUSTED_DATA <იგივე id>>>` ფორმს; id არის random 8-byte hex (`secrets.token_hex(8)`) — ორი გამოძახება იგივე input-ზე → განსხვავებული id; `source`/`provenance` verbatim ხვდება attributes-ში; embedded `<<<UNTRUSTED_DATA`-ის მსგავსი და `<<<END_UNTRUSTED_DATA`-ის მსგავსი strings body-ში → defanged insert-მდე (wrapped output-ში inner marker აღარ ematch-ება real delimiter pattern-ს). `tests/property/kernel/test_wrap_defang.py` — **Hypothesis property: arbitrary text-ზე delimiter injection attempts-ით (embedded markers, nested markers, unicode, NUL/RTL control chars) wrapped output-ში ზუსტად ერთი valid opening/closing delimiter წყვილია (outer) და არცერთი inner substring არ ემთხვევა real delimiter regex-ს; defang idempotent-ია (`defang(defang(x)) == defang(x)`)**. `tests/unit/kernel/test_untrusted.py` — turn შეიცავს ახალ untrusted block-ს action-requesting ტექსტით → `untrusted_turn=True`; heuristic: user direct instruction quote-ი → flag არ ბლოკავს (მაგრამ R3 მაინც მუშაობს non-read-ზე, ხდება CONFIRM_EXACT, არა auto); flag reset შემდეგ სუფთა turn-ზე. `tests/property/kernel/test_untrusted_capability.py` — **Hypothesis property: arbitrary (turn content, tool request) წყვილებზე, სადაც turn untrusted-ია, kernel არასდროს გასცემს AUTO გადაწყვეტილებას non-AUTO_READ მოთხოვნაზე** (I7). ბრძანებები: `pytest tests/unit/kernel/test_untrusted.py tests/unit/kernel/test_wrap_untrusted.py -q`, `pytest tests/property/kernel/test_untrusted_capability.py tests/property/kernel/test_wrap_defang.py -q` — ImportError.
- **GREEN (implementation):** `untrusted.py` — pure მოდული (არანაირი I/O): `defang(text) -> str` — embedded marker-like strings-ის neutralization insert-მდე (§4.6 step 1; Hermes `_neutralize_delimiters` / OpenClaw `foldMarkerTextWithIndexMap` pattern-ების independent reimplementation); `wrap_untrusted(text, source, provenance) -> str` — `secrets.token_hex(8)` id, `defang()`-გავლილი body, closing tag იგივე id-ით; `TurnTrust` dataclass + `compute_turn_trust(turn_blocks, user_direct_intents) -> TurnTrust` delimiter block metadata-ზე დაფუძნებით; wiring: `PolicyContext.untrusted_turn` შევსება POLICY_CHECK guard-მდე machine.py-ში. ეს მოდული არის მთელს codebase-ში ერთადერთი delimiter producer — T4.08/T4.12/T5.05/T6.01 მოიხმარენ მას import-ით; საკუთარი wrapping/defang იმპლემენტაცია consumer ფაზებში აკრძალულია.
- **Expected results:** ტესტები მწვანე; property test-ები 200+ case-ზე; injection/nested/unicode ვექტორებზე 0 un-defanged inner marker; heuristic boundary დოკუმენტირებულია code comment-ში როგორც signal layer (§2.1), არა boundary.
- **Verification:** `pytest tests/unit/kernel tests/property/kernel -q`; `mypy --strict src/lsassist/kernel`; coverage 100% branch `untrusted.py`-ზე.
- **Review checkpoint:** ადამიანი ამოწმებს, რომ helper pure-ია (არანაირი I/O, მხოლოდ stdlib), id-ები random 8-byte hex-ია თითო wrap-ზე, defang მოქმედებს insert-მდე, flag მხოლოდ აწიათებს კლასს (ვერასდროს დაუწევებს) და რომ honesty პუნქტი §4.6-4 (limit honesty) ასახულია შესაბამის CLI-ფაზის ჩანაწერში fragment 03/04-ისთვის.
- **Rollback:** `git rm src/lsassist/kernel/untrusted.py tests/unit/kernel/test_untrusted.py tests/unit/kernel/test_wrap_untrusted.py tests/property/kernel/test_untrusted_capability.py tests/property/kernel/test_wrap_defang.py` + machine.py wiring revert. (SPEC §4.6 steps 1–2, I7)

---

### T2.12 — TCB LOC checkpoint gate

- **Scope:** CI/dev gate, რომელიც ითვლის TCB LOC-ს (`kernel/`, `policy/`, `sandbox/`, `audit/`, `recovery/`, `config/` secrets resolver, `tools/` dispatcher core) `scripts/loc-count`-ით და ამოწმებს §2.3 budget-ს: target ≤ 6,000, hard stop 8,000 — breach-ზე feature freeze.
- **Files:** `scripts/loc-count` (T1.02-ში აგებული — აქ მხოლოდ config/glue), `scripts/tcb-loc-manifest.txt`, `tests/unit/scripts/test_loc_gate.py`, `.github/workflows/ci.yml` (amendment: `tcb-loc` job-ის დამატება T1.02-ის skeleton-ზე — ფაილის შექმნა ამ task-ის საგანი არაა)
- **Depends on:** T2.11, T1.02 (`scripts/loc-count`)
- **RED (tests first):** `tests/unit/scripts/test_loc_gate.py` — manifest-ში ჩამოთვლილი პაკეტების არსებობა; gate script-ის exit codes: count ≤ 6,000 → pass (exit 0); 6,000 < count ≤ 8,000 → warning exit 0 + stderr notice; count > 8,000 → exit 1; manifest-ში არარსებული TCB ფაილი → exit 1 (manifest drift fail-closed). ბრძანება: `pytest tests/unit/scripts/test_loc_gate.py -q` — ჩავარდება gate config-ის არარსებობის გამო.
- **GREEN (implementation):** `scripts/tcb-loc-manifest.txt` — TCB პაკეტების ზუსტი ჩამონათვალი §2.3-ის მიხედვით; `scripts/loc-count --manifest scripts/tcb-loc-manifest.txt --target 6000 --hard-stop 8000` invocation glue (thin wrapper ან CI step); CI job `tcb-loc` — pull request-ზე blocking. Feature-freeze behavior დოკუმენტირდება პირდაპირ gate output-ში: breach-ზე მისაღებია მხოლოდ LOC-ს შემამცირებელი ან TCB-გარე ცვლილებები, budget-ის მოშვება აკრძალულია (§2.3).
- **Expected results:** `scripts/loc-count` current TCB-ზე (kernel+policy+sandbox) რიცხვს იძლევა ≤ 6,000-ზე ამ ეტაპზე; CI job green; განზრახ hard-stop breach test fixture-ით exit 1.
- **Verification:** `pytest tests/unit/scripts/test_loc_gate.py -q`; manual run: `scripts/loc-count --manifest scripts/tcb-loc-manifest.txt --target 6000 --hard-stop 8000` → exit 0; CI config syntax check (`actionlint` ან `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"`).
- **Review checkpoint:** ადამიანი ამოწმებს manifest-ის შესაბამისობას §2.3 TCB definition-თან (რა შედის / რა არა) და freeze policy-ის ფორმულირებას.
- **Rollback:** `git rm scripts/tcb-loc-manifest.txt tests/unit/scripts/test_loc_gate.py` + CI job-ის revert. (SPEC §2.3, §23.1 CI gates)

---

### T2.13 — Coverage gate: 100% branch kernel/policy/sandbox-ზე CI-ში

- **Scope:** CI config-ში enforce-ია §23.1-ის coverage floor: `src/lsassist/kernel`, `src/lsassist/policy`, `src/lsassist/sandbox` — 100% branch coverage, blocking job.
- **Files:** `.github/workflows/ci.yml` (იგივე T1.02-ის skeleton-ის extension — coverage job-ის დამატება T2.12-ის `tcb-loc` amendment-ის შემდეგ), `pyproject.toml` (coverage config section), `tests/unit/scripts/test_coverage_gate.py`
- **Depends on:** T2.12
- **RED (tests first):** `tests/unit/scripts/test_coverage_gate.py` — pyproject-ში `[tool.coverage]` config არსებობს `branch = true`-ით და `fail_under = 100` TCB scope-ზე; CI yaml შეიცავს coverage job-ს `--cov-fail-under=100`-ით; fixture-ით: coverage config-ის დაქვეითება → ტესტი წითელდება (gate-ის gate). ბრძანება: `pytest tests/unit/scripts/test_coverage_gate.py -q` — ჩავარდება config-ის არარსებობით.
- **GREEN (implementation):** `pyproject.toml`-ში `[tool.coverage.run] branch = true`, `[tool.coverage.report] fail_under = 100`, `include = ["src/lsassist/kernel/*", "src/lsassist/policy/*", "src/lsassist/sandbox/*"]`; CI job: `pytest tests/unit tests/property -q --cov=src/lsassist/kernel --cov=src/lsassist/policy --cov=src/lsassist/sandbox --cov-branch --cov-report=term-missing --cov-fail-under=100`.
- **Expected results:** local run ზუსტად იგივე ბრძანებით exit 0 (100% branch სამივე პაკეტზე — T2.01–T2.11-ის ტესტებით უკვე მიღწეული); CI job green.
- **Verification:** `pytest tests/unit tests/property -q --cov=src/lsassist/kernel --cov=src/lsassist/policy --cov=src/lsassist/sandbox --cov-branch --cov-fail-under=100` → exit 0; `pytest tests/unit/scripts/test_coverage_gate.py -q` green; CI yaml parse valid.
- **Review checkpoint:** ადამიანი ამოწმებს, რომ scope-ში მხოლოდ სამი TCB პაკეტია (audit/recovery თავის ფაზებში შეუერთდება იგივე gate-ს) და რომ `# pragma: no cover` TCB-ში აკრძალულია (grep check gate-ში).
- **Rollback:** `git checkout -- pyproject.toml .github/workflows/ci.yml` + `git rm tests/unit/scripts/test_coverage_gate.py`. (SPEC §23.1, §23.2)
