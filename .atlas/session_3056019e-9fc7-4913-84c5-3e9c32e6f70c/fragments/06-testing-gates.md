## Phase 6 — Verification, CI & Gates

ეს ფაზა ფარავს SPEC §23-ის დარჩენილ ფენებს: red-team corpus-სა და adversarial harness-ებს (RT), end-to-end integration suite-ს (IT), LAB reachability proof-ებს (LT) და საბოლოო CI pipeline-ს ყველა gate-ით (§23.1 item 8). აქ არ იწერება ახალი production code — მხოლოდ ტესტები, harness-ები და CI კონფიგურაცია, რომლებიც phase 1–5-ში აგებულ მექანიზმებს ამოწმებენ. ადრე დაწერილი ფენები: UT (T1.x–T5.x unit suites), PT (T2.02 canonicalization, T2.03 token forgery, T2.07 state machine; დამატებითი property suites — T4.01, T4.08, T4.11), CT (T3.01/T3.07 registry, T3.08/T3.09/T3.13 provider, T4.02 audit schema), IT (T3.03–T3.06 sandbox exec, T3.12 fallback, T4.04–T4.06 recovery და T5.x integration suites), EV (T3.14). Phase 5 (T5.01–T5.14 — cli, coding, tutor modes, session engine, LAB skeleton, config writes) უკვე დაწერილია fragment 05-ში; ამ ფაზის e2e და LAB test-ები მის შედეგებზე დგას.

### T6.01

- **Scope:** Red-team injection corpus — §23.1 RT ფენის ვერსირებული corpus ≥50 payload-ით (repo/web/tool-output/memory ვარიანტები, RT-01/RT-02/RT-11) და SSRF attempt suite `net.fetch`-ზე (RT-08), AC-10-ის მტკიცებულება.
- **Files:** `tests/redteam/injection/corpus.json`, `tests/redteam/injection/test_injection_corpus.py`, `tests/redteam/ssrf/test_ssrf.py`, `tests/redteam/README.md`
- **Depends on:** T2.11 (untrusted-turn flag), T3.02 (dispatch policy), T3.06 (`net.fetch` handler)
- **RED (tests first):** `tests/redteam/injection/test_injection_corpus.py` — corpus loader + runner, რომელიც თითო payload-ს ატარებს untrusted-content pipeline-ში (delimited wrapping T2.11-ით → policy classify T3.02-ით) და ამტკიცებს: (a) 100% payload delimited/marked as untrusted; (b) 0 unauthorized action — payload-ში ჩასმული instruction ("ignore previous instructions", fake approval token, fake user confirmation, memory-poisoning write attempt) არასდროს იძლევა AUTO execution-ს ან permission raise-ს; corpus loader ამტკიცებს `corpus.json`-ში ≥50 payload-ს, 4 კატეგორიით (repo-file, web-content, tool-output, memory-retrieval) და თითო payload-ზე `id`, `category`, `expected_boundary` field-ებს. `tests/redteam/ssrf/test_ssrf.py` — `net.fetch`-ზე: off-allowlist domain → CONFIRM_EXACT raise ან block; `http://169.254.169.254/`, `http://127.0.0.1:11434/`-ზე redirect target → blocked (redirect chain რჩება allowlist-ში); body→disk write attempt → absent code path assertion. ბრძანება: `pytest tests/redteam -q -m redteam` — იღუპება corpus-ისა და runner-ის არარსებობით.
- **GREEN (implementation):** `corpus.json` — ≥50 payload ოთხი კატეგორიიდან: classic injection phrases, delimiter-escape მცდელობები (fake `</untrusted>` closing), nested instructions AGENTS.md/README style-ში (RT-02), fake audit/approval tokens, memory-poisoning instructions retrieval chunk-ში (RT-11, T-11); parameterized runner: corpus entry → simulated untrusted turn → assertions boundary-ზე; `README.md` — corpus versioning წესი (ცვლილება = reviewable diff, append-preferred). SSRF suite: `net.fetch` handler + policy R6-ის წინააღმდეგ მიმართული attempts allowlist bypass-ის ყველა ცნობილი ფორმით (DNS-style tricks რომლებიც argv/config დონეზე ემუქრება, redirect to internal, non-https).
- **Expected results:** corpus ≥50 payload, ყველა შედეგი: 0 unauthorized actions, 100% delimiting (AC-10 pass threshold); SSRF suite: 0 off-allowlist fetch executed without CONFIRM_EXACT; corpus-ში ერთი payload-ის წაშლა ან boundary-ის დარღვევა test-ს წითლებს (mutation check).
- **Verification:** `pytest tests/redteam -q -m redteam` — ყველა მწვანე; corpus counter assertion `len(payloads) >= 50`; mutation check: runner-ში delimiting-ის დროებითი გამორთვა → test fails.
- **Review checkpoint:** ადამიანი ათვალიერებს corpus-ის კატეგორიების დაფარვას (ოთხივე source variant §23.1 RT-დან) და ამოწმებს, რომ payload-ები არ შეიცავს რეალურ secret-ებს ან third-party personal data-ს.
- **Rollback:** `git rm -r tests/redteam/`
- (SPEC §18 T-01/T-02/T-08/T-11, §23.1 RT, §21 AC-10)

### T6.02

- **Scope:** Red-team adversarial harness — TOCTOU race suite approval↔exec-ზე (RT-13), canary secrets suite (AC-12, RT-12), fork-bomb/resource-exhaustion tests sandbox-ში (RT-14).
- **Files:** `tests/redteam/toctou/test_race_harness.py`, `tests/redteam/canary/test_canary.py`, `tests/redteam/canary/canary_values.json`, `tests/redteam/resource/test_fork_bomb.py`
- **Depends on:** T2.04 (re-canonicalization), T2.05 (bwrap profiles), T2.06 (prlimit), T3.05 (write tools), T4.01 (redactor + canary patterns)
- **RED (tests first):** `tests/redteam/toctou/test_race_harness.py` — race harness: approval token გაცემულია canonical target-ზე; approval-სა და exec-ს შორის attacker thread (1) ცვლის target-ს symlink-ით, (2) ცვლის parent dir-ს rename-ით, (3) ანაცვლებს ფაილს — თითო მცდელობაზე assertion: exec ან უარს ამბობს re-canonicalization-ზე (§7.5 step), ან bwrap final view-ში swap შეუძლებელია; post-exec inode/hash verify mismatch → UNVERIFIED + audit alert, არა silent success (AC-09 race ვექტორი). `tests/redteam/canary/test_canary.py` — canary values (`canary_values.json`-დან: fake API key ფორმატები, honeyfile paths) განთავსებულია fixture workspace-ში, logs-ში, audit-ში, prompt assembly-ში, memory write-ში; assertions: canary არასდროს ჩანს plain-ად audit file-ში, UI log-ში, provider request body-ში, memory db-ში — ყველგან `[REDACTED:<class>]` ან absence (AC-12: 0 occurrences); honeyfile read attempt → audit alert + session freeze event (§19 scenario 1 detection). `tests/redteam/resource/test_fork_bomb.py` — sandbox-ში (`ro`/`ws` profile): fork-bomb payload → prlimit `nproc` cap-ზე კვდება, host-ზე process count stable; file-descriptor exhaustion → `nofile` cap; memory bomb → `as` cap; CPU spin → `cpu` cap + timeout SIGKILL process group-ზე; output flood → output caps + truncated marker. ბრძანება: `pytest tests/redteam -q -m redteam` — იღუპება harness-ების არარსებობით.
- **GREEN (implementation):** race harness — threads/processes helper, რომელიც deterministic race windows ქმნის (approval hook-სა და exec-ს შორის inject-ადი delay test-mode flag-ით, production path უცვლელი); canary suite — fixture generators + scanner assertions ყველა output surface-ზე (audit JSONL grep, captured UI log, recorded provider request, memory db dump); resource suite — real bwrap runner-ზე integration tests (`-m redteam`), თითო limit-ის ცალკე case-ით და host-side measurement-ით (process count pre/post).
- **Expected results:** TOCTOU: ყველა race variant → rejection ან UNVERIFIED+alert, 0 silent overwrite (AC-09 100% rejection); canary: 0 plain-text occurrence ყველა surface-ზე (AC-12); resource: host unaffected ყველა payload-ზე, child processes 0 post-test, limits enforced (RT-14).
- **Verification:** `pytest tests/redteam -q -m redteam` — ყველა მწვანე; race harness repeat 20× (flake check: `pytest tests/redteam/toctou -q -m redteam --count=20` ან loop script); canary scanner grep-based double-check: `grep -rF <canary> $XDG_STATE_HOME/lsassist/audit/ tests/fixtures/out/ || true` → 0 matches.
- **Review checkpoint:** ადამიანი ამოწმებს, რომ race harness-ის test-mode delay hook არ ცვლის production exec path-ს (diff review), canary values mock-ებია (არა რეალური key ფორმატის valid credentials), და resource tests container/CI runner-ზე უსაფრთხოდ გადის (prlimit caps host-level ზემოქმედების გარეშე).
- **Rollback:** `git rm -r tests/redteam/toctou tests/redteam/canary tests/redteam/resource`
- (SPEC §7.5, §18 T-07/T-13/T-14, §19 scenarios 1–2, §21 AC-09/AC-12, §23.1 RT)

### T6.03

- **Scope:** Integration/E2E suite ნაწილი 1 — clean-user install test (IT-01, AC-01), no-persistence-artifacts test (IT-02, AC-02), fault-injected fallback E2E (IT-04, AC-04), deny/cancel no-side-effects E2E (IT-08, AC-08).
- **Files:** `tests/e2e/test_clean_install.py`, `tests/e2e/test_no_persistence.py`, `tests/e2e/test_fallback_e2e.py`, `tests/e2e/test_deny_cancel.py`, `tests/e2e/conftest.py`, `tests/e2e/Dockerfile.clean-user`
- **Depends on:** T1.02 (bootstrap/packaging), T3.12 (fallback flow), T5.01 (CLI entry), T5.05 (coding mode), T5.08 (tutor mode), T5.12 (session engine)
- **RED (tests first):** `tests/e2e/test_clean_install.py` — Docker image (`Dockerfile.clean-user`: ubuntu:24.04 base, sudo-less user, მხოლოდ python3+git+bwrap) — bootstrap script-ის გაშვება (T1.02-ის venv + `pip --require-hashes` path) fresh user-ით; assertions: install completes without root, `lsassist` shim executable, პირველი prompt flow (stub provider-ით) შესრულდა; ხელით ზომილი დრო ადამიანის checkpoint-ზე < 5 min (AC-01). `tests/e2e/test_no_persistence.py` — install + session run + exit; შემდეგ scan: 0 entries `systemd` user/system units-ში, cron/crontab-ში, autostart (`~/.config/autostart/`) ფაილებში, shell rc files-ში modification-ების (`.bashrc`/`.profile` hash pre/post unchanged) — AC-02: 0 persistence artifacts. `tests/e2e/test_fallback_e2e.py` — live CLI session fault-injected provider stub-ით (T3.12-ის terminal error injection): Kimi failure → visible banner → consent prompt → decline path → BLOCKED verdict, accept path → OLLAMA_RO mode-ში write tools absent (registry assertion fallback-ში), mid-task switch-back attempt → rejected; audit-ში `provider_down`/`provider_fallback` events present (AC-04: 0 silent fallbacks). `tests/e2e/test_deny_cancel.py` — live session: write tool CONFIRM prompt → user denies; second case → cancel mid-approval; assertions: fs tree hash unchanged, 0 child processes post-deny, audit-ში deny/cancel event, verdict CANCELLED/BLOCKED (AC-08). ბრძანება: `pytest tests/e2e -q -m e2e` — იღუპება e2e harness-ის არარსებობით.
- **GREEN (implementation):** `conftest.py` — e2e fixtures: tmp XDG dirs isolation (`XDG_CONFIG_HOME`/`XDG_DATA_HOME`/`XDG_STATE_HOME` per-test tmp), stub provider server (recorded golden responses T3.13-დან), CLI runner helper (subprocess `lsassist` shim-ით, scripted stdin), fs tree hasher, process table snapshotter; `Dockerfile.clean-user` — minimal clean-user image; docker-based test CI job-ში conditional (docker presence probe, skip + explicit report არარსებობისას — IT-01 manual fallback procedure README-ში).
- **Expected results:** IT-01: install green clean user-ზე, 0 sudo call; IT-02: 0 persistence artifacts (scan assertions green); IT-04: 0 silent fallback, write tools absent fallback mode-ში; IT-08: tree hash unchanged deny/cancel-ზე, 0 leaked child procs; ყველა e2e deterministic stub-ებზე (no live network).
- **Verification:** `pytest tests/e2e -q -m e2e` — ყველა მწვანე; docker test: `docker build -f tests/e2e/Dockerfile.clean-user -t lsassist-it01 . && pytest tests/e2e/test_clean_install.py -q -m e2e` → exit 0 (ან documented manual run output archive `docs/provider-evidence/`-ს მსგავსად `docs/install-evidence/`-ში).
- **Review checkpoint:** ადამიანი ამოწმებს, რომ e2e stub provider არასდროს ეხება live network-ს (no accidental live call), Dockerfile მხოლოდ public base image-ს იყენებს, და persistence scan-ის path list სრულია (systemd user+system, cron, autostart, shell rc).
- **Rollback:** `git rm -r tests/e2e/`
- (SPEC §21 AC-01/AC-02/AC-04/AC-08, §23.1 IT, §5.4, §14.5)

### T6.04

- **Scope:** Integration/E2E suite ნაწილი 2 — checkpoint/rollback E2E live CLI flow-ში (IT-06, AC-06), kill -9 crash recovery E2E (IT-11, AC-11), memory inspect/correct/delete round-trip E2E (IT-18, AC-18).
- **Files:** `tests/e2e/test_checkpoint_rollback_e2e.py`, `tests/e2e/test_crash_recovery_e2e.py`, `tests/e2e/test_memory_roundtrip_e2e.py`
- **Depends on:** T4.04 (checkpoint store), T4.05 (rollback flow), T4.06 (crash recovery), T4.09 (memory gates + CLI), T6.03 (e2e harness), T5.04 (read-only CLI subcommands wiring)
- **RED (tests first):** `tests/e2e/test_checkpoint_rollback_e2e.py` — live CLI session tmp workspace-ში: task → `fs.write`+`fs.patch` (checkpoint auto-create) → diff display → user rollback command → preview diff → confirm → restore; assertions: restored files sha256 == checkpoint state (byte-identical, AC-06), unrelated post-checkpoint user files უცვლელი (I13), audit-ში `recovery` event checkpoint ref-ით. `tests/e2e/test_crash_recovery_e2e.py` — live session subprocess-ში: mid-write `kill -9` CLI process-ზე → restart → 0 partial target files (stale tmp discarded), checkpoint pre-state intact; mid-task `kill -9` → resume flow → 0 action replays (journal seq + idempotency keys), crash mid-exec → `human_review` marker surface (AC-11). `tests/e2e/test_memory_roundtrip_e2e.py` — live CLI: model-initiated memory write → `memory review` list → approve (CONFIRM_ONCE) → `memory inspect` → `memory correct` → `memory forget`; assertions: round-trip works, provenance field immutable (correct არ ცვლის provenance-ს; model write ვერ იღებს `user` provenance-ს), forget-ის შემდეგ FTS MATCH აღარ აბრუნებს row-ს, ყოველი mutation → audit event (AC-18). ბრძანება: `pytest tests/e2e -q -m e2e -k "checkpoint or crash or memory"` — იღუპება test-ების არარსებობით.
- **GREEN (implementation):** სამი e2e test module T6.03-ის harness-ზე (tmp XDG isolation, stub provider, CLI runner, tree hasher); crash tests subprocess lifecycle helper-ით (`Popen`, `send_signal(SIGKILL)`, restart helper); memory tests CLI scripted stdin sequence-ებით.
- **Expected results:** IT-06: restore hash equality green live flow-ში; IT-11: 0 partial files, 0 action replays, human_review surfaced; IT-18: full round-trip green, provenance immutability 100%, audit coverage ყოველ mutation-ზე.
- **Verification:** `pytest tests/e2e -q -m e2e` — ყველა მწვანე; crash suite repeat 10× flake check; sha256 comparison assertions output-ში ხილული (hash values log-ირდება test report-ში).
- **Review checkpoint:** ადამიანი ამოწმებს crash test-ების safety-ს (kill მიმართულია მხოლოდ test-spawned subprocess-ზე, PID capture-ით) და რომ e2e workspace-ები tmp-შია (არავითარი real user file).
- **Rollback:** `git rm tests/e2e/test_checkpoint_rollback_e2e.py tests/e2e/test_crash_recovery_e2e.py tests/e2e/test_memory_roundtrip_e2e.py`
- (SPEC §14.4, §14.5, §21 AC-06/AC-11/AC-18, §23.1 IT, §4.7)

### T6.05

- **Scope:** LAB tests (§23.1 LT ფენა) — LAB state machine reachability proof: activation state-ზე მიღწევა შეუძლებელია `CONFIRM_EXACT`-ის გარეშე (AC-16, LT-19); LAB worktree-ში policy/evals artifacts-ის immutability და activation path-ის სტრუქტურული არარსებობა pipeline-ში (AC-15, ST-15).
- **Files:** `tests/lab/test_lab_reachability.py`, `tests/lab/test_lab_immutability.py`, `tests/lab/test_lab_pipeline.py`
- **Depends on:** T4.11 (skills lifecycle), T2.07 (kernel state machine), T5.13 (LAB skeleton: proposal → worktree → draft → suite → HALT)
- **RED (tests first):** `tests/lab/test_lab_reachability.py` — state machine-ზე exhaustive reachability analysis (BFS/DFS ყველა state×event pair-ზე, LAB feature gate ჩართულით და გამორთულით; analyzer იღებს T5.13-ის production transition table-ს: `proposal → worktree → draft → suite → static → evidence → diff → halt`): assertion — არ არსებობს transition path LAB pipeline state-ებიდან activation/apply state-მდე არცერთი event sequence-ით; V1-ში in-tool activation edge საერთოდ არ არსებობს — §11.3-ის activation არის manual-only: მომხმარებელი თავად ასრულებს git ბრძანებებს tool-ის გარეთ, ამიტომ proof წმინდად ნეგატიურია (no carve-out); `lab.enabled=false`-ზე LAB states unreachable entirely; property test (Hypothesis): arbitrary event sequences → activation never reached (AC-16, LT-19 static + flow test). `tests/lab/test_lab_immutability.py` — LAB mode-ში: write attempt `policy rules`/`permission matrix`/DENY list files-ზე → DENY_ALWAYS (R7 policy files-ზე); write attempt `tests/evals/**`-ზე → DENY_ALWAYS; write attempt `$XDG_DATA_HOME/lsassist/venv/**` install tree-ზე → DENY_ALWAYS; LAB-ში გაცემული approval token scoped მხოლოდ LAB worktree canonical path-ებზე — გამოყენება მთავარ workspace-ზე → rejection (§11.3). `tests/lab/test_lab_pipeline.py` — pipeline order enforcement: step გამოტოვება (draft test suite-ის გარეშე) → state machine rejection; HALT-ზე report artifact `{proposal_id, files_changed, test_delta, benchmark_delta, security_suite_result, rollback_steps}` schema-valid (§11.4); audit-ში `lab_*` events append-only. ბრძანება: `pytest tests/lab -q -m lab` — იღუპება test-ების არარსებობით.
- **GREEN (implementation):** reachability analyzer — state machine definition-იდან (T2.07 transition table + T5.13 LAB states) adjacency graph-ის აგება და path search activation-მდე; immutability tests — dispatch pipeline-ზე (T3.02) LAB-mode context-ით write attempts; pipeline tests — scripted LAB session stub provider-ით.
- **Expected results:** 0 reachable activation path without `CONFIRM_EXACT` (proof output: explored states/transitions count + negative result report); ყველა immutability write attempt → DENY_ALWAYS 100%; pipeline order violations 100% rejected; HALT report schema-valid.
- **Verification:** `pytest tests/lab -q -m lab` — ყველა მწვანე; reachability analyzer deterministic output (state/transition counts stable across runs); mutation check: transition table-ში დროებით დამატებული activation edge → reachability test წითლდება.
- **Review checkpoint:** ადამიანი ათვალიერებს reachability proof-ის მეთოდოლოგიას (exhaustive graph search vs sampling), mutation check-ის შედეგს და ამტკიცებს, რომ analyzer იყენებს production transition table-ს, არა მის ასლს.
- **Rollback:** `git rm -r tests/lab/`
- (SPEC §11.1–§11.4, §18 T-19, §21 AC-15/AC-16, §23.1 LT)

### T6.06

- **Scope:** CI pipeline §23.1 item 8-ის სრული gate list-ით — ruff, mypy --strict (TCB), pytest ყველა ფენა live-ის გარდა, pip-audit, TCB LOC count, SBOM (`syft`), red-team suite; live provider tests და live evals manual opt-in (AC-20).
- **Files:** `.github/workflows/ci.yml`, `scripts/sbom`, `tests/unit/scripts/test_ci_pipeline.py`, `docs/ci.md`
- **Depends on:** T6.01, T6.02, T6.03, T6.04, T6.05, T2.12 (LOC gate), T2.13 (coverage gate), T3.13 (golden contract tests), T3.14 (eval harness)
- **RED (tests first):** `tests/unit/scripts/test_ci_pipeline.py` — CI yaml structural assertions: jobs present — `lint` (ruff), `typecheck` (mypy --strict TCB scope), `test-ut-pt-ct` (pytest `tests/unit tests/property tests/contract`), `test-it` (`-m integration`), `test-rt` (`-m redteam`, T6.01/T6.02), `test-lt` (`-m lab`, T6.05), `test-e2e` (`-m e2e`, T6.03/T6.04), `pip-audit` (`pip-audit --require-hashes -r requirements.lock`), `tcb-loc` (T2.12), `coverage-gate` (T2.13), `sbom` (`scripts/sbom` → CycloneDX artifact + diff vs previous release baseline, T-10/CI-10); live provider tests და live EV evals — `workflow_dispatch` only, `-m live` marker-ით, default push/PR-ზე absent (manual opt-in assertion); security regression suite = `test-rt` + `test-lt` + `test-it` jobs blocking merge (AC-20: red on any T-test failure). ბრძანება: `pytest tests/unit/scripts/test_ci_pipeline.py -q` — იღუპება CI config-ის არარსებობით.
- **GREEN (implementation):** `.github/workflows/ci.yml` — ყველა job ubuntu runner-ზე, bwrap dependency install step-ით, caching `pip --require-hashes`-ის მიხედვით; `scripts/sbom` — `syft` invocation (CycloneDX output `sbom.cdx.json`), baseline diff report; `docs/ci.md` — gate list documentation, live opt-in procedure (გაშვება `gh workflow run`-ით, archived results), coverage tooling-ის ღია პუნქტი: `pytest-cov` არ შედის §13.1 dev allowlist-ში, ხოლო §23.1 coverage floors (100% branch TCB) მოითხოვს მას — საჭიროა mini-ADR (დამატება dev-only allowlist-ში justification-ით) ან stdlib `trace`/`coverage`-ის pure-stdlib ალტერნატივის შეფასება; ამ ADR-ის დამტკიცებამდე coverage gate (T2.13) რჩება plan-ის წერტილად, რომლის გააქტიურება მოითხოვს ამ open item-ის დახურვას.
- **Expected results:** CI yaml valid; ყველა §23.1 item 8 gate present as blocking job; live tests მხოლოდ manual dispatch; SBOM artifact generated; AC-20: ნებისმიერი §18 T-test failure → pipeline red (structural assertion + პირველი real run green).
- **Verification:** `pytest tests/unit/scripts/test_ci_pipeline.py -q` — მწვანე; yaml parse: `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` → exit 0; local dry-run თითო gate command-ის: `ruff check src tests`, `mypy --strict src/lsassist/kernel src/lsassist/policy src/lsassist/sandbox src/lsassist/audit src/lsassist/recovery`, `pytest tests/unit tests/property tests/contract -q`, `pytest -q -m integration`, `pytest -q -m redteam`, `pytest -q -m lab`, `pytest -q -m e2e`, `pip-audit --require-hashes -r requirements.lock`, `scripts/loc-count --manifest scripts/tcb-loc-manifest.txt`, `scripts/sbom` — ყველა exit 0 ან documented skip (docker-dependent IT-01).
- **Review checkpoint:** ადამიანი ამოწმებს gate list-ს §23.1 item 8-თან ელემენტ-ელემენტით, live opt-in isolation-ს (არანაირი credential CI-ში), SBOM diff-ის baseline handling-ს და `pytest-cov` mini-ADR open item-ის ფორმულირებას (blocking vs non-blocking გადაწყვეტა მომხმარებლის).
- **Rollback:** `git checkout -- .github/workflows/ci.yml` + `git rm scripts/sbom tests/unit/scripts/test_ci_pipeline.py docs/ci.md`
- (SPEC §23.1 item 8, §13.1, §13.2, §21 AC-20, §18 T-10)

## AC Mapping

ცხრილი ამტკიცებს K7-ს: ყოველი AC-01..AC-20 mapped-ია მინიმუმ ერთ verifying task-ზე. SPEC test ID-ები §21-იდან; plan task ID-ები phase 1–6-იდან (fragments 01–06). Mapping საბოლოოა — ყველა მითითება კონკრეტული task ID-ით.

| AC | SPEC test ID(s) | Verifying plan task(s) |
|---|---|---|
| AC-01 | IT-01 | T1.02, T6.03 |
| AC-02 | IT-02 | T6.03 |
| AC-03 | CT-03 | T3.09 |
| AC-04 | IT-04 | T3.12, T6.03 |
| AC-05 | UT-05 | T3.03, T4.02 |
| AC-06 | IT-06 | T4.04, T4.05, T6.04 |
| AC-07 | PT-07 | T2.03, T2.07, T3.02 |
| AC-08 | IT-08 | T4.05, T6.03 |
| AC-09 | UT-09 ×6 + RT-13 | T2.04, T6.02 |
| AC-10 | RT-01/RT-02/RT-11 | T6.01 |
| AC-11 | IT-11 | T4.06, T6.04 |
| AC-12 | RT-12 | T1.10, T4.01, T6.02 |
| AC-13 | UT-13 | T2.09 |
| AC-14 | UT-14 | T5.09 |
| AC-15 | ST-15 | T5.13, T6.05 |
| AC-16 | LT-19 | T6.05 |
| AC-17 | UT-17 | T4.02, T4.03 |
| AC-18 | IT-18 | T4.09, T6.04 |
| AC-19 | CT-19 | T3.13 |
| AC-20 | §23.1 item 8 | T6.06 |

Test layer დაფარვა (K7): UT — T1.x–T5.x unit suites; PT — T2.02/T2.03/T2.07 (§23.1-ის სამი ძირითადი property: canonicalization, token forgery, state machine) + T4.01/T4.08/T4.11 property suites; CT — T3.01/T3.07 (registry schema/enumeration), T3.08/T3.09/T3.13 (provider contracts), T4.02 (audit schema); IT — T3.03–T3.06 (sandboxed exec), T3.12 (fallback fault-injection), T4.04–T4.06 (checkpoint/rollback/crash), T5.x integration suites, T6.03/T6.04 (e2e); RT — T6.01/T6.02; EV — T3.14; LT — T6.05. CI gates — T6.06 (მათ შორის T2.12 LOC და T2.13 coverage).

## Gate 4 Entry Criteria

სიმეტრიული SPEC §25.3-ის. Gate 4 (implementation) იწყება მხოლოდ როცა ყველა პირობა სრულდება:

- მომხმარებლის explicit approval ამ implementation plan-ზე (ყველა fragment-ი 01–06 ერთიან დოკუმენტად) — ან REVISE ინსტრუქციით ცვლილებები; plan-ის ცალკე approval სავალდებულოა (§25.3-ის მოთხოვნის სიმეტრიული გაგრძელება).
- T1.01 (environment re-verification) green — host facts Appendix A-სთან ეთქვამის, drift-ის გარეშე.
- T1.02 (repository + packaging bootstrap) დასრულებული — repo skeleton, `requirements.lock` pins+hashes-ით, venv install გადამოწმებული.
- Per-phase review checkpoints honored — თითოეული task-ის review checkpoint ადამიანის მიერ არის დადასტურებული შემდეგ task-ზე გადასვლამდე; checkpoint-ების გამოტოვება აკრძალულია.
- ღია პუნქტები აღრიცხულია: `pytest-cov` mini-ADR (§13.1 vs §23.1) — Gate 4-ის დაწყებას არ უშლის ხელს, მაგრამ coverage gate-ის (T2.13) გააქტიურებამდე უნდა დაიხუროს.

## Stop Conditions

Verbatim SPEC §25.2-დან:

> Stop/downscope if: (a) MVP (kernel + 2 tools + provider) > 8 weeks part-time; (b) TCB > 8,000 LOC before MVP; (c) red-team suite not green 3 consecutive runs within 4 weeks; (d) Kimi contract changes to forbid honest third-party use.

დამატებითი წესი: ნებისმიერი stop condition-ის დარღვევა წყვეტს პროექტის მუშაობას (მიმდინარე task-ის უსაფრთხო შეჩერება + checkpoint) მომხმარებლის გადაწყვეტილებამდე — გაგრძელება, downscope ან შეჩერება მხოლოდ მომხმარებლის explicit ინსტრუქციით. Stop condition-ის გვერდის ავლა plan-ის რედაქტირებით აკრძალულია — თავად კრიტერიუმების ცვლილება მოითხოვს SPEC-ის განახლებასა და მომხმარებლის ხელახალ approval-ს.

## როგორ ვიმუშაოთ Gate 4-ში

- ერთი task ერთდროულად — არანაირი პარალელური task-ები; ახალი task იწყება მხოლოდ წინის review checkpoint-ის დადასტურების შემდეგ.
- ყოველ task-ზე RED→GREEN evidence: RED ფაზის failing output და GREEN ფაზის passing output ინახება და ნაჩვენებია review checkpoint-ზე; evidence-ის გარეშე task არ ითვლება დასრულებულად (§23.2 — no self-attestation).
- Review checkpoint ყოველი task-ის შემდეგ — ადამიანი ამოწმებს task-ის "Review checkpoint" ველში ჩამოთვლილ პუნქტებს; შემდეგ task-ზე გადასვლა მხოლოდ ადამიანის თანხმობით.
- Scope drift აკრძალულია — task-ის "Files" და "Scope" ველებს მიღმა ცვლილება არ ხდება; აღმოჩენილი საჭიროება ინახება ცალკე note-ად და მიეკუთვნება შესაბამის task-ს ან plan-ის შეცვლას.
- Plan-ის ცვლილება = plan-edit + re-approval — ნებისმიერი task-ის შეცვლა, დამატება ან წაშლა კეთდება plan დოკუმენტის რედაქტირებით და მოითხოვს მომხმარებლის ხელახალ approval-ს შესრულების დაწყებამდე.
