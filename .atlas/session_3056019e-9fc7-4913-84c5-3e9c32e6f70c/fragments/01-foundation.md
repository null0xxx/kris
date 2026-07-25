# LinuxSec Assistant — Implementation Plan (Gate 3)

- **Version:** 0.1.0-draft
- **Date:** 2026-07-24
- **Status:** GATE 2 APPROVED / GATE 3 APPROVED (მომხმარებლის მიერ, 2026-07-24) / GATE 4 IN PROGRESS
- **Technical specification:** `SPEC.md` (Gate 2, დამტკიცებული 2026-07-24) — ეს plan მხოლოდ SPEC.md-ს ახორციელებს; კონფლიქტის შემთხვევაში SPEC.md უპირატესია.
- **Product contract:** `2026-07-23-personal-linux-ai-assistant-master-prompt.md` (SHA-256 `469c1d7313c8335b59dedbe448a70d173ec516cfef95766990791398ec82f04d`)
- **Gate rule:** SPEC §25.3 — ეს დოკუმენტი მოითხოვს ცალკე explicit approval-ს; production code (Gate 4) იწყება მხოლოდ ამ plan-ის დამტკიცების შემდეგ.

**როგორ კითხვის:** plan შედგება ფაზებისგან; თითო ფაზა — პატარა, მკაცრად sequential task-ებისგან (თითო ≤ ~4 საათი part-time). ყველა task იყენებს §0-ში განსაზღვრულ ერთნაირ schema-ს: ჯერ იწერება მარცხნილი ტესტი (**RED**), შემდეგ იმპლემენტაცია (**GREEN**), შემდეგ ზომადი verification და human review checkpoint. `Depends on` ჯაჭვი არ ირღვება — შემდეგი task არ იწყება წინის checkpoint-ის დამტკიცებამდე. ყველა task მთავრდება SPEC anchor-ით, რომლის მიხედვითაც იგი იწერება.

---

## 0. Task schema

ყოველი task ამ plan-ში იყენებს ზუსტად ამ ცხრილს, ამ ველებით და ამ რიგით:

| ველი | მნიშვნელობა |
|---|---|
| **Scope:** | ერთი წინადადება — რას აკეთებს task და რას არა. |
| **Files:** | ზუსტი path-ები repo root-იდან (`lsassist/`); ახალი თუ შეცვლილი. |
| **Depends on:** | `none` ან explicit task ID-ები; ჯაჭვი მკაცრად sequential-ია. |
| **RED (tests first):** | ზუსტი test ფაილები + ზუსტი pytest command; რა უნდა დაიმარცხოს და რატომ. იმპლემენტაცია RED-ის გარეშე აკრძალულია. |
| **GREEN (implementation):** | რა იწერება RED-ის გასამწვანებლად (მოკლე; სრული კოდი არა — ეს plan-ია, არა code). |
| **Expected results:** | ზომადი შედეგი (test count, coverage, artifact). |
| **Verification:** | ზუსტი command-ები + pass criteria (მაგ. `mypy --strict` clean, ტესტები green). |
| **Review checkpoint:** | რას ამოწმებს ადამიანი შემდეგი task-ის დაწყებამდე. |
| **Rollback:** | ზუსტი ნაბიჯები task-ის გაუქმებისთვის (repo git-initialized-ია T1.02-დან). |

Task-ის ბოლოს SPEC anchor `(SPEC §x.y, Iz)` აჩვენებს საფუძველს. რომელიმე ველი თუ განუსაზღვრელია, task ვერ ითვლება დასრულებულად.

**Execution order (topological, not phase-order):** plan-ის build order არის `Depends on` graph-ის topological order. Phase ნომრები (T1…T6) მხოლოდ authoring grouping-ია, არა execution sequence — ამიტომ cross-phase `Depends on` edges ლეგიტიმურია და ნორმალური (მაგ. ზოგი T3 task დამოკიდებულია T4 producer-ზე, როგორიცაა T4.01-ის redactor; T4 task-ები — T1/T2-ზე). სავალდებულოა მხოლოდ: dependency task-ის Review checkpoint-ის დამტკიცება შემდეგი task-ის დაწყებამდე. Strict phase-order კითხვა ("ჯერ ყველა T1, შემდეგ ყველა T2…") არ არის საჭირო და არ უნდა მოვა cross-phase edge-ებთან კონფლიქტში.

---

## Phase 1 — Foundation

ამ ფაზის მიზანი: გარემოს ხელახალი შემოწმება (read-only), repository-სა და packaging-ის bootstrap SPEC §22 / ADR-005-ის მიხედვით, და ორი საფუძვლური პაკეტი — `contracts/` (ყველა data contract, რომელზეც დანარჩენი ფაზები დგას) და `config/` (XDG layout, canary honeyfiles, config schema, secrets resolution, redaction pattern data — თავად redactor engine `audit/`-შია, fragment 04 T4.01). Production logic ამ ფაზაში მხოლოდ contracts/config-ის ტიპების დონეზე; kernel, policy, tools, providers — შემდგომი ფაზების საგანია.

### T1.01 — Environment re-verification (read-only, Gate 0-style)

**Scope:** Appendix A-ს host fact-ების ხელახალი შემოწმება მხოლოდ read-only command-ებით, სანამ რაიმე დაიწერება; drift-ზე plan ჩერდება.

**Files:** არცერთი repo ფაილი (repo ჯერ არ არსებობს); transcript ინახება `/tmp/lsassist-env-gate3.txt`-ში და commit-დება T1.02-ში `docs/env-verification-gate3.md`-ად.

**Depends on:** none

**RED (tests first):** ტესტი აქ არის თავად assertion block — იგი მარცხდება, თუ რომელიმე fact Appendix A-ს აღარ ემთხვევა (სწორედ ეს არის მისი დანიშნულება; drift = halt):

```bash
set -euo pipefail
exec > >(tee /tmp/lsassist-env-gate3.txt) 2>&1
uname -r                                            # მოსალოდნელი: 7.0.0-28-generic
python3 --version                                   # მოსალოდნელი: Python >= 3.12 (host: 3.12.3)
bwrap --version                                     # მოსალოდნელი: bubblewrap >= 0.9.0
[ "$(sysctl -n kernel.unprivileged_userns_clone)" = "1" ]
[ "$(sysctl -n user.max_user_namespaces)" -gt 0 ]   # host: 112429
bwrap --unshare-all --die-with-parent --new-session \
  --ro-bind /usr /usr -- true                       # functional userns probe; write-ების გარეშე
curl -fsS http://127.0.0.1:11434/api/version        # მოსალოდნელი: {"version":"0.30.6",...}
ldconfig -p | grep -q libsecret-1                   # libsecret runtime არსებობს (ADR-004)
git --version                                       # მოსალოდნელი: >= 2.43
for d in "${XDG_CONFIG_HOME:-$HOME/.config}" \
         "${XDG_DATA_HOME:-$HOME/.local/share}" \
         "${XDG_STATE_HOME:-$HOME/.local/state}" \
         "${XDG_CACHE_HOME:-$HOME/.cache}"; do
  [ -w "$d" ] || { echo "NOT WRITABLE: $d"; exit 1; }
done
command -v uv >/dev/null && echo "uv present (optional fast-path)" || echo "uv absent — venv path (ADR-005)"
command -v pipx >/dev/null && echo "pipx present" || echo "pipx absent (open question §25.1.1 resolved)"
```

pytest ამ ეტაპზე ჯერ არ არსებობს (venv T1.02-ში იქმნება) — assertion shell script-ია; fail-დება პირველივე drifted fact-ზე non-zero exit-ით.

**GREEN (implementation):** კოდი არ იწერება; მხოლოდ ზედმეტი command block-ის გაშვება და transcript-ის შენახვა. თითოეული შედეგი ფიქსირდება Appendix A-ს გვერდით (match / drift).

**Expected results:** ყველა assertion PASS (exit 0); `/tmp/lsassist-env-gate3.txt` შეიცავს სრულ transcript-ს; `pipx`-ის ყოფნა/არარსებობა ხურავს open question §25.1.1-ს.

**Verification:** `echo $?` = 0 assertion block-ის შემდეგ; transcript-ში `uname`, `python3`, `bwrap`, ollama version, userns მნიშვნელობები, libsecret, git, XDG writability — ყველა ხელით შედარებული Appendix A-სთან. Pass criteria: 0 drift; ნებისმიერი drift → task FAIL, plan შეჩერდება SPEC update-მდე.

**Review checkpoint:** ადამიანი კითხულობს transcript-ს და ადასტურებს, რომ Gate 1 fact-ები ძალაშია; განსაკუთრებით: bwrap probe წარმატებულია (T1.02+ და Phase-ის sandbox task-ები ამაზე დგას) და libsecret ხელმისაწვდომია (T1.09-ის წინაპირობა).

**Rollback:** არაფერი საჭიროებს rollback-ს — task არ ქმნის და არ ცვლის ფაილებს; სურვილისამებრ: `rm -f /tmp/lsassist-env-gate3.txt`.

(SPEC Appendix A, ADR-002, ADR-004, ADR-005, §25.1)

### T1.02 — Repository + packaging bootstrap

**Scope:** repo layout SPEC §22-ის მიხედვით, git init, `pyproject.toml`, `requirements.lock` pins+hashes-ით (§13.1), venv + `pip --require-hashes` install (ADR-005), shim, dev tooling config (pytest, hypothesis, mypy, ruff), `scripts/loc-count` TCB budget-ისთვის; production code არ იწერება.

**Files:** `lsassist/pyproject.toml`, `lsassist/requirements.lock`, `lsassist/requirements-dev.lock`, `lsassist/README.md`, `lsassist/.gitignore`, `lsassist/src/lsassist/__init__.py`, `lsassist/src/lsassist/__main__.py` (version-print stub მხოლოდ), `lsassist/src/lsassist/{contracts,kernel,policy,tools,sandbox,providers,memory,skills,audit,recovery,config,tutor,coding,cli}/__init__.py` (ცარიელი package markers), `lsassist/tests/{unit,property,contract,integration,e2e,redteam,evals}/__init__.py`, `lsassist/tests/unit/test_repo_layout.py`, `lsassist/scripts/loc-count`, `lsassist/scripts/verify-env.sh`, `lsassist/docs/env-verification-gate3.md`, `lsassist/.github/workflows/ci.yml` (minimal CI skeleton); repo-ს გარეთ: `~/.local/share/lsassist/venv/`, `~/.local/bin/lsassist`.

**Depends on:** T1.01

**RED (tests first):** `lsassist/tests/unit/test_repo_layout.py` — ამტკიცებს: (1) §22-ის ყველა package directory + `__init__.py` არსებობს; (2) `pyproject.toml` parse-დება და შეიცავს `requires-python = ">=3.12"`; (3) `scripts/loc-count` executable-ია და empty tree-ზე `0`-ს აბრუნებს; (4) `.github/workflows/ci.yml` არსებობს, valid YAML-ია და შეიცავს სამ job placeholder-ს: `ruff`, `unit` (pytest tests/unit), `loc-count`. Command: `python3 -m pytest tests/unit/test_repo_layout.py -q` — მარცხდება collection error-ით, რადგან repo structure ჯერ არ არსებობს.

**GREEN (implementation):** `mkdir lsassist && cd lsassist && git init`; ცარიელი package tree §22-ის მიხედვით; `pyproject.toml` (setuptools, src layout, `[project.scripts] lsassist = "lsassist.__main__:main"`, `[tool.pytest.ini_options]`, `[tool.mypy]` — `strict = true` მხოლოდ TCB module-ებზე (`lsassist.kernel`, `lsassist.policy`, `lsassist.sandbox`, `lsassist.audit`, `lsassist.recovery`, `lsassist.config`, `lsassist.contracts`), `[tool.ruff]`); runtime lock: `httpx`, `pydantic`, `jsonschema`, `prompt_toolkit`, `rich`, `secretstorage` — hashes-ის გენერაცია `pip download -r requirements.in -d /tmp/wheels && pip hash /tmp/wheels/*.whl`-ით, ჩაწერა `requirements.lock`-ში `--hash=sha256:...` ეntry-ებად; dev lock: `pytest`, `hypothesis`, `mypy`, `ruff`, `pip-audit`, `syft`; venv: `python3 -m venv ~/.local/share/lsassist/venv && ~/.local/share/lsassist/venv/bin/pip install --require-hashes -r requirements.lock -r requirements-dev.lock && ~/.local/share/lsassist/venv/bin/pip install -e . --no-deps`; shim `~/.local/bin/lsassist` (exec venv python `-m lsassist`; სანამ cli/ არ არსებობს, `__main__.py` ბეჭდავს version-ს და "not installed yet"-ს); `scripts/verify-env.sh` = T1.01-ის assertion block + transcript `docs/env-verification-gate3.md`-ად commit-ით; `scripts/loc-count` — stdlib-only python script: ითვლის non-blank, non-comment LOC-ს TCB package-ებში (§2.3 list) და ბეჭდავს ჯამს vs budget (6,000 warn / 8,000 fail, exit 1 ზღვარზე); `.github/workflows/ci.yml` — minimal skeleton (`on: [push, pull_request]`; სამი job: `ruff` = `ruff check src tests`, `unit` = `pytest tests/unit -q`, `loc-count` = `scripts/loc-count`; venv dependency cache-ით) — T2.12/T2.13 (fragment 02) და fragment 06-ის CI task-ები ამ ფაილს აფართოებენ, skeleton იქმნება აქ.

**Expected results:** `test_repo_layout.py` green; venv შეიცავს მხოლოდ §13.1 allowlist-ს (`pip freeze` ემთხვევა lock-ს); `pip install --require-hashes` მეორე გაშვებაზე no-op-ია (reproducible); `scripts/loc-count` გამოაქვს `TCB LOC: 0 / 6000 (hard stop 8000)`.

**Verification:** `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/test_repo_layout.py -q` green; `~/.local/share/lsassist/venv/bin/python -m mypy --version && ~/.local/share/lsassist/venv/bin/ruff --version` მუშაობს; hash tamper test: ერთი hash-ის ხელით შეცვლა lock-ში → install fail-დება (supply-chain გარანტია, T-10); `git log --oneline | wc -l` ≥ 1 (initial commit). Pass criteria: ყველა green, tamper test fail-დება install-ზე.

**Review checkpoint:** ადამიანი ამოწმებს: (1) lock-ში მხოლოდ §13.1 deps-ია, არაფერი ზედმეტი; (2) mypy strict scope ზუსტად TCB-ზეა; (3) `loc-count` output სწორია; (4) **open item:** branch-coverage tooling (`coverage.py`/`pytest-cov`) §13.1-ში არ არის — საჭიროებს mini-ADR-ს Phase 6-მდე; მანამდე verification = tests green + mypy strict.

**Rollback:** `rm -rf lsassist ~/.local/share/lsassist/venv ~/.local/bin/lsassist` — სრული წაშლა; T1.01-ის transcript უვნებელია `/tmp`-ში.

(SPEC §22, §13.1, §13.2, §2.3, ADR-005)

### T1.03 — contracts/: enums, Verdict, evidence rules

**Scope:** `contracts/` package-ის ბირთვი — `PermissionClass`, `ExitReason` (§4.4), `EvidenceType`, `Evidence`, `Verdict` pydantic model-ებით, I12 validator-ით (VERIFIED მოითხოვს ≥1 evidence-ს დასაშვი ტიპით).

**Files:** `lsassist/src/lsassist/contracts/__init__.py`, `lsassist/src/lsassist/contracts/enums.py`, `lsassist/src/lsassist/contracts/verdict.py`, `lsassist/tests/unit/contracts/__init__.py`, `lsassist/tests/unit/contracts/test_enums.py`, `lsassist/tests/unit/contracts/test_verdict.py`

**Depends on:** T1.02

**RED (tests first):** `tests/unit/contracts/test_enums.py` — `ExitReason`-ის ყველა member ზუსტად §4.4 list-იდან (`completed`, `budget_exhausted:*`, `loop_detected`, `policy_blocked:*`, `approval_denied`, `approval_timeout`, `provider_unavailable:*`, `malformed_model_output`, `user_cancelled`, `verification_failed`, `grounding_failed`); parameterized ტესტი თითო value-ზე. `tests/unit/contracts/test_verdict.py` — (1) `Verdict(status="VERIFIED", evidence_refs=[])` → `ValidationError`; (2) VERIFIED evidence-ით, რომლის `type` ∉ {`test_result`, `exit_code`, `diff_hash`, `file_snapshot`, `command_output_digest`} → `ValidationError`; (3) VERIFIED valid evidence-ით → ok; (4) `UNVERIFIED` მოითხოვს `missing_evidence` list-ს; (5) `BLOCKED` მოითხოვს `rule_id` ან `provider_status`-ს; (6) `CANCELLED`/`PARTIAL` შესაბამისი წესებით (§4.5 ცხრილი). Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/contracts/ -q` — მარცხდება `ModuleNotFoundError: lsassist.contracts`-ით.

**GREEN (implementation):** `enums.py`: `PermissionClass` (§6.2 enum), `ExitReason` (str enum, `:`-იანი ვარიანტები prefix+parameter pattern-ით — ცალკე `policy_rule_id`/`provider` field-ებით model-ში, არა enum value-ში), `EvidenceType`, `VerdictStatus`. `verdict.py`: `Evidence` (type, ref, digest) და `Verdict` pydantic model-ები `model_validator`-ით, რომელიც enforce-ავს §4.5-ის თითო row-ს და I12-ს (evidence-less VERIFIED შექმნა შეუძლებელია — AC-13-ის საფუძველი).

**Expected results:** ორივე test file green; ≥12 test case; `Verdict` model-ი უარს ამბობს ყველა invalid კომბინაციაზე.

**Verification:** `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/contracts/ -q` green; `~/.local/share/lsassist/venv/bin/python -m mypy --strict src/lsassist/contracts` clean; `~/.local/share/lsassist/venv/bin/ruff check src/lsassist/contracts` clean; `scripts/loc-count` განახლებული ჯამით. Pass criteria: ყველა command exit 0.

**Review checkpoint:** ადამიანი ადარებს `ExitReason` members-ს §4.4-ს და Verdict validator-ის თითო branch-ს §4.5-ის ცხრილს — contract-ის ნებისმიერი გადახრა აქ ყველა შემდგომ ფაზაზე ვრცელდება.

**Rollback:** `git checkout -- src/lsassist/contracts tests/unit/contracts` (ან ფაილების წაშლა, თუ ჯერ uncommitted-ია: `rm -rf src/lsassist/contracts/{enums,verdict}.py tests/unit/contracts`).

(SPEC §4.4, §4.5, I12, AC-13)

### T1.04 — contracts/: ToolManifest + ToolResult

**Scope:** `ToolManifest` pydantic model + მისი JSON Schema export (§6.2-ის verbatim schema) და `ToolResult` model (§6.5) — tool registry-ისა და dispatcher-ის (Phase 3) data foundation.

**Files:** `lsassist/src/lsassist/contracts/manifest.py`, `lsassist/src/lsassist/contracts/tool_result.py`, `lsassist/schemas/tool-manifest.schema.json` (generated artifact), `lsassist/tests/unit/contracts/test_manifest.py`, `lsassist/tests/unit/contracts/test_tool_result.py`

**Depends on:** T1.03

**RED (tests first):** `test_manifest.py` — (1) minimal valid manifest (§6.2 required ყველა field) parse-დება; (2) თითო required field-ის დაკარგვა → `ValidationError` (parameterized, 15 case); (3) `name` pattern violation (`Fs.Read`, `1bad`) → error; (4) `additionalProperties: false` — უცნობი field → error; (5) `output_limits.max_stdout_bytes > 1048576` → error (§6.2 cap); (6) generated JSON schema file ტოლია SPEC §6.2-ის schema-ს (canonical diff, I4); (7) `redaction` items მხოლოდ დასაშვები enum-დან. `test_tool_result.py` — (1) valid `ToolResult` (§6.5 example) round-trip; (2) `status="error"` მოითხოვს `error.kind`-ს; (3) digest field-ები `sha256:` prefix-ით validated; (4) `exit_code` integer bounds. Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/contracts/test_manifest.py tests/unit/contracts/test_tool_result.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `manifest.py`: `ToolManifest` (ყველა §6.2 field, `model_config = ConfigDict(extra="forbid")`), `Capabilities` და `OutputLimits` sub-models; `export_manifest_schema(path)` helper, რომელიც `model_json_schema()`-ს ინახავს `schemas/tool-manifest.schema.json`-ად და test-ში შედარება SPEC-ის canonical version-თან ხდება. `tool_result.py`: `ToolResult`, `ToolError`, digest fields `Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]`-ით.

**Expected results:** ≥25 test case green; `schemas/tool-manifest.schema.json` დაგენერირებული და SPEC §6.2-თან შესაბამისი; schema regeneration deterministic-ია (ორივე გაშვება იგივე bytes).

**Verification:** pytest command green; `mypy --strict src/lsassist/contracts` clean; `python -c "import json; json.load(open('schemas/tool-manifest.schema.json'))"` valid JSON; schema-vs-SPEC diff test green. Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ხელით ადარებს generated schema-ს SPEC §6.2 code block-ს (required list, patterns, caps, enums) — ეს schema I4-ის enforcement-ია და Phase 3-ის registry test-ები მასზე დგას.

**Rollback:** `git checkout -- src/lsassist/contracts/manifest.py src/lsassist/contracts/tool_result.py schemas tests/unit/contracts/test_manifest.py tests/unit/contracts/test_tool_result.py` (ან `rm` uncommitted ფაილებზე).

(SPEC §6.2, §6.5, I4)

### T1.05 — contracts/: ApprovalRecord canonical form + BudgetState

**Scope:** `ApprovalRecord` model §7.4-ის ზუსტი field-ებით + `policy_note`/`rollback_hint` display field-ები (§7.1 classification-ის annotation) + deterministic `canonical_json()` serialization (HMAC input — Phase 2-ის token service ამას იყენებს) და `BudgetState` model §4.3-ის budget table-ით.

**Files:** `lsassist/src/lsassist/contracts/approval.py`, `lsassist/src/lsassist/contracts/budget.py`, `lsassist/tests/unit/contracts/test_approval.py`, `lsassist/tests/unit/contracts/test_budget.py`

**Depends on:** T1.04

**RED (tests first):** `test_approval.py` — (1) §7.4-ის example record parse-დება; (2) `canonical_json()` deterministic-ია: key order, no whitespace, unicode escape — იგივე record ორჯერ → byte-identical; (3) ნებისმიერი field-ის mutation (args, path, cwd, ttl, max_uses) → canonical bytes იცვლება (I5/I6 binding-ის საფუძველი; 6 vector, AC-09-ის წინაპირობა); (4) `max_uses ≥ 1`, `ttl_s > 0`; (5) `class` მხოლოდ `CONFIRM_ONCE`/`CONFIRM_EXACT` (token-ი არასდროს AUTO კლასზე); (6) `policy_note` და `rollback_hint` field-ები არსებობს (default `""`), შედის `canonical_json()`-ში (display = record, §7.4) — თითოეულის mutation canonical bytes-ს ცვლის. `test_budget.py` — (1) defaults ზუსტად §4.3 (`max_tool_calls=25`, `max_plan_revisions=8`, `max_tokens=180_000`, `max_wall_clock_s=1800`, `max_output_per_tool=(50_000, 20_000)`, `max_session_tool_calls=200`); (2) `consume(tool_calls=1)` ზღვარზე → `budget_exhausted` flag შესაბამისი kind-ით; (3) refund rule: schema-validation failure არ ამცირებს `max_tool_calls`-ს (§4.3). Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/contracts/test_approval.py tests/unit/contracts/test_budget.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `approval.py`: `ApprovalRecord` pydantic model (§7.4 field-ები + `policy_note: str = ""` და `rollback_hint: str = ""` — populate ხდება classify/dispatch time-ზე T3.02-ში §7.1-ის კლასის მიხედვით [risk line = policy rule reference, rollback hint], render — T5.03 approval box-ში; ორივე canonical form-ის ნაწილია, რომ user-visible prompt ზუსტად approved record-ი იყოს; `token_id` uuid4, `issued_at` UTC ISO-8601) + `canonical_json()` — `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=True)`-ის ზედა thin wrapper ერთადერთ canonical form-ად (მთელს codebase-ში მხოლოდ ეს ფუნქცია გამოიყენება HMAC input-ისთვის — token mint/verify Phase 2-ში). `budget.py`: `BudgetState` frozen-defaults model + pure `consume`/`refund`/`is_exhausted` methods (I/O გარეშე, §2.2 contracts-ის წესით stdlib+pydantic only).

**Expected results:** ≥20 test case green; canonical form byte-stable ორ გაშვებას შორის; mutation vectors ყველა detectable-ია.

**Verification:** pytest command green; `mypy --strict src/lsassist/contracts` clean; determinism check: `python -c "..."` ორჯერ გაშვებული canonical_json SHA-256 იგივე. Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს `ApprovalRecord` field list-ს §7.4-სთან ერთი-ერთში და თანხმდება, რომ canonicalization ერთადერთი წერტილია — მეორე serialization path-ის არსებობა token forgery class-ია (T-12).

**Rollback:** `git checkout -- src/lsassist/contracts/approval.py src/lsassist/contracts/budget.py tests/unit/contracts/test_approval.py tests/unit/contracts/test_budget.py` (ან `rm` uncommitted ფაილებზე).

(SPEC §7.4, §7.1, §4.3, I5, I6)

### T1.06 — contracts/: ProviderProfile, StreamEvent, ProviderError

**Scope:** provider-neutral contract-ები §5.1-ის ცხრილით — `ModelCapabilities`, `StreamEvent`, `ProviderError`, `AssistantTurn`, `UsageAccounting`, `Health`, `ProviderProfile` (typing Protocol); adapter-ების აკრძალვების type-level საფუძველი.

**Files:** `lsassist/src/lsassist/contracts/provider.py`, `lsassist/tests/unit/contracts/test_provider.py`

**Depends on:** T1.05

**RED (tests first):** `test_provider.py` — (1) `ModelCapabilities` ყველა §5.1 field-ით; unknown field conservative-default-ად `false` (extra fields ignored→false); (2) `StreamEvent` discriminator: `text_delta | tool_call_delta | reasoning_delta | usage | error | done` — invalid kind → error; (3) `ProviderError.kind` enum: `auth|quota|rate_limit|overload|transient|client|terminated`; unmapped → `transient, retryable=True` default constructor helper (safe side, §5.1); (4) `ProviderError.terminal=True` აკრძალვა `retryable=True`-თან კომბინაციაში (validator); (5) `AssistantTurn.reasoning_opaque` field არსებობს, მაგრამ `repr`/serialization-ში არ გამოდის (I16-ის საფუძველი: audit-ში ჩაწერა შეუძლებელი უნდა იყოს — `model_dump(exclude=...)` default); (6) `ProviderProfile` Protocol structural check: dummy class, რომელსაც `stream_chat` აკლია, `isinstance`/runtime-checkable check-ზე ვერ გადის. Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/contracts/test_provider.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `provider.py`: ზედმეტი model-ები §5.1 ცხრილის ერთი-ერთში; `StreamEvent` discriminated union (`Literal` kinds); `ProviderError.normalize_unmapped()` classmethod (transient/retryable default); `reasoning_opaque` — `Field(exclude=True)` (I16); `ProviderProfile` — `typing.Protocol` + `@runtime_checkable` მეთოდებით: `id`, `capabilities`, `stream_chat`, `complete_tool_request`, `normalize_error`, `usage`, `healthcheck`.

**Expected results:** ≥15 test case green; Protocol check მუშაობს positive და negative მაგალითზე; `model_dump()` არასდროს შეიცავს `reasoning_opaque`-ს.

**Verification:** pytest command green; `mypy --strict src/lsassist/contracts` clean; static check: `grep -rn "subprocess\|os.open" src/lsassist/contracts/provider.py` — ცარიელი (I1-ის adapter-side prelude). Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ადარებს model field-ებს §5.1 ცხრილს და ადასტურებს `reasoning_opaque`-ის exclusion-ს (I16) — Phase 3-ის kimi/ollama adapter-ები ამ contract-ს implement-ავენ.

**Rollback:** `git checkout -- src/lsassist/contracts/provider.py tests/unit/contracts/test_provider.py` (ან `rm` uncommitted ფაილებზე).

(SPEC §5.1, I16, I1)

### T1.11 — contracts/: ToolRequest, PolicyContext, IntentRecord, sandbox Profile

**Scope:** policy (T2.01) და dispatcher (T3.02) contract-ების დამატება `contracts/`-ში — `ToolRequest` (მოდელის tool call request), `PolicyContext` (classification context, `skill_ceiling` field-ით §9.4-ის მიხედვით), `IntentRecord` (§16.2: `{text, digest, ts}` immutable) და sandbox `Profile` enum (`ro`, `ws` — §8).

**Files:** `lsassist/src/lsassist/contracts/tool_request.py`, `lsassist/src/lsassist/contracts/policy_context.py`, `lsassist/src/lsassist/contracts/intent.py`, `lsassist/src/lsassist/contracts/sandbox_profile.py`, `lsassist/tests/unit/contracts/test_tool_request.py`, `lsassist/tests/unit/contracts/test_policy_context.py`, `lsassist/tests/unit/contracts/test_intent.py`, `lsassist/tests/unit/contracts/test_sandbox_profile.py`

**Depends on:** T1.04

**RED (tests first):** `test_tool_request.py` — (1) valid `ToolRequest` (`call_id`, `tool` §6.2 name pattern-ით, `args` object) parse-დება; (2) `tool` name pattern violation (`Fs.Read`, `1bad`) → `ValidationError`; (3) `args` default `{}`; (4) unknown field → error (`extra="forbid"`). `test_policy_context.py` — (1) fields: `workspace_root` (canonical absolute path), `untrusted_turn: bool = False` (§4.6/R3), `skill_ceiling: PermissionClass | None = None` (§9.4 — active skill-ის `permission_class_max`; set-ზე skill turn-ის classification ceiling); (2) relative/non-canonical `workspace_root` → validation error; (3) `skill_ceiling` მხოლოდ `PermissionClass` member-ია ან `None`. `test_intent.py` — (1) `IntentRecord{text, digest, ts}` — `digest` = `sha256:`-prefixed canonical text hash; (2) frozen model: ნებისმიერი field-ის mutation attempt → `ValidationError` (§16.2 immutable; every plan references digest); (3) digest helper deterministic-ია (იგივე text → იგივე digest ორ გაშვებაზე). `test_sandbox_profile.py` — (1) `Profile` enum-ის members ზუსტად `ro` და `ws` (§8.1/§8.2; `ws-net` V1-ში არ არსებობს — §8.2/§20); (2) lowercase str values. Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/contracts/test_tool_request.py tests/unit/contracts/test_policy_context.py tests/unit/contracts/test_intent.py tests/unit/contracts/test_sandbox_profile.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `tool_request.py`: `ToolRequest` frozen pydantic model (`call_id: str`, `tool: str` §6.2 name pattern-ით, `args: dict` default empty, `extra="forbid"`) — dispatcher-ის (T3.02) input contract. `policy_context.py`: `PolicyContext` — `workspace_root` canonical-path validator-ით (resolve + must be absolute), `untrusted_turn`, `skill_ceiling` (§9.4 injection rules: ceiling-ს აღმატებული request → raise/BLOCKED — enforcement T2.01-ში, type აქ). `intent.py`: `IntentRecord` frozen model `{text, digest, ts}` + `make_intent(text) -> IntentRecord` (digest = `sha256:` + sha256(canonical text), `ts` = UTC ISO-8601) — coding mode-ის (T5.06) intent capture ამას იყენებს. `sandbox_profile.py`: `Profile(str, Enum)` — `RO = "ro"`, `WS = "ws"` (§8); sandbox builder (T2.04) მხოლოდ ამ enum-ს იღებს.

**Expected results:** ≥15 test case green; ოთხივე model `contracts/` package-ში stdlib+pydantic only (§2.2); T2.01/T3.02-ის contract import-ები აღარ არის დაბლოკილი.

**Verification:** pytest command green; `~/.local/share/lsassist/venv/bin/python -m mypy --strict src/lsassist/contracts` clean; `ruff check src/lsassist/contracts` clean; static: `grep -n "subprocess\|os\.open\|httpx" src/lsassist/contracts/tool_request.py src/lsassist/contracts/policy_context.py src/lsassist/contracts/intent.py src/lsassist/contracts/sandbox_profile.py` — ცარიელი (§2.2 contracts rule). Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) `PolicyContext.skill_ceiling` ზუსტად §9.4-ის ceiling semantics-ს შეესაბამება (type-level აქ, enforcement policy/-ში); (2) `IntentRecord` მართლა immutable-ა და digest plan binding-ისთვის გამოსაყენებელია (§16.2); (3) `Profile` enum-ში მხოლოდ V1 profiles (`ro`, `ws`) — `ws-net` გამორიცხულია §20 non-goal-ით.

**Rollback:** `git checkout -- src/lsassist/contracts/tool_request.py src/lsassist/contracts/policy_context.py src/lsassist/contracts/intent.py src/lsassist/contracts/sandbox_profile.py tests/unit/contracts/test_tool_request.py tests/unit/contracts/test_policy_context.py tests/unit/contracts/test_intent.py tests/unit/contracts/test_sandbox_profile.py` (ან `rm` uncommitted ფაილებზე).

(SPEC §6.2, §7.1, §8, §9.4, §16.2, §2.2)

### T1.07 — config/: XDG layout, permissions, startup checks

**Scope:** XDG directory resolution და §12.1-ის ცხრილის enforce-მენტი — შექმნა mode-ებით (dir 0700 / file 0600), startup ownership + symlink fail-closed checks; plus canary honeyfile provisioning install/first-run-ზე (§19 scenario 1).

**Files:** `lsassist/src/lsassist/config/__init__.py`, `lsassist/src/lsassist/config/xdg.py`, `lsassist/src/lsassist/config/canary.py`, `lsassist/tests/unit/config/__init__.py`, `lsassist/tests/unit/config/test_xdg.py`, `lsassist/tests/unit/config/test_canary.py`

**Depends on:** T1.06

**RED (tests first):** `test_xdg.py` (tmp_path + monkeypatched `XDG_*` env): (1) default fallback-ები `~/.config`/`~/.local/share`/`~/.local/state`/`~/.cache` როცა env არ არის set; (2) `ensure_layout()` ქმნის §12.1-ის ყველა directory-ს ზუსტი mode-ით (`secrets/` 0700, `skills/` 0700, `audit/` 0700, `checkpoints/` 0700, cache 0700; `evals/` 0644); (3) არსებული directory loose permissions-ით (მაგ. 0755 secrets/) → შესწორება ან fail policy-ით (ცხრილი: "at most as listed"); (4) symlink რომელიმე layout path-ზე → typed error `ConfigSecurityError`, fail-closed (არაფერი იქმნება symlink-ის მიღმა); (5) directory owned by სხვა uid → `ConfigSecurityError`; (6) `kernel.secret` path-ის expected mode 0600 declarative table-ში; (7) `test_canary.py` (§19 scenario 1): (a) `provision_canaries()` ქმნის `$XDG_CONFIG_HOME/lsassist/canary/` (dir 0700) fake-credential decoy ფაილებით (decoy API key, fake AWS-style credentials, fake private-key block — ყველა synthetic, განზრახ invalid) თითო 0600 mode-ით; (b) idempotency — მეორე გაშვება no-op-ია (file digests unchanged); (c) `canary_registry()` აბრუნებს თითო honeyfile-ის path + sha256 digest-ს (audit-canary registration — შემდგომი kernel watch და T6.02-ის canary tests ამ registry-ს მოიხმარენ); (d) გარედან შეცვლილი decoy (content tamper) → registry digest mismatch → `ConfigSecurityError` fail-closed; (e) symlink canary dir-ში → `ConfigSecurityError`. Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/config/ -q` — მარცხდება `ModuleNotFoundError: lsassist.config`-ით.

**GREEN (implementation):** `xdg.py`: `XdgPaths` dataclass (resolution ერთ წერტილში), `LAYOUT: list[tuple[relpath, kind, mode]]` declarative ცხრილი §12.1-დან, `ensure_layout(paths) -> None` (create+chmod), `check_security(paths) -> None` (ownership `os.stat().st_uid == os.geteuid()`, `os.path.islink` per component — `lstat`-ით, fail-closed). `canary.py`: `CANARY_HONEYFILES` declarative table (filename, synthetic decoy content — არასდროს რეალური secret), `provision_canaries(paths) -> None` (create `os.open(O_CREAT|O_EXCL|O_NOFOLLOW, 0o600)`-ით, idempotent registry digest check-ით), `canary_registry(paths) -> list[CanaryEntry]` (path + sha256 თითო decoy-ზე — §19 scenario 1 detection-ის data source; decoy read-ზე alert/freeze logic kernel/audit ფენისაა, არა ამ task-ის); `LAYOUT`-ში `canary/` entry (dir 0700). რეალური secret material-ის handling ამ task-ში არ ხდება — decoy-ები განზრახ invalid-ია.

**Expected results:** ≥20 test case green; symlink და ownership attack vectors ორივე fail-closed-ია; layout table ზუსტად §12.1-ის row-ებს შეესაბამება (+ `canary/` §19-დან); canary honeyfiles provisioned და registered.

**Verification:** pytest command green; `mypy --strict src/lsassist/config` clean; manual: `XDG_CONFIG_HOME=$(mktemp -d) python -c "from lsassist.config.xdg import ...; ensure_layout(...)"` შემდეგ `stat -c '%a' <dirs>` ემთხვევა ცხრილს. Pass criteria: ყველა exit 0 + stat match.

**Review checkpoint:** ადამიანი ადარებს `LAYOUT` ცხრილს §12.1-ს row-by-row და symlink test-ის მიდგომას (interior component symlink-იც უნდა იჭერდეს, არა მხოლოდ final) — §7.5-ის კავშირი config სფეროში.

**Rollback:** `git checkout -- src/lsassist/config tests/unit/config` (ან `rm -rf src/lsassist/config tests/unit/config` uncommitted მდგომარეობაში).

(SPEC §12.1, §7.5, §19)

### T1.08 — config/: config schema versioning

**Scope:** `config.toml`/`policy.toml`-ის pydantic schema `config_version = 1`-ით — unknown field → warning + ignored; invalid → refuse to start exact field errors-ით (§12.2).

**Files:** `lsassist/src/lsassist/config/schema.py`, `lsassist/tests/unit/config/test_config_schema.py`

**Depends on:** T1.07

**RED (tests first):** `test_config_schema.py`: (1) minimal valid config (`config_version = 1`) parse-დება defaults-ით; (2) `config_version = 2` → refuse (`ConfigVersionError`, migration არ არსებობს V1-ში); (3) missing `config_version` → refuse; (4) unknown top-level field → parse ok + `warnings` list-ში ერთი entry, field **არ** ინახება model-ში (never silently honored); (5) deprecated field (test fixture) → explicit warning; (6) invalid type (`budgets.max_tool_calls = "abc"`) → refuse exact field path-ით error message-ში; (7) key fields არსებობს: `providers.kimi.{base_url, model, timeout_s}`, `providers.ollama.{endpoint, model, num_ctx}`, `budgets.*`, `net.allowlist[]`, `memory.retention_days`, `lab.enabled` (default `false` — §11.1), `ui.language` (`ka|en`); (8) Ollama `endpoint` allowlist regex-ით validated (`^https?://(127\.0\.0\.1|\[::1\]|localhost)(:\d+)?$`) — remote endpoint → refuse (§5.3). Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/config/test_config_schema.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `schema.py`: `Config` root model + sub-models (`KimiConfig`, `OllamaConfig`, `BudgetsConfig`, `NetConfig`, `MemoryConfig`, `LabConfig`, `UiConfig`); `model_config = ConfigDict(extra="allow")` + `model_validator`-ი, რომელიც extra field-ებს გადაიტანს `warnings`-ში და შლის stored model-დან; `load_config(path) -> Config` (TOML parse stdlib `tomllib`-ით); version gate პირველი check-ი. Ollama endpoint regex §5.3-დან.

**Expected results:** ≥18 test case green; unknown field არასდროს აღწევს runtime-ს warning-ის გარეშე; remote Ollama endpoint შეუძლებელია config-დან.

**Verification:** pytest command green; `mypy --strict src/lsassist/config` clean; `ruff check src/lsassist/config` clean. Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს ორ უსაფრთხოების წერტილს: (1) unknown-field policy "warn+ignore, never fatal, never honored" ზუსტად §12.2-ის ფორმულირებით; (2) `lab.enabled` default `false` და ვერ იცვლება config-ით validation-ის გვერდის ავლით (§11.1).

**Rollback:** `git checkout -- src/lsassist/config/schema.py tests/unit/config/test_config_schema.py` (ან `rm` uncommitted ფაილებზე).

(SPEC §12.2, §5.3, §11.1)

### T1.09 — config/: secrets resolution order

**Scope:** `LSASSIST_KIMI_API_KEY` env → OS keyring (`secretstorage`) → `0600` fallback ფაილი — resolution order ADR-004/§12.3-ით, materialization მხოლოდ memory-ში, fail-closed ქცევები; გარდა ამისა, `kernel_secret` (§7.4): install-time first-run generation + ownership-checked startup load `$XDG_STATE_HOME/lsassist/kernel.secret`-ისთვის — Kimi API-key chain-ისგან სრულიად დამოუკიდებელი.

**Files:** `lsassist/src/lsassist/config/secrets.py`, `lsassist/src/lsassist/config/kernel_secret.py`, `lsassist/tests/unit/config/test_secrets.py`, `lsassist/tests/unit/config/test_kernel_secret.py`

**Depends on:** T1.08

**RED (tests first):** `test_secrets.py`: (1) env var set → env-დან წაკითხვა, keyring/file არ ეხება (order guarantee, fake keyring-ზე access-counter-ით); (2) env არ არის → keyring-დან (fake `secretstorage` backend inject-ით); (3) keyring unavailable (import error / D-Bus absent) → file fallback `$XDG_CONFIG_HOME/lsassist/secrets/kimi-api-key`; (4) fallback file mode `0600`-ზე უფრო loose → refuse; (5) fallback file symlink → refuse; (6) file owned by სხვა uid → refuse; (7) არცერთი source → typed `SecretNotFoundError` first-run wizard hint-ით (არა crash); (8) resolved secret არ ჩნდება: return type `Secret` wrapper, რომლის `repr`/`str` = `[REDACTED:secret]`, value მხოლოდ explicit `.reveal()`-ით (short-lived, §12.3 materialization); (9) resolution არაფერს წერს disk-ზე და არ ლოგავს. `test_kernel_secret.py` (§7.4): (10) first run — `$XDG_STATE_HOME/lsassist/kernel.secret` absent → იქმნება ზუსტად 32 random byte-ით, file mode 0600; (11) generation idempotency — მეორე load იგივე bytes-ს აბრუნებს, regeneration არ ხდება (file digest unchanged); (12) symlink path-ზე → fail-closed `ConfigSecurityError` (§12.1); (13) სხვა uid-ის ownership → fail-closed; (14) mode 0600-ზე loose → fail-closed; (15) length ≠ 32 B → fail-closed; (16) kernel_secret არ გადის Kimi resolver chain-ში — structural: `kernel_secret.py` არ იმპორტებს `secrets.py`-ს. Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/config/test_secrets.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `secrets.py`: `resolve_secret(name) -> Secret` — სამი resolver function ordered list-ით (env, keyring via `secretstorage` lazily imported, file), თითოეული fail-closed check-ებით (T1.07-ის `check_security` reuse file path-ზე); `Secret` wrapper class (no `__str__`/`__repr__` leak); write-side `store_secret(name, value, backend)` მხოლოდ keyring-ში (setup wizard-ისთვის, Phase 5); file write helper mode `0600` + `O_NOFOLLOW`-ით fallback setup-ისთვის. `kernel_secret.py`: `load_or_generate_kernel_secret(paths) -> bytes` — install/first-run generation `secrets.token_bytes(32)`-ით (`os.open(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0o600)`), startup load ownership/mode/symlink/length check-ებით (T1.07 `check_security` reuse, §7.4 "ownership-checked at startup"); env/keyring არ ეხება — kernel-local secret, materializes მხოლოდ kernel memory-ში (Phase 2 token service mint/verify მოიხმარს).

**Expected results:** ≥20 test case green; resolution order ერთი-ერთში ADR-004-სთან; `Secret`-ის accidental stringification შეუძლებელია; `kernel.secret` generation idempotent-ია, mode 0600, symlink/ownership fail-closed.

**Verification:** pytest command green; `mypy --strict src/lsassist/config` clean; static: `grep -n "print\|logging" src/lsassist/config/secrets.py` — არანაირი secret-bearing log call (§2.2 config rule: "logging secrets" აკრძალული). Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) order ზუსტად env→keyring→file; (2) ყველა fallback check (mode/owner/symlink) fail-closed-ია, ვერცერთი "warn and continue" ვერ გაუსვა secret material-ს; (3) `Secret.reveal()` ერთადერთი გასასვლელია — adapter-ები (Phase 3) მხოლოდ ამას გამოიყენებენ.

**Rollback:** `git checkout -- src/lsassist/config/secrets.py tests/unit/config/test_secrets.py` (ან `rm` uncommitted ფაილებზე).

(SPEC §12.3, §7.4, ADR-004, I8)

### T1.10 — config/: redaction pattern data + canary seed corpus

**Scope:** redaction-ის pattern data module §12.4-ით — ordered pattern list (regex source + class label), canary seed corpus, configured-secret exact-match hook — მხოლოდ data, არა engine. თავად redactor engine არის ერთადერთი module `audit/`-ში (§2.2) და მისი მფლობელია fragment 04-ის task T4.01 (`src/lsassist/audit/redactor.py`), რომელიც ამ pattern data-ს მოიხმარს; sink integration (audit/UI/prompt/memory) შემდგომი ფაზების საგანია.

**Files:** `lsassist/src/lsassist/config/redaction_patterns.py`, `lsassist/tests/unit/config/test_redaction.py`, `lsassist/tests/unit/config/canary_corpus.json`

**Depends on:** T1.09

**RED (tests first):** `test_redaction.py` + `canary_corpus.json` (synthetic, არარეალური canary values — AC-12-ის ნაწარმი) — ტესტები pattern data-ზე, არა engine-ზე: (1) pattern table ფარავს §12.4-ის ყველა class-ს: Kimi-format key, `sk-*`, `ghp_*`, `AKIA*`, private key blocks (`-----BEGIN … PRIVATE KEY-----`), configured exact-match hook, DENY-path content hook placeholder; (2) corpus-driven parameterized test: canary corpus-ის თითო entry-ს თავისი class-ის pattern-ი `re.search`-ით ემთხვევა — 100% coverage; (3) false-positive guard entries (normal paths, code snippets, hash strings) არცერთ pattern-ს არ ემთხვევა; (4) ordering invariant: უფრო სპეციფიური pattern (private key block) table-ში generic key-format pattern-ებმდე დგას; (5) `exact_match_pattern(value)` hook — configured secret value-დან `re.escape`-დ literal pattern, რომელიც მხოლოდ იმ value-ს ემთხვევა (regex injection secret value-დან შეუძლებელია; value-ს reveal-ს engine აკეთებს T1.09 `Secret`-იდან); (6) malformed regex source table-ში → `validate_patterns()` fail-closed `RedactionConfigError`-ით (§14.3 fail-closed — engine ამ error-ს digest-only branch-ად გარდაქმნის). Command: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/config/test_redaction.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `redaction_patterns.py`: `RedactionPattern` frozen dataclass `(name, class_label, pattern_src)` — `pattern_src` არაკომპილირებული source string-ია (compilation engine-ის საქმეა); `REDACTION_PATTERNS: tuple[RedactionPattern, ...]` — §12.4-ის ordered list; `CANARY_SEED: tuple[CanaryValue, ...]` — synthetic decoy values + class labels, რომლებიც `canary_corpus.json`-ს ავსებენ; `exact_match_pattern(value: str) -> RedactionPattern` — `re.escape`-ზე დაფუძნებული literal hook configured-secret exact-match-ისთვის; `validate_patterns()` — ყველა `pattern_src` კომპილირდება load time-ზე, failure → `RedactionConfigError`. არანაირი `redact()`/apply/scan ფუნქცია ამ module-ში — engine = T4.01 `audit/redactor.py` (§2.2: redactor = single module `audit/`-ში; `config/` ინახავს მხოლოდ redaction-pattern configuration data-ს).

**Expected results:** corpus 100% pattern coverage; false-positive guard green; ≥12 test case; module-ში 0 apply-engine ფუნქცია.

**Verification:** pytest command green; `mypy --strict src/lsassist/config` clean; static ownership check: `grep -n "def redact\|re\.sub" src/lsassist/config/redaction_patterns.py` — ცარიელი (engine აქ არ ცხოვრობს; T4.01 `audit/redactor.py` consume-ს); `scripts/loc-count` — Phase 1-ის საბოლოო TCB LOC baseline დაფიქსირებული (config package TCB-შია, §2.3). Pass criteria: ყველა exit 0, corpus coverage = 100%.

**Review checkpoint:** ადამიანი ამოწმებს: (1) pattern list ფარავს §12.4-ის ყველა კლასს; (2) canary corpus-ში არანაირი რეალური secret არ არის (მხოლოდ synthetic); (3) ownership boundary დაცულია — აქ მხოლოდ data, engine T4.01-ში; (4) Phase 1 სრულად: T1.01→T1.11 ჯაჭვი green, TCB LOC baseline ცნობილია → Gate 3-ის Phase 1 done, Phase 2 (kernel/policy/sandbox) შეიძლება დაიწყოს.

**Rollback:** `git checkout -- src/lsassist/config/redaction_patterns.py tests/unit/config/test_redaction.py tests/unit/config/canary_corpus.json` (ან `rm` uncommitted ფაილებზე).

(SPEC §12.4, §14.3, §2.2, I8, AC-12)
