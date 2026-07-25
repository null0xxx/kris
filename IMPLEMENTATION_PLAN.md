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


---

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


---

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


---

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


---

## Phase 5 — Modes & CLI (cli, coding, tutor)

ამ ფაზის მიზანი: user-facing ფენა — ჯერ `cli/` (შესვლის წერტილი, session flags, turn rendering, approval prompt renderer, Ctrl+C), შემდეგ `coding/` (intent capture, kernel-ზე დაყრდნობით pipeline, baseline guard I13, bounded fix loop, final report), ბოლოს `tutor/` (EXPLAIN/GUIDED/DO_AND_TEACH, pedagogy contract, sudo escape hatch). ორივე mode render-დება `cli/`-ის output contract-ით (§15.3), ამიტომ `cli/` პირველია. Approval prompt-ის renderer-ის input არის canonical token record (§7.4) — არასდროს მოდელის ტექსტი. `cli/` და mode პაკეტები TCB-ში შედიან მხოლოდ იმ ნაწილით, რაც approval render-ს ეხება — rendering-ის სისწორე სავალდებულოა snapshot test-ებით; ყველა side effect რჩება kernel/policy/tools ფენაში. დამატებით ეს ფაზა ფარავს: T5.12 — kernel session orchestration + prompt assembly (გენერიკული turn engine: input → CLASSIFY → GROUND → PLAN → provider turn, memory/skill/tool-result injection-ით), რომელსაც interactive loop (T5.01) და ორივე mode იყენებს; T5.13 — LAB skeleton (proposal → isolated worktree → draft → suites → evidence → diff+rollback plan → HALT, §11.2, activation path-ის გარეშე); T5.14 — gated config writes (`lab.enabled` activation) + workspace registration (`workspaces.toml`, §12.1). Task-ები: T5.01–T5.14; შესრულების რიგითობა topological-ია Depends-on გრაფზე (frag. 01 §0), არა ნუმერაციული.

### T5.01 — cli/: entry point, subcommand skeleton, prompt_toolkit interactive loop, `version` + `doctor`

**Scope:** `lsassist` console script-ის და CLI skeleton-ის შექმნა §15.1-ით — ყველა subcommand-ის dispatch table (`version`, `doctor`, `audit`, `memory`, `skills`, `checkpoint`, `rollback`, `usage`, `resume`), `prompt_toolkit` interactive loop (no daemon, manually launched), `version` და `doctor` სრული იმპლემენტაციით; დანარჩენი subcommand-ები ამ task-ში მხოლოდ registered stub-ებია (wiring T5.04-ში).

**Files:** `lsassist/pyproject.toml` (console script entry point განახლება), `lsassist/src/lsassist/cli/__init__.py`, `lsassist/src/lsassist/cli/entry.py`, `lsassist/src/lsassist/cli/loop.py`, `lsassist/src/lsassist/cli/doctor.py`, `lsassist/tests/unit/cli/test_entry.py`, `lsassist/tests/unit/cli/test_doctor.py`, `lsassist/tests/unit/cli/test_loop.py`

**Depends on:** T1.02, T1.07, T5.12

**RED (tests first):** (1) `test_entry.py`: `main(["version"])` → exit 0, output შეიცავს semver-ს `__version__`-დან; `main(["--help"])` → exit 0, ჩამოთვლილია §15.1-ის ყველა subcommand ზუსტი სახელით; unknown subcommand → exit 2 + usage hint; `main([])` → interactive loop-ის entry point იძახება (mock assert), loop exit-ზე exit 0; stub subcommand-ები (`audit`, `memory`, `skills`, `checkpoint`, `rollback`, `usage`, `resume`) → dispatch table-ში registered, მაგრამ ამ ეტაპზე აბრუნებენ typed `NotWiredError`-ს (exit 3), რომელიც T5.04-ში ჩანაცვლდება; (2) `test_doctor.py`: `doctor` read-only env check §15.1-ით — probes: providers reachable (timeout-ით, no auth attempt), `bwrap` binary present (T2.06 probe-ის გამოყენება), keyring backend active ან 0600 fallback (R11 — report აჩვენებს რომელი backend-ია), XDG permissions (T1.07 checks), config schema version; თითო probe → `ok|warn|fail` status; ყველა fail-ზე exit 1, warn-ზე exit 0; **doctor არ წერს არაფერს** — fs tree hash unchanged assertion test-ში; probe-ები fault-injected (bwrap absent, keyring down) → correct status; (3) `test_loop.py`: `prompt_toolkit` loop — EOF (`Ctrl+D`) → graceful exit 0; ცარიელი input → no-op; input `exit`/`quit` → exit; თითო turn გადადის T5.12-ის session engine-ზე (`on_user_turn(text) -> TurnResult` — wiring test-ში mock, საბოლოო იმპლემენტაცია T5.12-ის `SessionEngine`-ი); loop არ ინახავს history-ს disk-ზე V1-ში (assert: no history file). ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/cli -q` — მარცხდება `ModuleNotFoundError`-ით (`lsassist.cli` არ არსებობს).

**GREEN (implementation):** `entry.py`: argparse-based dispatch (stdlib, no click — §13.1 allowlist), console script `lsassist = lsassist.cli.entry:main`; exit code contract: 0 ok, 2 usage error, 3 not-wired stub; `loop.py`: `prompt_toolkit.PromptSession` history-ის გარეშე, input → T5.12-ის `SessionEngine.on_user_turn(text) -> TurnResult` (loop ამ engine-ს მართავს: turn შედეგი renderer-ზე გადაეცემა; დროებითი echo-stub callback დასაშვებია მხოლოდ როგორც intermediate RED ნაბიჯი T5.12-ის ლოკალური განვითარებისას — საბოლოო მდგომარეობაში loop პირდაპირ session engine-ზეა დაკავშირებული), EOF/exit handling; `doctor.py`: probe functions (provider TCP reachability 2 s timeout, `shutil.which("bwrap")` + T2.06 availability probe, secrets backend resolution T1.09-დან read-only, XDG perms T1.07-დან) — თითო probe isolated try/except-ში (ერთის crash ≠ სხვის დაკარგვა), structured report.

**Expected results:** ≥20 test case green; `lsassist version` და `lsassist doctor` მუშაობს real env-ში; doctor-ის fs-side-effect assertion 0.

**Verification:** ზედა pytest command green; `~/.local/share/lsassist/venv/bin/python -m mypy --strict src/lsassist/cli` clean; `~/.local/share/lsassist/venv/bin/python -m ruff check src/lsassist/cli tests/unit/cli` clean; manual: `lsassist --help` აჩვენებს §15.1-ის სრულ სიას. Pass criteria: ყველა command exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) dispatch table-ის subcommand სახელები ზუსტად §15.1-ს ემთხვევა (არავითარი დამატებითი command V1 scope-ის გარეშე); (2) doctor მართლა read-only-ა (probe-ები არ ახორციელებს auth call-ს და არ წერს state-ს); (3) interactive loop-ში history disk-ზე არ იქმნება.

**Rollback:** `git checkout -- pyproject.toml 2>/dev/null; rm -rf src/lsassist/cli tests/unit/cli` — სხვა ფაილები უვნებელი რჩება (T5.01 არ შლის phase 1–4 არტეფაქტებს).

(SPEC §15.1, §15.2, R11)

### T5.02 — cli/: session flags semantics (§15.2) — `--dry-run`, `--explain`, `--safe`, `--offline`, `--no-tools`, `--lang`, `--model`

**Scope:** Session flag-ების parser და runtime application — თითო flag-ის ზუსტი §15.2 semantics: policy class ceiling (`--safe`), EXECUTE replacement plan render-ით (`--dry-run`), provider disable (`--offline`), registry empty (`--no-tools`), UI ენა (`--lang`), model resolution never-silent-substitute-ით (`--model`).

**Files:** `lsassist/src/lsassist/cli/flags.py`, `lsassist/src/lsassist/cli/entry.py` (flag parsing wiring), `lsassist/tests/unit/cli/test_flags.py`, `lsassist/tests/integration/cli/test_flags_kernel.py`

**Depends on:** T5.01, T2.01, T2.09, T3.09, T3.12

**RED (tests first):** (1) `test_flags.py` (unit): flag parse → `SessionFlags` pydantic model; `--dry-run` → kernel run context-ში `execute_replaced_by_plan=True` და verdict გამოთვლისას force `UNVERIFIED` (by-design, ExitReason დოკუმენტირებული — T2.09 contract-თან); `--safe` → policy classification wrapper: ყველა `CONFIRM_ONCE`/`AUTO_WRITE` class → `CONFIRM_EXACT` (rules can only RAISE — wrapper-იც მხოლოდ raise-ს აკეთებს, `AUTO_READ` უცვლელი); `--offline` → provider resolution raise-ს `ProvidersDisabled`-ს და tool registry filter: read-only local tools only (`net.*` excluded); `--no-tools` → registry snapshot empty (chat/explain only), tool request attempt → BLOCKED; `--lang ka|en` → renderer locale selection; unknown `--lang` value → exit 2; (2) **`--model` never-silent-substitute (§15.2):** catalog-ში (T3.09 cached catalog) არსებული id → resolved; **unknown id → hard error exit 2, list of available ids-ით — არავითარი fallback/substitution**; explicit negative test: `--model typo-id` → error, provider call არასდროს ხდება (mock assert 0 calls); (3) `test_flags_kernel.py` (integration): `--safe` + write-class action → approval prompt class `CONFIRM_EXACT` (renderer-მდე მისვლა mock-ით); `--dry-run`-ში pipeline მიდის PLAN-მდე და EXECUTE-ზე plan render-ით სრულდება — 0 side effects (fs tree hash assertion); `--offline` + Kimi-only config → BLOCKED შეტყობინებით (§5.4 fallback flow T3.12-ს არ ეწინააღმდეგება — offline-ში fallback არ იძახება); `--no-tools`-ში tool call attempt → policy deny event audit-ში. ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/cli/test_flags.py tests/integration/cli/test_flags_kernel.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `flags.py`: `SessionFlags` model + `apply(flags, ctx)` — თითო flag ერთი კონკრეტული hook-ზე: policy ceiling wrapper (raise-only, §7.2), kernel run options (`dry_run` → EXECUTE guard), provider resolver guard (`offline` → refuse before fallback state machine), registry filter (`no_tools` → empty snapshot, `offline` → non-net read-only subset), locale (`lang` → config override, no write to config file); `--model`: strict lookup T3.09 catalog-ში, miss → `UnknownModelError` ხელმისაწვდომი id-ების ჩამონათვალით, resolver არასდროს იძახებს default-ს implicit-ად; flag combination validation: `--offline` + `--model <kimi-id>` → upfront error (contradictory), `--no-tools` + `--dry-run` → allowed (dry-run trivially); ყველა flag application audit-ირდება `config_change`-ის მსგავსი session-start event-ით (payload: flags only, no secrets).

**Expected results:** თითო flag-ზე ≥2 positive + ≥1 negative test; `--model` substitution 0 შემთხვევა; integration: `--dry-run` side-effect assertion 0; ≥18 test case.

**Verification:** ზედა pytest commands green; `mypy --strict src/lsassist/cli` clean. Pass criteria: ყველა exit 0; `test_flags_kernel.py`-ში ყველა class-raising assertion დადებითი.

**Review checkpoint:** ადამიანი ამოწმებს: (1) `--model`-ის negative test მტკიცებულებით — silent substitution სტრუქტურულად შეუძლებელია (error path მხოლოდ exit 2); (2) `--safe` wrapper მხოლოდ raise-ს აკეთებს (კოდის წაკითხვა: არ არსებობს lower branch); (3) flag combination matrix დოკუმენტირებულია და contradictory combination-ები upfront error-ია.

**Rollback:** `git checkout -- src/lsassist/cli/entry.py; rm -f src/lsassist/cli/flags.py tests/unit/cli/test_flags.py tests/integration/cli/test_flags_kernel.py`.

(SPEC §15.2, §5.4, §7.2)

### T5.03 — cli/: turn rendering sections, approval prompt renderer (canonical record-დან), Ctrl+C semantics

**Scope:** §15.3 output contract-ის renderer — turn sections (`intent echo → plan summary → [approval prompt] → action → result summary → verification → verdict`), approval prompt-ის pure renderer რომლის input არის §7.4 canonical token record (არა მოდელის ტექსტი), და SIGINT handling §14.5-ით (graceful kill + CANCELLED verdict + second Ctrl+C hard exit).

**Files:** `lsassist/src/lsassist/cli/render.py`, `lsassist/src/lsassist/cli/approval_render.py`, `lsassist/src/lsassist/cli/signals.py`, `lsassist/src/lsassist/cli/loop.py` (SIGINT wiring), `lsassist/tests/unit/cli/test_render.py`, `lsassist/tests/unit/cli/test_approval_render.py`, `lsassist/tests/unit/cli/test_signals.py`, `lsassist/tests/integration/cli/test_ctrl_c.py`

**Depends on:** T5.02, T1.05, T2.03, T2.09, T4.02

**RED (tests first):** (1) `test_approval_render.py`: renderer input = `ApprovalRecord` (T1.05 canonical model) — golden snapshot test §15.3 box format-ზე (box borders, field order: Tool/argv/cwd/Risk/Rollback/Token + action keys `[y]/[s]/[n]/[i]`); **renderer never receives model text** — API signature არ იღებს free-text field-ს (structural: signature inspection test); record field mutation (argv, cwd, ttl) → output ზუსტად იცვლება (snapshot per vector); `class=CONFIRM_EXACT` → header-ში `CONFIRM_EXACT`; risk line `record.policy_note`-დან verbatim (მაგ. `recursive delete (policy rule R5)` — populate ხდება classify time-ზე T3.02-ში); rollback line `record.rollback_hint`-დან verbatim, ცარიელისას → `none for delete outside workspace`-სტილის explicit fallback text (არასდროს ცარიელი ხაზი); **structural test: renderer risk/rollback ხაზებს კითხულობს მხოლოდ record-ის `policy_note`/`rollback_hint` field-ებიდან (T1.05), არასდროს მოდელის ტექსტიდან** — თითო field-ის mutation → output-ში შესაბამისი ხაზი ზუსტად იცვლება (snapshot per vector), record-ში არარსებული risk text renderer-ში ვერ ჩანს; unicode/wide chars box-ში → borders aligned; (2) `test_render.py`: turn sections renderer — თითო section conditional: `approval prompt` მხოლოდ approval event-ზე; section order assertion; streaming text allowed (chunks render incrementally), მაგრამ tool request display ყოველთვის execution-მდე (ordering assertion event stream-ზე); **never hidden "working…"** — გრძელი operation-ისას status section explicit-ად ჩანს (elapsed + current state name kernel state machine-დან), spinner-only UI არ არსებობს (structural test: renderer API-ში anonymous-progress function არ არის); verdict section T2.09 verdict + ExitReason-ით; `--lang` locale switch sections-ზე (ka/en label sets); (3) `test_signals.py` + `test_ctrl_c.py`: first SIGINT → handler: child process group-ის kill (mock `os.killpg`), journal checkpoint event (T4.02 writer mock: `recovery` event), verdict `CANCELLED` with ExitReason, exit code 130; second SIGINT grace window-ში → hard exit (still journaled — writer called before `_exit`); SIGINT approval prompt-ის დროს → denial-equivalent (token not consumed, §14.5/AC-08 no side effects — fs tree hash assertion integration test-ში); handler re-entrancy safe. ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/cli/test_render.py tests/unit/cli/test_approval_render.py tests/unit/cli/test_signals.py tests/integration/cli/test_ctrl_c.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `render.py`: section renderers `rich`-ით (§13.1 allowlist, display-only) — თითო section ცალკე function, input = typed events (kernel/verdict contracts), locale label dicts ka/en; `approval_render.py`: pure function `render_approval(record: ApprovalRecord) -> str` — box layout fixed width-aware, ყველა ველი record-დან verbatim (display = record, §7.4 "user sees exactly what is approved"); risk/rollback lines strictly `record.policy_note`/`record.rollback_hint` field-ებიდან (T1.05 canonical fields, populate T3.02 classify time-ზე) — renderer არ იღებს ცალკე free-text risk/rollback parameter-ს და არასდროს კითხულობს მოდელის output-ს (structural: single-argument signature, model-text path არ არსებობს); `signals.py`: SIGINT handler install/restore context manager — first signal: killpg → journal `recovery` event → `CANCELLED` verdict path kernel-თან; second signal: best-effort journal flush → `os._exit(130)`; loop-ში handler active მხოლოდ turn execution-ისას (prompt input-ზე default behavior).

**Expected results:** approval renderer 100% snapshot-covered (≥8 vector: classes, rollback present/absent, long argv, unicode); renderer-ში model-text input path არ არსებობს (structural assertion); Ctrl+C tests 4/4; ≥26 test case.

**Verification:** ზედა pytest commands green; `mypy --strict src/lsassist/cli` clean; manual: sandboxed test workspace-ში `lsassist` + mock task + Ctrl+C → journal-ში `recovery` event + verdict `CANCELLED`. Pass criteria: ყველა exit 0, snapshot diff-ები reviewed.

**Review checkpoint:** ადამიანი ამოწმებს: (1) approval prompt-ის golden snapshot ზუსტად §15.3 box-ს შეესაბამება (field order, action keys, `CONFIRM_EXACT` header); (2) renderer-ის single input source = canonical record — diff review-ში არავითარი model-text parameter; (3) SIGINT flow-ში journal write second-Ctrl+C-მდეც ხდება (code read).

**Rollback:** `git checkout -- src/lsassist/cli/loop.py; rm -f src/lsassist/cli/render.py src/lsassist/cli/approval_render.py src/lsassist/cli/signals.py tests/unit/cli/test_render.py tests/unit/cli/test_approval_render.py tests/unit/cli/test_signals.py tests/integration/cli/test_ctrl_c.py`.

(SPEC §15.3, §7.4, §14.5, AC-08)

### T5.04 — cli/: read-only subcommand wiring — `audit`, `memory`, `skills`, `checkpoint|rollback`, `usage`, `resume`

**Scope:** T5.01-ის stub subcommand-ების real wiring არსებულ backend services-ზე: `audit show` (T4.03 reader + on-read redaction), `memory` inspect/correct/delete (T4.09 API), `skills` list/info/enable/disable (T4.11 lifecycle), `checkpoint create|list` + `rollback <id>` (T4.04/T4.05 flow: preview diff → confirm → restore), `usage` (T4.03 session stats §14.2), `resume` (T4.06 journal resume); ასევე dispatch table-ში `config set` და `workspace add|remove` registered როგორც stub-ები `cli/commands_config.py`-ისთვის (real wiring T5.14-ში, რომელიც ამ task-ზეა დამოკიდებული).

**Files:** `lsassist/src/lsassist/cli/commands_audit.py`, `lsassist/src/lsassist/cli/commands_memory.py`, `lsassist/src/lsassist/cli/commands_skills.py`, `lsassist/src/lsassist/cli/commands_checkpoint.py`, `lsassist/src/lsassist/cli/commands_usage.py`, `lsassist/src/lsassist/cli/commands_resume.py`, `lsassist/src/lsassist/cli/entry.py` (stub-ების ჩანაცვლება), `lsassist/tests/unit/cli/test_commands.py`, `lsassist/tests/integration/cli/test_subcommands.py`

**Depends on:** T5.03, T4.03, T4.05, T4.06, T4.09, T4.11

**RED (tests first):** (1) `test_commands.py` (unit, backend-ები mock-ით): `audit show --session N --type T` → reader call exact args-ით, output reader-ის redacted records (on-read redaction applied — T4.03); `memory list|show|correct|forget` → T4.09 gate API calls, mutating ops require `--yes` ან interactive confirm (CLI-დან memory mutation არასდროს silent); `skills list|info|enable|disable` → T4.11 lifecycle calls, `enable` → CONFIRM_EXACT-style prompt T4.11 contract-ით; `checkpoint create|list` → T4.04; `rollback <id>` → T4.05 flow verbatim: preview diff render (T5.03 renderer) → user confirm prompt → restore; `--yes` გარეშე non-TTY-ში → refuse (exit 3); `usage` → session stats render §14.2: tool-call counts by class, verdict distribution, budget usage, provider usage, fallback events, repair-rate metric — ყველა field present (schema assertion); `resume` → T4.06 resume flow, interrupted session list-ით როცა arg არ არის; (2) `test_subcommands.py` (integration, real XDG tmp dirs): სრული chain: session → events → `audit show` ხედავს redacted records-ს; `usage` აჩვენებს real counts-ს; `checkpoint create` → file mutation → `rollback` preview+confirm → restore byte-identical (AC-06 hash equality re-assertion CLI level-ზე); interrupted session (simulated journal cut) → `resume` აღადგენს §4.7 rules-ით (already-executed seq არ მეორდება — T4.06). ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/cli/test_commands.py tests/integration/cli/test_subcommands.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** თითო `commands_*.py` — thin adapter: argparse subparser → backend API call → T5.03 renderer-ით output; არავითარი business logic CLI ფენაში (ყველა invariant backend-ში რჩება); mutating subcommand-ებზე uniform confirm helper (interactive y/n, `--yes` override, non-TTY refuse); `config`/`workspace` subcommand-ები dispatch table-ში registered `commands_config`-ისთვის — ამ task-ში stub entry (სხვა stub-ების მსგავსად), real adapter wiring T5.14-ში; `usage` renderer: §14.2-ის ექვსი metric group table-ებით, repair-rate არასდროს იმალება (ყოველთვის ჩანს, 0-ზეც); `rollback` არ აქვეყნებს restore-ს preview+confirm-ის გარეშე (structural: restore call მხოლოდ confirm branch-ში).

**Expected results:** ყველა 7 subcommand functional; integration: rollback hash equality, resume replay 0; CLI ფენაში 0 business-logic branch (code review assertion); ≥24 test case.

**Verification:** ზედა pytest commands green; `mypy --strict src/lsassist/cli` clean; manual smoke: real tmp XDG env-ში `lsassist checkpoint create && lsassist rollback <id>` cycle. Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) CLI adapters მართლა thin-ა — policy/gates არ დუბლირდება CLI-ში; (2) `rollback` preview→confirm→restore sequence ხელით გავლილი; (3) `usage`-ში repair-rate metric ყოველთვის ხილულია (§14.2 "masks model degradation if hidden").

**Rollback:** `git checkout -- src/lsassist/cli/entry.py; rm -f src/lsassist/cli/commands_*.py tests/unit/cli/test_commands.py tests/integration/cli/test_subcommands.py` — stub-ები უბრუნდება წინა მდგომარეობას.

(SPEC §15.1, §14.2, §14.4, §14.5, AC-06)

### T5.05 — coding/: immutable intent_record capture + pipeline wiring kernel-ზე (§16.1)

**Scope:** Coding Mode-ის ჩარჩო: `intent_record` `{text, digest, ts}` immutable capture-ით (§16.2) და §16.1 pipeline-ის stage wiring არსებულ kernel/tools/checkpoint ფენებზე — capture → inspect (AUTO_READ) → scope → plan → checkpoint/isolate → edit → test → security check → diff review → verify → report.

**Files:** `lsassist/src/lsassist/coding/__init__.py`, `lsassist/src/lsassist/coding/intent.py`, `lsassist/src/lsassist/coding/pipeline.py`, `lsassist/src/lsassist/coding/scope.py`, `lsassist/tests/unit/coding/test_intent.py`, `lsassist/tests/unit/coding/test_pipeline.py`, `lsassist/tests/unit/coding/test_scope.py`, `lsassist/tests/integration/coding/test_pipeline_kernel.py`

**Depends on:** T5.03, T1.11, T2.07, T2.11, T3.02, T3.03, T4.04

**RED (tests first):** (1) `test_intent.py`: `capture_intent(text)` → pydantic `IntentRecord{text, digest=sha256(canonical(text)), ts}` — frozen model (mutation attempt → validation error); plan object reference-ებს digest-ს (structural: plan schema-ში `intent_digest` required); audit-ში `intent` event (T4.02 writer mock) digest-ით, full text redaction pass-ით; (2) `test_scope.py`: declared path set parsing + validation — writes outside scope → policy raises (T2.01 classifier integration: out-of-scope write request → class raise/deny); scope empty → task BLOCKED pre-plan; scope-ში `..`/symlink → canonicalization fail-closed (T2.02); (3) `test_pipeline.py` (unit, stage mocks): §16.1 stage order enforced — stage transition table (pipeline არ გადადის edit-ზე plan-ის გარეშე); repo instructions (`AGENTS.md` content) იდება context-ში §4.6 delimiter block-ით, provenance tier-ით (T2.11 untrusted-turn flag propagation assert — repo-instruction turn-ში non-read request = CONFIRM_EXACT); checkpoint stage → T4.04 snapshot before first write (ordering assert); (4) `test_pipeline_kernel.py` (integration, tmp repo): პატარა end-to-end task (change a string in a file) — pipeline სრულად გადის real kernel-ზე: intent audit event → AUTO_READ inspect → plan → checkpoint created → fs.patch applied (T3.05) → test.run executed (T3.06) → verdict with evidence (I12); denial path: user denies approval → pipeline stops, 0 side effects (AC-08 hash assertion). ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/coding tests/integration/coding/test_pipeline_kernel.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `intent.py`: T1.11-ის `contracts/intent.py`-დან `IntentRecord`/`make_intent` import + audit emit wiring (კონტრაქტის ხელახალი განსაზღვრა აკრძალულია — single producer = T1.11); `scope.py`: scope declaration model (path list → canonicalized set T2.02-ით), scope guard hook policy classifier-ის წინ (out-of-scope → raise); `pipeline.py`: stage enum + driver — თითო stage delegate: inspect → tool dispatch (AUTO_READ only, registry filter), plan → provider turn (T3.08 contract), checkpoint → T4.04 API, edit → scoped tool requests, test → `test.run`, security check → redactor/policy re-check stage, diff review → git diff render T5.03 renderer-ით, verify → T5.07 placeholder hook, report → T5.07 placeholder hook (ორი ბოლო stage ამ task-ში interface-ით, იმპლემენტაცია T5.07-ში); ყველა stage transition kernel event-ად journal-ირდება.

**Expected results:** pipeline stage order 100% enforced (property-style: generated stage sequences-ზე invalid order rejected); integration e2e 1/1 green; denial path 0 side effects; ≥22 test case.

**Verification:** ზედა pytest commands green; `mypy --strict src/lsassist/coding` clean; `pytest --cov=src/lsassist/coding --cov-branch --cov-report=term-missing tests/unit/coding -q` — report reviewed (coding/ ≠ TCB core, მაგრამ ≥90% branch მიზნად). Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) `IntentRecord` მართლა immutable-ა და digest plan-ებში required-ია; (2) repo instructions მხოლოდ delimited user-role block-ად შედის (§4.6 — never system-role, never permission expansion); (3) checkpoint stage პირველ write-მდე დგას (stage order test მტკიცებულებით).

**Rollback:** `rm -rf src/lsassist/coding tests/unit/coding tests/integration/coding` — cli/ ფაილები უვნებელი რჩება.

(SPEC §16.1, §16.2, §4.6, I7, I12)

### T5.06 — coding/: baseline tree hash guard (I13) + mid-task foreign-modification pause (§16.3)

**Scope:** Baseline guard-ის იმპლემენტაცია §16.2/§16.3-ით: task start-ზე workspace tree hash (`.git` + registered ignores გამოკლებით), report-ზე assistant-ური და foreign changes-ის დაყოფა, mid-task foreign modification-ზე pause + user decision (I13).

**Files:** `lsassist/src/lsassist/coding/baseline.py`, `lsassist/src/lsassist/coding/pipeline.py` (guard hooks wiring), `lsassist/tests/unit/coding/test_baseline.py`, `lsassist/tests/integration/coding/test_baseline_guard.py`

**Depends on:** T5.05

**RED (tests first):** (1) `test_baseline.py`: `snapshot_tree(root, ignores)` → deterministic hash (file order-independent; same content = same hash; mtime არ მონაწილეობს — content-only); `.git` + registered ignore patterns (config-driven list) excluded — test: `.git` mutation → hash unchanged; empty workspace → defined constant hash; large-binary exclusion rule (§14.4-ის 50 MB-ის ანალოგი hash skip-ით + manifest note); symlink handling: symlink target content არ იჰეშება (link itself hashed, TOCTOU-safe); (2) `diff_since(baseline)` → changes classified: `assistant_touched` (pipeline-ის own write log-თან intersection) vs `foreign`; report-ზე foreign changes surfaced text-ით `"unrelated user changes detected, untouched"` (verbatim §16.2 phrase assertion) და pipeline არასდროს შლის/წერს foreign file-ს (negative: rollback/restore არ ეხება foreign list-ს); (3) `test_baseline_guard.py` (integration): task მუშაობს, parallel process ცვლის unrelated file-ს → next stage boundary-ზე guard detects → pipeline `PAUSED` + user prompt (`continue|abort|adopt`) — `abort` → checkpoint-ებით assistant changes rolled back, foreign file byte-identical (hash assert); `continue` → task proceeds, foreign file final report-ში listed, untouched; user edit assistant-ის own target file-ზე → foreign classification (assistant write log-ში არ არის ის მოდიფიკაცია) → pause too; AC-06 e2e scenario re-assertion baseline guard-ის კონტექსტში. ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/coding/test_baseline.py tests/integration/coding/test_baseline_guard.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `baseline.py`: `BaselineSnapshot` (root, hash, per-file manifest of assistant-relevant paths, ts, ignoreset) — capture task start-ზე (pipeline stage `capture`-ის შემდეგ); content-hash walker (sha256 per file, sorted rel paths, combined hash); `check_foreign_modifications(snapshot, assistant_write_log) -> ForeignChanges` — stage boundary hook pipeline-ში (ყოველ mutating stage-ის შემდეგ); pause integration: kernel PAUSED state + user decision prompt T5.03 renderer-ით; final report hook: foreign list → report section (T5.07 report contract-ში slot ამ task-ში დეფინირებული); assistant write log pipeline-იდან (ყველა fs.write/fs.patch target).

**Expected results:** guard detection latency = next stage boundary (documented); foreign file 0 bytes modified ყველა scenario-ში (3/3 integration hash asserts); report phrase verbatim; ≥14 test case.

**Verification:** ზედა pytest commands green; `mypy --strict src/lsassist/coding` clean. Pass criteria: ყველა exit 0; integration-ში foreign-file hash equality 100%.

**Review checkpoint:** ადამიანი ამოწმებს: (1) I13 guarantee კოდით: არავითარი code path, რომელიც foreign-classified file-ს წერს/შლის — rollback-იც manifest-driven-ია (T4.05); (2) ignore list config-დან მოდის და `.git` hardcoded excluded-ია; (3) pause prompt-ის სამივე option-ის behavior ხელით ნაცადი tmp repo-ში.

**Rollback:** `git checkout -- src/lsassist/coding/pipeline.py; rm -f src/lsassist/coding/baseline.py tests/unit/coding/test_baseline.py tests/integration/coding/test_baseline_guard.py`.

(SPEC §16.2, §16.3, I13, AC-06)

### T5.07 — coding/: verify_cmd inference (display+confirm), bounded fix loop ≤3, final diff+evidence+verdict report

**Scope:** Coding Mode-ის დასასრული §16.2/§16.3-ით: `verify_cmd` user-provided ან inferred (inference display + explicit confirm), test-fail → bounded fix loop (≤3) → PARTIAL failing evidence-ით, final report = diff summary + evidence list + verdict + foreign-changes section (T5.06).

**Files:** `lsassist/src/lsassist/coding/verify.py`, `lsassist/src/lsassist/coding/fixloop.py`, `lsassist/src/lsassist/coding/report.py`, `lsassist/src/lsassist/coding/pipeline.py` (verify/report stages real implementation), `lsassist/tests/unit/coding/test_verify.py`, `lsassist/tests/unit/coding/test_fixloop.py`, `lsassist/tests/unit/coding/test_report.py`, `lsassist/tests/integration/coding/test_coding_e2e.py`

**Depends on:** T5.06, T2.09

**RED (tests first):** (1) `test_verify.py`: user-provided `verify_cmd` → used verbatim (no inference call); absent → inference heuristics (pytest presence, Makefile `test` target, package.json scripts) → candidate **displayed to user + explicit confirm required** — unconfirmed inference never executes (negative: non-TTY/auto mode-ში inference → task asks, never assumes; `--yes`-სთვისაც confirm prompt rendered, logged); inference output audit event-ში (`policy_decision`-style log); inferred cmd executes via `test.run` tool only (structural: no direct subprocess in coding/); (2) `test_fixloop.py`: test fail after edit → fix iteration 1..3 → success-ზე VERIFIED (evidence-ით); 3 failures → loop stops, verdict `PARTIAL` + failing evidence attached (real exit code + output digest, T2.09 contract); 4-თის attempt structurally impossible (loop counter ceiling assert); loop-ში budget accounting T2.08-ით; scope violation attempt fix loop-ში → BLOCKED immediately (§16.3); (3) `test_report.py`: report model: `{diff_summary, evidence_list, verdict, exit_reason, foreign_changes, assistant_changes}` — evidence_list-ის თითო entry T2.09 evidence types-დან; verdict=VERIFIED requires ≥1 evidence (I12 re-assertion coding level-ზე — construction test); report render T5.03 sections-ით (`verification → verdict`); foreign_changes section T5.06-დან, verbatim phrase; (4) `test_coding_e2e.py`: ორი სცენარი tmp repo-ზე: (a) წარმატებული task — intent → edit → tests pass → VERIFIED report სრული ველებით; (b) failing task — fake broken change → 3 fix attempts → PARTIAL + evidence; ორივეში journal contains intent/plan/tool/verify/verdict events. ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/coding tests/integration/coding -q` — მარცხდება ახალი მოდულების არარსებობით.

**GREEN (implementation):** `verify.py`: `resolve_verify_cmd(declared, repo_signals) -> VerifyCmd | NeedsConfirm` — inference table (pytest, make test, npm test; priority ordered), confirm gate pipeline stage-ად; `fixloop.py`: bounded loop driver — iteration cap constant `MAX_FIX_ITERATIONS = 3`, per-iteration: diagnose (provider turn, real test output evidence-ად) → scoped edit → re-run verify_cmd; exit conditions: pass → verify stage; cap → PARTIAL assembly; scope violation → BLOCKED; `report.py`: `FinalReport` pydantic model + renderer bridge T5.03-ზე; pipeline verify/report stages-ის placeholder-ების ჩანაცვლება real wiring-ით.

**Expected results:** fix loop ceiling 3 enforced (100% generated sequences-ზე); unconfirmed inference 0 executions; VERIFIED-without-evidence construction impossible; e2e 2/2; ≥20 test case.

**Verification:** ზედა pytest commands green; `mypy --strict src/lsassist/coding` clean; manual: tmp repo-ში real coding task `lsassist`-ით → report reviewed. Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) `MAX_FIX_ITERATIONS = 3` — cap შეუვალია, PARTIAL path-ზე failing evidence სრულია; (2) verify_cmd inference-ზე ყოველთვის დგას display+confirm (ხელით ნაცადი); (3) final report-ის evidence list მხოლოდ deterministic evidence types-ს შეიცავს (I12).

**Rollback:** `git checkout -- src/lsassist/coding/pipeline.py; rm -f src/lsassist/coding/verify.py src/lsassist/coding/fixloop.py src/lsassist/coding/report.py tests/unit/coding/test_verify.py tests/unit/coding/test_fixloop.py tests/unit/coding/test_report.py tests/integration/coding/test_coding_e2e.py`.

(SPEC §16.2, §16.3, §4.5, I12)

### T5.08 — tutor/: EXPLAIN და GUIDED flows + progressive disclosure `prefs` user level-იდან (§17.1, §17.2)

**Scope:** Tutor Mode-ის პირველი ორი behavior: EXPLAIN (კონცეფცია + მაგალითი, no execution) და GUIDED (user executes; assistant steps + read-only checks; mistakes diagnosed real output-დან), pedagogy contract-ით — progressive disclosure per `prefs.level`, max 1 concept card per action.

**Files:** `lsassist/src/lsassist/tutor/__init__.py`, `lsassist/src/lsassist/tutor/modes.py`, `lsassist/src/lsassist/tutor/pedagogy.py`, `lsassist/src/lsassist/tutor/concept_card.py`, `lsassist/tests/unit/tutor/test_modes.py`, `lsassist/tests/unit/tutor/test_pedagogy.py`, `lsassist/tests/integration/tutor/test_guided_flow.py`

**Depends on:** T5.03, T1.08

**RED (tests first):** (1) `test_modes.py`: EXPLAIN flow — user question → response = concept + example, **0 tool requests emitted** (structural: EXPLAIN context-ში registry empty snapshot, dispatch impossible — T5.02 `--no-tools`-ის მსგავსი guard, მაგრამ flow-level); GUIDED flow — step list emission, თითო step-ზე assistant მხოლოდ read-only tools-ს იძახებს (`AUTO_READ` ceiling assert — write/exec request GUIDED step-დან → policy raise/BLOCKED); user pastes real command output → diagnosis references actual output text (no generic advice — assertion: diagnosis contain output tokens); user skips step → flow adapts, no fabrication that step happened; (2) `test_pedagogy.py`: `prefs.level ∈ {beginner, intermediate, advanced}` (config schema T1.08-დან) → disclosure depth mapping: beginner = full context + glossary, intermediate = standard, advanced = terse + man-page reference; commands/flags/paths ყოველთვის English (assertion: command tokens unchanged across levels); explanations `--lang`-ით ka/en; **concept-card constraint: max 1 per action** — response model-ში `concept_cards: list[ConceptCard]` `max_length=1` (pydantic enforcement + property test generated responses-ზე); "learn more" on demand — second card only explicit request-ზე; no lecture-dumping: response section budget (card ≤ N lines, documented constant); (3) `test_guided_flow.py` (integration): scripted GUIDED session tmp env-ში — 3-step task (e.g. inspect disk usage), user executes steps externally, pastes outputs → assistant verifies read-only-თი (`sys.info`/`fs.read` dispatch logs assert) → completion summary only after real verification. ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/tutor tests/integration/tutor/test_guided_flow.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `modes.py`: behavior enum + flow drivers — EXPLAIN: registry-empty context, single-turn concept+example assembly; GUIDED: step plan → per-step: instruction render (T5.03) → wait user output → read-only verification dispatch → diagnosis; `pedagogy.py`: level→disclosure profile mapping (beginner/intermediate/advanced), locale-aware explanation wrapper (English technical tokens preserved — allowlist tokenizer for command spans); `concept_card.py`: `ConceptCard` model `{title, body, learn_more_ref}`, response envelope `max_length=1` enforcement.

**Expected results:** EXPLAIN 0 tool requests (property assertion); GUIDED read-only ceiling 100%; concept card ≤1 per action 100% generated cases; ≥18 test case.

**Verification:** ზედა pytest commands green; `mypy --strict src/lsassist/tutor` clean. Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) EXPLAIN-ში execution path სტრუქტურულად არ არსებობს (არა conditional-ად — registry empty); (2) disclosure mapping სამივე level-ზე განსხვავებულია და `prefs`-დან მოდის (არა მოდელის self-assessment-დან); (3) concept-card cap enforcement pydantic level-ზეა (sample responses ხელით ნანახი).

**Rollback:** `rm -rf src/lsassist/tutor tests/unit/tutor tests/integration/tutor`.

(SPEC §17.1, §17.2, §15.2)

### T5.09 — tutor/: DO_AND_TEACH flow — teaching overlay schema-tested (AC-14), never-fabricate-success (I12)

**Scope:** DO_AND_TEACH behavior: თითო policy-permitted action + teaching overlay (რა/რატომ/რას ცვლის/რისკი/როგორ მოწმდება/rollback) — UT-14 schema test-ით 100% coverage-ზე (AC-14) და never-fabricate-success enforcement-ით (ყველა success claim evidence-backed, I12).

**Files:** `lsassist/src/lsassist/tutor/overlay.py`, `lsassist/src/lsassist/tutor/do_and_teach.py`, `lsassist/tests/unit/tutor/test_overlay_schema.py`, `lsassist/tests/unit/tutor/test_do_and_teach.py`, `lsassist/tests/integration/tutor/test_do_and_teach_flow.py`

**Depends on:** T5.08, T2.09

**RED (tests first):** (1) `test_overlay_schema.py` (**UT-14, AC-14**): `TeachingOverlay` pydantic schema — required fields exactly §17.1: `what`, `why`, `what_changes`, `risk`, `how_verified`, `rollback`; empty/missing field → validation error; schema test fuzzed DO_AND_TEACH session-ებზე (hypothesis-generated action sequences): **100% of actions carry valid overlay** — gate assertion `len(actions) == len(overlays) == valid_count`; overlay fields-ში commands/flags English, explanations locale (§17.2 re-assertion overlay level-ზე); (2) `test_do_and_teach.py`: flow — action proposed → overlay rendered (T5.03 sections) → approval per policy (write actions → token flow unchanged) → execute via dispatch (T3.02/T3.03) → **success narration only from real result**: narration builder input = `ToolResult` (T1.04), structural test — narration function signature არ იღებს planned-success text-ს; failed action → narration states failure + real exit code/output digest (never-fabricate, I12); post-action verification step: `how_verified` field-ის command executed read-only-თი და result interpreted from real output; (3) `test_do_and_teach_flow.py` (integration): scripted DO_AND_TEACH session (e.g. create + verify a file in tmp workspace) — journal shows: overlay event → approval → tool_result → verification → teaching summary; injected failure (make verify fail) → summary reports failure, verdict not VERIFIED (I12 end-to-end). ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/tutor/test_overlay_schema.py tests/unit/tutor/test_do_and_teach.py tests/integration/tutor/test_do_and_teach_flow.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `overlay.py`: `TeachingOverlay` model + audit payload adapter (overlay content audit-ირდება redaction pass-ით); `do_and_teach.py`: flow driver — per action: overlay assembly (model turn-დან draft, schema-validate → missing/invalid → BLOCKED with repair retry ≤3 budget-refunded §14.5, then fail-closed), render, policy/approval unchanged path, execute, `narrate_result(tool_result, overlay)` — narration strictly result-derived (template slots: exit code, stdout digest, file snapshot), verification sub-step read-only dispatch.

**Expected results:** UT-14 gate: 100% actions with valid overlay fuzzed sessions-ზე (AC-14 pass threshold verbatim); failure narration 0 fabricated-success cases; ≥16 test case.

**Verification:** ზედა pytest commands green; `mypy --strict src/lsassist/tutor` clean. Pass criteria: ყველა exit 0; UT-14 threshold line test output-ში explicit-ად ჩანს.

**Review checkpoint:** ადამიანი ამოწმებს: (1) overlay schema-ის ექვსი field ზუსტად §17.1-ის ჩამონათვალია; (2) narration builder-ში არავითარი "success by default" path — კოდის წაკითხვით; (3) AC-14-ის 100% assertion fuzz test-ში მართლა gate-ია (fail-ზე red).

**Rollback:** `rm -f src/lsassist/tutor/overlay.py src/lsassist/tutor/do_and_teach.py tests/unit/tutor/test_overlay_schema.py tests/unit/tutor/test_do_and_teach.py tests/integration/tutor/test_do_and_teach_flow.py`.

(SPEC §17.1, §17.2, §4.5, I12, AC-14, UT-14)

### T5.10 — tutor/: sudo escape-hatch flow (§17.3) — preparation, manual run, read-only result check

**Scope:** Sudo/package/service სცენარების documented escape hatch: assistant ამზადებს exact command-ს + full teaching overlay + risks + verification + rollback steps; **user runs it manually**; assistant შემდეგ read-only-ით ამოწმებს შედეგს — DENY_ALWAYS-ის დარღვევის გარეშე (I6/I7).

**Files:** `lsassist/src/lsassist/tutor/sudo_hatch.py`, `lsassist/tests/unit/tutor/test_sudo_hatch.py`, `lsassist/tests/integration/tutor/test_sudo_hatch_flow.py`

**Depends on:** T5.09

**RED (tests first):** (1) `test_sudo_hatch.py`: sudo-intent detection (user request mentions sudo/apt/systemctl/...) → flow switch to escape hatch; `SudoPlan` model: `{exact_command, overlay (TeachingOverlay from T5.09), risks: list[str], verification_cmd (read-only), rollback_steps: list[str]}` — ყველა field required; **assistant never executes**: structural test — flow-ში dispatch call არ არსებობს privileged command-ზე; `proc.exec`/`test.run` request containing `sudo` argv → DENY_ALWAYS classifier hit (T2.02 re-assertion tutor context-ში); registry enumeration negative re-check: no `shell`/`pkg.install`/`service.*` tool (T3.07) — escape hatch არ ქმნის backdoor-ს; preparation render: exact command copy-paste-able block + overlay + risks + verification + rollback, explicit instruction "run this yourself, then tell me / paste output"; (2) post-run check: user reports done / pastes output → assistant executes ONLY `verification_cmd` via read-only tools (`sys.info`, `pkg.query`, `fs.read` — ceiling AUTO_READ assert) → result interpretation real output-დან; verification fails → assistant reports failure honestly + suggests rollback steps (never claims success, I12); user says "done" without evidence → assistant runs verification anyway before any success statement (assertion: no success narration before verification tool result); (3) `test_sudo_hatch_flow.py` (integration): simulated package-install scenario — plan rendered, "user" runs equivalent non-privileged simulation in tmp env, assistant verifies via `pkg.query`-style read-only → summary correct both ways (success + simulated failure). ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/tutor/test_sudo_hatch.py tests/integration/tutor/test_sudo_hatch_flow.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `sudo_hatch.py`: `SudoPlan` model (reuses `TeachingOverlay` T5.09-დან, + `risks`, `verification_cmd` constrained to read-only tool mapping, `rollback_steps`); flow driver: detect → plan assembly → schema validate → render (T5.03) → wait-for-user state (no kernel EXECUTE stage — documented state bypass, audit event `intent` subtype `sudo_hatch`) → verification dispatch (AUTO_READ ceiling guard) → honest summary; audit: preparation და verification ორივე journal-ირდება.

**Expected results:** privileged execution path 0 (structural + classifier tests); verification-before-success 100%; both outcome narrations honest; ≥14 test case.

**Verification:** ზედა pytest commands green; `mypy --strict src/lsassist/tutor` clean; manual: real host-ზე read-only simulation (e.g. `pkg.query` based scenario) ხელით გავლილი. Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) flow-ში ფიზიკურად არ არსებობს privileged dispatch — code read + classifier re-assertion; (2) `verification_cmd` mapping მხოლოდ read-only tools-ზეა (allowlist table reviewed); (3) §17.3-ის სრული promise (exact command + overlay + risks + verification + rollback, user runs manually) ერთი რეალური სცენარით ხელით ნაცადი.

**Rollback:** `rm -f src/lsassist/tutor/sudo_hatch.py tests/unit/tutor/test_sudo_hatch.py tests/integration/tutor/test_sudo_hatch_flow.py`.

(SPEC §17.3, §17.1, §7.3, I12)

### T5.11 — e2e smoke: first-run scenario manual execution with evidence checklist

**Scope:** Scripted first-run smoke test — setup wizard → secrets to keyring → `doctor` → ერთი Coding Mode task → ერთი Tutor Mode task — ხელით, manual procedure document-ით და evidence checklist-ით (live provider opt-in, §23.1 "live provider tests manual opt-in").

**Files:** `lsassist/docs/smoke/first-run-checklist.md`, `lsassist/tests/e2e/test_smoke_harness.py`, `lsassist/scripts/smoke-evidence.sh`

**Depends on:** T5.04, T5.07, T5.10

**RED (tests first):** `test_smoke_harness.py`: smoke harness automation-ის ნაწილი — tmp XDG env fixture (isolated `$XDG_CONFIG_HOME`/`$XDG_STATE_HOME`/`$XDG_DATA_HOME`), first-run detection (no config → setup wizard path), wizard writes config with correct permissions (T1.07 checks re-asserted e2e level: dirs `0700`, files `0600`), secrets entered → keyring write (T1.09 resolver: `secretstorage` available-ზე keyring, else 0600 fallback — both paths parameterized), `doctor` post-setup → all probes ok/warn, exit 0; no systemd/cron/autostart entries created (AC-02 assertion: fixture scans common locations pre/post). ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/e2e/test_smoke_harness.py -q` — მარცხდება ფაილის არარსებობით. (Manual ნაწილი — Coding/Tutor live runs — RED-ად: checklist document არ არსებობს; იქმნება GREEN-ში და სრულდება ხელით.)

**GREEN (implementation):** harness fixture + assertions ზედა; `first-run-checklist.md`: step-by-step manual procedure — (1) clean env bootstrap (venv install ADR-005), (2) first run: setup wizard (secrets to keyring — verify `doctor` reports active backend, R11), (3) `lsassist doctor` output snapshot, (4) Coding Mode task: scratch repo-ში პატარა change with `verify_cmd` — expected: intent echo → plan → approval prompt (canonical record) → checkpoint → edit → tests → VERIFIED report with evidence; evidence items: journal excerpt (intent/approval/tool_result/verdict events), report text, rollback test (`lsassist rollback` restores), (5) Tutor Mode task: GUIDED scenario (e.g. permissions explanation) + ერთი sudo escape-hatch preparation (not executed — plan only reviewed); evidence items: overlay rendered, read-only verification log; (6) `lsassist usage` output snapshot (§14.2 metrics incl. repair-rate); `smoke-evidence.sh`: collects journal excerpts + outputs into timestamped evidence dir under `docs/smoke/evidence/` (gitignored optional), checklist-ის თითო item-თან mapping.

**Expected results:** automated harness green (setup/doctor/AC-02 parts); manual checklist ყველა item-ზე evidence captured; Coding task verdict VERIFIED real evidence-ით; Tutor overlay 100% (AC-14 spot check live).

**Verification:** `~/.local/share/lsassist/venv/bin/python -m pytest tests/e2e/test_smoke_harness.py -q` green; manual: checklist executed end-to-end, `bash scripts/smoke-evidence.sh` produces evidence dir; reviewer signs off each checklist item. Pass criteria: harness exit 0 + checklist 100% completed with evidence files present.

**Review checkpoint:** ადამიანი (Gate 3 plan-ის მფლობელი) ამოწმებს: (1) evidence checklist-ის ყოველი item-ს აქვს შესაბამისი artifact; (2) approval prompt live render ემთხვევა §15.3 format-ს; (3) sudo escape-hatch plan სრულია (command+overlay+risks+verification+rollback) და არაფერი შესრულებულა assistant-ის მიერ; (4) AC-02 assertion (no persistence artifacts) evidence-ით დადასტურებული.

**Rollback:** `rm -f docs/smoke/first-run-checklist.md tests/e2e/test_smoke_harness.py scripts/smoke-evidence.sh; rm -rf docs/smoke/evidence` — smoke artifacts მხოლოდ; mode/cli კოდი უვნებელი რჩება.

(SPEC §15.1, §16.1, §17.1, §17.3, §23.1, AC-02, AC-14)

### T5.12 — kernel/: session orchestration (generic turn engine) + prompt assembly (memory/skill/tool-result injection)

**Scope:** გენერიკული turn engine, რომელსაც interactive loop (T5.01) და ორივე mode იყენებს: user input → immutable `intent_record` → CLASSIFY (`task_type ∈ {coding, tutor, sysinfo, memory, skill, meta}` §4.2-ით) → GROUND (read cap-ით) → PLAN → provider turn (T3.08 contract-ზე) — ყველა გადასვლა T2.07 state machine-ის pure guard-ებით; და prompt assembly, რომელიც აყენებს provider message list-ს: memory retrieval (T4.08, top-k ≤ 8), skill context (T4.12), wrapped tool results (§6.5 contract, §4.6 delimiters T2.11 `wrap_untrusted`/`defang`-ით) — ყველა untrusted block მხოლოდ user-role-ში, provenance label-ით (§4.6 rule 3).

**Files:** `lsassist/src/lsassist/kernel/session.py`, `lsassist/src/lsassist/kernel/prompt.py`, `lsassist/tests/unit/kernel/test_session.py`, `lsassist/tests/unit/kernel/test_prompt.py`, `lsassist/tests/integration/kernel/test_session_turn.py`

**Depends on:** T1.11, T2.07, T2.11, T3.08, T4.08, T4.12

**RED (tests first):** (1) `test_session.py`: `SessionEngine.on_user_turn(text)` → `intent_record` frozen capture → CLASSIFY deterministic table-ით (§4.2-ის ექვსი task_type ზუსტად; unknown → `meta` fallback არა — explicit `BLOCKED` with reason); state transitions strictly §4.2 transition table-ით — property test (Hypothesis): generated event sequences არასდროს აღწევს EXECUTE-ს POLICY_CHECK-ის გარეშე (T2.07 guards re-assertion session level-ზე); GROUND `ground_read_cap=40` enforcement (41-ე read attempt → transition refused); თითო stage audit event §4.2 side-effect სვეტით (`intent`, `ground`, `plan_revision` — T4.02 writer mock); provider turn მხოლოდ T3.08 base adapter contract-ზე (mock provider; structural: kernel/session-ში არავითარი HTTP/provider-specific import); provider unavailable → BLOCKED path verdict-ით; (2) `test_prompt.py`: `assemble_prompt(ctx)` — memory hits (T4.08 mock) ინექცირდება `<<<UNTRUSTED_DATA … source="memory:…">>` block-ად, user-role, top-k ≤ 8 assertion; skill context (T4.12 mock) იგივე rule-ით, `permission_class_max` hook propagation `PolicyContext.skill_ceiling`-ში; tool results (§6.5 shape) იფუთება T2.11 `wrap_untrusted`-ით, embedded delimiter-like strings defanged insert-მდე; **never system-role** — structural assertion: assembled message list-ში არცერთი system message არ შეიცავს untrusted block-ს; ახალი external content turn-ში → `untrusted_turn=True` flag PolicyContext-ში (T1.11 contract); message order deterministic (snapshot test: identical ctx → identical list); token-budget truncation rule: oldest memory hits ჯერ იშლება, skill integrity fields არასდროს (documented constant); (3) `test_session_turn.py` (integration): scripted სრული turn — user text → classify `coding` → ground (mock reads) → plan → provider turn (mock adapter) → well-formed `ToolRequest` emission dispatch pipeline-ისთვის (T3.02 interface, ამ task-ის scope-ის გარეშე); denial path: provider down → BLOCKED + audit trail სრული. ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/kernel/test_session.py tests/unit/kernel/test_prompt.py tests/integration/kernel/test_session_turn.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `session.py`: `SessionEngine` — `on_user_turn(text) -> TurnResult`: intent capture (frozen record + digest), CLASSIFY (deterministic task_type table: declared mode signals + keyword rules, §4.2), T2.07 state machine driver (guard call ყოველ transition-ზე, side effects მხოლოდ §4.2 სვეტით), stage delegates: ground → registry read-only dispatch (cap counter), plan → provider turn T3.08 contract-ით, tool request handoff dispatch pipeline-ზე (interface only); `prompt.py`: `assemble_prompt` — system message = base policy text მხოლოდ (static, untrusted-free), user-role context blocks fixed order-ით (memory → skills → tool results), თითო block T2.11 wrap + defang-ით provenance tier label-ით; `untrusted_turn` detection (ახალი external content ბოლო turn-ის შემდეგ) → PolicyContext flag; truncation policy documented constant-ით.

**Expected results:** ≥20 test case green; never-system-role structural assertion green; state-machine property test green (EXECUTE მხოლოდ POLICY_CHECK-ის გზით); prompt snapshot deterministic; provider-agnostic code (structural).

**Verification:** ზედა pytest command green; `~/.local/share/lsassist/venv/bin/python -m mypy --strict src/lsassist/kernel` clean; `~/.local/share/lsassist/venv/bin/python -m ruff check src/lsassist/kernel tests/unit/kernel tests/integration/kernel` clean; kernel/ TCB-შია — T2.13 coverage gate იღებს ახალ მოდულებს (100% branch მიზნად session/prompt guard-ებზე). Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) CLASSIFY table ზუსტად §4.2-ის ექვს task_type-ს შეესაბამება, silent fallback-ის გარეშე; (2) prompt assembly-ში system-role injection path სტრუქტურულად არ არსებობს (code read); (3) session engine provider-agnostic-ია — მხოლოდ T3.08 contract, არავითარი Kimi/Ollama import.

**Rollback:** `rm -f lsassist/src/lsassist/kernel/session.py lsassist/src/lsassist/kernel/prompt.py lsassist/tests/unit/kernel/test_session.py lsassist/tests/unit/kernel/test_prompt.py lsassist/tests/integration/kernel/test_session_turn.py` — cli/ და mode ფაილები უვნებელი რჩება (T5.01 loop კვლავ callback interface-ზეა).

(SPEC §4.1, §4.2, §4.6, §6.5, §9.4, §10.3)

### T5.13 — lab/: LAB skeleton (proposal → worktree → draft → suites → evidence → diff+rollback → HALT)

**Scope:** §11.2 LAB pipeline-ის skeleton ზუსტად ამ რიგით: structured proposal record → isolated `git worktree` (T3.05-ის `git.worktree` tool-ით) + branch `lab/<id>` → draft (code/skill/policy text) **იგივე tool/permission rules-ით** (არავითარი LAB პრივილეგია) → full test suite + security suite worktree-ში → static checks (lint, type, `pip-audit` თუ deps შეიცვალა) → before/after evidence frozen evals-ით (§11.4 hash-pinned snapshot) → human-readable diff + rollback plan → **HALT** (report verdict-ით; activation path არ არსებობს ამ pipeline-ში). Plus §11.3 hard prohibitions-ის enforcement hooks: policy artifacts და `tests/evals/**` LAB worktree-ში immutable (write attempt → DENY_ALWAYS), LAB-ში გაცემული tokens scoped მხოლოდ LAB worktree canonical path-ებზე, self-install-tree (`$XDG_DATA_HOME/lsassist/venv/**`) writes DENY_ALWAYS. Feature gate: მთლიანი მოდული inert-ია `lab.enabled=false`-ზე (§11.1, activation T5.14-ით).

**Files:** `lsassist/src/lsassist/lab/__init__.py`, `lsassist/src/lsassist/lab/proposal.py`, `lsassist/src/lsassist/lab/pipeline.py`, `lsassist/src/lsassist/lab/report.py`, `lsassist/tests/lab/test_proposal.py`, `lsassist/tests/lab/test_pipeline_steps.py`, `lsassist/tests/lab/test_report.py`

**Depends on:** T1.08 (`lab.enabled` config field), T2.07, T3.05, T4.11, T5.12

**RED (tests first):** (1) `test_proposal.py`: `Proposal` frozen record `{id, description, rationale, expected_benefit, risk_notes}` — ყველა field required, missing → validation error; submit → audit `lab_proposal` event (T4.02 mock); `lab.enabled=false`-ზე ნებისმიერი LAB entry point → `LabDisabled` raise (feature gate §11.1 — pipeline constructor-ც); (2) `test_pipeline_steps.py`: step order state machine-ით (T2.07-style pure guards) — step გამოტოვება rejected (draft worktree-მდე → error; suite draft-ის გარეშე → error; evidence suite-ის გარეშე → error); worktree creation მხოლოდ `git.worktree` tool dispatch-ით (structural: `lab/`-ში არავითარი direct subprocess/git call); branch name exactly `lab/<proposal_id>`; draft stage PolicyContext იდენტურია normal session-ისთვის — privilege probe: LAB context-ში grant-ების diff = 0 (structural assertion); suite stage full test suite + security suite worktree cwd-ში (dispatch log assertion); static checks: lint+type ყოველთვის, `pip-audit` მხოლოდ dependency manifest/lock change-ზე (diff-driven); frozen evals: eval snapshot hash-pinned run-ის დასაწყისში, mid-run change detection → HALT with error (§11.4); **final state HALT — pipeline state enum-ში activation/apply member არ არსებობს** (structural: enum absence assertion, AC-15) და HALT-დან გამავალი transition არ არის; (3) `test_report.py`: HALT report schema exactly §11.4: `{proposal_id, files_changed, test_delta, benchmark_delta, security_suite_result, rollback_steps}` — missing field → validation error; human-readable diff render; rollback plan steps non-empty; report persist + audit `lab_halt` event append-only. ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/lab -q` — მარცხდება ახალი მოდულების არარსებობით.

**GREEN (implementation):** `proposal.py`: frozen `Proposal` model + uuid id + audit emit; `pipeline.py`: `LabPipeline` — state enum (`proposal → worktree → draft → suite → static → evidence → diff → halt`) + pure guard-ები T2.07 pattern-ით; step delegates: worktree → T3.05 dispatch (branch `lab/<id>`, path constraint-ით), draft → T5.12 session engine worktree-scoped session-ში (LAB tokens მხოლოდ worktree canonical path binding-ით, §11.3 — token scope T2.03 mint-ში record path-ებით), suites → `test.run` dispatch worktree cwd-ში, static checks → ruff/mypy read-only invocations + conditional `pip-audit`, evidence → frozen eval snapshot runner (hash-pin ჯერ, run მერე), diff → git diff render; §11.3 hooks: LAB worktree-ში policy files / `tests/evals/**` / install-tree path-ები register-დება არსებული DENY_ALWAYS classifier rule-ების scope-ში (ახალი policy engine არა — R7/extension assertion integration test-ით); skill drafts = ფაილები LAB worktree-ის შიგნით, რომლებიც T4.11-ის skill lifecycle-ში არასდროს რეგისტრირდება (lifecycle-ში `draft` state არ არსებობს და არ ემატება — §9.3 transition table უცვლელი რჩება); `report.py`: `LabReport` pydantic model §11.4 schema-ით + renderer + audit.

**Expected results:** pipeline step order 100% enforced (generated stage sequences-ზე invalid order rejected); activation state enum-ში 0 (AC-15); `lab.enabled=false`-ზე 0 LAB functionality reachable; §11.3 prohibition hooks 3/3 classifier-backed; ≥16 test case; T6.05-ის reachability/immutability tests ამ იმპლემენტაციაზე შესრულდება.

**Verification:** ზედა pytest command green; `~/.local/share/lsassist/venv/bin/python -m mypy --strict src/lsassist/lab` clean; `~/.local/share/lsassist/venv/bin/python -m ruff check src/lsassist/lab tests/lab` clean; manual: tmp repo-ში proposal → HALT walk-through isolated config-ით (`lab.enabled=true`) — worktree branch `lab/<id>` არსებობს, main tree unmutated (hash assertion). Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) activation path-ის არარსებობა — state enum + transitions code read (AC-15); (2) LAB არ იღებს პრივილეგიას — PolicyContext parity assertion მტკიცებულებით; (3) §11.3-ის prohibition hooks (policy/evals immutability, token path scoping, install-tree guard) ყველა classifier-ზეა დაყრდნობილი, არა LAB-ის საკუთარ ლოგიკაზე; (4) HALT report schema verbatim §11.4.

**Rollback:** `rm -rf lsassist/src/lsassist/lab; rm -f lsassist/tests/lab/test_proposal.py lsassist/tests/lab/test_pipeline_steps.py lsassist/tests/lab/test_report.py` — T6.05-ის test ფაილები უვნებელი რჩება (ისინი კვლავ red რჩებიან implementation-ის გარეშე).

(SPEC §11.1, §11.2, §11.3, §11.4, §20, AC-15, AC-16)

### T5.14 — config/: gated runtime config writes (`lab.enabled` activation) + workspace registration (`workspaces.toml`)

**Scope:** Runtime config write path CONFIRM_EXACT gate-ით §11.1-ით (`lab.enabled` activation = CONFIRM_EXACT + config write; config writes themselves CONFIRM_EXACT — ორსაფეხურიანი gate) და workspace registration command §12.1-ით (`workspaces.toml` add/remove, canonical paths, CONFIRM_EXACT write-guard). ყოველი მიღებული write audit-ირდება `config_change` event-ით (§14.1); writes atomic და permission-preserving (0600, T1.07).

**Files:** `lsassist/src/lsassist/config/runtime_write.py`, `lsassist/src/lsassist/cli/commands_config.py`, `lsassist/src/lsassist/cli/entry.py` (amendment: T5.04-ის stub → real wiring + session-start LAB banner hook), `lsassist/tests/unit/config/test_runtime_write.py`, `lsassist/tests/unit/cli/test_commands_config.py`, `lsassist/tests/integration/cli/test_config_workspace.py`

**Depends on:** T1.08, T2.03, T4.02, T5.04

**RED (tests first):** (1) `test_runtime_write.py`: `gated_config_write(key, value, token)` — schema validation T1.08-ით (unknown key → reject; type mismatch → reject); **valid CONFIRM_EXACT token-ის გარეშე write არ ხდება** — negative: file bytes unchanged (fs tree hash assertion), token verify T2.03-ით re-canonicalization-ჩათვლით (mutated record → reject); write atomic (tmp+fsync+rename — crash simulation: partial tmp file არ რჩება canonical path-ზე); permissions 0600 re-asserted write-ის შემდეგ (T1.07 check); `lab.enabled=true` → CONFIRM_EXACT + write, შემდეგ `lab_banner_active(config)` true (§11.1 session banner contract T5.01 loop-ისთვის); ყოველი accepted write → audit `config_change` `{key, old_digest, new_digest}` — digests, not values (redaction T4.01 pass-ით); (2) `test_commands_config.py`: `config set lab.enabled true` → flow: old→new diff render (T5.03) → CONFIRM_EXACT approval prompt canonical record-დან → token mint → write → confirmation output; `workspace add <path>` / `workspace remove <path>` → canonicalization fail-closed (nonexistent path → reject; symlink → reject; `..` → reject — T2.02), `workspaces.toml` update იგივე CONFIRM_EXACT gate-ით; duplicate add → no-op explicit message-ით; non-TTY prior token-ის გარეშე → refuse exit 3; (3) `test_config_workspace.py` (integration, tmp XDG): სრული chain — `config set` approval-ით → `config.toml` updated, schema კვლავ valid, perms 0600, audit hash-chain intact + `config_change` present; `workspace add` → T2.02 canonicalization ახალ workspace-ს ხედავს; tampered token → write rejected, file unchanged; `lab.enabled=true` write-ის შემდეგ შემდეგი session banner active. ბრძანება: `~/.local/share/lsassist/venv/bin/python -m pytest tests/unit/config/test_runtime_write.py tests/unit/cli/test_commands_config.py tests/integration/cli/test_config_workspace.py -q` — მარცხდება `ModuleNotFoundError`-ით.

**GREEN (implementation):** `runtime_write.py`: `gated_config_write(key, value, approval_token)` — strict order: token verify (T2.03) → schema validate (T1.08) → atomic write (tmp file იმავე dir-ში, fsync, rename) → perms enforce 0600 → audit `config_change` (T4.02) — write call მხოლოდ verify-ის შემდეგ (structural: no pre-verify write path); `WorkspaceRegistry` — `workspaces.toml` load/save (canonical paths only T2.02-ით), add/remove იგივე gate-ით; `lab_banner_active(config)` helper session banner-ისთვის; `commands_config.py`: thin CLI adapters T5.04-ის pattern-ით — argparse subparsers (`config set`, `workspace add|remove`) → diff render → CONFIRM_EXACT approval flow (T2.03 mint prompt-ის დადასტურების შემდეგ) → runtime_write call; `lab.enabled` activation explicit-ად დოკუმენტირებული ორსაფეხურიანად (§11.1: activation prompt + config write itself CONFIRM_EXACT); `cli/entry.py` amendment: T5.04-ის `config`/`workspace` dispatch stub-ების real wiring-ით ჩანაცვლება + session-start hook — loop-ის გაშვებაზე `lab_banner_active(config)` true-ის შემთხვევაში LAB banner-ის რენდერი (§11.1 "LAB active = session banner" — owner ეს task-ია, banner text static, untrusted-free).

**Expected results:** write-without-valid-token 0 შემთხვევა (ყველა negative path file-unchanged assertion-ით); audit `config_change` accepted writes-ის 100%-ზე; workspace canonicalization fail-closed 3/3 vector; atomic write crash test clean; ≥16 test case.

**Verification:** ზედა pytest command green; `~/.local/share/lsassist/venv/bin/python -m mypy --strict src/lsassist/config src/lsassist/cli` clean; `~/.local/share/lsassist/venv/bin/python -m ruff check src/lsassist/config src/lsassist/cli tests/unit/config tests/unit/cli tests/integration/cli` clean; manual: isolated XDG env-ში `lsassist config set lab.enabled true` walk-through → banner შემდეგ run-ზე + audit trail. Pass criteria: ყველა exit 0.

**Review checkpoint:** ადამიანი ამოწმებს: (1) არ არსებობს code path, რომელიც config-ს token verification-ის გარეშე წერს (code read — write მხოლოდ verify-ის შემდეგ); (2) `config_change` payload digests-ს შეიცავს, არა secrets/values-ს; (3) §11.1-ის ორსაფეხურიანი activation flow ხელით ნაცადი; (4) `workspaces.toml` entry-ები მხოლოდ canonical paths-ია.

**Rollback:** `rm -f lsassist/src/lsassist/config/runtime_write.py lsassist/src/lsassist/cli/commands_config.py lsassist/tests/unit/config/test_runtime_write.py lsassist/tests/unit/cli/test_commands_config.py lsassist/tests/integration/cli/test_config_workspace.py; git checkout -- lsassist/src/lsassist/cli/entry.py 2>/dev/null` — `config`/`workspace` subcommand-ები უბრუნდებიან stub მდგომარეობას.

(SPEC §11.1, §12.1, §12.2, §14.1, §7.4)


---

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


---

