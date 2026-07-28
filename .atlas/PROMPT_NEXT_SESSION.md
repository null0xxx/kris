# LinuxSec — next-session prompt (paste everything below the line as one message)

> **How to use.** Open a new session at `/home/null/Desktop/LinuxSec` (the git root,
> **not** `lsassist/`) and paste everything below the line as a single message.
>
> Written 2026-07-28 at commit `e2e7522`, after T3.03. Every number below is a
> **HYPOTHESIS TO FALSIFY**, never a fact to trust — §1 says why.

---

ვმუშაობთ პროექტზე `/home/null/Desktop/LinuxSec` (git root). ქართულად ვსაუბრობთ.

## 0. სამი წესი, რომელიც ყველაფერზე მაღლა დგას

1. ამ მანქანაზე `gentle-ai`/ecosystem დაყენებულია, მაგრამ **ამ პროექტში `sdd-*`
   skill-ებს ნუ გამოიყენებ.** `SPEC.md` და `IMPLEMENTATION_PLAN.md` **გაყინულია**
   და ერთადერთი ავტორიტეტული წყაროა.
2. **engram-ში მხოლოდ მდგრადი ფაქტები.** venv-ის გზა, bare-pytest-ის ნიუანსი, CI
   job-ები, TCB LOC ზღვრები, review-loop-ის ქცევა. **პროგრესის რიცხვები არასოდეს** —
   git არის ჭეშმარიტების წყარო და ყოველ სესიაზე თავიდან იზომება.
3. **კრიტიკოსების ეტაპზე იზოლირებული ქვე-აგენტები:** `review-risk`,
   `review-reliability`, `review-resilience`, `review-readability` — თითოეული
   მხოლოდ {frozen intent, ერთი diff, ერთი ლინზა, floors} ხედავს, **არასოდეს
   სხვისი findings**. მერე `review-refuter` findings-ების შესამოწმებლად.

## 1. ჯერ გაზომე — არ დაიწყო კოდის წერა

1. `git log --oneline -8` — **git არის ჭეშმარიტების წყარო**, თუ ledger-ს ეწინააღმდეგება.
   მოსალოდნელი HEAD: `e2e7522` (`docs:`), მის ქვეშ `d4f12c7` (`T3.03`).
2. წაიკითხე `.atlas/GATE4_PROGRESS.md` — Gate-4-ის ავტორიტეტული ledger.
3. **თვითონ გაზომე ყველა floor.** ნუ ენდობი დოკუმენტირებულ რიცხვს:

```bash
cd /home/null/Desktop/LinuxSec/lsassist
V=~/.local/share/lsassist/venv/bin     # ADR-005: venv is NOT in the repo

$V/python -m pytest                     # bare! `pytest -q` yields -qq (addopts already
                                        # has -q) and SUPPRESSES the pass/fail summary
$V/python -m ruff check src tests
for p in contracts config policy sandbox kernel audit; do $V/python -m mypy --strict src/lsassist/$p; done
$V/python -m mypy --strict src/lsassist/tools/dispatcher.py
$V/python -m mypy --strict src/lsassist/tools/result.py
python3 scripts/loc-count --manifest scripts/tcb-loc-manifest.txt --target 6000 --hard-stop 8000

# §23.1 package floor
$V/python -m coverage run --branch \
  --source=src/lsassist/kernel,src/lsassist/policy,src/lsassist/sandbox,src/lsassist/audit \
  -m pytest tests/unit tests/property && $V/python -m coverage report

# the TWO TCB files inside a non-TCB package (§2.3) — their own blocking job
$V/python -m coverage run --branch \
  --source=lsassist.tools.dispatcher,lsassist.tools.result \
  -m pytest tests/unit/tools && $V/python -m coverage report
```

**მოსალოდნელი (გაზომილი 2026-07-28, `d4f12c7`):** pytest **2632 passed, 0 failed** ·
ruff clean · `mypy --strict` clean (contracts 12 · config 7 · policy 8 · sandbox 5 ·
kernel 8 · audit 4 · dispatcher 1 · result 1) · **TCB LOC 5359 / 6000** (hard stop
8000) · **100% branch, 0 partial, 0 pragmas** ორივე იატაკზე · CI **7 job**
(`ruff`, `unit`, `loc-count`, `tcb-loc`, `coverage`, `dispatcher-coverage`,
`integration`).

**თუ რომელიმე რიცხვი არ ემთხვევა — გაჩერდი და მომახსენე.** ნუ ააშენებ აუხსნელ delta-ზე.

## 2. სად ვართ

- **30 / 70 task.** Phase 1 ✅ (11/11) · Phase 2 ✅ (13/13) · Phase 3: 4/14 ·
  Phase 4: 2/12 · Phase 5: 0/14 · Phase 6: 0/6
- აშენებული: `contracts` `config` `policy` `sandbox` `kernel` `audit`,
  `tools` (registry + dispatcher + result), `providers` (base)
- ცარიელი scaffold: `recovery` `memory` `skills` `tutor` `coding` `cli`
- **`lsassist` ჯერ არ ეშვება** — `__main__.py` არის T1.02-ის stub. ეს არაა
  დეფექტი; §2.2-ის dependency direction-ია. შეკრების წერტილები: **T3.02+T3.03
  dispatcher** (გაკეთდა) და **T5.12 session engine**.
- `main` == `origin/main` == `e2e7522`

## 3. შემდეგი frontier

გამოთვალე **თვითონ**, `IMPLEMENTATION_PLAN.md`-ის `Depends on` გრაფის ტრანზიტული
ჩაკეტვით — რიგი **ტოპოლოგიურია**, არა ფაზების მიხედვით. `e2e7522`-ზე მზადაა
**ექვსი**:

| Task | რა | რატომ ახლა |
|---|---|---|
| **T3.04** | read-only tool batch: `fs.read` `fs.list` `fs.find` `sys.info` `pkg.query` `git.read` | **პირველი task რეალური handler-ებით**, და T3.03-ის დასახელებული ვალდებულების მფლობელი. ხსნის T3.05→T3.06→T3.07-ს |
| T3.09 / T3.11 | Kimi / Ollama adapter | T3.08-ზეა დამოკიდებული, დამოუკიდებელი შტოა |
| T4.03 | audit reader (`lsassist audit show`) | T4.02-ზეა |
| T4.04 / T4.07 / T4.10 | recovery checkpoint / memory store / skills loader | T4.02 (+T2.02/T1.07/T2.01) |

**რეკომენდაცია: T3.04.** ის ხურავს ჯაჭვს, რომელზეც ყველაზე მეტი რამაა
დამოკიდებული, და ის არის ერთადერთი, ვინც T3.03-ის cross-phase ვალდებულებას ფლობს.

### T3.04 ატარებს ჩაწერილ ვალდებულებებს — შეამოწმე თითოეული

- **§7.5 step 6 write-only-ია (SPEC:564).** T3.03 read/exec tool-ებზე
  `Verification.NOT_APPLICABLE`-ს აბრუნებს — **განზრახ**, რომ ხარვეზი
  **დასახელებული** დარჩეს და არა pass-ად შენიღბული. **T3.04-მა უნდა დახუროს:**
  handler-მა `os.open(path, O_NOFOLLOW|…, dir_fd=canonical_parent)` უნდა გააკეთოს
  და მერე **იმავე fd-ს** `fstat`-ი approval-დროინდელ node identity-ს შეადაროს
  (`normalized.path_snapshots`-ში უკვე დევს). სხვაგვარად same-path file-swap
  TOCTOU ღიად რჩება.
- **canary honeyfiles (§19 scenario 1).** `fs.read` T1.07-ის `canary_registry()`-ს
  (path + sha256) უნდა შეამოწმოს; honeyfile-ზე read → `CANARY_TRIPPED`, session
  freeze, audit alert, **content არასოდეს ბრუნდება**.
- **§7.3 DENY handler-side double-check.** dispatcher უკვე ამოწმებს, მაგრამ §7.5
  ჯაჭვი ორმაგ შემოწმებას ითხოვს.
- `fs.read`: utf-8 `errors=replace`, binary → hex head ≤ 4 KB.
- ყველა manifest: class `AUTO_READ`, caps/limits **§6.4 ცხრილიდან verbatim**.

### T3.03-ის დასახელებული residual-ები, რომლებიც T3.04/T3.06-ს ეხება

- **§6.4-ის `test.run` ამჟამად საერთოდ არ dispatch-დება.** ის `write_scoped`-ია
  argv-ით და **path არგუმენტის გარეშე** — ზუსტად ის ფორმა, რომელსაც T3.02-ის
  guard უარყოფს („declares capabilities.fs=write_scoped but no path_args were
  declared"). **T3.06-ის საზღვარია:** ან target გამოცხადდეს, ან guard-ს დასჭირდეს
  „write_scoped without a declared target" carve-out.
- **§7.2 R2 უშვებს დამტკიცებულ workspace-გარე write-ს, რომელსაც V1-ის არცერთი
  პროფილი ვერ გამოხატავს.** T3.03 step 5-ზე უარყოფს `workspace_scope`-ით. სრული
  გადაწყვეტა §7.2 ან §8 SPEC-ცვლილებაა — **ჩემი თანხმობით**.
- **§6.5-ს ერთი `evidence` ობიექტი აქვს**, ანუ multi-path write tool მხოლოდ
  პირველი სამიზნის snapshot-ს აქვეყნებს.
- **§6.5-ს არ აქვს „პროცესი არ გაშვებულა" ფორმა**: BLOCKED შედეგი `exit_code=0`-ს
  წერს და აზრს `status=error` + `error.kind` ატარებს.
- ბავშვს `LC_ALL`/`TERM` არ ეძლევა, თუმცა §8.3 უშვებს — T3.02-მა `env_digest`
  მათ გარეშე დააკავშირა.
- `create_if_missing` მოითხოვს `fs=write_scoped`-ს, მაგრამ manifest ვერ არჩევს
  `fs.write`-ს (ქმნის) `fs.patch`-ისგან (არ ქმნის) — T3.04/T3.05-ის საზღვარია.
- dispatcher-ის token-შემოწმება **pre-filter**-ია, არა I15 gate:
  `machine._g_valid_token`-ის 4 პირობიდან 2-ს ამოწმებს; consent liveness და §4.7
  replay verdict kernel-ის მდგომარეობაა (T5.12).

## 4. როგორ ვმუშაობთ (სავალდებულო)

**თითო task:** ground → **RED first** (აჩვენე ჩავარდნილი output) → GREEN →
დეტერმინისტული floors → **იზოლირებული ადვერსარიული კრიტიკოსები** → refute →
refine ≤2 → **მუტაციები** → commit.

### მწვანე სუიტა არაფერს ამტკიცებს — ოთხი პრეცედენტი

ამ პროექტზე **ოთხჯერ** თანაარსებობდა 100% branch + `mypy --strict` + CRITICAL:

- **T4.01:** 86 მწვანე ტესტი, 100% branch — GPG კერძო გასაღები სრულიად გაუშიფრავი
- **T3.02:** მწვანე სუიტა — §7.3-ის აბსოლუტური DENY symlink-ით შემოვლილი
- **T4.02:** მწვანე სუიტა — U+2028 ერთ record-ს ორ ხაზად ყოფდა
- **T3.03:** მწვანე სუიტა, 100% branch, 0 partial — და **ოთხი CRITICAL**:
  wall-clock timeout სრულიად გვერდით ავლილი (`timeout_s=1` → დაბრუნდა **20.00
  წამში**), მოდელის argv env-სინტაქსად წაკითხული (`IndexError`, უტიპო, audit-ის
  გარეშე), და **ორი უაudit-ო გაქცევა** უკვე გაშვებული tool-ის შემდეგ.

Coverage **შესრულებას** ზომავს, არა **მტკიცებას** (ADR-011-ის საკუთარი „Named
limitation"). ხაზი სრულდებოდა; უბრალოდ ვერცერთი შემავალი მას სწორ პასუხს არ სთხოვდა.

### T3.03-ის ახალი გაკვეთილები — გამოიყენე ისინი

- **ჩავარდნის ერთი ფორმა red-ი არაა.** T4.02-ზე FIFO-მ სუიტა **ჩაკიდა**. T3.03-ზე
  timeout-ის დეფექტი **ჩაკიდებით** ვლინდებოდა, არა წითლით. ყოველ spawn-იან ტესტს
  **საკუთარი ზღვარი** დაუწესე და გაზომე რეალური elapsed time.
- **substring-grep-ით დაწერილი „N call site" ტესტი უსარგებლოა injected default-ზე.**
  `grep 'spawn_capped('` `src/`-ში მხოლოდ **`def`-ს** იჭერდა, რადგან რეალური
  გამოძახება `runner(...)`-ია. ნულ caller-ზეც გაივლიდა. **გამოიყენე `ast.walk`**
  (`ast.Name`/`ast.Attribute`/`ast.ImportFrom`) და **სიმრავლეთა ტოლობა** (`==`,
  არა `<=`), რომ სანქცირებული მითითების გაქრობაც ჩავარდეს.
- **გარანტია სტრუქტურული გახადე, არა დოკუმენტირებული.** `run()`-ის `audit`
  არჩევითი იყო → „ყოველი გაშვება ჩაწერილია" იმის თვისება ხდებოდა, ვინც არგუმენტი
  გაიხსენა. ახლა სავალდებულოა. იგივე იდიომია `compose_exec_argv`-ის receipt-ი.
- **ყოველი `except`-ის მიმართულება გადაამოწმე.** T3.03-ის სამი CRITICAL-იდან
  ორი იყო „კოდი მხოლოდ იქ იცავს, სადაც შეცდომას ველოდი".
- **ყოველი material claim თვითონ რეპროდუცირე.** R4-ის HIGH („bwrap-ის
  `--new-session` პროცესს killed group-იდან აშორებს") **გაზომვით გაბათილდა**:
  3 sleeper რეალურ sandbox-ში, `timeout_s=2` → 2.00 წამი, rc 137, ნული გადარჩენილი.
- **ყოველი შესწორების შემდეგ mutation.** T3.03-ზე 7 fix → 7 mutant → 7 killed.
  ადრე გადარჩენილმა mutant-მა **ორჯერ** გამოააშკარავა არასრული შესწორება.

### ოპერაციული ნიუანსი კრიტიკოსებზე

`review-risk`, `review-readability` და `review-resilience` თავიანთ prompt-ში
`GENTLE_AI_REVIEW_BINDING`-ს ეძებენ (`subject_hash`, `lineage_id`, …). მისი
გარეშე ისინი **ჩერდებიან** native JSON-ის გამოცემამდე და findings-ს **პროზად**
აბრუნებენ. findings გამოსადეგია — უბრალოდ preamble-ს ელოდე და გაშვება
წარუმატებლად ნუ ჩათვლი. `review-reliability` და `review-refuter` სუფთა სიას
აბრუნებენ.

### წესები, რომლებიც არ იცვლება

- **ნუ გააფართოვებ scope-ს ჩუმად.** სხვისი task-ის ფაილში დეფექტი → გაასწორე შენი,
  **დაასახელე** residual კოდის docstring-ში + ledger-ში. ცალკე `HARDEN-NN:` commit
  საჭიროებს ჩემს თანხმობას (პრეცედენტი: HARDEN-01…04).
- **ნურც შეავიწროვებ:** ცნობილი credential ფორმატის გაუშიფრავად დატოვება უარესია,
  ვიდრე დოკუმენტირებული საზღვრის გადაჭიმვა.
- **თითო task = თითო commit** `Tx.yy: …` სტილით. Rollback-ის ერთეულია. საერთო
  ფაილები (`pyproject.toml`, `ci.yml`, `tcb-loc-manifest.txt`) hunk-ებად გაყავი.
- **Review checkpoint commit-ის ტექსტში მიდის** (RED evidence · floors · critics ·
  mutations · residuals). ნუ გაჩერდები task-ებს შორის ნებართვის სათხოვნელად —
  კითხე მხოლოდ მაშინ, თუ ორი წაკითხვა არსებითად სხვა სამუშაოს იძლევა.
- **Push მხოლოდ ცალკე თხოვნით.** Remote `github.com/null0xxx/kris` **private**-ია.
- `SPEC.md` და `IMPLEMENTATION_PLAN.md` **გაყინულია** — არასოდეს შეცვალო ტესტის
  გასამწვანებლად. SPEC-ის შეცვლა მხოლოდ: **გაზომილი** კორექცია + ჩემი თანხმობა +
  revision table (პრეცედენტი: §8.1 HARDEN-03-ის შემდეგ).
- **არასოდეს** განაახლო `.atlas/session_3056019e-…` — დასრულებული, hash-chained
  Gate-3 ledger-ია (`current_state: OUTPUT`, terminal).

## 5. წვრილმანი, რომელიც დროს გიშველის

- **`/tmp` sandbox-ისთვის აკრძალულია.** §8.1 მას tmpfs-ით ფარავს, ამიტომ
  `build_argv` უარყოფს `/tmp`-ის ქვეშ მყოფ workspace-ს. pytest-ის `tmp_path`
  **არ გამოდგება** sandbox-იან ტესტში — გამოიყენე `~/.cache/lsassist/<uuid>/ws`
  cleanup-ით (იხ. `tests/unit/tools/test_dispatch_execute.py`-ის `workspace` fixture).
- **`sh -c env` ბავშვის env-ს ვერ ზომავს** — shell თვითონ სვამს `PWD`-ს.
  გამოიყენე `/bin/cat /proc/self/environ`.
- **§7.2-ის R4 ყოველ shell-metachar-იან argv-ს CONFIRM_EXACT-ზე აწევს.** integration
  ტესტებში `|`/`>`/`&` ნიშნავს, რომ **რეალური token უნდა მოჭრა** (იხ.
  `tests/integration/tools/test_dispatch_sandbox.py`-ის `proceeding`).
- `tests/contract/`, `tests/integration/`, `tests/e2e/` **უნდა გაუშვას CI-მ.**
  `tests/unit/scripts/test_coverage_gate.py`-ში `CI_JOBS` **ზუსტი ტოლობითაა**
  დაპინული — ახალი job მისი განახლების გარეშე წითლდება. იქვეა layer-ების პინი.
- პროექტის root-ში შეიძლება გაჩნდეს `.atl/` — plugin-ის skill-registry cache.
  **არაა** პროექტის ნაწილი; root-ის `.gitignore` მას უკვე ფარავს.

---

დაიწყე §1-ის გაზომვით და §3-ის frontier-ის დადასტურებით, მერე გააგრძელე **T3.04**-ით.
