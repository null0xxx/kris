# LinuxSec — next-session prompt (paste everything below the line as one message)

> **How to use.** Open a new session at `/home/null/Desktop/LinuxSec` (the git root,
> **not** `lsassist/`) and paste everything below the line as a single message.
>
> Written 2026-07-30 at commit `d98851e`, with **T4.04 uncommitted on disk and
> already corrected**. Every number below is a **HYPOTHESIS TO FALSIFY** — §1 says why.

---

ვმუშაობთ პროექტზე `/home/null/Desktop/LinuxSec` (git root). ქართულად ვსაუბრობთ,
რეპოს ყველა artifact ინგლისურად.

## 0. ოთხი წესი, რომელიც ყველაფერზე მაღლა დგას

1. **`gentle-ai` პლაგინი სავალდებულოდ და სრულფასოვნად გამოიყენე.** ის დაყენებულია
   (`gentle-ai 2.2.0`, `review mode: on`). **ყოველი task-ის candidate გაივლის native
   review-ს:** `review start` → იზოლირებული 4R ლინზები → `capture-result` → საჭიროებისას
   `review-refuter` → `capture-evidence` → `finalize` → `validate --gate pre-commit`.
   Receipt-ის გარეშე commit **არ ხდება** — გამონაკლისი მხოლოდ შენი ცალსახა
   `explicit-maintainer-action`-ია, და ის commit-ის ტექსტში პირდაპირ იწერება.
   **მაგრამ `sdd-*` skill-ებს ამ პროექტში ნუ გამოიყენებ** — `SPEC.md` და
   `IMPLEMENTATION_PLAN.md` **გაყინულია** და ერთადერთი ავტორიტეტული წყაროა; SDD
   მათ პარალელურ, კონკურენტ artifact-ებს შექმნიდა. ანუ: **review machinery დიახ,
   SDD phases არა.**
2. **engram-ში მხოლოდ მდგრადი ფაქტები.** venv-ის გზა, bare-pytest-ის ნიუანსი, CI
   job-ები, TCB ზღვრები, review-ის ზუსტი ინვოკაცია. **პროგრესის რიცხვები
   არასოდეს** — git არის ჭეშმარიტების წყარო და ყოველ სესიაზე თავიდან იზომება.
3. **კრიტიკოსების ეტაპზე იზოლირებული ქვე-აგენტები:** `review-risk`,
   `review-reliability`, `review-resilience`, `review-readability` — თითოეული
   მხოლოდ {frozen intent, ერთი diff, ერთი ლინზა, floors} ხედავს, **არასოდეს სხვისი
   findings**. მერე `review-refuter`.
4. **`review start`-ის შემდეგ candidate-ის ფაილს ნუ შეეხები**, სანამ
   `capture-result` არ დასრულდა — რედაქტირება გაყინვას აუქმებს. ეს ამ სესიაზე
   ორჯერ დაგვიჯდა.

## 1. ჯერ გაზომე — არ დაიწყო კოდის წერა

```bash
cd /home/null/Desktop/LinuxSec && git log --oneline -6 && git status --short
```

**მოსალოდნელი HEAD: `d98851e`**, და **სამუშაო ხე არაა სუფთა** — T4.04 დისკზეა:
`recovery/{manifest,checkpoints}.py`, `tests/{unit,integration}/recovery/`, პლუს
შეცვლილი `ci.yml`, `pyproject.toml`, `test_coverage_gate.py`.

```bash
cd /home/null/Desktop/LinuxSec/lsassist
V=~/.local/share/lsassist/venv/bin     # uv-ის standalone CPython 3.12.13

$V/python -m pytest                    # bare! `-q` ორმაგდება და summary იკარგება
$V/python -m ruff check src tests
for p in contracts config policy sandbox kernel audit recovery; do $V/python -m mypy --strict src/lsassist/$p; done
$V/python -m mypy --strict src/lsassist/tools/dispatcher.py
$V/python -m mypy --strict src/lsassist/tools/result.py
python3 scripts/loc-count --manifest scripts/tcb-loc-manifest.txt --target 6000 --hard-stop 8000

# §23.1 — ხუთი პაკეტი, `recovery` T4.04-ზე შემოვიდა
$V/python -m coverage run --branch \
  --source=src/lsassist/kernel,src/lsassist/policy,src/lsassist/sandbox,src/lsassist/audit,src/lsassist/recovery \
  -m pytest tests/unit tests/property tests/integration/recovery && $V/python -m coverage report

# §2.3-ის ორი TCB ფაილი არა-TCB პაკეტში — საკუთარი blocking job
$V/python -m coverage run --branch \
  --source=lsassist.tools.dispatcher,lsassist.tools.result \
  -m pytest tests/unit/tools && $V/python -m coverage report
```

**მოსალოდნელი (გაზომილი 2026-07-30):** pytest **2921 passed, 0 failed, 0 skipped** ·
ruff clean · `mypy --strict` clean ცხრავეზე · **TCB LOC 5955 / 6000** (hard stop
8000) · §23.1 **100% branch, 0 partial** · dispatcher+result **100%** ·
`recovery` თავად **100%, pragma ნული**.

**თუ რომელიმე რიცხვი არ ემთხვევა — გაჩერდი და მომახსენე.**

⚠️ **venv არ არის რეპოში და 3.12-ია.** თუ `No module named pytest` — venv გატეხილია
დისტრიბუტივის Python-ის განახლებით. **3.14-ზე ნუ ააშენებ**: `requirements.lock`
თითო პაკეტზე თითო cp312 wheel hash-ს აპინავს და `--require-hashes` cp314-ს
სამართლიანად უარყოფს. სწორი გზა:
`uv python install 3.12 && /home/null/.local/share/uv/python/cpython-3.12-linux-x86_64-gnu/bin/python3.12 -m venv ~/.local/share/lsassist/venv`
მერე `pip install --require-hashes -r requirements.lock -r requirements-dev.lock && pip install -e . --no-deps`.

## 2. სად ვართ

- **32 / 70 task.** Phase 1 ✅ (11/11) · Phase 2 ✅ (13/13) · Phase 3: 5/14 ·
  Phase 4: 2/12 (+T4.04 დისკზე) · Phase 5: 0/14 · Phase 6: 0/6
- აშენებული: `contracts` `config` `policy` `sandbox` `kernel` `audit`, `tools`
  (registry + dispatcher + result + **handlers**), `providers` (base),
  **`recovery` (T4.04, დაუკომიტებელი)**
- ცარიელი scaffold: `memory` `skills` `tutor` `coding` `cli`
- **`lsassist` ჯერ არ ეშვება.** T3.04-ის handler-ები აშენებულია, მაგრამ
  production-ში მათ **არავინ აერთებს** — `dispatcher.run(handler=…)`-ს ტესტების
  გარეთ გამომძახებელი არ ჰყავს. შეკრების წერტილი **T5.12** (session engine).
- `main` == `origin/main` == `eeae643` (**push ჩამორჩენილია 6 commit-ით** — push
  მხოლოდ ცალკე თხოვნით)

## 3. პირველი საქმე: T4.04 დაასრულე

**T4.04 კოდურად მზადაა და უკვე გასწორებულია.** Review გაიარა, **ექვსი severe
finding** იპოვა (ერთი BLOCKER, ოთხი CRITICAL), ყველა გასწორებულია და 14 მუტანტით
დადასტურებული. სრული ისტორია `.atlas/GATE4_PROGRESS.md`-ში.

⚠️ **`review-3972124de4485ae8` მოძველებულია** — გასწორებებმა ხე შეცვალა, ანუ მისი
target აღარ ემთხვევა. **ნუ სცადებ მის finalize-ს.** საჭიროა **ახალი `review start`**.

ზუსტი რიგი:

```bash
gentle-ai review start --cwd /home/null/Desktop/LinuxSec        # lineage + target
gentle-ai review start --cwd /home/null/Desktop/LinuxSec \
  --contract gentle-ai.review-integration/v1 --target <target> --projection workspace
# → candidate_diff (base64), changed_path_manifest, artifact_subjects (თითო ლინზას თავისი subject_hash)
```

მერე ოთხი ლინზა **იზოლირებულად**, თითოეულს `GENTLE_AI_REVIEW_BINDING`-ით და
**მხოლოდ თავისი** `subject_hash`-ით. მერე:

```bash
gentle-ai review capture-result --lineage <l> --target <t> --lens <lens> --order <n> --input <file> --cwd .
# severe + inferential finding → gentle-ai review schema refuter; შედეგი --refuter <file>-ით
gentle-ai review finalize --cwd . --captured-results        # → state: validating, აბრუნებს store_revision
gentle-ai review capture-evidence --cwd . --lineage <l> --target <t> --expected-revision <store_revision> --input <evidence.txt>
gentle-ai review finalize --cwd . --captured-results --captured-evidence
gentle-ai review validate --gate pre-commit --cwd .          # უნდა იყოს result: allow
```

**Reviewer artifact-ის ზუსტი ფორმა** (`gentle-ai review schema reviewer`):
top level `subject_hash`, `inspection{status,paths}`, `findings[]`, `evidence[]`
— **`evidence` მასივია**. finding-ის ველები **ზუსტად** `location` (`path:line`),
`severity`, `claim`, `evidence_class` (`deterministic|inferential|insufficient`),
`causal_disposition`, `proof_refs[]`. სხვა ველი (`file`, `detail`, `title`)
**უარყოფილია**. validator-ის `follow_ups` ელემენტები `{observation, proof_refs}`.

მერე **ერთი `T4.04:` commit** + ცალკე `docs:` ledger-ისთვის.

## 4. მერე: frontier

**თვითონ გამოთვალე**, `IMPLEMENTATION_PLAN.md`-ის `Depends on` გრაფის ტრანზიტული
ჩაკეტვით. ⚠️ **ledger-ის frontier-ის ხაზი ერთხელ უკვე ტყუოდა** — T3.05 „მზადად"
იყო დასახელებული, მაშინ როცა `Depends on: T3.04, T4.04` და მე მხოლოდ პირველი
წავიკითხე. **მხოლოდ პირველ დამოკიდებულებას ნუ წაიკითხავ.**

T4.04-ის ჩაკომიტების შემდეგ **T3.05 იხსნება** (`fs.write`, `fs.patch`,
`git.worktree`). ის §6.4-ით `write_scoped / none / none`-ია, ანუ **`proc: none`
პირველი write ინსტრუმენტია** და იმავე მარშრუტიზაციის კითხვას შეხვდება, რაც T3.04-ს:
`dispatcher.run()`-ის in-process შტო `proc is NONE **და** handler მიწოდებული`-ზე
ირთვება, ანუ write ინსტრუმენტს handler-ის მიწოდება in-process გზაზე გადაიყვანს.
**ეს გადაწყვეტილებაა, არა დეტალი** — გადამოწმდი.

## 5. როგორ ვმუშაობთ (სავალდებულო)

**თითო task:** ground → **RED first** (აჩვენე ჩავარდნილი output) → GREEN →
დეტერმინისტული floors → **იზოლირებული ადვერსარიული 4R** → refute → **მუტაციები**
→ commit.

### მწვანე სუიტა არაფერს ამტკიცებს — ექვსი პრეცედენტი

100% branch + `mypy --strict` + CRITICAL **ექვსჯერ** თანაარსებობდა:
**T4.01** (GPG გასაღები გაუშიფრავი) · **T3.02** (§7.3 DENY symlink-ით შემოვლილი) ·
**T4.02** (U+2028 ერთ record-ს ორად ყოფდა) · **T3.03** (timeout გვერდით ავლილი,
`timeout_s=1` → 20 წამი) · **T3.04** (`path_scope` არსად არ აღსრულდებოდა —
`fs.read ~/.netrc` პაროლს აბრუნებდა) · **T4.04** (2 GB-ის ჩარჩენა + index-ის
დაგროვება, `tree ≠ entries`).

### ხუთი გაკვეთილი, რომელიც ამ სესიამ მოიტანა — გამოიყენე

1. **Correction budget ვალდებულებაა, არა შეფასება.** `min(200, ceil(lines/2))` და
   START-ზე იყინება. ამ რეპოში **ტესტები კოდზე 3-4-ჯერ მეტია.** თუ პატიოსანი
   რიცხვი ბიუჯეტს აჭარბებს — **transaction საერთოდ ნუ გახსნი**; გაასწორე გარეთ და
   ხელახლა გაატარე review. T3.04-ზე 180 ვიწინასწარმეტყველე, 349 დაჯდა, authority
   escalate-ი გაკეთდა.
2. **R2-ის „ზედმეტად დიდი candidate" წამყვანი ინდიკატორია, არა სტილი.** T3.04
   (3789 ხაზი): BLOCKER + 5 CRITICAL, ბიუჯეტი აფეთქდა. T4.04 (1785): BLOCKER + 4
   CRITICAL, ბიუჯეტი კომფორტში. **`review start` ეტაპობრივად** გაუშვი ერთი task-ის
   შიგნით, თუ candidate 2000 ხაზს უახლოვდება.
3. **ჩემი „ოპტიმიზაცია" ორჯერ იყო დეფექტი.** T4.04-ის „თითო workspace-ზე თითო
   index" cross-workspace გაჟონვას ხურავდა — და მისი მდგრადობა `tree ≠ entries`
   გახდა. **დაფიქრდი, რას ინახავს მდგომარეობა და რამდენ ხანს.**
4. **მუტაცია სუსტ ტესტს იჭერს, არა მხოლოდ არასრულ გასწორებას.** ამ სესიაზე
   **სამჯერ**. ბოლო: მუდმივად ამოწურული `store_size` stub „თითო-თითოს" და
   „ყველას" ვერ განასხვავებდა. **ყოველი გასწორებაზე მუტანტი, და მუტანტი უნდა
   მოკლას *დასახელებულმა* ტესტმა.**
5. **Integration იჭერს, რასაც stub ვერ.** ორჯერ T4.04-ზე: shadow store არ
   ინიციალიზდებოდა (`fatal: not a git repository`), და `git init` უარს ამბობს,
   როცა work tree დასახელებულია git dir-ის გარეშე. **ყალბი git ყველაფერს
   პასუხობს.**

### წესები, რომლებიც არ იცვლება

- **ნუ გააფართოვებ scope-ს ჩუმად.** სხვისი task-ის ფაილში დეფექტი → გაასწორე შენი,
  **დაასახელე** residual docstring-ში + ledger-ში. ცალკე `HARDEN-NN:` commit
  ჩემს თანხმობას საჭიროებს (პრეცედენტი: HARDEN-01…05).
- **ნურც შეავიწროვებ:** ცნობილი credential ფორმატის გაუშიფრავად დატოვება უარესია,
  ვიდრე დოკუმენტირებული საზღვრის გადაჭიმვა.
- **თითო task = თითო commit** `Tx.yy: …` სტილით. საერთო ფაილები (`pyproject.toml`,
  `ci.yml`, `tcb-loc-manifest.txt`) hunk-ებად გაყავი.
- **Review checkpoint commit-ის ტექსტში მიდის** (RED evidence · floors · critics ·
  mutations · residuals · receipt-ის მდგომარეობა). **escalated ≠ approved** — ეს
  პირდაპირ დაწერე.
- **Push მხოლოდ ცალკე თხოვნით.** Remote **private**-ია.
- `SPEC.md` და `IMPLEMENTATION_PLAN.md` **გაყინულია** — არასოდეს შეცვალო ტესტის
  გასამწვანებლად. SPEC-ის შეცვლა მხოლოდ: **გაზომილი** კორექცია + ჩემი თანხმობა +
  revision table (პრეცედენტი: §8.1 HARDEN-03-ისა და HARDEN-05-ის შემდეგ).
- **არასოდეს** განაახლო `.atlas/session_3056019e-…` — დასრულებული, hash-chained
  Gate-3 ledger-ია (`current_state: OUTPUT`, terminal).
- **TCB-ში `# pragma: no cover` აკრძალულია** (§23.1) და CI-ის scan ახლა
  `recovery`-საც ფარავს. მიუწვდომელი დაცვითი შტო **წაშალე**, ნუ დაფარავ.

## 6. წვრილმანი, რომელიც დროს გიშველის

- **`/tmp` sandbox-ისთვის აკრძალულია** (§8.1 tmpfs-ით ფარავს). pytest-ის
  `tmp_path` **არ გამოდგება** sandbox-იან ტესტში — `~/.cache/lsassist/<uuid>/ws`.
- **`sh -c env` ბავშვის env-ს ვერ ზომავს.** Arch-ზე `/bin/sh` **bash-ია** და
  `SHLVL`/`_`-ს თვითონ სვამს. გამოიყენე `/bin/cat /proc/self/environ`.
- **§6.4 ორჯერ Debian-ს ვარაუდობს:** `/etc/alternatives` (HARDEN-05-მა დახურა) და
  `pkg.query`-ის `dpkg-query`/`apt-cache` (**ღია residual** — Arch-ზე არ არსებობს,
  ჩავარდნა ხმამაღალია).
- `sys.info os_release` **`/usr/lib/os-release`-ს** კითხულობს: §8.1 `/usr`-ს აბამს,
  `/etc`-ს არა.
- **`git.read`-ის `path` არჩევითია**, ანუ caller-მა `path_args=["path"]` მაინც უნდა
  გამოაცხადოს — იგივე ფორმა, რაც T3.03-მა `test.run`-ზე დაასახელა.
- `tests/unit/scripts/test_coverage_gate.py`-ში `TCB_PACKAGES`, `CI_JOBS` და
  layer-ები **ზუსტი ტოლობითაა** დაპინული — იატაკის გაფართოება **სამფაილიანი**
  ცვლილებაა by construction (pyproject `source` + CI `--source=` + CI pragma scan).
- **TCB LOC 5955 / 6000** — target-იდან 45 ხაზი. შემდეგი TCB პაკეტი გადააჭარბებს;
  hard stop 8000, ანუ არ იბლოკება, მაგრამ დაასახელე.
- პროექტის root-ში შეიძლება გაჩნდეს `.atl/` — plugin-ის cache, `.gitignore`-შია.

---

დაიწყე §1-ის გაზომვით, მერე §3 — **T4.04-ის ხელახალი review და ჩაკომიტება**.
`gentle-ai` სრულფასოვნად, ყოველ candidate-ზე.
