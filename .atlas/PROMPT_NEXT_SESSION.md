# LinuxSec — next-session prompt (paste everything below the line as one message)

> **How to use.** Open a new session at `/home/null/Desktop/LinuxSec` (the git root,
> **not** `lsassist/`) and paste everything below the line as a single message.
>
> Written 2026-07-30 at commit `9c7c5e6`, with **T4.04 LANDED and the working tree
> clean**. Every number below is a **HYPOTHESIS TO FALSIFY** — §1 says why.

---

ვმუშაობთ პროექტზე `/home/null/Desktop/LinuxSec` (git root). ქართულად ვსაუბრობთ,
რეპოს ყველა artifact ინგლისურად.

## 0. წესები, რომლებიც ყველაფერზე მაღლა დგას

### 0.1 `gentle-ai` სავალდებულოა — და ერთი დამტკიცებული ხაფანგი აქვს

პლაგინი დაყენებულია (`gentle-ai 2.2.0`, `review mode: on`) და **ყოველი task-ის
candidate გაივლის native review-ს:** `review start` → იზოლირებული 4R ლინზები →
`capture-result` → საჭიროებისას `review-refuter` → `capture-evidence` →
`finalize` → `validate --gate pre-commit`.

⚠️ **მაგრამ: `review start` მხოლოდ მაშინ გახსენი, როცა მზად ხარ, რომ candidate-ს
correction არ დასჭირდეს.** ეს ამ ვერსიაში **ერთმხრივი კარია** — დამტკიცებული
T4.04-ზე ორჯერ. როცა `finalize` დააბრუნებს `correction_required`-ს, ის ორ
**ურთიერთგამომრიცხავ** პირობას მოითხოვს:

- ხე ბაიტ-ზუსტად გაყინულ candidate-ზე → `targeted validation request requires a
  changed correction candidate`
- correction გამოყენებული → `code: stale_target_identity` / `no compact FINALIZE
  authority matches the live target`

ოთხივე ვარიანტი შემოწმებულია (validation+evidence forecast-ის გარეშე;
`--correction-lines 400`, რომ ბიუჯეტის ნიღბიანი უარი გამოირიცხოს; მხოლოდ
forecast; მხოლოდ validation) — **ოთხივე იდენტური `stale_target_identity`.**
`review inspect-authority` → **`sanctioned_exits: []`**.

**პრაქტიკული შედეგი:**

1. review-ს **მაინც ატარებ** — სამმა რაუნდმა T4.04-ზე 1 BLOCKER და 11 CRITICAL
   იპოვა, მათ შორის CI gate, რომელიც 99%-ზე იჯდა. **დეფექტების პოვნა მუშაობს.**
2. თუ findings blocking-ია, გაასწორე, დაასაბუთე, და დააკომიტე
   **`explicit-maintainer-action`**-ით, რომელიც commit-ის ტექსტში პირდაპირ იწერება.
   **`escalated ≠ approved`.**
3. **გაჭედილი lineage ბლოკავს ყოველ ახალ `review start`-ს**
   (`action: blocked-scope-action`), ანუ შემდეგი task-ის დაწყებამდე გვერდზე უნდა
   გადაიდოს: `.git/gentle-ai/quarantine-manual/`, **არაფრის წაშლის გარეშე**, README-ით.
4. **pristine** lineage სწორად იხურება: `gentle-ai review abandon` ზუსტი
   ექვსხაზიანი LF-only `--maintainer-authorization` binding-ით (გაუშვი `abandon`
   დროშების გარეშე — template-ს დაბეჭდავს; მნიშვნელობები `review status`-ის
   `entries[]`-იდან). `review-4b139fbedd5ec1ff`-ზე იმუშავა.

**`sdd-*` skill-ებს ამ პროექტში ნუ გამოიყენებ** — `SPEC.md` და
`IMPLEMENTATION_PLAN.md` **გაყინულია** და ერთადერთი ავტორიტეტული წყაროა; SDD მათ
კონკურენტ artifact-ებს შექმნიდა. **Review machinery დიახ, SDD phases არა.**

### 0.2 დანარჩენი წესები

- **engram-ში მხოლოდ მდგრადი ფაქტები.** პროგრესის რიცხვები არასოდეს — git არის
  ჭეშმარიტების წყარო და ყოველ სესიაზე თავიდან იზომება.
- **კრიტიკოსების ეტაპზე იზოლირებული ქვე-აგენტები:** `review-risk`,
  `review-resilience`, `review-readability`, `review-reliability` — თითოეული
  მხოლოდ {frozen intent, ერთი diff, ერთი ლინზა, floors} ხედავს, **არასოდეს სხვისი
  findings**. მერე `review-refuter` inferential severe findings-ზე.
- **`review start`-ის შემდეგ candidate-ს ნუ შეეხები**, სანამ `capture-result` არ
  დასრულდება. ეს ორჯერ დაგვიჯდა.
- **Push მხოლოდ ცალკე თხოვნით.** Remote `github.com/null0xxx/kris` **private**-ია.
- **არასოდეს** განაახლო `.atlas/session_3056019e-…` — დასრულებული, hash-chained
  Gate-3 ledger.

## 1. ჯერ გაზომე — არ დაიწყო კოდის წერა

```bash
cd /home/null/Desktop/LinuxSec && git log --oneline -4 && git status --short
```

**მოსალოდნელი HEAD: `9c7c5e6` ან უფრო ახალი `docs:` commit; სამუშაო ხე სუფთა.**

```bash
cd /home/null/Desktop/LinuxSec/lsassist
V=~/.local/share/lsassist/venv/bin     # uv-ის standalone CPython 3.12.13

$V/python -m pytest                    # bare! `-q` ორმაგდება და summary იკარგება
$V/python -m ruff check src tests
$V/python -m mypy --strict src/lsassist/contracts src/lsassist/config \
  src/lsassist/policy src/lsassist/sandbox src/lsassist/kernel src/lsassist/audit \
  src/lsassist/recovery src/lsassist/tools/dispatcher.py src/lsassist/tools/result.py
python3 scripts/loc-count --manifest scripts/tcb-loc-manifest.txt --target 6000 --hard-stop 8000
```

⚠️ **§23.1-ის coverage gate გაუშვი ზუსტად ისე, როგორც CI უშვებს — `ci.yml:130`.**
ის **მხოლოდ** `tests/unit tests/property`-ს უშვებს და `tests/integration`-ს
**გამორიცხავს**. ეს განსხვავება T4.04-ზე CRITICAL იყო: ჩემი დოკუმენტირებული
ბრძანება `tests/integration/recovery`-ს რთავდა და 100%-ს კითხულობდა, CI კი 99%-ს
და `--fail-under=100`-ს ჩააგდებდა.

```bash
$V/python -m coverage run --branch \
  --source=src/lsassist/kernel,src/lsassist/policy,src/lsassist/sandbox,src/lsassist/audit,src/lsassist/recovery \
  -m pytest tests/unit tests/property && $V/python -m coverage report --fail-under=100

$V/python -m coverage run --branch \
  --source=lsassist.tools.dispatcher,lsassist.tools.result \
  -m pytest tests/unit/tools && $V/python -m coverage report --fail-under=100
```

**მოსალოდნელი (გაზომილი 2026-07-30, `9c7c5e6`):** pytest **2958 passed, 0 failed,
0 skipped** · ruff clean · `mypy --strict` clean 49 ფაილზე · **TCB LOC 6020 / 6000**
· §23.1 **100% branch, 0 partial** · dispatcher+result **100%** · pragma ნული.

**თუ რომელიმე რიცხვი არ ემთხვევა — გაჩერდი და მომახსენე.**

⚠️ **venv არ არის რეპოში და 3.12-ია.** თუ `No module named pytest` — **3.14-ზე ნუ
ააშენებ**: `requirements.lock` cp312 wheel hash-ებს აპინავს და `--require-hashes`
cp314-ს სამართლიანად უარყოფს. სწორი გზა:
`uv python install 3.12 && /home/null/.local/share/uv/python/cpython-3.12-linux-x86_64-gnu/bin/python3.12 -m venv ~/.local/share/lsassist/venv`
მერე `pip install --require-hashes -r requirements.lock -r requirements-dev.lock && pip install -e . --no-deps`.

## 2. სად ვართ

- **33 / 70 task.** Phase 1 ✅ (11/11) · Phase 2 ✅ (13/13) · Phase 3: 5/14 ·
  Phase 4: 3/12 · Phase 5: 0/14 · Phase 6: 0/6
- აშენებული: `contracts` `config` `policy` `sandbox` `kernel` `audit`, `tools`
  (registry + dispatcher + result + handlers), `providers` (base), **`recovery`**
- ცარიელი scaffold: `memory` `skills` `tutor` `coding` `cli`
- **`lsassist` ჯერ არ ეშვება.** T3.04-ის handler-ები და T4.04-ის store არსებობს,
  მაგრამ production-ში მათ **არავინ აერთებს**. შეკრების წერტილი **T5.12**.
- `main` `origin/main`-ზე (`eeae643`) **9 commit-ით წინაა** — push მხოლოდ ცალკე თხოვნით.

## 3. 🚨 ორი გადაწყვეტილება, რომელიც შენ გელოდება

### 3.1 FEATURE FREEZE — TCB LOC 6020 / 6000, და რატომ არ ბლოკავს T3.05-ს

SPEC.md:132 (§2.3): „TCB ≤ 6,000 LOC **Gate 4 MVP-ზე**; hard stop 8,000. ზღვარზე
გადასვლა = **feature freeze**, არა budget-ის მოშვება." **მრიცხველი განზრახ არ
გადაფორმატდა** — ხაზების შეკუმშვა იმავე წესის დარღვევაა უკუღმა.

✅ **T3.05 არც ერთ TCB ხაზს არ ამატებს, ანუ freeze-ს არ ეწინააღმდეგება.** მისი
ყველა ფაილი `tools/handlers/`, `tools/manifests/` და `tests/`-ია, რომლებიც
`scripts/tcb-loc-manifest.txt`-ში **`non-tcb src/lsassist/tools`**-ია (§2.3-ის
„tools/ dispatcher core **without individual handlers**"). ⚠️ **მაგრამ თუ T3.05
შეეხება `tools/dispatcher.py`-ს ან `tools/result.py`-ს — ისინი `tcb`-ია და
ითვლება.** ის ხაზები მინიმალური უნდა იყოს და commit-ში დასახელებული.

⚠️ **NEGATIVE RESULT — reviewer-ის შემოთავაზებული LOC-ის დაბრუნება გაზომილია და
არ ღირს. ნუ გააკეთებ.** შემოთავაზება იყო: `recovery/checkpoints.py`-ის
`_ensure_dir_chain` იმეორებს `config/xdg.py`-ის `_ensure_dir`-ს, გააზიარე.
გაზომვა:

- `_ensure_dir_chain` არის **59 ფიზიკური, ~26 code ხაზი**. `loc-count` **მხოლოდ
  კოდს ითვლის** (docstring-ები ცალკე). wrapper ~5-ს ხარჯავს → **წუთი ~21 ხაზი**,
  ანუ 6020 → **5999**. ერთი ხაზი ზღვარს ქვემოთ — არანაირი მარაგი.
- `config` **90% branch-ზეა** (39 statement, 14 partial ოთხ ფაილში), და
  **§23.1-ის ხუთეულში არ არის** (`TCB_PACKAGES` = kernel, policy, sandbox, audit,
  recovery). ანუ primitive გადავიდოდა 100%-იანი იატაკიდან **იატაკის გარეშე**
  პაკეტში.
- ეს **ზუსტად residual 3-ია `tcb-loc-manifest.txt`-ის საკუთარი სიიდან** — „TCB
  ლოგიკის გადატანა პაკეტში, რომელსაც TCB მერე იმპორტს უკეთებს… მხოლოდ review
  იცავს ამ proxy-ს".

**ნამდვილი გზა, თუ ამას მოგინდება:** ცალკე task, რომელიც `config`-ს §23.1-ის
იატაკს ქვეშ შეიყვანს (სამფაილიანი gate ცვლილება + `TCB_PACKAGES`-ის ზუსტი
ტოლობა), **მერე** გააზიარებს primitive-ს. თანმიმდევრობა მნიშვნელოვანია: სხვა
რიგით gate სუსტდება. ჩემს თანხმობას საჭიროებს.

### 3.2 T4.04 `explicit-maintainer-action`-ით დაკომიტდა

Receipt **არ არის approved** — მიზეზი §0.1-ის facade-ის ჩიხია, არა შეუმოწმებელი
candidate. სრული ჩანაწერი `9c7c5e6`-ის commit-ის ტექსტშია და
`.atlas/GATE4_PROGRESS.md`-ის ბოლო სექციაში. თუ გინდა, რომ T4.04-ს ნამდვილი
`allow` receipt ჰქონდეს, ერთადერთი გზა კიდევ ერთი სრული 4R რაუნდია, რომელიც
**ნულ blocking finding-ს** დააბრუნებს.

## 4. შემდეგი task: T3.05

**T3.05 გახსნილია** (`Depends on: T3.04, T4.04` — ორივე დაფარულია): `fs.write`,
`fs.patch`, `git.worktree`.

⚠️ **წინასწარი ხაფანგი, გადამოწმდი:** §6.4 `fs.write`-ს აძლევს
`write_scoped / none / none` — ეს **პირველი WRITE ინსტრუმენტია, რომელიც
`proc: none`-იცაა**, ანუ იმავე მარშრუტიზაციის კითხვას შეხვდება, რაც T3.04-ს:
`dispatcher.run()`-ის in-process შტო ირთვება `proc is NONE **და** handler
მიწოდებული`-ზე, ანუ write ინსტრუმენტისთვის handler-ის მიწოდება მას in-process
გზაზე გადაიყვანს. **ეს გადაწყვეტილებაა, არა დეტალი.**

⚠️ **`fs.write`-ს checkpoint სჭირდება.** §6.4 ამბობს „checkpoint pre-write" და
გეგმის GREEN ამბობს „checkpoint pre-write call" — T4.04-ის `CheckpointStore.create`
უკვე არსებობს, ანუ ეს wiring-ია, არა ახალი მექანიზმი. **Write ინსტრუმენტი
rollback-ის გარეშე თავისთავად საშიში ნახევარია.**

**Frontier თვითონ გამოთვალე** `Depends on` გრაფის ტრანზიტული ჩაკეტვით. ⚠️ ამ
ledger-ის frontier-ის ხაზი ერთხელ უკვე ტყუოდა — **მხოლოდ პირველ დამოკიდებულებას
ნუ წაიკითხავ.**

## 5. როგორ ვმუშაობთ

**თითო task:** ground → **RED first** (აჩვენე ჩავარდნილი output) → GREEN →
დეტერმინისტული floors → **იზოლირებული ადვერსარიული 4R** → refute → **მუტაციები**
→ commit.

### მწვანე სუიტა არაფერს ამტკიცებს — შვიდი პრეცედენტი

100% branch + `mypy --strict` + CRITICAL **შვიდჯერ** თანაარსებობდა:
**T4.01** (GPG გასაღები გაუშიფრავი) · **T3.02** (§7.3 DENY symlink-ით შემოვლილი) ·
**T4.02** (U+2028 ერთ record-ს ორად ყოფდა) · **T3.03** (timeout გვერდით ავლილი) ·
**T3.04** (`path_scope` არსად არ აღსრულდებოდა — `fs.read ~/.netrc` პაროლს აბრუნებდა) ·
**T4.04 რაუნდი 1** (2 GB-ის ჩარჩენა, `tree ≠ entries`) · **T4.04 რაუნდი 2**
(workspace-ის `.gitattributes` შენახულ ბაიტებს გადაწერდა).

### ტესტის ტავტოლოგიის სამი დამტკიცებული ფორმა — ეძებე ისინი

1. **`pytest.raises(match=...)` არის `re.search` მთელ შეტყობინებაზე, და
   შეტყობინებაში გზაა.** `tmp_path` **ტესტის სახელს შეიცავს**, ანუ ყოველი `match=`,
   რომელიც ტესტის სახელის ქვესტრიქონია, უფასოდ ემთხვევა. `match="symlink"` ტესტში
   `..._symlinked_...` გადიოდა დაცვის წაშლის შემდეგაც. **გამოიყენე პუნქტუაცია:**
   `r"symlink \(fail-closed\)"`.
2. **Short-circuit-ი დამოკიდებულებას საერთოდ არ იძახებს.**
   `while candidates and store_size() > cap` ერთი checkpoint-ით — `candidates`
   ცარიელია, `store_size` არასოდეს გამოიძახება, ტესტი არაფერს ამტკიცებს.
3. **შემთხვევით დამთხვეული რიგი.** workspace-ები `heavy`/`light` ანბანურად
   ქრონოლოგიურ რიგში დგებოდა, ანუ ტესტი ვერ განასხვავებდა `sort(key=id)`-ს
   `sort(key=workspace)`-გან. `zzz-heavy`/`aaa-light` განასხვავებს.

### ხუთი გაკვეთილი, რომელიც უახლესმა სესიამ მოიტანა

1. **Correction ბიუჯეტი დავიცავე: forecast 195, დაიხარჯა 183, ბიუჯეტი 200.**
   `min(200, ceil(lines/2))` და START-ზე იყინება. ამ რეპოში ტესტები კოდზე 3-4-ჯერ
   მეტია, ანუ პატიოსანი შეფასება მაინც უნდა გააკეთო რედაქტირებამდე.
2. **მუტაციამ ჩემსავე გასწორებაში იპოვა დეფექტი.** `_remove` manifest-ს ჯერ შლიდა
   — ერთადერთი **გამოუსწორებელი** ნახევარ-ჩავარდნა. **ყოველ გასწორებაზე მუტანტი,
   და მუტანტმა უნდა დაადასტუროს, რომ ნამდვილად გამოიყენა** (`count == 1`), თორემ
   „გადარჩენილი" და „არ გამოყენებული" ერთნაირად გამოიყურება.
3. **Refuter-მა ჩემი ემპირიული probe დაამარცხა.** ჩემი `gitattributes` probe cwd-ს
   work tree-ს გარეთ უშვებდა. **გაზომვაც შეიძლება არასწორად აწყობილი იყოს.**
4. **`env=env`-ის მუტანტი host-ის რეპოს აბინძურებს.** რეალური git ამბიენტური
   env-ით LinuxSec-ს აღმოაჩენს და `update-index`-ს მის index-ში წერს. მუტაციის
   შემდეგ **ყოველთვის** შეამოწმე `git diff --cached`.
5. **`text=True` მკაცრად დეშიფრავს.** `subprocess.run(text=True)` ერთ არასწორ
   ბაიტზე `UnicodeDecodeError`-ს აგდებს, რომელიც `ValueError`-ია — არც `OSError`,
   არც `SubprocessError`. Injectable runner-ზე catch-tuple **პრინციპში** ვერ იქნება
   სრული; `Exception` დაიჭირე, `BaseException` დატოვე.

### წესები, რომლებიც არ იცვლება

- **ნუ გააფართოვებ scope-ს ჩუმად.** სხვისი task-ის ფაილში დეფექტი → გაასწორე შენი,
  **დაასახელე** residual docstring-ში + ledger-ში. ცალკე `HARDEN-NN:` commit ჩემს
  თანხმობას საჭიროებს (პრეცედენტი: HARDEN-01…05).
- **ნურც შეავიწროვებ:** ცნობილი credential ფორმატის გაუშიფრავად დატოვება უარესია,
  ვიდრე დოკუმენტირებული საზღვრის გადაჭიმვა.
- **თითო task = თითო commit** `Tx.yy: …` სტილით.
- **Review checkpoint commit-ის ტექსტში მიდის** (RED evidence · floors · critics ·
  mutations · residuals · receipt-ის მდგომარეობა). **escalated ≠ approved.**
- `SPEC.md` და `IMPLEMENTATION_PLAN.md` **გაყინულია** — არასოდეს შეცვალო ტესტის
  გასამწვანებლად. SPEC-ის შეცვლა მხოლოდ: **გაზომილი** კორექცია + ჩემი თანხმობა +
  revision table (პრეცედენტი: §8.1 HARDEN-03 და HARDEN-05).
- **TCB-ში coverage-exclusion კომენტარი აკრძალულია** (§23.1) და CI-ის scan
  `recovery`-საც ფარავს — ის **ტექსტურ ძებნას** აკეთებს, ანუ თუნდაც კომენტარში
  ხსენება ჩააგდებს job-ს. მიუწვდომელი დაცვითი შტო **წაშალე**, ნუ დაფარავ.

## 6. წვრილმანი, რომელიც დროს გიშველის

- **`/tmp` sandbox-ისთვის აკრძალულია** (§8.1 tmpfs-ით ფარავს). pytest-ის
  `tmp_path` **არ გამოდგება** sandbox-იან ტესტში — `~/.cache/lsassist/<uuid>/ws`.
- **`sh -c env` ბავშვის env-ს ვერ ზომავს.** Arch-ზე `/bin/sh` bash-ია და
  `SHLVL`/`_`-ს თვითონ სვამს. გამოიყენე `/bin/cat /proc/self/environ`.
- **§6.4 ორჯერ Debian-ს ვარაუდობს:** `/etc/alternatives` (HARDEN-05-მა დახურა) და
  `pkg.query`-ის `dpkg-query`/`apt-cache` (**ღია residual** — Arch-ზე არ არსებობს).
- `sys.info os_release` **`/usr/lib/os-release`-ს** კითხულობს: §8.1 `/usr`-ს აბამს.
- **`git.read`-ის `path` არჩევითია**, ანუ caller-მა `path_args=["path"]` მაინც უნდა
  გამოაცხადოს.
- `tests/unit/scripts/test_coverage_gate.py`-ში `TCB_PACKAGES`, `CI_JOBS` და
  layer-ები **ზუსტი ტოლობითაა** დაპინული — იატაკის გაფართოება **სამფაილიანი**
  ცვლილებაა by construction.
- **Reviewer artifact-ის ზუსტი ფორმა** (`gentle-ai review schema reviewer`): top
  level `subject_hash`, `inspection{status,paths}`, `findings[]`, `evidence[]` —
  `evidence` **მასივია**. finding-ის ველები **ზუსტად** `location`, `severity`,
  `claim`, `evidence_class`, `causal_disposition`, `proof_refs[]`, არჩევითი
  `id`/`lens`. ⚠️ **`proof_ref`, რომელიც candidate-ის გარეთ არსებულ, repo-root-იდან
  ამოსახსნელ გზას ასახელებს (`SPEC.md:857`), უარყოფილია `out_of_scope`-ით** —
  დაწერე პროზად. ⚠️ **JSON-ს regex-ით ნუ ასწორებ** — დაუესქეიპებელი ბრჭყალები
  `reviewer payload contains no complete JSON object`-ს იძლევა; შეასწორე
  გაპარსულ ობიექტზე და ხელახლა სერიალიზება.
- **Negotiated START-ის პასუხში `candidate_diff` არის კონვერტი**
  `{encoding, data, sha256, byte_size}`, არა base64 სტრიქონი; `lens_bindings` არის
  `null` — თითო ლინზის `subject_hash` `artifact_subjects[]`-იდან მოდის.
- **Boolean დროშები**: `--next-transition`, არასოდეს `--next-transition true`.
- **დიაგნოზისთვის გამოიყენე negotiated ფორმა**
  (`--contract gentle-ai.review-integration/v1`) — plain ფორმა მხოლოდ ერთხაზიან
  `Error:`-ს ბეჭდავს, negotiated კი `code`-ს (`stale_target_identity`,
  `out_of_scope`, `authority_corrupted`).
- პროექტის root-ში შეიძლება გაჩნდეს `.atl/` — plugin-ის cache, `.gitignore`-შია.

---

დაიწყე §1-ის გაზომვით. მერე §3-ის ორ გადაწყვეტილებაზე მკითხე, და §4 — **T3.05**.
`gentle-ai` სრულფასოვნად, ყოველ candidate-ზე, §0.1-ის ხაფანგის ცოდნით.
