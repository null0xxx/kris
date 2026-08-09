# LinuxSec — next-session prompt (paste everything below the line as one message)

> **How to use.** Open a new session at `/home/null/Desktop/LinuxSec` (the git root,
> **not** `lsassist/`) and paste everything below the line as a single message.
>
> Written 2026-08-09 after commit `2753917`, with **T4.07 LANDED**. `main` was
> **15 commits ahead of `origin/main` before this documentation edit**; nothing
> was pushed. Every number below is a **HYPOTHESIS TO FALSIFY** — §1 says why.

---

ვმუშაობთ პროექტზე `/home/null/Desktop/LinuxSec` (git root). ქართულად ვსაუბრობთ,
რეპოს ყველა artifact ინგლისურად.

## 0. წესები, რომლებიც ყველაფერზე მაღლა დგას

### 0.1 `gentle-ai` სავალდებულოა — და ერთი დამტკიცებული ხაფანგი აქვს

პლაგინი დაყენებულია (`gentle-ai 2.2.4`, `review mode: on`) და **ყოველი task-ის
candidate გაივლის native review-ს:** `review start` → native-ის მიერ შერჩეული
იზოლირებული ლინზები →
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

**მოსალოდნელი HEAD: `2753917` ან უფრო ახალი `docs:` commit.** დოკუმენტაციის
commit-მდე branch იყო `origin/main`-ზე **15 commit-ით წინ**. Push არ უნდა იყოს.

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

**მოსალოდნელი (გაზომილი 2026-08-09, `2753917`):** pytest **3071 passed, 0 failed,
0 skipped** · ruff clean · `mypy --strict` clean 49 ფაილზე · **TCB LOC 6020 / 6000**
· §23.1 **100% branch, 0 partial** · dispatcher+result **100%** · pragma ნული.

**თუ რომელიმე რიცხვი არ ემთხვევა — გაჩერდი და მომახსენე.**

⚠️ **venv არ არის რეპოში და 3.12-ია.** თუ `No module named pytest` — **3.14-ზე ნუ
ააშენებ**: `requirements.lock` cp312 wheel hash-ებს აპინავს და `--require-hashes`
cp314-ს სამართლიანად უარყოფს. სწორი გზა:
`uv python install 3.12 && /home/null/.local/share/uv/python/cpython-3.12-linux-x86_64-gnu/bin/python3.12 -m venv ~/.local/share/lsassist/venv`
მერე `pip install --require-hashes -r requirements.lock -r requirements-dev.lock && pip install -e . --no-deps`.

## 2. სად ვართ — გაზომილი

**33 / 70 task აშენებულია = 47.1%.** ეს ხელახლა დათვლილია artifact-ების
არსებობით და არა commit-message grep-ით. 34/70 იქნებოდა T3.05-ის ორჯერ დათვლა:
მისი ფაილები ჯერ კიდევ uncommitted 32/70 snapshot-ში უკვე არსებობდა და ითვლებოდა;
T4.07-მა მხოლოდ ერთი ახალი built task დაამატა.

| Phase | | |
|---|---|---|
| 1 | 10/11 | 90.9% |
| 2 | 13/13 | **100%** |
| 3 | 6/14 | 42.9% |
| 4 | 4/12 | 33.3% |
| 5 | 0/14 | **0%** |
| 6 | 0/6 | **0%** |

⚠️ **47.1% task-ია, 0% მუშა პროგრამა.** `lsassist` ჯერ არ ეშვება: Phase 5 (CLI,
session engine, coding/tutor) ხელუხლებელია და `src/`-ში **არაფერი აერთებს** არც
T3.04/T3.05-ის handler-ებს, არც T4.04-ის store-ს. შეკრების წერტილი **T5.12**.
Task-ების პროცენტი ≠ პროგრესი მუშა ხელსაწყოსკენ.

**როგორ გაზომო თავიდან** (commit-ის სახელებით grep **აკლებს**): თითო `### Tx.yy`
ბლოკიდან აიღე `**Files:**`, გახსენი brace-ნოტაცია
(`{contracts,kernel,…}/__init__.py`), და თითო გზა შეამოწმე **სამივე** ფესვზე:
repo root, `lsassist/`, და წინა `lsassist/`-ის მოჭრით. `lstrip("./")` წერტილს
აჭამს `.github/…`-ს — ნუ გამოიყენებ.

## 3. T4.07-ის ბოლო, ზუსტი მდგომარეობა

**T4.07 დაეშვა `2753917`-ზე.** შეიცვალა ზუსტად:

- `lsassist/pyproject.toml`;
- `lsassist/src/lsassist/memory/{__init__.py,migrations.py,schema.sql,store.py}`;
- `lsassist/tests/unit/memory/{__init__.py,test_migrations.py,test_store.py}`.

არქიტექტურა: §10.2-ის ზუსტი DDL + `schema_migrations`; WAL და foreign keys
startup-ზე; ordered transactional migrations; unknown-newer-version refusal;
0600 database creation; startup integrity check და actionable recovery message.
`schema.sql` package data-ადაა გამოცხადებული და wheel-ში მისი არსებობა
შემოწმებულია. Linux path boundary descriptor-anchored-ია: parent კომპონენტები
`openat`/`O_NOFOLLOW`-ით იხსნება, ხოლო pinned parent/database descriptor-ები
ancestor ან leaf symlink swap-ს database/WAL/SHM-ის გადამისამართების საშუალებას
არ აძლევს. Native review-მდე გასწორდა ორივე: wheel-ში schema-ის არშეტანა და
ancestor/leaf symlink authority-ის არასაკმარისი დაცვა.

**დამტკიცებული floors:** 35 focused memory test · 3071 full test · Ruff clean ·
mypy clean · §23.1 და dispatcher/result coverage ორივე **100%, 0 partial** · TCB
**6020**, უცვლელი · wheel-ში `lsassist/memory/schema.sql` არის.

Native review: **medium / reliability**, **1 CRITICAL + 3 WARNING**. CRITICAL იყო
concurrent migration stale-version race: ორმა first-start connection-მა lock-მდე
version 0 წაიკითხა. გასწორება lock-ის აღების შემდეგ ledger-ს თავიდან კითხულობს;
deterministic two-connection test waiter-ს idempotent no-op-ად ამტკიცებს.
Correction იყო **45 ხაზი**, forecast 60, frozen budget 200; scoped validator =
**PASS**.

სამი დარჩენილი WARNING:

1. newer-version refusal WAL negotiation-ის შემდეგ ხდება და refusal-მდე შეიძლება
   WAL/SHM sidecar-ები შექმნას;
2. broad `sqlite3.DatabaseError` operational failure-ს შეიძლება corruption-ის
   სახელით წარმოაჩენდეს;
3. ერთსა და იმავე missing parent component-ის concurrent creation-მა SQLite-ის
   გახსნამდე შეიძლება `FileExistsError` გაატაროს.

⚠️ **RECEIPT: NOT APPROVED.** `gentle-ai 2.2.4` corrected target-ზე captured
verification evidence-ს ვერ აბამს. Maintainer-მა დაადასტურა
`explicit-maintainer-action`; approval არ მოგვიგონია. სრული lineage ინახება
`.git/gentle-ai/quarantine-manual/review-6710ab6c47fc08a3`-ში.

### FEATURE FREEZE — TCB LOC 6020 / 6000

SPEC.md:132 (§2.3): „TCB ≤ 6,000 LOC **Gate 4 MVP-ზე**; hard stop 8,000. ზღვარზე
გადასვლა = **feature freeze**, არა budget-ის მოშვება."

✅ **T3.05-მა ნული TCB ხაზი დაამატა** — counter 6020-ია მის წინაც და შემდეგაც.
ხერხი: checkpoint store **closure**-ით მიეწოდება (`make_writer(store)`), ანუ
`tools/dispatcher.py`-ს (`tcb`) არ ეხება. **გაიმეორე ყოველ handler-ზე.**

⚠️ **NEGATIVE RESULT — reviewer-ის LOC refactor გაზომილია და არ ღირს. ნუ
გააკეთებ.** `_ensure_dir_chain`-ის გაზიარება `config/xdg.py`-სთან იძლევა **~21
ხაზს** (არა 55 — `loc-count` მხოლოდ კოდს ითვლის), ანუ 5999: ერთი ხაზი ზღვარს
ქვემოთ. ფასი: `config` **90% branch**-ზეა და §23.1-ის ხუთეულში **არ არის** —
primitive გადავიდოდა 100%-იანი იატაკიდან იატაკის გარეშე პაკეტში. ეს
`tcb-loc-manifest.txt`-ის **საკუთარი residual 3-ია**. სწორი გზა: ცალკე task,
რომელიც **ჯერ** `config`-ს იატაკს ქვეშ შეიყვანს — ჩემი თანხმობით.

## 4. შემდეგი საქმე — T3.06

**T3.05 (`a9293d4`) და T4.07 (`2753917`) ორივე დაფარულია, ამიტომ T3.06 ახლა
ნამდვილად განბლოკილია.** ეს არის შემდეგი deepest-chain work unit: `test.run`,
`proc.exec`, `net.fetch`; `net.fetch` body მხოლოდ T4.07 memory store-ში მიდის და
არა disk-ზე. ჯერ grounding, მერე RED:

```bash
cd /home/null/Desktop/LinuxSec/lsassist
V=~/.local/share/lsassist/venv/bin
$V/python -m pytest tests/unit/tools/test_exec_net_tools.py -q
$V/python -m pytest tests/integration/tools/test_exec_net_sandbox.py -q -m integration
```

გახსნილი კანდიდატები: **T4.03** (audit reader), **T4.05** (rollback flow —
T4.04-ს ეყრდნობა და მისი პირდაპირი გაგრძელებაა), **T3.09/T3.11** (provider
adapters). **T4.08-ც ღიაა** და memory retrieval-ის პირდაპირი გაგრძელებაა, მაგრამ
ჯერ T3.06 აიღე, რადგან ის T3.07-ს და უფრო ღრმა execution chain-ს ხსნის.

⚠️ **T3.05-ის ორი residual, რომლებიც შემდეგმა task-მა უნდა იცოდეს:**
- checkpoint-ის აღდგენადობა და „workspace-ის `.git` ხელუხლებელია" მხოლოდ
  `tests/integration`-ში მტკიცდება, რომელსაც §23.1-ის gate **არ უშვებს**. ეს
  **მეორედ** ჩნდება (T4.04-ის მეშვიდე CRITICAL იყო პირველი) და **მფლობელი არ
  ჰყავს**. თუ სამჯერ გამეორდა — ეს აღარ არის residual, არამედ gate-ის ხარვეზი.
- `fs_patch` იმპორტს უკეთებს `fs_write`-ის პრივატულ `_checkpoint`-სა და
  არა-ექსპორტირებულ `publish`-ს; პაკეტის კონვენცია `_common.py`-ია.

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

დაიწყე §1-ის გაზომვით. თუ baseline ზუსტად ემთხვევა, გააგრძელე §4 — **T3.06**.
`gentle-ai` სრულფასოვნად, ყოველ candidate-ზე, §0.1-ის ხაფანგის ცოდნით.
