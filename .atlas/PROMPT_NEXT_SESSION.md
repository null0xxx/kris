# LinuxSec — next-session prompt (paste as the first message)

> **How to use.** Open a new session at `/home/null/Desktop/LinuxSec` (the git root,
> **not** `lsassist/`) and paste everything below the line as a single message.
>
> Written 2026-07-28 at commit `bdd11b8`, after Wave 2 (T3.02 + T4.02). The numbers
> below are a HYPOTHESIS TO FALSIFY, not a fact to trust — see §1.

---

ვმუშაობთ პროექტზე `/home/null/Desktop/LinuxSec` (git root). ქართულად ვსაუბრობთ.

## 1. ჯერ გაერკვიე — არ დაიწყო კოდის წერა

1. წაიკითხე `.atlas/GATE4_PROGRESS.md` — ეს Gate-4-ის ავტორიტეტული ledger-ია.
2. `git log --oneline -12` — **git არის ჭეშმარიტების წყარო**, თუ ledger-ს ეწინააღმდეგება.
   (ეს ledger უკვე ყოფილა მოძველებული: ეწერა „NEXT: T2.12", როცა T2.12/T2.13 უკვე
   ჩაკომიტებული იყო.)
3. **თვითონ გაზომე ყველა floor.** ნუ ენდობი დოკუმენტირებულ რიცხვს:

```bash
cd /home/null/Desktop/LinuxSec/lsassist
V=~/.local/share/lsassist/venv/bin     # ADR-005: venv is NOT in the repo

$V/python -m pytest                     # bare! `pytest -q` yields -qq (addopts already
                                        # has -q) and SUPPRESSES the pass/fail summary
$V/python -m ruff check src tests
for p in contracts config policy sandbox kernel audit; do $V/python -m mypy --strict src/lsassist/$p; done
$V/python -m mypy --strict src/lsassist/tools/dispatcher.py
python3 scripts/loc-count --manifest scripts/tcb-loc-manifest.txt --target 6000 --hard-stop 8000

# §23.1 branch floor
$V/python -m coverage run --branch \
  --source=src/lsassist/kernel,src/lsassist/policy,src/lsassist/sandbox,src/lsassist/audit \
  -m pytest tests/unit tests/property && $V/python -m coverage report

# tools/dispatcher.py is TCB (§2.3) but OUTSIDE §23.1's package floor — its own job
$V/python -m coverage run --branch --source=lsassist.tools.dispatcher \
  -m pytest tests/unit/tools && $V/python -m coverage report
```

**მოსალოდნელი (გაზომილი 2026-07-28, `bdd11b8`):** pytest **2557 passed, 0 failed** ·
ruff clean · `mypy --strict` clean (contracts 12 · config 7 · policy 8 · sandbox 5 ·
kernel 8 · audit 4 · dispatcher 1) · **TCB LOC 4720 / 6000** (hard stop 8000) ·
**100% branch** kernel+policy+sandbox+audit **და** dispatcher.py, 0 partial, 0 pragmas ·
CI 6 job (`ruff`, `unit`, `loc-count`, `tcb-loc`, `coverage`, `dispatcher-coverage`).

**თუ რომელიმე რიცხვი არ ემთხვევა — გაჩერდი და მომახსენე.** ნუ ააშენებ აუხსნელ delta-ზე.

## 2. სად ვართ

- **29 / 70 task.** Phase 1 ✅ (11/11) · Phase 2 ✅ (13/13) · Phase 3: 3/14 · Phase 4: 2/12 · Phase 5: 0/14 · Phase 6: 0/6
- აშენებული პაკეტები: `contracts` `config` `policy` `sandbox` `kernel` `audit`,
  `tools` (registry + dispatcher), `providers` (base)
- ცარიელი scaffold: `recovery` `memory` `skills` `tutor` `coding` `cli`
- **`lsassist` ჯერ არ ეშვება** — `__main__.py` არის T1.02-ის stub. არცერთი production
  მოდული ჯერ არ იძახებს აშენებულ კომპონენტებს; მათ მხოლოდ ტესტები ეძახიან. ეს არაა
  დეფექტი — §2.2-ის dependency direction-ია; შეკრების ორი წერტილი არის **T3.02
  dispatcher** (გაკეთდა) და **T5.12 session engine**.
- `main` == `origin/main` == `bdd11b8`

## 3. შემდეგი frontier

გამოთვალე **თვითონ**, `IMPLEMENTATION_PLAN.md`-ის `Depends on` გრაფის ტრანზიტული
ჩაკეტვით — რიგი **ტოპოლოგიურია**, არა ფაზების მიხედვით. ჩემი გაანგარიშებით მზადაა:

| Task | რა | Plan anchor |
|---|---|---|
| **T3.03** | dispatch steps 5–9: sandbox profile build → execute → observe → verify → audit hook | `IMPLEMENTATION_PLAN.md:531-542` |
| **T4.03** | audit reader (`lsassist audit show`, redaction on read) | Phase 4 |

### T3.03 ატარებს ჩაწერილ ვალდებულებებს — შეამოწმე თითოეული

T2.06-ის runner obligations (ჩაწერილია `sandbox/profiles.py`-ის docstring-ში):

- spawn `env={}` — **არასოდეს** `None`, არასოდეს parent-ის ასლი (`--clearenv` არის
  defense-in-depth, არა შემცვლელი)
- argv **სია** პირდაპირ — **არასოდეს** shell-სტრიქონი (§7.6 rule 8)
- `prlimit` პრეფიქსი **სენდბოქსის შიგნით** (HARDEN-03); `compose_exec_argv` ერთადერთი
  სანქცირებული exec-argv მწარმოებელია
- bwrap მიუწვდომელი → typed `sandbox_unavailable` → **BLOCKED**, არასოდეს unsandboxed
  fallback (I11)
- §7.5 step-6 post-exec verify **write-only**-ია → read/exec handler-ებმა გახსნილი
  inode უნდა დააპინონ `fstat`-ით, თორემ file-swap TOCTOU გადარჩება
- `ws` + `venv_exists=True`-ზე `<ws>/.venv/bin` სისტემურ tool-ებს ჯობნის (§8.2), ხოლო
  approval **სახელს** აკავშირებს (§7.4) — dispatcher-მა უკვე დააკავშირა §8.2-ის PATH
  `env_digest`-ში; T3.03-მა უნდა უზრუნველყოს, რომ ნამდვილად ის binary გაეშვას

T3.02-ის named residuals, რომლებიც T3.03/T3.04-ს ეხება:

- `create_if_missing` მოითხოვს `fs=write_scoped`-ს, მაგრამ manifest ვერ არჩევს
  `fs.write`-ს (ქმნის) `fs.patch`-ისგან (არ ქმნის) — T3.04-ის საზღვარია
- მოდელის მიერ მოთხოვნილი dangling path ამჟამად **wiring-კლასის** შეცდომად ვრცელდება;
  T3.03/T3.04 გადაწყვეტს tool-დონის `error.kind`-ს
- dispatcher-ის token-შემოწმება **pre-filter**-ია, არა I15 gate: `machine._g_valid_token`-ის
  4 პირობიდან 2-ს ამოწმებს; consent liveness და §4.7 replay verdict kernel-ის მდგომარეობაა

## 4. როგორ ვმუშაობთ (სავალდებულო)

**თითო task:** ground → **RED first** (აჩვენე ჩავარდნილი output) → GREEN →
დეტერმინისტული floors → **იზოლირებული ადვერსარიული კრიტიკოსები** → refute →
refine ≤2 → commit.

- **მწვანე სუიტა არაფერს ამტკიცებს.** ამ პროექტზე **სამჯერ** თანაარსებობდა 100% branch
  coverage + `mypy --strict` + CRITICAL დეფექტი:
  - T4.01: 86 მწვანე ტესტი, 100% branch — და GPG კერძო გასაღები **სრულიად გაუშიფრავი**
  - T3.02: მწვანე სუიტა — და §7.3-ის აბსოლუტური DENY **symlink-ით შემოვლილი**
  - T4.02: მწვანე სუიტა — და U+2028-ი ერთ record-ს **ორ ხაზად ყოფდა**

  Coverage **შესრულებას** ზომავს, არა **მტკიცებას** (ADR-011-ის საკუთარი „Named
  limitation"). ხაზი სრულდებოდა; უბრალოდ ვერცერთი შემავალი მას სწორ პასუხს არ სთხოვდა.
- **კრიტიკოსები იზოლირებული უნდა იყოს.** თითო ხედავს მხოლოდ {frozen intent, ერთი diff,
  ერთი ლინზა, floors-ის output} — არასოდეს სხვისი findings. T3.02-ზე **ოთხივე ლინზა
  დამოუკიდებლად ერთსა და იმავე CRITICAL-ზე დაეთანხმა**; სწორედ ამ სიგნალისთვისაა
  იზოლაცია. ყოველი findings-ს მერე **ადვერსარიული refuter** — refuter-ებმა სწორად
  მოკლეს ცრუ findings და სწორად ჩამოწიეს severity.
- **ყოველი material claim თვითონ რეპროდუცირე**, სანამ იმოქმედებ.
- **ყოველი შესწორების შემდეგ mutation.** გადარჩენილმა mutant-მა **ორჯერ** გამოააშკარავა:
  ერთხელ **არასრული შესწორება** (ტიპი შემოვიღე, `except` ვერ განვაახლე), ერთხელ **სუსტი
  ტესტი** (არასწორ jsonschema შეცდომას იყენებდა). ტესტი იმას ამტკიცებს, რასაც **მართლა**
  ასრულებს, არა იმას, რასაც სახელი ჰპირდება.
- **ჩავარდნის ერთი ფორმა red-ი არაა:** T4.02-ზე FIFO-მ სუიტა **ჩაკიდა**, არ გააწითლა.
  ჩაკიდება უარესია — გეუბნება მხოლოდ იმას, რომ რაღაც არასწორია.
- **ნუ გააფართოვებ scope-ს ჩუმად.** სხვისი task-ის ფაილში დეფექტი → გაასწორე შენი,
  **დაასახელე** residual კოდის docstring-ში + ledger-ში. ცალკე `HARDEN-NN:` commit
  საჭიროებს ჩემს თანხმობას (პრეცედენტი: HARDEN-01…04).
- **ნურც შეავიწროვებ:** ცნობილი credential ფორმატის გაუშიფრავად დატოვება უარესია, ვიდრე
  დოკუმენტირებული საზღვრის გადაჭიმვა.
- **თითო task = თითო commit** `Tx.yy: …` სტილით (იხ. `git log`). Rollback-ის ერთეულია.
  საერთო ფაილები (`pyproject.toml`, `ci.yml`) hunk-ებად გაყავი, რომ ყოველი commit-ზე ხე
  მწვანე და bisectable დარჩეს.
- **Push მხოლოდ ცალკე თხოვნით.** Remote `github.com/null0xxx/kris` **private**-ია.
- **ნუ გაჩერდები task-ებს შორის ნებართვის სათხოვნელად.** Review-checkpoint commit-ის
  ტექსტში მიდის (RED evidence · floors · critics · mutations · residuals). კითხე მხოლოდ
  მაშინ, თუ ორი წაკითხვა არსებითად სხვა სამუშაოს იძლევა.
- `SPEC.md` და `IMPLEMENTATION_PLAN.md` **გაყინულია** — არასოდეს შეცვალო ტესტის
  გასამწვანებლად. SPEC-ის შეცვლა მხოლოდ: **გაზომილი** კორექცია + ჩემი თანხმობა +
  revision table (პრეცედენტი: §8.1 HARDEN-03-ის შემდეგ).
- **არასოდეს** განაახლო `.atlas/session_3056019e-…` — დასრულებული, hash-chained Gate-3
  ledger-ია (`current_state: OUTPUT`, terminal). არა-ტერმინალურად ქცევა Gate-3-ის ჩანაწერს
  გააფუჭებს.

## 5. წვრილმანი

- პროექტის root-ში შეიძლება გაჩნდეს `.atl/` — plugin-ის skill-registry cache. **არაა**
  პროექტის ნაწილი, ნუ დააკომიტებ.
- `tests/contract/` **უნდა** გაუშვას CI-მ (`unit` job უშვებს `tests/unit tests/contract`).
  ერთხელ არცერთი job არ უშვებდა და ორივე ახალი node-ის ერთადერთი gate იქ იყო.

---

დაიწყე §1-ის გაზომვით და §3-ის frontier-ის დადასტურებით, მერე გააგრძელე **T3.03**-ით.
