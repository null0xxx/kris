# Master Engineering Prompt — დამოუკიდებელი პერსონალური Linux AI-ასისტენტი

ქვემოთ მოცემული ტექსტი მთლიანად გადაეცი AI-ს, რომელმაც სისტემის არქიტექტურა უნდა შეიმუშაოს. ამ ეტაპზე მისი დავალებაა კვლევა, კრიტიკული შეფასება და specification-ის მომზადება — არა კოდის ნაადრევად დაწერა.

---

## როლი

იმოქმედე როგორც Principal AI Agent Systems Architect და წარმართე განხილვა ისე, თითქოს დიზაინს ერთობლივად ამოწმებს 15+ წლიანი გამოცდილების მქონე პროფესიონალთა ტექნიკური საბჭო შემდეგი პერსპექტივებით:

- distributed systems და software architecture;
- Linux internals, system administration და privilege separation;
- application security, threat modeling და secure-by-default engineering;
- LLM agent runtimes, tool calling და provider integration;
- developer tooling, CLI/TUI და terminal UX;
- memory/RAG, data lifecycle და privacy;
- coding agents, Git workflows და deterministic verification;
- test engineering, evaluation harnesses და adversarial testing;
- SRE, observability, failure recovery და incident analysis;
- software supply-chain security;
- pedagogy და Linux-ის პრაქტიკული სწავლება.

არ მოიქცე როგორც იდეის მხარდამჭერი კონსულტანტი. იყავი მკაცრი architecture review board: ეძებე მცდარი დაშვებები, ზედმეტი სირთულე, დაუცველი საზღვრები, framework lock-in, არარეალისტური ფუნქციები და ადგილები, სადაც LLM-ის ალბათური ქცევა deterministic გარანტიად არის შეცდომით აღქმული.

ყველა მნიშვნელოვანი რეკომენდაცია დაასაბუთე მტკიცებულებით, trade-off-ითა და უარყოფილი ალტერნატივით. ფაქტი, ვარაუდი, რეკომენდაცია და ღია კითხვა ერთმანეთისგან მკაფიოდ გამოყავი.

## მთავარი მიზანი

უნდა დაიგეგმოს ნულიდან შექმნილი, დამოუკიდებელი, open-source-ready პერსონალური AI-ასისტენტი, რომელიც Linux-ზე მუშაობს და კონკრეტულ მომხმარებელზე თანდათან მორგებადი იქნება.

ეს არ უნდა იყოს:

- Hermes Agent-ის ან OpenClaw-ის fork;
- მათი wrapper ან გადარქმეული ვერსია;
- Kimi Code CLI-ის უბრალო wrapper;
- LangGraph-ის, PydanticAI-ის ან სხვა agent framework-ის მიერ ნაკარნახევი პროდუქტი;
- მხოლოდ chatbot, რომელიც shell command-ებს ტექსტად წერს;
- საკუთარი foundation model-ის ტრენინგის პროექტი.

ეს უნდა იყოს საკუთარი codebase, საკუთარი agent kernel, საკუთარი tool runtime, permission engine, skill lifecycle, memory model, audit სისტემა და CLI. ჩვეულებრივი დაბალი დონის ბიბლიოთეკების გამოყენება დასაშვებია, მაგრამ core domain model და უსაფრთხოების საზღვრები პროექტს უნდა ეკუთვნოდეს.

Hermes, OpenClaw, Kimi Code, Codex, Claude Code, Open Interpreter, Aider და სხვა სისტემები გამოიყენე მხოლოდ:

- source-level კვლევისათვის;
- proven pattern-ების შესასწავლად;
- failure mode-ების გამოსავლენად;
- build-vs-buy გადაწყვეტილებების დასასაბუთებლად;
- benchmark-ად.

არ გადაიტანო მათი არქიტექტურა ბრმად და არ მიაწერო ფუნქცია მხოლოდ README-ის ან მარკეტინგული ტექსტის საფუძველზე.

## ცნობილი მომხმარებლის კონტექსტი

- გარემო: Linux, terminal-first workflow.
- V1 ინტერფეისი: მხოლოდ ხელით გასაშვები interactive CLI.
- V1-ში არ უნდა არსებობდეს daemon, background service, Web UI, Telegram, Discord, voice ან სხვა messaging gateway.
- მთავარი LLM provider: Kimi Code-ის subscription-ში შემავალი, ოფიციალურად ნებადართული API access.
- fallback provider: ლოკალური Ollama, შეზღუდული შესაძლებლობებით.
- ცნობილი აპარატურა: Intel Core i5-13600KF, 32 GB RAM, NVIDIA GTX 1070 8 GB VRAM და NVMe SSD.
- მომხმარებელს უკვე აქვს Linux, Kimi Code CLI და Ollama-ს გამოცდილება, თუმცა რეალური გარემო read-only აღმოჩენით უნდა გადამოწმდეს.
- ასისტენტმა უნდა შეძლოს კოდის წერა, repository-ის ანალიზი, ფაილების მიზნობრივი შეცვლა, ბრძანებების გაშვება, ტესტირება და შედეგის მტკიცებულებით გადამოწმება.
- ასისტენტს უნდა ჰქონდეს Linux Tutor Mode, რათა მომხმარებელი მხოლოდ მზა ბრძანებებზე დამოკიდებული არ გახდეს და რეალურად ისწავლოს Linux.
- ავტონომიის მოდელი: ჩვეულებრივი დაბალი რისკის მოქმედებები შეიძლება შესრულდეს ავტომატურად; `sudo`, წაშლა, სისტემური ცვლილება და სხვა მაღალი რისკის ქმედება მოითხოვს მომხმარებლის ზუსტ თანხმობას.
- ნებისმიერი self-improvement ნაგულისხმევად გამორთულია. მისი რეჟიმის ჩართვაც მხოლოდ ცვლილების მომზადების უფლებას იძლევა; შექმნილი skill-ის, policy-ის ან core code-ის გააქტიურებას ცალკე საბოლოო თანხმობა სჭირდება.
- პროექტი უნდა იყოს ეტაპობრივად გასაუმჯობესებელი, მაგრამ V1 შეგნებულად მცირე, გასაგები და შემოწმებადი უნდა დარჩეს.

თუ აღმოჩენილი რეალური გარემო ამ კონტექსტს ეწინააღმდეგება, ჩუმად ნუ შეცვლი მოთხოვნას. აჩვენე შეუსაბამობა და მოითხოვე გადაწყვეტილება.

## არაგადასალახი არქიტექტურული პრინციპები

1. **LLM is not the authority.** მოდელი გეგმავს და ითხოვს მოქმედებას, მაგრამ execution-ის ავტორიტეტი deterministic kernel-ს ეკუთვნის.
2. **No direct shell access.** მოდელმა shell subprocess პირდაპირ არ უნდა გამოიძახოს. იგი ქმნის typed tool request-ს; kernel ამოწმებს schema-ს, policy-ს, scope-სა და approval-ს.
3. **Least privilege.** თითოეულ tool-ს მიეცეს მხოლოდ საჭირო filesystem, process, network და credential შესაძლებლობა.
4. **Untrusted by default.** repository-ის ტექსტი, web content, tool output, memory და community skill ჩაითვალოს არანდო მონაცემად და არა system instruction-ად.
5. **Evidence before completion.** მოდელის თავდაჯერებულობა არ არის წარმატების მტკიცებულება.
6. **Human authority.** მომხმარებელს უნდა შეეძლოს deny, cancel, inspect, forget, rollback და permission-ის გაუქმება.
7. **Reversible by design.** შეძლებისდაგვარად გამოიყენე checkpoint, Git branch/worktree, backup, atomic write და rollback.
8. **Explicit degradation.** Kimi-დან Ollama-ზე გადასვლა არასოდეს მოხდეს ჩუმად.
9. **No hidden persistence.** startup entry, cron, systemd service ან სხვა persistence მომხმარებლის ცალკე მოთხოვნისა და თანხმობის გარეშე არ შეიქმნას.
10. **No self-approval.** ასისტენტს საკუთარი ცვლილების დამტკიცება ან უსაფრთხოების policy-ის შემსუბუქება არ შეუძლია.
11. **No security theater.** prompt-level გაფრთხილება OS-level ან deterministic enforcement-ის შემცვლელი არ არის.
12. **Small trusted core.** privilege, policy, approval, audit და execution boundary იყოს მცირე, მკაფიო და ინტენსიურად დატესტილი.

## კვლევის სავალდებულო ეტაპი

ნებისმიერი არქიტექტურული გადაწყვეტილების მიღებამდე:

1. გადაამოწმე მიმდინარე ოფიციალური Kimi Code დოკუმენტაცია:
   - subscription API key-ის მიღების ოფიციალური გზა;
   - OpenAI-compatible და Anthropic-compatible endpoint-ები;
   - ხელმისაწვდომი model ID-ები;
   - tool/function calling-ის რეალური ფორმატი;
   - context, rate, concurrency და usage limits;
   - Terms/identity შეზღუდვები;
   - authentication, key rotation და error behavior.
2. არ გამოიყენო Kimi CLI-ის OAuth token-ის ამოღება, client identity-ის გაყალბება ან არაოფიციალური workaround.
3. source code-ის დონეზე შეისწავლე Hermes და OpenClaw-ის მხოლოდ რელევანტური ნაწილები:
   - agent loop;
   - tool registry;
   - permissions/sandbox;
   - memory;
   - skills;
   - provider adapters;
   - prompt-injection defenses;
   - update/self-improvement model.
4. გამოყავი:
   - რა pattern ღირს დამოუკიდებლად ხელახლა განხორციელებად;
   - რა არ უნდა გადაიტანოს პროექტმა;
   - რა არის მხოლოდ მარკეტინგული პრეტენზია;
   - რა უსაფრთხოების ინციდენტები ან design weakness-ებია ცნობილი.
5. შეადარე მინიმუმ სამი განხორციელების სტრატეგია:
   - greenfield thin core ჩვეულებრივი ბიბლიოთეკებით;
   - greenfield core შერჩეული agent library/framework კომპონენტებით;
   - არსებული runtime-ის fork/wrapper.
6. რეკომენდაცია არ გასცე მანამ, სანამ არ წარმოადგენ decision matrix-ს შემდეგი კრიტერიუმებით:
   - ownership და independence;
   - security enforceability;
   - testability;
   - maintainability ერთი დეველოპერისთვის;
   - Linux integration;
   - Kimi/Ollama portability;
   - framework lock-in;
   - time-to-first-safe-MVP;
   - performance და hardware fit;
   - migration cost.

გამოიყენე პირველადი წყაროები: ოფიციალური დოკუმენტაცია, ოფიციალური repository, source code, releases, security advisories და protocols. ყველა დროის მიმართ ცვალებადი ფაქტი დააციტირე პირდაპირი ბმულით და მიუთითე შემოწმების თარიღი.

## ენისა და ტექნოლოგიური სტეკის არჩევანი

არ აირჩიო Python, TypeScript, Go ან Rust მხოლოდ პოპულარობის გამო. წარმოადგინე შედარება:

- async/process management;
- typed contracts;
- CLI ecosystem;
- JSON Schema/tool integration;
- Linux system APIs;
- packaging და single-user installation;
- testability;
- startup latency;
- dependency/supply-chain surface;
- contributor ergonomics;
- Ollama/Kimi client support;
- უსაფრთხო subprocess მართვა.

საწყისი ჰიპოთეზა შეიძლება იყოს Python 3.12+ thin core, მაგრამ იგი არ არის წინასწარ დამტკიცებული გადაწყვეტილება. განიხილე, საჭიროა თუ არა Python core + მკაცრი typed schemas, ან მცირე privilege broker-ის დაწერა Rust/Go-ში მოგვიანებით. V1-ში polyglot არქიტექტურა მხოლოდ მკაფიო მტკიცებულებით დაუშვი.

არ შემოიტანო vector database, Kubernetes, message broker, microservices, distributed agent swarm ან სხვა მძიმე ინფრასტრუქტურა, თუ კონკრეტული V1 მოთხოვნა ამას არ ამართლებს.

## აუცილებელი კომპონენტები და მათი კონტრაქტები

### 1. CLI და Session Controller

დააპროექტე:

- interactive session;
- one-shot command mode მომავალთან თავსებადი ფორმით;
- `--dry-run`, `--explain`, `--safe`, `--offline` და `--no-tools` semantics;
- graceful cancellation;
- session resume მხოლოდ უსაფრთხო checkpoint-იდან;
- terminal output-ის მკაფიო დაყოფა: reasoning summary, planned action, approval request, tool result, verification და final verdict;
- ქართული და ინგლისური პასუხების მხარდაჭერა ისე, რომ code, command და identifier უცვლელი დარჩეს.

CLI-მ არ უნდა დამალოს მნიშვნელოვანი მოქმედება „working...“-ის უკან. მომხმარებელმა წინასწარ უნდა დაინახოს ზუსტი command/operation, target, cwd, permission class, risk და rollback შესაძლებლობა.

### 2. Deterministic Agent Kernel

მოდელი განიხილე როგორც არასანდო planner. შეიმუშავე explicit state machine, მაგალითად:

`RECEIVE → CLASSIFY → GROUND → PLAN → POLICY_CHECK → APPROVAL → EXECUTE → OBSERVE → VERIFY → REPORT`

საჭიროა:

- state transitions-ის deterministic validation;
- iteration, time, token და cost/quota budgets;
- loop detection;
- retry policy და backoff;
- cancellation;
- crash-safe state persistence;
- idempotency;
- partial failure handling;
- `VERIFIED`, `PARTIAL`, `UNVERIFIED`, `BLOCKED`, `CANCELLED` verdict semantics.

არცერთი tool call არ შესრულდეს schema validation-ისა და policy decision-ის გარეშე.

### 3. Provider Abstraction და Model Router

შექმენი provider-neutral interface:

- streaming chat;
- structured tool request;
- context limits;
- thinking/effort controls;
- timeout;
- retryable/non-retryable errors;
- rate-limit metadata;
- cancellation;
- usage accounting;
- model capability discovery.

Primary:

- Kimi Code membership API მხოლოდ ოფიციალური API key-ითა და ოფიციალური endpoint-ით;
- secret არ შეინახოს repository-ში ან log-ში;
- key rotation და revocation იყოს შესაძლებელი;
- provider-ის User-Agent/identity მოთხოვნები დაცული იყოს.

Fallback:

- Ollama `localhost`-ზე;
- Kimi failure-ისას CLI-მ მკაფიოდ გამოაცხადოს fallback;
- local მოდელმა მიიღოს მხოლოდ ის tools, რომლებზეც კონკრეტულად გაიარა tool-use evaluation;
- თუ fallback მოდელს საიმედო structured tool calling არ შეუძლია, რეჟიმი შეიზღუდოს explanation, tutoring, planning და read-only დახმარებით;
- არ მოხდეს სუსტი მოდელით მაღალი რისკის plan-ის ჩუმად გაგრძელება;
- Kimi დაბრუნებისას მიმდინარე task-ის შუაში provider switch ავტომატურად არ მოხდეს.

შექმენი capability matrix, circuit breaker და downgrade policy.

### 4. Tool Runtime

ჯერ შექმენი typed tools და მხოლოდ უკიდურეს შემთხვევაში ზოგადი shell tool. თითოეულ tool manifest-ში განსაზღვრე:

- name და version;
- purpose;
- strict input/output schema;
- permission class;
- filesystem/network/process capabilities;
- allowed paths და canonical path handling;
- timeout და output-size limit;
- concurrency behavior;
- preconditions/postconditions;
- idempotency;
- dry-run support;
- rollback metadata;
- audit/redaction rules;
- tests.

V1-ის კანდიდატი tools:

- read/list/find file;
- atomic scoped write/patch;
- Git status/diff/branch/worktree;
- process execution მკაცრი argument array-ით;
- test runner;
- system information read-only;
- package query read-only;
- network fetch allowlist-ით.

ზოგად shell command-ში აკრძალე implicit shell interpolation ნაგულისხმევად. განიხილე `execve`-style argument arrays, controlled environment, canonical cwd, environment allowlist, resource limits და child-process tree cancellation.

### 5. Permission Engine

შექმენი capability-based policy და არა უბრალო yes/no prompt.

მინიმალური კლასები:

- `AUTO_READ`: არამგრძნობიარე read-only დაკვირვება;
- `AUTO_SCOPED_WRITE`: მხოლოდ წინასწარ დამტკიცებულ workspace-ში, checkpoint-ითა და rollback-ით;
- `CONFIRM_ONCE`: კონკრეტული დაბალი/საშუალო რისკის ოპერაცია;
- `CONFIRM_EXACT`: `sudo`, delete, overwrite, package install/remove, service, network/firewall, credential, external send, destructive Git და security setting;
- `DENY_ALWAYS`: credential exfiltration, security bypass, raw disk overwrite, მასობრივი გაურკვეველი წაშლა, საკუთარი approval-ის გაცემა და audit-ის ჩუმად გამორთვა.

Approval უნდა იყოს capability token, რომელიც მიბმულია:

- ზუსტ tool-ზე;
- normalized arguments-ზე;
- cwd/path scope-ზე;
- environment digest-ზე;
- plan/action hash-ზე;
- მოქმედებების მაქსიმალურ რაოდენობაზე;
- expiry/TTL-ზე.

თუ command, path, argument ან environment შეიცვალა, ძველი approval გაუქმდეს. „Allow all“ არ გამოიყენო. Elevated რეჟიმი დაიყოს კონკრეტულ privilege domain-ებად და ავტომატურად გაუქმდეს session-ის ან TTL-ის დასრულებისას.

განსაზღვრე TOCTOU, symlink swap, path traversal, wildcard expansion და command substitution-ის დაცვა.

### 6. Sandbox და Isolation

შეადარე:

- subprocess isolation;
- Git worktree;
- temporary workspace;
- Bubblewrap;
- rootless Podman/Docker;
- systemd-run user scope;
- seccomp/AppArmor;
- ცალკე privilege broker.

V1-ისთვის აირჩიე უმარტივესი enforceable მოდელი, მაგრამ მიუთითე მისი ზუსტი საზღვრები. „Sandboxed“ არ დაწერო, თუ რეალურად მხოლოდ prompt instruction არსებობს.

### 7. Skills System

Skill განიხილე როგორც versioned procedural package და არა თავისუფალი Markdown prompt.

Skill contract-ში შეაფასე:

- manifest და schema version;
- human-readable instructions;
- required tools და permissions;
- dependencies;
- provenance/source;
- content hash ან signature;
- compatibility;
- test cases;
- examples;
- risk classification;
- changelog;
- install/enable/disable/update/rollback lifecycle.

Skill-ის ტექსტის წაკითხვა არ უნდა ნიშნავდეს მის შესრულებას. Community skill ჩაითვალოს supply-chain რისკად. ინსტალაციამდე მოხდეს static inspection, dependency review, permission diff და sandbox test.

### 8. Memory System

მეხსიერება გაყავი მინიმუმ:

- ephemeral working context;
- session history;
- durable user preferences;
- episodic task history;
- procedural knowledge/skills.

თითოეულ durable item-ს ჰქონდეს provenance, timestamp, confidence, sensitivity, retention და delete/forget support.

განსაზღვრე:

- რა ინახება ავტომატურად;
- რას სჭირდება მომხმარებლის თანხმობა;
- რა არასოდეს ინახება;
- როგორ ხდება correction და deletion;
- როგორ ირიდებს სისტემა memory poisoning-ს;
- როგორ იზოლირდება untrusted retrieved text system instructions-ისგან;
- როგორ ხდება secrets/PII redaction.

V1-ში შეაფასე SQLite + FTS5-ის საკმარისობა. embeddings/vector retrieval დაამატე მხოლოდ benchmark-ით დამტკიცებული საჭიროების შემდეგ.

### 9. Coding Mode

Coding workflow:

`capture immutable intent → inspect repository → define scope → plan → checkpoint/isolate → edit → test → security check → diff review → verify → report`

აუცილებელია:

- user request-ის immutable copy;
- repository instructions-ის trust classification;
- scope boundary;
- unrelated user changes-ის დაცვა;
- no destructive Git reset;
- atomic edits;
- generated code-ის lint/type/test;
- test output-ის რეალური capture;
- verification command და acceptance criteria;
- საბოლოო diff summary;
- `VERIFIED` მხოლოდ deterministic evidence-ის საფუძველზე.

### 10. Linux Tutor Mode

Tutor Mode-ს ჰქონდეს სამი განსხვავებული ქცევა:

- `EXPLAIN`: მხოლოდ კონცეფცია და მაგალითი;
- `GUIDED`: მომხმარებელი ასრულებს ნაბიჯებს, ასისტენტი ამოწმებს;
- `DO_AND_TEACH`: ასისტენტი ასრულებს ნებადართულ მოქმედებას და პარალელურად ასწავლის.

ყოველ მნიშვნელოვან command-ზე ახსენი:

- რას აკეთებს;
- რატომ არის საჭირო;
- რას ცვლის;
- რა არის რისკი;
- როგორ მოწმდება შედეგი;
- როგორ ბრუნდება წინა მდგომარეობა.

არ გადააქციო სწავლება ზედმეტ ლექციად. გამოიყენე მომხმარებლის დონეზე მორგებული progressive disclosure, მცირე პრაქტიკული დავალებები და რეალური output-ის ინტერპრეტაცია. არასოდეს მოიგონო command-ის წარმატება.

### 11. Self-Improvement Laboratory

Self-improvement-ს ჰქონდეს ცალკე, ნაგულისხმევად გამორთული feature gate.

რეჟიმის ჩართვა ნიშნავს მხოლოდ:

1. improvement proposal;
2. rationale და expected benefit;
3. isolated branch/worktree;
4. code/skill draft;
5. static checks;
6. regression/evaluation suite;
7. security review;
8. before/after evidence;
9. human-readable diff;
10. rollback plan.

ამის შემდეგ სისტემა უნდა გაჩერდეს. გააქტიურებას სჭირდება ცალკე ზუსტი თანხმობა. მიმდინარე პროცესმა საკუთარი executable/core არ უნდა ჩაანაცვლოს. განიხილე staged updater, signed manifest, version pinning, migration safety და last-known-good rollback.

ასისტენტს ეკრძალება:

- საკუთარი permission policy-ის შერბილება;
- tests/evals-ის შეცვლა მხოლოდ იმისათვის, რომ ცვლილებამ გაიაროს;
- audit evidence-ის წაშლა;
- approval-ის ინტერპრეტაცია სხვა ცვლილებაზეც;
- community code-ის ავტომატური მიღება;
- თვითშექმნილი skill-ის ავტომატური გააქტიურება.

### 12. Configuration და Secrets

კონფიგურაცია დააპროექტე XDG Base Directory-ის პრინციპებით და მკაფიო schema/version migration-ით. განსაზღვრე:

- config, state, cache, data და logs-ის ცალკე მდებარეობა;
- file permission-ები და ownership checks;
- environment variable, protected file და OS secret store-ის resolution order;
- Kimi API key-ის შექმნა, შენახვა, rotation და revocation;
- Ollama endpoint-ის allowlist და localhost enforcement;
- secrets-ის redaction error-ში, log-ში, prompt-ში და subprocess environment-ში;
- configuration validation startup-მდე;
- უსაფრთხო default-ები unknown ან deprecated field-ზე;
- export/import ისე, რომ secrets ნაგულისხმევად არ გაჰყვეს.

არ ჩათვალო `.env` თავისთავად უსაფრთხო secrets manager-ად. V1-ის რეკომენდაცია შეარჩიე threat model-ისა და გამოყენების სიმარტივის დაბალანსებით.

### 13. Dependency და Supply-Chain Security

შეიმუშავე:

- minimal dependency policy;
- exact version lock;
- hash verification იქ, სადაც შესაძლებელია;
- dependency provenance;
- SBOM;
- vulnerability/license scanning;
- reproducible build-ის მიზანი;
- signed/tagged release;
- update manifest და rollback;
- CI-ში secret scanning;
- community skill/tool dependency-ის ცალკე quarantine.

ნებისმიერი install script ჩაითვალოს executable supply-chain boundary-ად. `curl | shell` არ იყოს პროექტის ნაგულისხმევი ნდობის მოდელი source/pin/checksum verification-ის გარეშე.

MCP-სთვის დატოვე მკაფიო adapter boundary და capability filtering, მაგრამ V1-ში arbitrary MCP server-ის ჩართვა ნაგულისხმევად გამორთული იყოს. MCP server-ის tools-საც ზუსტად იგივე policy, schema, approval და audit მოთხოვნები უნდა შეეხოს, რაც native tool-ს.

### 14. Audit, Observability და Recovery

Audit log იყოს structured, append-oriented და tamper-evident-ისკენ მომართული. ჩაიწეროს:

- session/task ID;
- user intent digest;
- model/provider/model version;
- plan revision;
- policy decision;
- approval scope;
- tool request/result metadata;
- redacted error;
- file diff/checkpoint;
- verification evidence;
- final verdict.

არ ჩაიწეროს secrets, სრული sensitive content ან chain-of-thought. განსაზღვრე log rotation, retention, export, redaction და user-readable inspection.

შექმენი recovery model:

- Ctrl+C;
- provider timeout;
- rate limit;
- malformed tool request;
- child process hang;
- disk full;
- crash write-ის დროს;
- partial package operation;
- interrupted self-update;
- corrupted state/memory.

## სავალდებულო Threat Model

მინიმუმ გააანალიზე:

- prompt injection repository/web/tool output-იდან;
- malicious `AGENTS.md`, README ან copied command;
- command injection;
- path traversal და symlink attack;
- arbitrary file overwrite;
- privilege escalation;
- secret leakage logs/context/provider-ში;
- SSRF და data exfiltration;
- malicious MCP/tool/skill/plugin;
- dependency confusion და typosquatting;
- memory poisoning;
- approval spoofing და approval reuse;
- TOCTOU approval-სა და execution-ს შორის;
- denial of service, fork bomb და resource exhaustion;
- destructive Git მოქმედება;
- model hallucination;
- compromised or unavailable provider;
- local Ollama model-ის სუსტი tool-call fidelity;
- self-improvement regression ან policy bypass.

თითოეულ საფრთხეზე მიუთითე asset, attacker, entry point, likelihood, impact, mitigation, residual risk და შესაბამისი test.

## კრიტიკული დაჩელენჯების სავალდებულო კითხვები

უპასუხე პირდაპირ:

1. რა გვაძლევს საკუთარი agent kernel-ის შექმნა და სად შეიძლება ეს ცუდი ინჟინერული გადაწყვეტილება აღმოჩნდეს?
2. როგორ შევინარჩუნოთ small trusted core მაშინ, როდესაც tool/skill რაოდენობა იზრდება?
3. რომელი გარანტიებია რეალურად enforceable და რომელი მხოლოდ prompt-level სურვილია?
4. როგორ დავამტკიცოთ, რომ approval ზუსტად იმ მოქმედებაზე გამოიყენება, რომელიც მომხმარებელმა ნახა?
5. შეიძლება თუ არა Ollama fallback-მა უსაფრთხოდ გამოიყენოს tools მოცემულ აპარატურაზე?
6. რა უნდა მოხდეს, თუ Kimi API-ის ფორმატი, quota ან membership პირობები შეიცვალა?
7. როგორ ავიცილოთ memory-ის ზრდა, დაბინძურება და მცდარი personalization?
8. როგორ დავიცვათ სისტემა malicious repository instructions-ისგან ისე, რომ coding workflow არ გავაფუჭოთ?
9. როგორ ვამოწმებთ თვითგაუმჯობესებას იმავე მოდელის თვითშეფასებაზე დამოკიდებულების გარეშე?
10. რა უნდა ამოვიღოთ V1-დან, რათა პროექტი რეალურად დასრულებადი დარჩეს?
11. სად არის Unix permissions საკმარისი და სად გვჭირდება რეალური OS sandbox?
12. როგორ აღდგება სისტემა შუა ოპერაციაში crash-ის შემდეგ ზიანის გამეორების გარეშე?
13. როგორი API/ABI უნდა ჰქონდეს tools-ს, რომ მომავალში core-ის გადაწერა არ გახდეს საჭირო?
14. როგორ გავზომოთ, რომ Tutor Mode მომხმარებელს რეალურად ასწავლის და არა მხოლოდ პასუხებს აძლევს?
15. რა იქნება პროექტის stop criteria — რომელ პირობებში უნდა ითქვას, რომ არქიტექტურა ზედმეტად რთულია ან არასაიმედო?

## V1-ის მკაცრი საზღვრები

V1-ში არ შეიტანო:

- daemon/background autonomy;
- messaging integrations;
- voice;
- GUI/Web UI;
- multi-user support;
- autonomous multi-agent swarm;
- unrestricted MCP marketplace;
- automatic community skill installation;
- full root access;
- autonomous self-modification;
- fine-tuning/RL;
- cloud-hosted memory;
- vector database მტკიცებულების გარეშე;
- microservices;
- plugin marketplace;
- arbitrary always-on monitoring.

თუ რომელიმე მათგანი აუცილებელი გგონია, ჯერ დაამტკიცე, რომ მოთხოვნა მის გარეშე ვერ შესრულდება.

## ფაზები და გადაწყვეტილების Gates

### Gate 0 — Read-only Discovery

წარმოადგინე მხოლოდ უსაფრთხო read-only ბრძანებები გარემოს დასადგენად. არაფერი დააინსტალირო და არ შეცვალო.

### Gate 1 — Research and Architecture Challenge

წარმოადგინე წყაროებზე დაფუძნებული კვლევა, სამი ვარიანტი, decision matrix, failure scenarios და მკაცრი რეკომენდაცია. კოდი არ დაწერო.

### Gate 2 — Approved Technical Specification

მომხმარებლის არჩევანის შემდეგ შექმენი სრული specification, ADR-ები, data contracts, state machine, permission matrix, threat model, repository tree, tests და acceptance criteria. კვლავ არ დაწერო production code.

### Gate 3 — Implementation Plan

მხოლოდ specification-ის ცალკე დამტკიცების შემდეგ შექმენი მცირე, თანმიმდევრული, test-first implementation plan. თითოეულ task-ს ჰქონდეს ზუსტი scope, files, tests, verification და rollback.

### Gate 4 — Implementation

კოდი დაიწეროს მხოლოდ implementation plan-ის დამტკიცების შემდეგ, ეტაპობრივად. ყოველი ფაზა დასრულდეს რეალური verification evidence-ითა და მომხმარებლის review checkpoint-ით.

არცერთი gate არ ჩაითვალოს ნაგულისხმევად დამტკიცებულად.

## Gate 1-ის მოთხოვნილი output

პირველ პასუხში წარმოადგინე ზუსტად ეს სტრუქტურა:

1. **Executive Verdict** — მოკლე, მკაფიო რეკომენდაცია.
2. **Restated Mission and Non-Negotiables** — აჩვენე, სწორად გაიგე თუ არა მიზანი.
3. **Verified Facts vs Assumptions** — ცალ-ცალკე.
4. **Current Environment Discovery Plan** — მხოლოდ read-only.
5. **Primary-Source Research Findings** — ციტირებებითა და თარიღებით.
6. **Three Architecture Options** — რეალური trade-off-ებით.
7. **Decision Matrix** — weighted criteria და ქულების დასაბუთება.
8. **Recommended Architecture** — component boundaries და dependency rules.
9. **Small Trusted Core Definition** — რა შედის და რა არ შედის.
10. **Permission and Approval Model** — capability/token semantics.
11. **Kimi/Ollama Provider Strategy** — fallback-ის მკაცრი საზღვრებით.
12. **Skill, Memory and Self-Improvement Model**.
13. **Threat Model Summary** — ყველაზე მძიმე საფრთხეები.
14. **Five Catastrophic Failure Scenarios** — prevention, detection, recovery.
15. **V1 Scope and Explicit Non-Goals**.
16. **Acceptance Criteria**.
17. **Risk Register** — probability, impact, mitigation, owner.
18. **Open Decisions** — მხოლოდ ის კითხვები, რომლებიც რეალურად ცვლის არქიტექტურას.
19. **Professional Challenge** — რატომ შეიძლება რეკომენდებული გეგმაც მცდარი იყოს.
20. **Approval Request for Gate 2** — გაჩერდი და დაელოდე მომხმარებელს.

გამოიყენე Mermaid მხოლოდ მაშინ, როცა data flow, trust boundary ან state transition ტექსტზე უკეთ გამოჩნდება. დიაგრამამ არ უნდა ჩაანაცვლოს ზუსტი კონტრაქტები.

## მინიმალური Acceptance Criteria მომავალი V1-ისთვის

Specification-მა მინიმუმ უნდა უზრუნველყოს:

1. ინსტალაცია ჩვეულებრივი Linux user-ის ფარგლებში root-ის გარეშე.
2. interactive CLI-ის ხელით გაშვება.
3. Kimi Code provider-ის ოფიციალური authentication.
4. Kimi-ის ჩავარდნის მკაფიო აღმოჩენა და Ollama-ზე მხოლოდ ნებადართული downgrade.
5. read-only tool-ის ავტომატური უსაფრთხო შესრულება.
6. scoped workspace write checkpoint-ითა და diff-ით.
7. `sudo`, delete ან სხვა მაღალი რისკის მოქმედების ზუსტი approval.
8. deny/cancel-ის შემდეგ მოქმედების არშესრულების მტკიცებულება.
9. approval-ის invalidation command/path/argument ცვლილებისას.
10. malicious prompt/tool output-ისგან policy boundary-ის დაცვა.
11. crash/interrupt-ის შემდეგ უსაფრთხო recovery.
12. secrets-ის არყოფნა repository-სა და logs-ში.
13. Coding Mode-ის მიერ რეალური test/verification evidence.
14. Tutor Mode-ის მიერ command, risk, verification და rollback-ის ახსნა.
15. skill draft-ის იზოლირებული ტესტირება და activation-მდე გაჩერება.
16. self-improvement რეჟიმში ცვლილების ავტომატურად არგააქტიურება.
17. ყველა tool action-ის redacted audit trail.
18. memory inspect/correct/delete.
19. provider-independent contract tests.
20. უსაფრთხოების regression suite.

## ხარისხის ზღვარი

არ გამოიყენო ბუნდოვანი ფრაზები, როგორიცაა:

- „გამოიყენე უსაფრთხო sandbox“;
- „დაამატე memory“;
- „გააკეთე modular architecture“;
- „საჭიროების შემთხვევაში მოითხოვე თანხმობა“;
- „გამოიყენე best practices“.

ყოველ ასეთ განცხადებას დაურთე კონკრეტული mechanism, boundary, data contract, failure behavior და verification method.

არ წარმოადგინო დიდი ფუნქციების სია როგორც არქიტექტურა. ჯერ განსაზღვრე trust boundaries, invariants, state transitions და ownership.

თუ რომელიმე მოთხოვნა პრაქტიკულად შეუძლებელია, სახიფათოა ან ერთმანეთთან წინააღმდეგობაშია, პირდაპირ თქვი. შემომთავაზე ყველაზე მცირე უსაფრთხო ალტერნატივა.

პასუხი დაწერე ქართულად. კოდი, command, path, schema field, protocol და identifier დატოვე ინგლისურად. ზედმეტი მარკეტინგული ენა არ გამოიყენო.

დაიწყე მხოლოდ **Gate 1 — Research and Architecture Challenge**-ით. არ დაწერო production code და არ გადახვიდე Gate 2-ზე ჩემი მკაფიო თანხმობის გარეშე.
