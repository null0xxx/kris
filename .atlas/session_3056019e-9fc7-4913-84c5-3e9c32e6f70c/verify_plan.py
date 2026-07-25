#!/usr/bin/env python3
"""Deterministic structural verifier for IMPLEMENTATION_PLAN.md (Gate 3).

Pure checks only — no LLM judgment. Exit 0 = all checks pass.
Checks K1..K8 coverage, the 9-label task template, dependency sanity,
AC mapping completeness, tool catalog coverage, and placeholder hygiene.
"""
import re
import sys
from pathlib import Path

ROOT = Path("/home/null/Desktop/LinuxSec")
PLAN = ROOT / "IMPLEMENTATION_PLAN.md"

fails: list[str] = []


def check(cond: bool, label: str) -> None:
    if not cond:
        fails.append(label)


text = PLAN.read_text(encoding="utf-8")

# --- Global markers -------------------------------------------------------
check("GATE 3 DRAFT" in text, "missing GATE 3 status marker")
check("SPEC.md" in text, "no reference to SPEC.md")
check("## Gate 4 Entry Criteria" in text, "missing Gate 4 Entry Criteria section (K8)")
check("## Stop Conditions" in text, "missing Stop Conditions section (K8)")
check("8 weeks" in text or "8 კვირა" in text or "> 8" in text, "stop criteria content missing (K8)")
for bad in ("TODO", "FIXME", "XXX", "T5.NN", "T1.NN", "T2.NN", "T3.NN", "T4.NN", "T6.NN"):
    check(bad not in text, f"placeholder left in document: {bad}")

# --- Task template (9 labels, order, per task) ----------------------------
LABELS = [
    "**Scope:**", "**Files:**", "**Depends on:**", "**RED (tests first):**",
    "**GREEN (implementation):**", "**Expected results:**", "**Verification:**",
    "**Review checkpoint:**", "**Rollback:**",
]
task_heads = list(re.finditer(r"^### (T[1-6]\.\d{2})", text, re.M))
check(len(task_heads) >= 40, f"too few tasks found: {len(task_heads)} (< 40)")

ids = [m.group(1) for m in task_heads]
check(len(ids) == len(set(ids)), f"duplicate task IDs: {sorted({i for i in ids if ids.count(i) > 1})}")

bounds = [m.start() for m in task_heads] + [len(text)]
for idx, m in enumerate(task_heads):
    body = text[m.end():bounds[idx + 1]]
    pos = -1
    for lab in LABELS:
        p = body.find(lab)
        check(p != -1, f"{m.group(1)}: missing label {lab}")
        if p != -1:
            check(p > pos, f"{m.group(1)}: label out of order {lab}")
            pos = p

# --- Dependency sanity: all IDs exist, graph acyclic ----------------------
# Execution order is the topological order of the Depends-on graph (declared
# in §0 of the plan); phase numbers are authoring grouping, not build order.
def tid_key(t: str) -> tuple[int, int]:
    a, b = t.split(".")
    return (int(a[1]), int(b))

id_set = set(ids)
edges: dict[str, list[str]] = {i: [] for i in ids}
for m in task_heads:
    body = text[m.end():bounds[ids.index(m.group(1)) + 1]]
    dep_m = re.search(r"\*\*Depends on:\*\*(.+)", body)
    if not dep_m:
        continue
    # only the ID list before any parenthetical prose counts as dependencies
    head = dep_m.group(1).split("(", 1)[0]
    for dep in dict.fromkeys(re.findall(r"T[1-6]\.\d{2}", head)):
        check(dep in id_set, f"{m.group(1)}: depends on unknown task {dep}")
        check(dep != m.group(1), f"{m.group(1)}: self-dependency")
        if dep in id_set:
            edges[m.group(1)].append(dep)

# acyclicity via Kahn's algorithm
indeg = {i: 0 for i in ids}
for t, deps in edges.items():
    for d in deps:
        indeg[t] += 1
queue = [i for i in ids if indeg[i] == 0]
seen = 0
while queue:
    nxt = []
    for t in queue:
        seen += 1
        for u, deps in edges.items():
            if t in deps:
                indeg[u] -= 1
                if indeg[u] == 0:
                    nxt.append(u)
    queue = nxt
check(seen == len(ids), f"dependency cycle detected ({seen}/{len(ids)} tasks sortable)")

# --- Phase coverage (K1..K6) ----------------------------------------------
phase_checks = {
    "K1 env+bootstrap": [r"T1\.01", r"T1\.02", r"require-hashes", r"venv"],
    "K2 contracts+config": [r"contracts/", r"config/", r"ApprovalRecord", r"XDG"],
    "K3 kernel+policy+sandbox": [r"kernel/", r"policy/", r"sandbox/", r"bwrap", r"HMAC"],
    "K4 tools+providers": [r"tools/", r"providers/", r"kimi", r"ollama"],
    "K5 memory+skills+audit+recovery": [r"memory/", r"skills/", r"audit/", r"recovery/"],
    "K6 cli+tutor+coding": [r"cli/", r"tutor/", r"coding/"],
}
for label, pats in phase_checks.items():
    for p in pats:
        check(re.search(p, text, re.I) is not None, f"{label}: pattern missing: {p}")

# 12 tools of SPEC §6.4
for tool in ["fs.read", "fs.list", "fs.find", "sys.info", "pkg.query", "git.read",
             "fs.write", "fs.patch", "git.worktree", "test.run", "proc.exec", "net.fetch"]:
    check(f"`{tool}`" in text, f"tool missing from plan: {tool}")

# TCB LOC budget checkpoint (K3)
check("6000" in text and "8000" in text and "loc-count" in text,
      "TCB LOC checkpoint (6000/8000, loc-count) missing")

# --- AC mapping (K7) -------------------------------------------------------
ac_section = text.split("## AC Mapping", 1)
check(len(ac_section) == 2, "missing ## AC Mapping section")
if len(ac_section) == 2:
    tail = ac_section[1].split("\n## ", 1)[0]
    for i in range(1, 21):
        ac = f"AC-{i:02d}"
        check(ac in tail, f"AC Mapping: {ac} missing")
        row = next((l for l in tail.splitlines() if l.startswith(f"| {ac}")), None)
        if row is not None:
            check(re.search(r"T[1-6]\.\d{2}", row) is not None,
                  f"AC Mapping: {ac} row has no concrete task ID")
for layer in ["UT", "PT", "CT", "IT", "RT", "EV", "LT"]:
    check(re.search(rf"\b{layer}\b", text) is not None, f"test layer missing: {layer}")

# --- LAB coverage (SPEC §11, §20 V1 scope) ---------------------------------
check(re.search(r"LAB", text) is not None, "LAB absent from plan")
check("src/lsassist/lab/" in text,
      "no LAB implementation task found (no src/lsassist/lab/ files planned)")

print(f"tasks found: {len(task_heads)}")
print("checks failed:", len(fails))
for f in fails:
    print(" FAIL:", f)
sys.exit(1 if fails else 0)
