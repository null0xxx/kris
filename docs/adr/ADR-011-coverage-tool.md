# ADR-011: Branch-coverage tool — `coverage` (dev-only)

- **Status:** accepted (2026-07-25, human-gated at the T2.12 Review checkpoint)
- **Supersedes / amends:** SPEC §13.1's dev-only allowlist (`pytest`, `hypothesis`, `mypy`, `ruff`, `pip-audit`, `syft`), which states **"Nothing else without ADR."** This is that ADR.

## Context

SPEC §23.1 sets a coverage floor of **100% branch** on `kernel/`, `policy/`, `sandbox/`, `audit/`, `recovery/`, and T2.13 makes it a blocking CI gate. Neither `coverage` nor `pytest-cov` is in the §13.1 allowlist or in `requirements-dev.lock`, so today the project **cannot measure branch coverage at all**:

- `pytest` alone reports no coverage.
- stdlib `trace` reports **line** coverage only — it cannot answer §23.1's question. (T2.06 used it as a stopgap and said so.)

The consequence is sharper than a missing convenience: T2.13's own text assumes "100% branch … already achieved by T2.01–T2.11's tests". **That assumption has never been verified**, because no tool in the environment can verify it.

## Decision

Add **`coverage`** to the §13.1 **dev-only** allowlist. Not `pytest-cov`.

Invocation (no pytest plugin involved):

```bash
coverage run --branch -m pytest tests/unit tests/property
coverage report --fail-under=100 --show-missing
```

Configuration lives in `pyproject.toml` under `[tool.coverage.*]`, scoped to the TCB packages §23.1 names.

## Rationale

- **One dependency, not two.** `pytest-cov` is a thin adapter that pulls `coverage` in anyway; taking the base library keeps the added supply-chain surface minimal, which is the whole point of §13.1's allowlist discipline.
- **No coupling to the pytest process.** §23.1 defines seven test layers (UT/PT/CT/IT/RT/EV/LT), and the later ones (integration, red-team, eval harness) will not all be pytest invocations. `coverage run -m <anything>` measures them uniformly; a pytest plugin measures only what pytest runs.
- **Dev-only, never shipped.** It is absent from `requirements.lock`; nothing under `src/` imports it. §13.2's runtime posture is unchanged.
- **Pinned with a hash** in `requirements-dev.lock` per ADR-005, and covered by the existing `pip-audit` CI step.

## Consequences

- `requirements-dev.lock` gains `coverage==<pin>` with its sha256.
- The T2.13 CI gate runs the two commands above; `# pragma: no cover` is **forbidden** in TCB packages and the gate greps for it (§23.1 / T2.13 review checkpoint).
- **Known non-conformance to fix as part of T2.13:** `src/lsassist/policy/canonical.py:73` currently carries a `# pragma: no cover`. Under this ADR that line either gets a real test or the pragma is removed and the branch is covered — the gate must not be weakened to accommodate it.

## Named limitation (do not let this ADR overclaim)

**100% branch coverage is itself a Goodhart metric.** Coverage measures *execution*, not *assertion*: a test that imports a module and asserts nothing can reach 100%. It is a floor that catches unreached code, not evidence that behaviour is pinned. §23.2's verification philosophy is the governing rule, and this project pairs the coverage floor with:

- property tests (Hypothesis) over adversarial input spaces,
- mutation checks — break the invariant, prove the suite turns red,
- the seam/integration suite that drives modules with their real collaborators.

A future reviewer should read a green coverage gate as "no unreached branch", never as "tested".

## Rejected alternatives

- **`pytest-cov`** — better ergonomics (`--cov-fail-under=100` inline), but two packages instead of one and measurement bound to the pytest process. Rejected on §13.1 minimality.
- **stdlib `trace` only** — zero new dependencies, but it cannot produce branch coverage, so it cannot satisfy §23.1. Rejected as non-conforming.
- **Defer the gate to Phase 4** (when `audit/`/`recovery/` join the same floor) — would leave Phase 2 closing with an unmeasured floor and let a coverage debt accumulate silently across three more packages. Rejected.
