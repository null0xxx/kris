# lsassist

Personal Linux AI assistant — security-first, sandboxed, single-user. Gate 4
bootstrap (T1.02): repository layout + packaging only, **no production code yet**.

Design authority: SPEC (Gate 2, kept outside this repo at project root) and the
approved implementation plan (Gate 3).

## Layout (SPEC §22)

- `src/lsassist/` — packages: `contracts`, `kernel`, `policy`, `tools`,
  `sandbox`, `providers`, `memory`, `skills`, `audit`, `recovery`, `config`,
  `tutor`, `coding`, `cli`
- `tests/` — layers: `unit`, `property`, `contract`, `integration`, `e2e`,
  `redteam`, `evals`
- `scripts/` — dev-only: `verify-env.sh` (T1.01 host assertions),
  `loc-count` (TCB LOC budget, SPEC §2.3)
- `docs/` — evidence archives (`env-verification-gate3.md`)

## Install (ADR-005 — venv + pinned hashes, never `curl | bash`)

```sh
python3 -m venv ~/.local/share/lsassist/venv
~/.local/share/lsassist/venv/bin/pip install --require-hashes \
  -r requirements.lock -r requirements-dev.lock
~/.local/share/lsassist/venv/bin/pip install -e . --no-deps
```

`~/.local/bin/lsassist` is a shim that execs the venv interpreter.

## Dependencies (SPEC §13.1)

Runtime allowlist: `httpx`, `pydantic`, `jsonschema`, `prompt_toolkit`, `rich`,
`secretstorage` (+ transitive deps). Dev: `pytest`, `hypothesis`, `mypy`,
`ruff`, `pip-audit`. Exact pins + sha256 hashes in `requirements.lock` /
`requirements-dev.lock`; installs use `--require-hashes`.

**`syft` deviation:** SPEC §13.1 lists `syft` (dev) meaning Anchore's SBOM
generator — a Go binary, not pip-installable. The PyPI package named `syft`
is OpenMined's unrelated framework with a ~50-package server stack (fastapi,
uvicorn, sqlalchemy, boto3, matplotlib, docker, azure-…); installing it would
violate the minimal-allowlist policy, so it is **excluded** from the dev lock.
SBOM tooling install is deferred to the release-engineering task.

## TCB budget (SPEC §2.3)

TCB = `kernel`, `policy`, `sandbox`, `audit`, `recovery`, `config`, `contracts`
(+ `tools` dispatcher core when it lands). Budget 6,000 LOC warn / 8,000 hard
stop. Check: `scripts/loc-count`.

## Dev gates

```sh
~/.local/share/lsassist/venv/bin/pytest tests/unit -q
~/.local/share/lsassist/venv/bin/ruff check src tests
scripts/loc-count
```

CI skeleton (`.github/workflows/ci.yml`) runs the same three jobs. The
workflow file is written in the JSON subset of YAML 1.2 (JSON is valid YAML)
so tests can validate it with stdlib `json` without adding PyYAML to the
§13.1 allowlist.
