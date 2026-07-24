# Gate 3 environment verification (T1.01) — captured transcript

Host: Zorin OS 18.1 (Ubuntu 24.04 base), kernel 7.0.0-28-generic.
Assertions verified 2026-07-23/24 (SPEC §25.3 Gate 3 entry, Appendix A [G0]).

Original transcript: `/tmp/lsassist-env-gate3.txt` (verbatim below).

```
7.0.0-28-generic
Python 3.12.3
bubblewrap 0.9.0
userns_clone=1 OK
max_user_namespaces=112429 OK
bwrap functional probe OK (SPEC §8.1 binds)
{"version":"0.30.6"}git version 2.43.0
XDG writable OK
uv absent — venv path (ADR-005)
pipx present
libsecret-1.so.0 present (ldconfig) — OK (SIGPIPE-ზე echo ჩუმად გაქრა, პირდაპირ გადამოწმდა)
```

Re-run the live assertions any time with `scripts/verify-env.sh`.
