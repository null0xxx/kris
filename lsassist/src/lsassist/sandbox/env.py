"""Child-environment projection for sandboxed exec (SPEC §8.3; I8).

§8.3 is explicit: the sandbox child's environment is "constructed from scratch,
not inherited" and contains ONLY the allowlist ``PATH``, ``HOME``, ``LANG``,
``LC_ALL``, ``TERM`` plus tool-specific additions such as ``CI=1``. Adapter
secrets (ADR-004's ``LSASSIST_KIMI_API_KEY``, and every other credential the
parent may hold) must never be visible to a sandboxed tool.

:func:`project_env` therefore starts from an EMPTY dict and fills it from
parameters only. There is no inheritance path to audit, because there is no
inheritance code: this module never reads the process environment (§2.2 purity
— the parent's variables are simply not reachable from here).

TWO CLOSED ALLOWLISTS, both fail-closed:

- :data:`ENV_ALLOWLIST` — the five §8.3 names, each with a dedicated parameter
  and a §8.1 default.
- :data:`TOOL_ENV_ALLOWLIST` — the "tool-specific additions" channel. It is a
  CLOSED set too, not a free-form passthrough: an open channel would be an
  exact I8 bypass (``project_env(extra=<parent env>)``). ``PYTHONPATH`` and
  ``LD_PRELOAD`` are deliberately absent — both are code-injection vectors into
  the sandboxed interpreter/loader.

Every key additionally passes a secret-shape guard (:data:`SECRET_KEY_MARKERS`)
BEFORE the allowlist check, so a future allowlist edit that admits a
credential-looking name still fails. Every VALUE except ``PATH``/``HOME`` must
match a conservative locale/terminfo/flag shape, because ``--setenv`` values are
written into the child's argv and therefore into world-readable
``/proc/<pid>/cmdline`` (see ``_VALUE_RE``). Rejections raise
:class:`EnvProjectionError` — never a silent drop, since a silently dropped
``PATH`` or a silently dropped guard is indistinguishable from success at the
call site (fail-closed, §8.3 failure behavior).

PURE (§2.2): stdlib only (``re``); no filesystem, no environment, no child
processes, no network. Values are plain data supplied by the caller.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

__all__ = [
    "DEFAULT_HOME",
    "DEFAULT_LANG",
    "DEFAULT_PATH",
    "ENV_ALLOWLIST",
    "SECRET_KEY_MARKERS",
    "TOOL_ENV_ALLOWLIST",
    "EnvProjectionError",
    "project_env",
]

#: §8.3 child-env allowlist (the only inheritable-looking names that exist).
ENV_ALLOWLIST: frozenset[str] = frozenset({"PATH", "HOME", "LANG", "LC_ALL", "TERM"})

#: §8.3 "tool-specific additions" — a CLOSED set. Adding a name here is a TCB
#: change and must be reviewed against I8 (no credentials, no code-injection
#: vectors such as ``PYTHONPATH``/``LD_PRELOAD``/``LD_LIBRARY_PATH``).
TOOL_ENV_ALLOWLIST: frozenset[str] = frozenset(
    {
        "CI",
        "NO_COLOR",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONUNBUFFERED",
        "SOURCE_DATE_EPOCH",
    }
)

#: Substrings that make a name credential-shaped. Checked against EVERY key,
#: including allowlisted ones (defense in depth for future allowlist edits).
SECRET_KEY_MARKERS: tuple[str, ...] = (
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "AUTH",
    "PRIVATE",
    "SESSION",
    "COOKIE",
    "SIGNING",
)

# §8.1 `--setenv` defaults, verbatim from the profile template.
DEFAULT_PATH = "/usr/bin:/bin"
DEFAULT_HOME = "/tmp/lsassist-home"
DEFAULT_LANG = "C.UTF-8"

# POSIX-ish name, restricted to UPPER CASE: both allowlists are uppercase, so
# requiring it makes the case-insensitive secret-marker test total and removes
# any `path`-vs-`PATH` shadowing ambiguity in the emitted argv.
_NAME_RE = re.compile(r"\A[A-Z][A-Z0-9_]*\Z")

# Conservative VALUE shape for every variable except PATH/HOME (which are
# ``/``-bearing paths built by the caller). Every --setenv value is written into
# the child's argv, i.e. into world-readable /proc/<pid>/cmdline, `ps` output
# and audit records — the exact exposure that makes `--unsetenv` unacceptable —
# so the values that DO go there are held to a locale/terminfo/flag shape:
# no whitespace, no `=`, no `/`, no shell metacharacters, and a length cap.
# It admits every realistic value of these variables (``en_US.UTF-8``,
# ``xterm-256color``, ``1``, a unix timestamp).
#
# This is a SHAPE guard, not a credential detector: a short hyphenated
# alphanumeric token still matches, and no pure function could tell one from a
# terminfo name. Containment for values rests on (a) only seven names being
# settable at all and (b) values coming from the caller, never from the parent
# environment. Secret-bearing SINKS are the redactor's job (§14.3).
_VALUE_RE = re.compile(r"\A[A-Za-z0-9._@:+-]{0,64}\Z")

# PATH/HOME legitimately contain "/" (and PATH ":"), and a workspace path may
# legitimately contain spaces, so they carry the NUL check only.
_PATHLIKE_KEYS: frozenset[str] = frozenset({"PATH", "HOME"})


class EnvProjectionError(ValueError):
    """A key/value was refused by the §8.3 projection guards — fail-closed (I8)."""


def _checked(key: object, value: object) -> tuple[str, str]:
    """Validate one ``(name, value)`` pair, or raise :class:`EnvProjectionError`.

    Order matters: syntax → secret shape → allowlist → value. The secret-shape
    guard runs before the allowlist so it also covers allowlisted names.

    Error messages name the KEY but never echo the VALUE: the value is the part
    that could be a live credential, and exception text reaches logs and audit.
    """
    if not isinstance(key, str) or not _NAME_RE.match(key):
        raise EnvProjectionError(f"invalid environment variable name: {key!r}")
    for marker in SECRET_KEY_MARKERS:
        if marker in key:
            raise EnvProjectionError(
                f"refusing credential-shaped environment name {key!r} (I8, matched {marker!r})"
            )
    if key not in ENV_ALLOWLIST and key not in TOOL_ENV_ALLOWLIST:
        raise EnvProjectionError(f"{key!r} is not in the SPEC 8.3 child-env allowlist")
    if not isinstance(value, str):
        raise EnvProjectionError(
            f"value for {key!r} must be str, got {type(value).__name__}"
        )
    if "\x00" in value:
        raise EnvProjectionError(f"value for {key!r} contains NUL")
    if key not in _PATHLIKE_KEYS and not _VALUE_RE.match(value):
        # The value is NOT echoed: it is the part that could be a live
        # credential, and this message reaches logs and audit.
        raise EnvProjectionError(
            f"value for {key!r} is not of the permitted shape "
            f"([A-Za-z0-9._@:+-], max 64 chars; {len(value)} chars given)"
        )
    return key, value


def project_env(
    *,
    path: str = DEFAULT_PATH,
    home: str = DEFAULT_HOME,
    lang: str = DEFAULT_LANG,
    lc_all: str | None = None,
    term: str | None = None,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the sandbox child's environment FROM SCRATCH (§8.3).

    :param path: ``PATH`` for the child. §8.2's ``<workspace>/.venv/bin``
        prepend is computed by the CALLER (``profiles.build_argv``) and arrives
        here as a plain string — this module performs no existence check.
    :param home: ``HOME`` (§8.1 default: a tmpfs path, so the real home is not
        even nameable from inside).
    :param lang: ``LANG`` (§8.1 default ``C.UTF-8``).
    :param lc_all: ``LC_ALL``; omitted from the result when ``None``.
    :param term: ``TERM``; omitted from the result when ``None``.
    :param extra: tool-specific additions (§8.3, e.g. ``{"CI": "1"}``). Keys
        must be in :data:`TOOL_ENV_ALLOWLIST`; a key that collides with
        :data:`ENV_ALLOWLIST` is REFUSED rather than allowed to override the
        dedicated parameter (otherwise a caller could quietly undo the §8.2
        ``PATH`` computation or point ``HOME`` back at the real home).
    :returns: a fresh ``dict`` in sorted-key order (deterministic argv).
    :raises EnvProjectionError: on any non-allowlisted, credential-shaped, or
        malformed key/value — nothing is ever silently dropped.
    """
    env: dict[str, str] = {}
    for name, value in (
        ("PATH", path),
        ("HOME", home),
        ("LANG", lang),
        ("LC_ALL", lc_all),
        ("TERM", term),
    ):
        if value is None:
            continue
        key, checked = _checked(name, value)
        env[key] = checked

    if extra is not None:
        if not isinstance(extra, Mapping):
            # Typed, not a bare AttributeError from `.items()`: the caller must
            # see a §8.3 projection refusal, not a stack trace shape.
            raise EnvProjectionError(f"extra must be a Mapping, got {type(extra).__name__}")
        for name, value in extra.items():
            if name in ENV_ALLOWLIST:
                raise EnvProjectionError(
                    f"{name!r} is a SPEC 8.3 base variable; set it via its parameter, "
                    "not via `extra`"
                )
            key, checked = _checked(name, value)
            env[key] = checked

    return dict(sorted(env.items()))
