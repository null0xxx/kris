"""§7.5 canonicalization boundary + §7.4 hash primitives (SPEC §7.4, §7.5; T2.02).

This is the SOLE I/O-permitted module in ``policy/`` (the documented exception
to the §2.2 purity rule that governs the rest of the package). It performs the
§7.5 step-1 TOCTOU defense: resolve a path with :func:`os.path.realpath` AND
walk it per-component with :func:`os.lstat`, failing CLOSED (raising
:class:`CanonicalizationError`) on a dangling/missing component or ANY
``OSError`` — a missing component is tolerated ONLY under create-intent
(``allow_missing=True``) and ONLY when it is the FINAL component whose parent
exists and canonicalizes.

Type-safe closure of T2.01's S4: :data:`CanonicalPath` is a distinct
:class:`typing.NewType` and :func:`canonicalize` is its ONLY producer, so a
raw/un-canonicalized ``str`` cannot be handed to the §7.3 ``deny_match``
(which accepts only ``CanonicalPath``) without a deliberate, greppable
``CanonicalPath(...)`` cast at a trust boundary.

Also hosts the two PURE §7.4 token-binding primitives (:func:`env_digest`,
:func:`action_hash`) so the T2.03 token service reuses this exact,
single-sourced serialization when it recomputes the binding at verify time.

WORKSPACE-SCOPE NOTE: :func:`canonicalize` deliberately does NOT check that a
create-intent parent lies inside the approved workspace — that is the CALLER's
(dispatcher's) responsibility. This module only answers "what is the real,
existing (or final-missing) absolute path, and is it well-formed?".
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from typing import Any, NewType

# The ONLY type ``deny_match`` accepts; ONLY ``canonicalize`` produces it.
CanonicalPath = NewType("CanonicalPath", str)


class CanonicalizationError(Exception):
    """A path could not be canonicalized fail-closed (§7.5): non-absolute input,
    a dangling/missing component outside create-intent, an underlying
    ``OSError`` (ENOTDIR, permission denied, ...), or an UNRESOLVED final-
    component symlink loop (ELOOP) that would leave a symlink in the result."""


class ActionHashError(Exception):
    """An ``action_hash`` binding could not be computed (§7.4): a value in
    ``args_normalized`` is not JSON-native. Fail CLOSED — never silently coerce
    (that would let ``b"x"`` and ``"x"`` collide into the same binding)."""


def canonicalize(path: str, *, allow_missing: bool = False) -> CanonicalPath:
    """Resolve ``path`` to its real absolute form, fail-closed (§7.5 step 1).

    Requires an ABSOLUTE input (a relative path would resolve against the
    process cwd — refused). Resolves symlinks and collapses ``..``/``.``/``//``
    via :func:`os.path.realpath`, then walks the resolved path component by
    component with :func:`os.lstat` to detect a missing component that realpath
    would otherwise carry through lexically.

    A missing component raises :class:`CanonicalizationError` UNLESS
    ``allow_missing=True`` (create-intent) AND it is the FINAL component — i.e.
    the parent directory exists and canonicalizes. Any other ``OSError`` (e.g.
    a non-directory parent → ``ENOTDIR``, a symlink loop → ``ELOOP``) also fails
    closed. The in-scope-parent (workspace) check is the caller's job.
    """
    if not path or not os.path.isabs(path):
        raise CanonicalizationError(f"path must be absolute, got {path!r}")

    try:
        real = os.path.realpath(path)
    except OSError as exc:  # defense in depth (S2) — see the test that injects it
        raise CanonicalizationError(f"realpath failed for {path!r}: {exc}") from exc

    segments = [seg for seg in real.split("/") if seg]
    missing_index: int | None = None
    for index in range(len(segments)):
        prefix = "/" + "/".join(segments[: index + 1])
        try:
            os.lstat(prefix)
        except FileNotFoundError:
            missing_index = index
            break
        except OSError as exc:  # ENOTDIR, ELOOP, EACCES, ... — fail closed (S2).
            raise CanonicalizationError(f"lstat failed for {prefix!r}: {exc}") from exc

    if missing_index is not None:
        is_final_component = missing_index == len(segments) - 1
        if not (allow_missing and is_final_component):
            raise CanonicalizationError(
                f"dangling/missing path component: {path!r} -> {real!r}"
            )

    # A FINAL-component symlink loop (`ln -s a a`) is returned unresolved by a
    # non-strict realpath, and the per-component lstat above does not follow the
    # final link — so a symlink would survive into the "canonical" result and
    # break the CanonicalPath "no symlink remains" invariant deny_match relies
    # on. Reject it fail-closed (ELOOP). `os.path.islink` is a pure lstat probe.
    if missing_index is None and os.path.islink(real):
        raise CanonicalizationError(
            f"unresolved symlink (loop) at final component: {real!r}"
        )

    return CanonicalPath(real)


def env_digest(env: Mapping[str, str]) -> str:
    """Deterministic, INJECTIVE digest of an env mapping (§7.4 ``env_digest``).

    Uses the SAME canonical-JSON serialization as :func:`action_hash` (into which
    this feeds) so it is injective: a naive ``"{k}={v}\\n"`` join is NOT — POSIX
    env values may legally contain ``=``/newlines, so ``{"A": "1\\nB=2"}`` and
    ``{"A": "1", "B": "2"}`` would collide into the same binding (forgery, I6).
    ``sort_keys=True`` keeps it order-independent; JSON escaping keeps it
    value-sensitive AND injective. PURE."""
    blob = json.dumps(dict(env), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def action_hash(
    tool: str,
    args_normalized: Mapping[str, Any],
    canonical_paths: Sequence[str],
    cwd_real: str,
    env_digest: str,
) -> str:
    """The §7.4 approval-token binding hash. PURE, single-sourced for T2.03.

    SHA-256 over a CANONICAL JSON serialization
    (``sort_keys=True, separators=(",", ":"), ensure_ascii=False``) of
    ``{tool, args_normalized, canonical_paths, cwd_real, env_digest}``. Because
    every binding field is serialized, changing any one changes the hash; and
    because keys are sorted, the digest is independent of dict insertion order.
    Keep this serialization STABLE — the verifier recomputes it at exec time and
    compares (§7.5 step 3)."""
    payload: dict[str, Any] = {
        "tool": tool,
        "args_normalized": dict(args_normalized),
        "canonical_paths": list(canonical_paths),
        "cwd_real": cwd_real,
        "env_digest": env_digest,
    }
    # Fail CLOSED on a non-JSON-native value (e.g. bytes): silently coercing it
    # would let b"x" and "x" collide into the same binding (I6). Typed error.
    try:
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except TypeError as exc:
        raise ActionHashError(f"non-serializable value in args_normalized: {exc}") from exc
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()
