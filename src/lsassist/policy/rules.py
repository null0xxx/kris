"""Deterministic permission classifier — rules R1-R9 (SPEC §7.2, §7.3; T2.01).

:func:`classify` maps a ``(ToolRequest, PolicyContext, ToolManifest,
PolicyStores)`` tuple to a single
:class:`~lsassist.contracts.enums.PermissionClass`. The manifest class is the
FLOOR (R1); the ordered args-dependent rules R2, R4-R9 can only ever RAISE it
(via :func:`~lsassist.policy.classes.raise_to`), never lower it. A terminal
``DENY_ALWAYS`` short-circuits (first-match-wins for the terminal case). R3
(untrusted-turn elevation) is applied as a POST-FOLD step keyed off the FINAL
accumulated class, so a later rule (R8/R9) that lifted a read to a non-read
class is still forced to CONFIRM_EXACT (§4.6).

PURE (§2.2): NO filesystem / network / child-process / environment access — at
import OR at classify time. The XDG-configurable store trees (audit / policy /
kernel secret) and the home anchor are INJECTED via
:class:`~lsassist.policy.stores.PolicyStores`, which the dispatcher resolves
from ``XdgPaths``; this layer only does pure, segment-aware string comparison.
Path checks operate on the ALREADY-canonicalized absolute path the dispatcher
produced (HARDEN-02, §6.3 step 2 / §7.5); as defense-in-depth the deny
matchers ALSO apply ``os.path.normpath`` (a pure string collapse of ``..`` /
``.`` / ``//``) so a ``..``-bearing spelling of a secret path still resolves and
is denied. Symlink resolution remains the dispatcher's job (correct layering).

Conventional ``request.args`` keys inspected (the 12 tool manifests / exact arg
schemas land in later tasks; missing/mistyped keys → rule returns None, never
raises):

- ``path: str``   — a single canonicalized absolute filesystem target (R2, R7).
- ``argv: list``  — the exec argument vector; ``argv[0]`` is the program (R4, R5).
- ``domain: str`` — the fetch target host (R6).
- ``durable: bool`` / ``provenance: str`` — memory-write durability + origin (R8).
"""

from __future__ import annotations

import os
from collections.abc import Callable

from lsassist.contracts.enums import PermissionClass
from lsassist.contracts.manifest import ToolManifest
from lsassist.contracts.policy_context import PolicyContext
from lsassist.contracts.tool_request import ToolRequest
from lsassist.policy.classes import raise_to, rank
from lsassist.policy.stores import PolicyStores

_AR = PermissionClass.AUTO_READ
_C1 = PermissionClass.CONFIRM_ONCE
_CE = PermissionClass.CONFIRM_EXACT
_DENY = PermissionClass.DENY_ALWAYS


# --- pure path helpers --------------------------------------------------------


def _segments(path: str) -> list[str]:
    """Split a normalized path into non-empty segments (``/a//b/`` → ``["a", "b"]``)."""
    return [seg for seg in os.path.normpath(path).split("/") if seg]


def _within(path_segs: list[str], root_segs: list[str]) -> bool:
    """True if ``path_segs`` equals or is a segment-wise descendant of ``root_segs``.

    Segment-aware (NOT naive ``startswith``): ``/ws-evil`` is NOT within ``/ws``.
    """
    return len(path_segs) >= len(root_segs) and path_segs[: len(root_segs)] == root_segs


# Fixed OS secret subtrees under the home anchor (NOT XDG-relocatable). The
# XDG-configurable stores (audit/policy/kernel secret) come from PolicyStores.
_HOME_SECRET_RELS: tuple[str, ...] = (".ssh", ".gnupg", ".kimi-code", ".aws", ".config/gh")


def _matches_r2_deny(path: str, stores: PolicyStores) -> bool:
    """§7.3 secret/device paths whose mere ACCESS is denied (read OR write; I8).

    ``path`` is normalized first (S4 defense-in-depth) via :func:`_segments`.
    """
    segs = _segments(path)
    if not segs:
        return False
    base = segs[-1]
    # ~/.ssh/**, ~/.gnupg/**, ~/.kimi-code/**, ~/.aws/**, ~/.config/gh/**
    for rel in _HOME_SECRET_RELS:
        if _within(segs, _segments(os.path.join(stores.home, rel))):
            return True
    # **/.env  and  **/.env.*  (except the .env.example carve-out)
    if base == ".env":
        return True
    if base.startswith(".env.") and base != ".env.example":
        return True
    # /etc/shadow ; /etc/sudoers*  (sudoers, sudoers.d/…)
    if len(segs) >= 2 and segs[0] == "etc" and (
        segs[1] == "shadow" or segs[1].startswith("sudoers")
    ):
        return True
    # raw block devices: /dev/sd* , /dev/nvme*n*
    if len(segs) >= 2 and segs[0] == "dev":
        dev = segs[1]
        if dev.startswith("sd"):
            return True
        if dev.startswith("nvme") and "n" in dev[len("nvme"):]:
            return True
    return False


def _matches_r7_deny(path: str, stores: PolicyStores) -> bool:
    """§7.2 R7: self-approval / policy-tamper stores (.git internals, policy*,
    audit, kernel secret) — INJECTED so an ``$XDG_*`` override cannot slip them
    past. Denied for BOTH read and write: reading the HMAC ``kernel.secret`` is
    credential theft (I8), a harden over the SPEC's "write to …" wording.

    ``path`` is normalized first (S4 defense-in-depth) via :func:`_segments`.
    """
    segs = _segments(path)
    if not segs:
        return False
    # .git/ internals — any component named exactly ".git" (NOT ".gitignore"/".github").
    if ".git" in segs:
        return True
    # <policy_store>/policy*  — an entry under the policy store named policy*.
    policy_segs = _segments(stores.policy_store)
    if _within(segs, policy_segs):
        tail = segs[len(policy_segs):]
        if tail and tail[0].startswith("policy"):
            return True
    # audit store subtree; kernel secret (file/subtree).
    return _within(segs, _segments(stores.audit_store)) or _within(
        segs, _segments(stores.kernel_secret)
    )


# --- R5 exec allow/deny tables + wrapper peeling + git destructive detection ---

# argv[0] (basename) that raises to CONFIRM_EXACT.
_R5_CONFIRM_BINS: frozenset[str] = frozenset(
    {
        "rm", "rmdir", "shred", "dd", "mkfs", "mount", "umount", "chmod", "chown",
        "systemctl", "iptables", "nft", "ufw", "useradd", "userdel", "passwd",
        "visudo", "crontab", "curl", "wget", "ssh", "scp",
    }
)
# argv[0] (basename) that is DENY_ALWAYS in V1.
_R5_DENY_BINS: frozenset[str] = frozenset({"sudo", "doas", "su"})

# Exec wrappers that run a following program (S3). When argv[0] is one of these,
# EVERY subsequent token is treated as a program candidate — a wrapper's own
# positional args (a `timeout` duration, a `taskset` mask, a `nice -n` value)
# are not in the danger tables, so the real wrapped program is still reached.
# NECESSARILY INCOMPLETE (named residual) — see the r5 docstring: an UNKNOWN
# launcher defeats this argv[0] heuristic but not the sandbox/gate boundary.
_EXEC_WRAPPERS: frozenset[str] = frozenset(
    {
        # process / resource launchers
        "env", "nice", "ionice", "nohup", "setsid", "stdbuf", "timeout", "xargs",
        "chrt", "taskset", "flock", "time", "watch",
        # namespace / privilege / sandbox launchers
        "unshare", "nsenter", "setpriv", "runuser", "chroot", "command",
        "catchsegv", "proot", "bwrap",
    }
)
# Shells: ``<shell> -c <string>`` runs arbitrary shell we cannot inspect → at
# least CONFIRM_EXACT (ADR-010: no general shell tool in V1).
_SHELLS: frozenset[str] = frozenset({"sh", "bash", "zsh", "dash", "ash", "ksh", "fish"})

# git global options that CONSUME the following token as a value; skipped when
# locating the subcommand (so ``git -C /repo reset`` reads subcommand ``reset``).
_GIT_VALUE_OPTS: frozenset[str] = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix"}
)


def _basename(tok: str) -> str:
    """Last path component of an argv token (``/usr/bin/sudo`` → ``sudo``)."""
    return tok.rsplit("/", 1)[-1]


def _has_c_flag(toks: list[str]) -> bool:
    """True if any token is ``-c`` or a combined short flag containing ``c`` (``-lc``)."""
    for t in toks:
        if t == "-c":
            return True
        if len(t) >= 2 and t[0] == "-" and t[1] != "-" and "c" in t:
            return True
    return False


def _git_subcommand_index(argv: list[str]) -> int | None:
    """Index of git's subcommand token in ``argv`` (``argv[0]`` is git), or None."""
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok.startswith("-"):
            i += 2 if tok in _GIT_VALUE_OPTS else 1
            continue
        return i
    return None


def _git_is_destructive(argv: list[str]) -> bool:
    """True for history/tree-destroying git subcommands (reset/clean/checkout -f/
    push -f/branch -D/stash drop|clear/rebase). ``argv[0]`` is the git token."""
    idx = _git_subcommand_index(argv)
    if idx is None:
        return False
    sub = argv[idx]
    rest = argv[idx + 1:]
    if sub in {"reset", "clean", "rebase"}:
        return True
    if sub == "checkout":
        return any(a in {"-f", "--force"} for a in rest)
    if sub == "push":
        return any(a in {"-f", "--force"} or a.startswith("--force-with-lease") for a in rest)
    if sub == "branch":
        return "-D" in rest or ("--delete" in rest and "--force" in rest)
    if sub == "stash":
        return bool(rest) and rest[0] in {"drop", "clear"}
    return False


# --- misc rule tables ---------------------------------------------------------

# Tools that carry a free ``path`` and write to it (R2 clause B: outside-workspace
# write → CONFIRM_EXACT). The R2 secret DENY and R7 tamper DENY are tool-agnostic
# (any path access), matching the read-exposure invariant I8.
_WRITE_INTENT_TOOLS: frozenset[str] = frozenset({"fs.write", "fs.patch"})

# R6 net.fetch domain allowlist. Empty DEFAULT for now — every fetch domain is
# thus off-allowlist → CONFIRM_EXACT until the configured allowlist is wired
# (later task). Documented as an intentional empty constant.
_NET_ALLOWLIST: frozenset[str] = frozenset()


# --- rules (each pure over (request, context, stores); R3 is applied post-fold) --
# ``stores`` is threaded to every rule for a uniform fold signature; only R2/R7
# consult it (the injected §7.3 store trees).


def r2(
    request: ToolRequest, context: PolicyContext, stores: PolicyStores
) -> PermissionClass | None:
    """R2: §7.3 secret/device ``path`` access → DENY; WRITE-intent target OUTSIDE
    ``workspace_root`` → CONFIRM_EXACT. Reads ``path: str``."""
    raw = request.args.get("path")
    if not isinstance(raw, str) or not raw:
        return None
    if _matches_r2_deny(raw, stores):  # read OR write of a secret/device path (I8)
        return _DENY
    path = os.path.normpath(raw)  # S4: collapse .. before the workspace check
    if (
        request.tool in _WRITE_INTENT_TOOLS
        and path.startswith("/")
        and not _within(_segments(path), _segments(context.workspace_root))
    ):
        return _CE
    return None


def r4(
    request: ToolRequest, context: PolicyContext, stores: PolicyStores
) -> PermissionClass | None:
    """R4: ``proc.exec`` argv carrying shell-metachar DATA tokens → CONFIRM_EXACT
    (allowed as data — no shell — but elevated + displayed). Reads ``argv: list``."""
    if request.tool != "proc.exec":
        return None
    argv = request.args.get("argv")
    if not isinstance(argv, list):
        return None
    metachars = (";", "&&", "|", "`", "$(", ">")
    for tok in argv:
        if isinstance(tok, str) and any(m in tok for m in metachars):
            return _CE
    return None


def r5(
    request: ToolRequest, context: PolicyContext, stores: PolicyStores
) -> PermissionClass | None:
    """R5: ``proc.exec`` dangerous program → CONFIRM_EXACT; sudo/doas/su → DENY;
    destructive ``git`` subcommand → CONFIRM_EXACT; arbitrary ``<shell> -c`` →
    CONFIRM_EXACT. Reads ``argv: list``. Basenames are compared (so
    ``/usr/bin/sudo`` is caught) and known exec WRAPPERS (env/nice/timeout/…) are
    peeled so ``env sudo``, ``nice rm``, ``timeout 5 sudo`` cannot escape (S3).

    DEFENSE-IN-DEPTH, NOT THE BOUNDARY: R5 is a display/elevation heuristic over
    a KNOWN wrapper set (``_EXEC_WRAPPERS``), which is necessarily incomplete
    (named residual). The load-bearing security boundary is the OS sandbox
    (bwrap: no privileges, no network, scoped mounts — SPEC §2.1) PLUS the fact
    that ``proc.exec`` is itself a gated tool. An UNKNOWN exec launcher can
    defeat this argv[0] heuristic, but cannot escape the sandbox or gain
    privilege."""
    if request.tool != "proc.exec":
        return None
    argv = request.args.get("argv")
    if not isinstance(argv, list) or not argv:
        return None
    toks = [t for t in argv if isinstance(t, str)]
    if not toks:
        return None

    result: PermissionClass | None = None
    # Arbitrary shell we cannot inspect (ADR-010) → at least CONFIRM_EXACT.
    if _has_c_flag(toks) and any(_basename(t) in _SHELLS for t in toks):
        result = _CE
    # Peel wrappers: if argv[0] is a wrapper, every following token is a program
    # candidate; otherwise only argv[0] is the program.
    program_indices = range(1, len(toks)) if _basename(toks[0]) in _EXEC_WRAPPERS else range(1)
    for i in program_indices:
        base = _basename(toks[i])
        if base in _R5_DENY_BINS:  # privilege escalation — terminal, wins over all
            return _DENY
        if base == "git":
            if _git_is_destructive(toks[i:]):
                result = _CE
        elif base in _R5_CONFIRM_BINS or base.startswith("mkfs."):
            result = _CE
    return result


def r6(
    request: ToolRequest, context: PolicyContext, stores: PolicyStores
) -> PermissionClass | None:
    """R6: ``net.fetch`` whose ``domain`` is not in the allowlist → CONFIRM_EXACT.
    Reads ``domain: str``. Default allowlist is empty (see ``_NET_ALLOWLIST``)."""
    if request.tool != "net.fetch":
        return None
    domain = request.args.get("domain")
    if not isinstance(domain, str) or not domain:
        return None
    return None if domain in _NET_ALLOWLIST else _CE


def r7(
    request: ToolRequest, context: PolicyContext, stores: PolicyStores
) -> PermissionClass | None:
    """R7: ``path`` in a .git dir / the policy store / audit / kernel secret →
    DENY (self-approval / policy-tamper prevention). Reads ``path: str``."""
    raw = request.args.get("path")
    if not isinstance(raw, str) or not raw:
        return None
    return _DENY if _matches_r7_deny(raw, stores) else None


def r8(
    request: ToolRequest, context: PolicyContext, stores: PolicyStores
) -> PermissionClass | None:
    """R8: durable ``memory.write`` with model provenance → CONFIRM_ONCE (§10.4).
    Reads ``durable: bool`` and ``provenance: str``."""
    if request.tool != "memory.write":
        return None
    if request.args.get("durable") is not True:
        return None
    if request.args.get("provenance") != "model":
        return None
    return _C1


def r9(
    request: ToolRequest, context: PolicyContext, stores: PolicyStores
) -> PermissionClass | None:
    """R9: skill-turn ceiling raise (decision #3). ``ToolRequest`` has no
    ``skill_provenance`` field (it is ``{call_id, tool, args}``), so the presence
    of ``context.skill_ceiling`` IS the skill-turn signal; ``classify`` raises to
    it. ``None`` → no-op. Per-request skill-provenance wiring is a later task
    (T4.12)."""
    return context.skill_ceiling


# Ordered rules folded onto the manifest floor. R3 is NOT here: its "any
# non-AUTO_READ → CONFIRM_EXACT" elevation depends on the FINAL accumulated
# class, so it runs as a post-fold step in ``classify`` (see C1).
_ORDERED_RULES: tuple[
    Callable[[ToolRequest, PolicyContext, PolicyStores], PermissionClass | None], ...
] = (r2, r4, r5, r6, r7, r8, r9)


def classify(
    request: ToolRequest,
    context: PolicyContext,
    manifest: ToolManifest,
    stores: PolicyStores,
) -> PermissionClass:
    """Classify one request → permission class (SPEC §7.2, decision #2).

    Composition: start from the manifest floor (R1), fold each rule R2, R4-R9
    with ``raise_to`` (raise-only), returning immediately on a terminal DENY
    (first-match-wins). Then apply R3 (§4.6) as a POST-FOLD elevation keyed off
    the FINAL class: an untrusted turn forces any non-AUTO_READ result to
    CONFIRM_EXACT (a pure read stays AUTO_READ; DENY stays DENY). Monotonicity
    is asserted: the result is always ≥ the manifest floor.
    """
    base = manifest.permission_class
    result = base

    for rule in _ORDERED_RULES:
        proposed = rule(request, context, stores)
        if proposed is None:
            continue
        result = raise_to(result, proposed)
        if result == _DENY:  # terminal short-circuit (first-match-wins for DENY)
            break

    # R3 (§4.6) — POST-FOLD, keyed off the FINAL class so an R8/R9-lifted read is
    # still forced to CONFIRM_EXACT in an untrusted turn (C1). raise_to keeps
    # DENY at DENY; an untrusted pure read stays AUTO_READ.
    if context.untrusted_turn and result != _AR:
        result = raise_to(result, _CE)

    assert rank(result) >= rank(base), "policy rule lowered class below manifest floor (R1)"
    return result
