"""§7.3 DENY_ALWAYS matcher — the single authority for the deny patterns (T2.02).

Consolidates the §7.3 pattern knowledge that previously lived inline in
``rules.py`` (``_matches_r2_deny`` / ``_matches_r7_deny`` / ``_R2_SECRET_DIRS``)
into ONE pure, segment-aware matcher. :func:`deny_match` accepts ONLY a
:data:`~lsassist.policy.canonical.CanonicalPath` (T2.02 decision #1) so a
raw/un-canonicalized ``str`` cannot be DENY-matched at the type level; the raw
→ canonical cast happens deliberately at the ``rules.py`` boundary.

PURE (§2.2): NO filesystem / network / child-process / environment access — at
import OR at call time. It imports NOTHING from ``os`` and reads no environment;
the home anchor and the XDG-configurable store roots arrive INJECTED via
:class:`~lsassist.policy.stores.PolicyStores` (so an ``$XDG_*`` override cannot
slip the real audit/policy/kernel stores past the deny set — I8).

Because the input is ALREADY a ``CanonicalPath`` (symlink resolution + ``..``
collapse happened in ``canonical.canonicalize``), NO path normalization is
performed here; a defensive empty-segment split is retained so ``//`` / slashes
never defeat the segment-aware comparison (which is NOT a naive ``startswith``:
``/ws-evil`` is not within ``/ws``).

Full §7.3 coverage: ``~/.ssh`` ``~/.gnupg`` ``~/.kimi-code`` ``~/.aws``
``~/.config/gh``; ``**/.env`` and ``**/.env.*`` (except ``.env.example``);
``/etc/shadow``; ``/etc/sudoers*``; raw block devices ``/dev/sd*`` and
``/dev/nvme*n*``; the injected audit store, policy-store ``policy*`` entries,
and kernel secret; ``.git`` internals.
"""

from __future__ import annotations

from lsassist.policy.canonical import CanonicalPath
from lsassist.policy.stores import PolicyStores

# Fixed OS secret subtrees under the home anchor (NOT XDG-relocatable). The
# XDG-configurable stores (audit/policy/kernel secret) come from PolicyStores.
_HOME_SECRET_RELS: tuple[str, ...] = (".ssh", ".gnupg", ".kimi-code", ".aws", ".config/gh")


def _segments(path: str) -> list[str]:
    """Split a path into non-empty segments (``/a//b/`` → ``["a", "b"]``).

    Pure string split — NO ``normpath``: the input is already canonical, so no
    ``..``/``.`` remain; this only drops empty segments from ``//`` or a
    trailing slash so the segment-aware comparison stays robust."""
    return [seg for seg in path.split("/") if seg]


def _within(path_segs: list[str], root_segs: list[str]) -> bool:
    """True if ``path_segs`` equals or is a segment-wise descendant of ``root_segs``.

    Segment-aware (NOT naive ``startswith``): ``/ws-evil`` is NOT within ``/ws``.
    """
    return len(path_segs) >= len(root_segs) and path_segs[: len(root_segs)] == root_segs


def deny_match(path: CanonicalPath, stores: PolicyStores) -> bool:
    """True if the canonical ``path`` is on the §7.3 DENY_ALWAYS list.

    Denied for BOTH read and write (the I8 read-exposure invariant: reading the
    HMAC ``kernel.secret`` is credential theft, a harden over the SPEC's
    "write to …" wording)."""
    segs = _segments(path)
    if not segs:
        return False
    base = segs[-1]
    home_segs = _segments(stores.home)

    # ~/.ssh/** ~/.gnupg/** ~/.kimi-code/** ~/.aws/** ~/.config/gh/**
    for rel in _HOME_SECRET_RELS:
        if _within(segs, home_segs + _segments(rel)):
            return True

    # **/.env and **/.env.* (except the .env.example carve-out).
    if base == ".env":
        return True
    if base.startswith(".env.") and base != ".env.example":
        return True

    # /etc/shadow ; /etc/sudoers* (sudoers, sudoers.d/…).
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

    # .git/ internals — any component named exactly ".git" (NOT ".gitignore"/".github").
    if ".git" in segs:
        return True

    # <policy_store>/policy* — an entry under the injected policy store named policy*.
    policy_segs = _segments(stores.policy_store)
    if _within(segs, policy_segs):
        tail = segs[len(policy_segs):]
        if tail and tail[0].startswith("policy"):
            return True

    # audit store subtree ; kernel secret (file/subtree) — injected (S1/I8).
    return _within(segs, _segments(stores.audit_store)) or _within(
        segs, _segments(stores.kernel_secret)
    )
