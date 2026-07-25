"""Injected, pre-resolved store locations for the policy engine (SPEC §7.3, §12.1).

The §7.3 DENY list references XDG-configurable store trees — the audit journal,
the policy store, and the kernel secret — whose real locations move when
``$XDG_STATE_HOME`` / ``$XDG_DATA_HOME`` / ``$XDG_CONFIG_HOME`` are set
(``lsassist.config.xdg.XdgPaths.resolve``). The policy layer is PURE (§2.2) and
must never read the environment or the filesystem, so it CANNOT resolve these
itself. Instead the dispatcher (which legitimately holds a resolved
``XdgPaths``) constructs this frozen record and injects it into
:func:`lsassist.policy.rules.classify`. Hardcoding default ``~/.local/...``
paths here would let an ``$XDG_*`` override slip the real kernel-secret / audit
/ policy stores past R2/R7 — an I8 kernel-secret leak → HMAC token forgery →
total gate bypass. Injection closes that.

Every field is an ABSOLUTE, already-resolved path (as produced from
``XdgPaths``); the policy layer only does pure segment-wise string comparison
against them. Authoritative defaults (SPEC §12.1 / ``config/xdg.py`` LAYOUT):

- ``audit_store``   → ``$XDG_STATE_HOME/lsassist/audit``      (state_home)
- ``policy_store``  → ``$XDG_CONFIG_HOME/lsassist``           (config_home; guards ``policy*``)
- ``kernel_secret`` → ``$XDG_STATE_HOME/lsassist/kernel.secret`` (state_home)

``home`` anchors the fixed OS secret dirs (``~/.ssh``, ``~/.gnupg``,
``~/.kimi-code``, ``~/.aws``, ``~/.config/gh``) which are NOT XDG-relocatable.

§2.2: stdlib only; a frozen data record — no I/O, no child process, no network.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


class PolicyStoresError(ValueError):
    """A ``PolicyStores`` field is empty or not absolute — fail-closed (§7.3)."""


@dataclass(frozen=True)
class PolicyStores:
    """Resolved absolute store roots injected into policy classification (§7.3)."""

    home: str
    audit_store: str
    policy_store: str
    kernel_secret: str

    def __post_init__(self) -> None:
        # FAIL-CLOSED (S2): an empty or relative field would ``normpath`` to "."
        # and match nothing, silently deleting the ENTIRE §7.3 DENY set (incl.
        # the I8 kernel.secret read guard) on a construction/misconfig bug.
        # ``os.path.isabs`` is a pure string check — no filesystem, environment,
        # or symlink access (§2.2 purity preserved).
        for name, value in (
            ("home", self.home),
            ("audit_store", self.audit_store),
            ("policy_store", self.policy_store),
            ("kernel_secret", self.kernel_secret),
        ):
            if not value or not os.path.isabs(value):
                raise PolicyStoresError(
                    f"PolicyStores.{name} must be a non-empty absolute path, got {value!r}"
                )
