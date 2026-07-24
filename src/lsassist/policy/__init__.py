"""policy/ — permission classes + deterministic classification rules (SPEC §7).

PURE (§2.2): the policy engine imports only ``contracts`` (plus its own
submodules) and does NO I/O — classification is a pure function of the contract
models and the INJECTED :class:`PolicyStores`. Public surface:

- :func:`classify` — ``(ToolRequest, PolicyContext, ToolManifest, PolicyStores)
  → PermissionClass``.
- :class:`PolicyStores` — injected, pre-resolved §7.3 store roots (§2.2 purity).
- :data:`PolicyClass` — the policy-class enum (alias of ``PermissionClass``).
- :func:`raise_to` / :func:`rank` / :data:`CLASS_ORDER` — class ordering helpers.
"""

from lsassist.policy.classes import CLASS_ORDER, PolicyClass, raise_to, rank
from lsassist.policy.rules import classify
from lsassist.policy.stores import PolicyStores

__all__ = [
    "CLASS_ORDER",
    "PolicyClass",
    "PolicyStores",
    "classify",
    "raise_to",
    "rank",
]
