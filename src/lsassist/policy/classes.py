"""Policy class ordering + monotonic raise (SPEC §7.1; T2.01 decision #1).

The five permission classes form a total order from least to most restrictive::

    AUTO_READ < AUTO_SCOPED_WRITE < CONFIRM_ONCE < CONFIRM_EXACT < DENY_ALWAYS

:func:`raise_to` returns the MORE restrictive (higher-ordered) of two classes.
The classifier (:func:`lsassist.policy.rules.classify`) composes each rule's
result onto the manifest floor with it, so a rule can only ever RAISE the
class, never lower it (monotonicity invariant, R1).

PURE (§2.2): no filesystem, network, or child-process access — pure ordering
math over the :class:`~lsassist.contracts.enums.PermissionClass` contract enum.
"""

from __future__ import annotations

from lsassist.contracts.enums import PermissionClass

# ``PolicyClass`` is the policy engine's name for the shared contract enum: the
# SPEC §7.1 policy classes ARE the §6.2 manifest ``permission_class`` values, so
# there is exactly one enum. Aliasing (rather than defining a parallel enum)
# keeps ``manifest.permission_class``, ``context.skill_ceiling`` and the
# classifier result mutually type-compatible with nothing to keep in sync.
PolicyClass = PermissionClass

# SPEC §7.1 / decision #1: least → most restrictive. Index == restrictiveness.
CLASS_ORDER: tuple[PermissionClass, ...] = (
    PermissionClass.AUTO_READ,
    PermissionClass.AUTO_SCOPED_WRITE,
    PermissionClass.CONFIRM_ONCE,
    PermissionClass.CONFIRM_EXACT,
    PermissionClass.DENY_ALWAYS,
)

_RANK: dict[PermissionClass, int] = {cls: i for i, cls in enumerate(CLASS_ORDER)}


def rank(cls: PermissionClass) -> int:
    """Return the restrictiveness rank (0 = AUTO_READ … 4 = DENY_ALWAYS)."""
    return _RANK[cls]


def raise_to(a: PermissionClass, b: PermissionClass) -> PermissionClass:
    """Return the MORE restrictive (higher-ordered) of two policy classes.

    The monotone join used to compose a rule result onto the manifest floor
    (R1): it can only hold or raise, never lower. Commutative and idempotent —
    ``raise_to(x, x) == x`` and ``raise_to(a, b) == raise_to(b, a)``.
    """
    return a if _RANK[a] >= _RANK[b] else b
