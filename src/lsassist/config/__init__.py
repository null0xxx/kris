"""config/ — XDG layout, startup security checks, canary honeyfiles (SPEC §12.1, §19.1)."""

from lsassist.config.canary import (
    CANARY_HONEYFILES,
    CanaryEntry,
    canary_registry,
    expected_canary_digests,
    provision_canaries,
)
from lsassist.config.schema import (
    Config,
    ConfigVersionError,
    load_config,
)
from lsassist.config.xdg import (
    LAYOUT,
    ConfigSecurityError,
    LayoutKind,
    XdgPaths,
    check_security,
    ensure_layout,
)

__all__ = [
    "CANARY_HONEYFILES",
    "LAYOUT",
    "CanaryEntry",
    "Config",
    "ConfigSecurityError",
    "ConfigVersionError",
    "LayoutKind",
    "XdgPaths",
    "canary_registry",
    "check_security",
    "ensure_layout",
    "expected_canary_digests",
    "load_config",
    "provision_canaries",
]
