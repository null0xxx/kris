"""config/ — XDG layout, startup security checks, canary honeyfiles (SPEC §12.1, §19.1)."""

from lsassist.config.canary import (
    CANARY_HONEYFILES,
    CanaryEntry,
    canary_registry,
    expected_canary_digests,
    provision_canaries,
)
from lsassist.config.kernel_secret import (
    KERNEL_SECRET_LEN,
    load_or_generate_kernel_secret,
)
from lsassist.config.schema import (
    Config,
    ConfigVersionError,
    load_config,
)
from lsassist.config.secrets import (
    Keyring,
    KeyringUnavailableError,
    Secret,
    SecretNotFoundError,
    resolve_secret,
    store_secret,
    store_secret_file,
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
    "KERNEL_SECRET_LEN",
    "LAYOUT",
    "CanaryEntry",
    "Config",
    "ConfigSecurityError",
    "ConfigVersionError",
    "Keyring",
    "KeyringUnavailableError",
    "LayoutKind",
    "Secret",
    "SecretNotFoundError",
    "XdgPaths",
    "canary_registry",
    "check_security",
    "ensure_layout",
    "expected_canary_digests",
    "load_config",
    "load_or_generate_kernel_secret",
    "provision_canaries",
    "resolve_secret",
    "store_secret",
    "store_secret_file",
]
