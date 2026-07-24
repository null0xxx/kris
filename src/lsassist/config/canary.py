"""Canary honeyfiles (SPEC §19 scenario 1, §12.1).

Fake-credential decoys provisioned at install/first-run into
``$XDG_CONFIG_HOME/lsassist/canary/`` (dir 0700, files 0600). All decoy
material is synthetic and deliberately invalid — real secret material is
never handled in this module. Any read attempt on a honeyfile is a
compromise signal; the alert/freeze reaction on decoy reads belongs to the
kernel/audit layers, not here.

Tamper- and symlink-safety: honeyfiles are created with
``os.open(O_CREAT|O_EXCL|O_NOFOLLOW, 0o600)``; provisioning is idempotent
(second run verifies digests instead of rewriting); any digest mismatch,
missing honeyfile, or symlink raises :class:`ConfigSecurityError`
(fail-closed).
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from lsassist.config.xdg import ConfigSecurityError, XdgPaths

__all__ = [
    "CANARY_HONEYFILES",
    "CanaryEntry",
    "canary_registry",
    "expected_canary_digests",
    "provision_canaries",
]

# Declarative decoy table: (filename, synthetic content). Deliberately
# invalid credentials that merely *look* like the §12.4 redaction classes.
CANARY_HONEYFILES: tuple[tuple[str, str], ...] = (
    (
        "kimi-api-key",
        "sk-lsassist-canary-decoy-invalid-0000000000000000000000\n",
    ),
    (
        "aws-credentials",
        "# canary honeyfile (SPEC §19 scenario 1) — synthetic, intentionally invalid\n"
        "[default]\n"
        "aws_access_key_id = AKIALSASSISTCANARY00\n"
        "aws_secret_access_key = canary/Decoy+NotARealSecret000000000000\n",
    ),
    (
        "id_rsa",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "Y2FuYXJ5LWRlY295LW5vdC1hLXJlYWwta2V5LWludmFsaWQAAAAA\n"
        "Q0FOQVJZIERFQ09ZOiBOT1QgQSBSRUFMIEtFWSAtIElOVkFMSUQAAAA=\n"
        "canary decoy — not a real key, intentionally invalid\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
    ),
)

_CANARY_RELPATH = "config/lsassist/canary"
_DIR_MODE = 0o700
_FILE_MODE = 0o600


@dataclass(frozen=True)
class CanaryEntry:
    """One provisioned honeyfile: absolute path + sha256 of its decoy content."""

    path: Path
    sha256: str


def expected_canary_digests() -> dict[str, str]:
    """Expected sha256 per honeyfile filename, from the declarative table."""
    return {
        name: hashlib.sha256(content.encode("utf-8")).hexdigest()
        for name, content in CANARY_HONEYFILES
    }


def _canary_dir(paths: XdgPaths) -> Path:
    return paths.layout_path(_CANARY_RELPATH)


def _ensure_canary_dir(paths: XdgPaths) -> Path:
    current = paths.config_home
    for part in ("lsassist", "canary"):
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            os.mkdir(current, _DIR_MODE)
            continue
        if stat.S_ISLNK(st.st_mode):
            raise ConfigSecurityError(f"canary path is a symlink (fail-closed): {current}")
        if not stat.S_ISDIR(st.st_mode):
            raise ConfigSecurityError(f"canary path is not a directory: {current}")
    mode = stat.S_IMODE(os.lstat(current).st_mode)
    if mode & ~_DIR_MODE:
        os.chmod(current, _DIR_MODE)
    return current


def _verify_honeyfile(path: Path, expected_digest: str) -> str:
    """lstat + digest-check one honeyfile; fail-closed on any violation."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise ConfigSecurityError(f"canary honeyfile missing: {path}") from None
    if stat.S_ISLNK(st.st_mode):
        raise ConfigSecurityError(f"canary honeyfile is a symlink (fail-closed): {path}")
    if not stat.S_ISREG(st.st_mode):
        raise ConfigSecurityError(f"canary honeyfile is not a regular file: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected_digest:
        raise ConfigSecurityError(
            f"canary honeyfile digest mismatch (tamper?): {path}"
        )
    return digest


def provision_canaries(paths: XdgPaths) -> None:
    """Create the canary dir and honeyfiles; idempotent (§19 scenario 1).

    New honeyfiles are written with ``O_CREAT|O_EXCL|O_NOFOLLOW`` at 0600.
    Existing honeyfiles are never rewritten — their digest is verified and a
    mismatch raises :class:`ConfigSecurityError`.
    """
    canary_dir = _ensure_canary_dir(paths)
    expected = expected_canary_digests()
    for name, content in CANARY_HONEYFILES:
        target = canary_dir / name
        try:
            fd = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, _FILE_MODE
            )
        except FileExistsError:
            _verify_honeyfile(target, expected[name])
        else:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
            os.chmod(target, _FILE_MODE)  # exact mode regardless of umask


def canary_registry(paths: XdgPaths) -> list[CanaryEntry]:
    """Path + sha256 digest per honeyfile; fail-closed on tamper/symlink/missing."""
    canary_dir = _canary_dir(paths)
    expected = expected_canary_digests()
    return [
        CanaryEntry(path=canary_dir / name, sha256=_verify_honeyfile(canary_dir / name, digest))
        for name, digest in expected.items()
    ]
