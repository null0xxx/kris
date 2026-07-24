"""Redaction pattern DATA (SPEC §12.4, fail-closed per §14.3).

This module is pure DATA for the redactor: an ordered table of known
secret-format patterns (regex *source* + class label), a synthetic canary
seed corpus (the AC-12 artifact), a configured-secret exact-match hook, and a
load-time validator that compiles every pattern source fail-closed.

It is deliberately NOT the redactor. The redactor ENGINE is a single module in
``audit/`` (SPEC §2.2, §14.3) owned by a future task (``audit/redactor.py``);
that engine CONSUMES this data — compiling the sources, applying the ordered
rules, emitting ``[REDACTED:<class>]``, and turning a
:class:`RedactionConfigError` into the digest-only branch. No substitution or
scanning engine logic lives here — this module is pattern data only.

§12.4 classes represented:

- ``kimi-api-key`` — the Kimi (Moonshot) coding key format,
- ``sk-api-key`` — the generic ``sk-*`` key prefix,
- ``github-pat`` — GitHub personal access tokens (``ghp_*``),
- ``aws-access-key-id`` — AWS access key ids (``AKIA*``),
- ``private-key`` — PEM ``-----BEGIN … PRIVATE KEY-----`` blocks,
- ``configured-secret`` — exact-match of a configured secret value (dynamic,
  via :func:`exact_match_pattern`),
- ``deny-path-content`` — placeholder for DENY-path content redaction, wired by
  the engine at runtime.

Ordering matters: the structural ``private-key`` block appears BEFORE the
generic key-format patterns, and the more-specific ``kimi-api-key`` appears
before the generic ``sk-api-key`` (the engine applies rules in order).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

__all__ = [
    "CANARY_SEED",
    "CLASS_AWS_ACCESS_KEY",
    "CLASS_CONFIGURED_SECRET",
    "CLASS_DENY_PATH_CONTENT",
    "CLASS_GITHUB_PAT",
    "CLASS_KIMI",
    "CLASS_PRIVATE_KEY",
    "CLASS_SK",
    "REDACTION_CLASSES",
    "REDACTION_PATTERNS",
    "CanaryValue",
    "RedactionConfigError",
    "RedactionPattern",
    "exact_match_pattern",
    "validate_patterns",
]


class RedactionConfigError(Exception):
    """A redaction pattern source is malformed; the engine must fail closed (§14.3)."""


# §12.4 class labels — the ``<class>`` in the engine's ``[REDACTED:<class>]`` tag.
CLASS_KIMI = "kimi-api-key"
CLASS_SK = "sk-api-key"
CLASS_GITHUB_PAT = "github-pat"
CLASS_AWS_ACCESS_KEY = "aws-access-key-id"
CLASS_PRIVATE_KEY = "private-key"
CLASS_CONFIGURED_SECRET = "configured-secret"
CLASS_DENY_PATH_CONTENT = "deny-path-content"

REDACTION_CLASSES: frozenset[str] = frozenset(
    {
        CLASS_KIMI,
        CLASS_SK,
        CLASS_GITHUB_PAT,
        CLASS_AWS_ACCESS_KEY,
        CLASS_PRIVATE_KEY,
        CLASS_CONFIGURED_SECRET,
        CLASS_DENY_PATH_CONTENT,
    }
)


@dataclass(frozen=True)
class RedactionPattern:
    """One ordered redaction rule as DATA (SPEC §12.4).

    ``pattern_src`` is an UN-compiled regex source string — compilation is the
    engine's job (§14.3), never this module's beyond the load-time self-check in
    :func:`validate_patterns`.
    """

    name: str
    class_label: str
    pattern_src: str


@dataclass(frozen=True)
class CanaryValue:
    """A synthetic decoy value and the §12.4 class it seeds (AC-12).

    Every value is deliberately fake — no real secret material is ever placed
    here. These correspond one-to-one with ``canary_corpus.json``.
    """

    value: str
    class_label: str


# Ordered §12.4 pattern table. The structural private-key block is FIRST, then
# the more-specific Kimi key before the generic ``sk-*``, then the remaining
# fixed-prefix key formats, then the DENY-path content placeholder.
#
# Rationale for each source:
#   - private-key: PEM header line, any key type (RSA/EC/OPENSSH/PKCS8).
#   - kimi-api-key: ``sk-`` + >=48 body chars (long Moonshot/Kimi coding key);
#     a strict superset-length refinement of the generic ``sk-*`` so the ordered
#     engine labels long ``sk-`` keys as Kimi.
#   - sk-api-key: generic ``sk-`` + >=20 body chars (OpenAI-style prefix).
#   The sk body class is ``[A-Za-z0-9_-]`` (``-`` last = literal) so hyphen/
#   underscore key formats — ``sk-or-v1-…`` (OpenRouter), ``sk-proj-…`` (OpenAI)
#   — are NOT truncated at the first separator (avoids an I8 false-negative). A
#   ``(?<![A-Za-z0-9])`` left boundary stops a ``sk-`` embedded in a benign word
#   (``disk-…``, ``risk-…``) from matching, while still catching keys after a
#   space / ``=`` / ``:`` / quote / ``_``.
#   - github-pat: ``ghp_`` + 36 base62 chars.
#   - aws-access-key-id: ``AKIA`` + 16 upper/digit chars.
#   - deny-path-content: never-match placeholder; the engine supplies the
#     concrete DENY-path body at runtime (content is not knowable statically).
REDACTION_PATTERNS: tuple[RedactionPattern, ...] = (
    RedactionPattern(
        name="pem-private-key-block",
        class_label=CLASS_PRIVATE_KEY,
        pattern_src=r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
    ),
    RedactionPattern(
        name="kimi-coding-key",
        class_label=CLASS_KIMI,
        pattern_src=r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{48,}",
    ),
    RedactionPattern(
        name="sk-generic-key",
        class_label=CLASS_SK,
        pattern_src=r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}",
    ),
    RedactionPattern(
        name="github-personal-access-token",
        class_label=CLASS_GITHUB_PAT,
        pattern_src=r"ghp_[A-Za-z0-9]{36}",
    ),
    RedactionPattern(
        name="aws-access-key-id",
        class_label=CLASS_AWS_ACCESS_KEY,
        pattern_src=r"AKIA[0-9A-Z]{16}",
    ),
    RedactionPattern(
        name="deny-path-content-hook",
        class_label=CLASS_DENY_PATH_CONTENT,
        # Never-match placeholder: valid regex, matches nothing until the engine
        # supplies DENY-path content at runtime (§12.4 path-based redaction).
        pattern_src=r"(?!)",
    ),
)


# Synthetic canary seed corpus (AC-12). One-to-one with ``canary_corpus.json``.
# Every value is a deliberately fake decoy — no real secret material.
CANARY_SEED: tuple[CanaryValue, ...] = (
    CanaryValue(
        value="sk-CANARYkimiDECOY0000000000000000000000000000000000000000",
        class_label=CLASS_KIMI,
    ),
    CanaryValue(
        value="sk-kimiFORcodingCANARYdecoySYNTHETIC0000000000000000000000",
        class_label=CLASS_KIMI,
    ),
    CanaryValue(
        value="sk-CANARYskDECOY00000000",
        class_label=CLASS_SK,
    ),
    CanaryValue(
        value="sk-DECOYopenaiStyleCANARYkey01234",
        class_label=CLASS_SK,
    ),
    CanaryValue(
        value="ghp_CANARYdecoyGITHUBpat0000000000000000",
        class_label=CLASS_GITHUB_PAT,
    ),
    CanaryValue(
        value="AKIACANARYDECOY00000",
        class_label=CLASS_AWS_ACCESS_KEY,
    ),
    CanaryValue(
        value=(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "U1lOVEhFVElDLUNBTkFSWS1ERUNPWS1OT1QtQS1SRUFMLUtFWQ==\n"
            "SYNTHETIC CANARY DECOY NOT A REAL KEY\n"
            "-----END RSA PRIVATE KEY-----"
        ),
        class_label=CLASS_PRIVATE_KEY,
    ),
    CanaryValue(
        value=(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "c3ludGhldGljIGNhbmFyeSBkZWNveSBub3QgcmVhbA==\n"
            "SYNTHETIC CANARY DECOY\n"
            "-----END OPENSSH PRIVATE KEY-----"
        ),
        class_label=CLASS_PRIVATE_KEY,
    ),
    CanaryValue(
        value=(
            "-----BEGIN PRIVATE KEY-----\n"
            "U1lOVEhFVElDLUNBTkFSWS1ERUNPWQ==\n"
            "SYNTHETIC CANARY DECOY\n"
            "-----END PRIVATE KEY-----"
        ),
        class_label=CLASS_PRIVATE_KEY,
    ),
    # Hyphen/underscore key formats (would break a base62-only class). Long
    # (>=48 body chars) -> Kimi under the ordered table; 20-47 -> generic sk.
    CanaryValue(
        value="sk-or-v1-CANARYdecoySYNTHETIC0123456789abcdef01234567",
        class_label=CLASS_KIMI,
    ),
    CanaryValue(
        value="sk-proj-CANARYdecoy00001234",
        class_label=CLASS_SK,
    ),
)


def exact_match_pattern(value: str) -> RedactionPattern:
    """Build a literal exact-match rule for a configured secret value (§12.4).

    The source is ``re.escape(value)`` so the configured secret is matched
    verbatim and can never inject regex syntax (a secret containing ``.*`` or
    ``(a|b)`` is matched as those literal characters, not as a pattern).

    An empty ``value`` is rejected fail-closed: ``re.escape("") == ""`` matches a
    zero-width span in every string, so an empty configured secret would redact
    everything. Raises :class:`RedactionConfigError` in that case.
    """
    if not value:
        raise RedactionConfigError(
            "exact-match hook rejects an empty configured secret (fail-closed): "
            "an empty value would match every string"
        )
    return RedactionPattern(
        name="configured-secret-exact",
        class_label=CLASS_CONFIGURED_SECRET,
        pattern_src=re.escape(value),
    )


def validate_patterns(patterns: Iterable[RedactionPattern] = REDACTION_PATTERNS) -> None:
    """Compile every ``pattern_src`` fail-closed (SPEC §14.3).

    Raises :class:`RedactionConfigError` on the first uncompilable source. The
    engine calls this at load time and, on failure, drops to the digest-only
    branch instead of running a partially-valid rule set.
    """
    for pattern in patterns:
        try:
            re.compile(pattern.pattern_src)
        except re.error as exc:
            raise RedactionConfigError(
                f"redaction pattern {pattern.name!r} has an invalid source "
                f"(fail-closed, §14.3): {exc}"
            ) from exc


# Fail-closed self-check: the shipped table must compile at import (§14.3).
validate_patterns()
