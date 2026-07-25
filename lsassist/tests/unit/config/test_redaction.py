"""T1.10 RED: redaction pattern DATA + canary seed corpus (SPEC §12.4, §14.3).

These tests exercise the pattern DATA module only — there is deliberately NO
redaction engine here (that is T4.01 in ``audit/``). Every canary value is
synthetic / deliberately fake; no real secret material appears. AC-12 artifact:
``canary_corpus.json``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from lsassist.config.redaction_patterns import (
    CANARY_SEED,
    CLASS_AWS_ACCESS_KEY,
    CLASS_CONFIGURED_SECRET,
    CLASS_DENY_PATH_CONTENT,
    CLASS_GITHUB_PAT,
    CLASS_KIMI,
    CLASS_PRIVATE_KEY,
    CLASS_SK,
    REDACTION_PATTERNS,
    CanaryValue,
    RedactionConfigError,
    RedactionPattern,
    exact_match_pattern,
    validate_patterns,
)

_CORPUS_PATH = Path(__file__).parent / "canary_corpus.json"
_CORPUS: dict[str, Any] = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
_CANARIES: list[dict[str, str]] = _CORPUS["canaries"]
_FALSE_POSITIVES: list[str] = _CORPUS["false_positives"]

# §12.4 classes that are backed by a concrete static regex in the table.
_STATIC_KEY_CLASSES = (
    CLASS_KIMI,
    CLASS_SK,
    CLASS_GITHUB_PAT,
    CLASS_AWS_ACCESS_KEY,
    CLASS_PRIVATE_KEY,
)
_SYNTHETIC_MARKERS = ("CANARY", "DECOY", "SYNTHETIC", "FAKE", "INVALID", "EXAMPLE")


def _pattern_by_class() -> dict[str, str]:
    return {p.class_label: p.pattern_src for p in REDACTION_PATTERNS}


# --- (1) coverage: table covers EVERY §12.4 class -----------------------------


def test_table_covers_every_12_4_class() -> None:
    labels = {p.class_label for p in REDACTION_PATTERNS}
    # Kimi, sk-*, ghp_*, AKIA*, private-key block, and the DENY-path placeholder
    # all live in the static table.
    for expected in (*_STATIC_KEY_CLASSES, CLASS_DENY_PATH_CONTENT):
        assert expected in labels, expected


def test_configured_exact_match_class_is_reachable() -> None:
    # The configured-secret exact-match hook is dynamic (per configured value),
    # so its class is reachable via the function, not the static table.
    pattern = exact_match_pattern("whatever")
    assert pattern.class_label == CLASS_CONFIGURED_SECRET


def test_deny_path_content_hook_is_a_placeholder() -> None:
    deny = [p for p in REDACTION_PATTERNS if p.class_label == CLASS_DENY_PATH_CONTENT]
    assert len(deny) == 1
    # Placeholder compiles cleanly but matches nothing on its own — the engine
    # (T4.01) supplies DENY-path content at runtime.
    compiled = re.compile(deny[0].pattern_src)
    assert compiled.search("anything at all -----BEGIN X----- sk-xxxx") is None


# --- (2) corpus-driven: each canary matched by ITS class's pattern ------------


@pytest.mark.parametrize(
    "entry",
    _CANARIES,
    ids=[f"{i}-{e['class_label']}" for i, e in enumerate(_CANARIES)],
)
def test_canary_matched_by_its_class_pattern(entry: dict[str, str]) -> None:
    pattern_src = _pattern_by_class()[entry["class_label"]]
    assert re.search(pattern_src, entry["value"]) is not None


def test_corpus_covers_all_static_key_classes() -> None:
    covered = {e["class_label"] for e in _CANARIES}
    assert set(_STATIC_KEY_CLASSES) <= covered


# --- (3) false-positive guard: normal strings match NO pattern ----------------


@pytest.mark.parametrize(
    "sample",
    _FALSE_POSITIVES,
    ids=[f"fp-{i}" for i in range(len(_FALSE_POSITIVES))],
)
def test_false_positive_matches_no_pattern(sample: str) -> None:
    for pattern in REDACTION_PATTERNS:
        assert re.search(pattern.pattern_src, sample) is None, pattern.name


# --- (4) ordering invariant: private-key block BEFORE generic key patterns ----


def test_private_key_block_precedes_generic_key_patterns() -> None:
    order = [p.class_label for p in REDACTION_PATTERNS]
    pk_index = order.index(CLASS_PRIVATE_KEY)
    for generic in (CLASS_KIMI, CLASS_SK, CLASS_GITHUB_PAT, CLASS_AWS_ACCESS_KEY):
        assert pk_index < order.index(generic), generic


def test_kimi_precedes_generic_sk() -> None:
    order = [p.class_label for p in REDACTION_PATTERNS]
    assert order.index(CLASS_KIMI) < order.index(CLASS_SK)


# --- (5) exact_match hook: re.escape literal, only that value, no injection ----


def test_exact_match_matches_only_that_value() -> None:
    secret = "SwordFish-2026-CANARY"
    pattern = exact_match_pattern(secret)
    assert re.search(pattern.pattern_src, f"prefix {secret} suffix") is not None
    assert re.search(pattern.pattern_src, "SwordFish-2025-CANARY") is None


def test_exact_match_escapes_regex_metacharacters() -> None:
    # A secret value full of regex metacharacters must be treated literally —
    # no regex injection is possible from a configured secret value.
    secret = ".*+[abc](d|e){2}^$"
    pattern = exact_match_pattern(secret)
    assert pattern.pattern_src == re.escape(secret)
    # Matches the literal string ...
    assert re.search(pattern.pattern_src, f"x{secret}y") is not None
    # ... but does NOT behave as the injected regex (which would match "aaaa").
    assert re.search(pattern.pattern_src, "aaaa") is None


def test_exact_match_returns_redaction_pattern() -> None:
    pattern = exact_match_pattern("value")
    assert isinstance(pattern, RedactionPattern)
    assert pattern.class_label == CLASS_CONFIGURED_SECRET


def test_exact_match_rejects_empty_value_fail_closed() -> None:
    # re.escape("") == "" matches a zero-width span in every string, which would
    # redact everything — reject fail-closed.
    with pytest.raises(RedactionConfigError):
        exact_match_pattern("")


# --- hyphen/underscore key formats: catch real keys, ignore embedded words ----


def test_hyphenated_sk_key_is_caught_by_sk_family() -> None:
    # OpenRouter/OpenAI-style keys use hyphens/underscores; a base62-only class
    # would truncate at the first '-' and let the secret escape (I8).
    patterns = _pattern_by_class()
    for key in (
        "sk-or-v1-" + "0123456789abcdef" * 3,  # long -> kimi
        "sk-proj-CANARYdecoy00001234",  # 20-47 -> generic sk
    ):
        assert any(
            re.search(patterns[cls], key) is not None for cls in (CLASS_KIMI, CLASS_SK)
        ), key


def test_sk_prefix_inside_benign_word_is_not_matched() -> None:
    # Left boundary stops 'sk-' inside 'disk-'; 'task_' has no literal 'sk-'.
    for benign in ("disk-0123456789abcdefghij", "task_0123456789abcdefghij"):
        for pattern in REDACTION_PATTERNS:
            assert re.search(pattern.pattern_src, benign) is None, (pattern.name, benign)


# --- (6) fail-closed: malformed regex source -> RedactionConfigError ----------


def test_validate_patterns_accepts_shipped_table() -> None:
    # The real table must compile cleanly (self-check).
    validate_patterns()
    validate_patterns(REDACTION_PATTERNS)


def test_validate_patterns_fails_closed_on_malformed_regex() -> None:
    broken = (
        RedactionPattern(
            name="broken", class_label="broken", pattern_src="[unclosed(group"
        ),
    )
    with pytest.raises(RedactionConfigError):
        validate_patterns(broken)


# --- dataclass / data-shape invariants ----------------------------------------


def test_redaction_pattern_is_frozen() -> None:
    pattern = REDACTION_PATTERNS[0]
    with pytest.raises(Exception):  # noqa: B017 - FrozenInstanceError is a dataclass detail
        pattern.name = "mutated"  # type: ignore[misc]


def test_pattern_src_is_uncompiled_string() -> None:
    # Compilation is the engine's job; this module ships source strings only.
    for pattern in REDACTION_PATTERNS:
        assert isinstance(pattern.pattern_src, str)


def test_redaction_config_error_is_exception() -> None:
    assert issubclass(RedactionConfigError, Exception)


# --- AC-12: corpus is synthetic and corresponds to the module seed ------------


def test_canary_seed_corresponds_to_corpus() -> None:
    seed_pairs = [(c.value, c.class_label) for c in CANARY_SEED]
    corpus_pairs = [(e["value"], e["class_label"]) for e in _CANARIES]
    assert seed_pairs == corpus_pairs


def test_canary_seed_entries_are_canary_values() -> None:
    assert len(CANARY_SEED) >= 5
    for canary in CANARY_SEED:
        assert isinstance(canary, CanaryValue)


@pytest.mark.parametrize(
    "value",
    [e["value"] for e in _CANARIES],
    ids=[f"synthetic-{i}" for i in range(len(_CANARIES))],
)
def test_every_canary_value_is_marked_synthetic(value: str) -> None:
    upper = value.upper()
    assert any(marker in upper for marker in _SYNTHETIC_MARKERS), value
