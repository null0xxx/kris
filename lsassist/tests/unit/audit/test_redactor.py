"""T4.01 RED: ``audit/redactor.py`` — THE redactor engine (SPEC §14.3, §12.4, I8).

§14.3: "Single module; ordered rules; fail-closed on pattern-engine error (event
stored digest-only). Tested by canary suite (AC-12) და fuzz."
§12.4: "Redaction = replace with ``[REDACTED:<class>]``, audit records the fact
of redaction."

**Ownership (§2.2, I8).** ``config/redaction_patterns.py`` (T1.10) is DATA; this
engine is the only module in the codebase permitted to apply it. The tests here
therefore assert both directions: the engine consumes T1.10's table verbatim,
and no substitution engine has appeared in ``config/``.

**The engine is strictly wider than the data, in three documented places.**

1. T1.10's ``private-key`` pattern matches the BEGIN HEADER LINE only. Applying
   it literally would replace ``-----BEGIN RSA PRIVATE KEY-----`` and leave the
   base64 body sitting in the audit log — an I8 false negative. The engine
   widens that one class to the whole PEM BLOCK: greedy to the LAST end line so
   an injected fake END cannot truncate it, tempered so it cannot cross into the
   next key, and consuming to end-of-text only when no end line exists at all.
2. OpenPGP armor (``-----BEGIN PGP PRIVATE KEY BLOCK-----``) is not matched by
   T1.10's source at all. The engine ships that BEGIN form; see the redactor's
   named residual, which says it belongs in T1.10's data.
3. T1.10 ships a never-matching ``(?!)`` placeholder for ``deny-path-content``
   and says in its own comment that "the engine supplies the concrete DENY-path
   body at runtime". The engine expands it in place, preserving T1.10's rule
   ORDER exactly.

Section 5b pins one regression test per defect an isolated adversarial critic
round reproduced against the first draft of this engine. Each one is a real leak
or a real fail-open that the rest of this file did not catch.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from lsassist.audit.redactor import (
    CLASS_ENGINE_ERROR,
    AuditRedaction,
    RedactionHit,
    Redactor,
    RedactorError,
    redact_for_audit,
)
from lsassist.config.redaction_patterns import (
    CLASS_AWS_ACCESS_KEY,
    CLASS_CONFIGURED_SECRET,
    CLASS_DENY_PATH_CONTENT,
    CLASS_GITHUB_PAT,
    CLASS_KIMI,
    CLASS_PRIVATE_KEY,
    CLASS_SK,
    REDACTION_PATTERNS,
    RedactionPattern,
)

_CORPUS_PATH = Path(__file__).resolve().parents[1] / "config" / "canary_corpus.json"
_CORPUS: dict[str, Any] = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
_CANARIES: list[dict[str, str]] = _CORPUS["canaries"]
_ENGINE_CANARIES: list[dict[str, str]] = _CORPUS["engine_canaries"]
_FALSE_POSITIVES: list[str] = _CORPUS["false_positives"]

#: The §7.3 DENY paths and configured secrets the engine canaries reference.
DENY_PATHS = tuple(
    entry["value"] for entry in _ENGINE_CANARIES if entry["class_label"] == CLASS_DENY_PATH_CONTENT
)
CONFIGURED_SECRETS = tuple(
    entry["value"]
    for entry in _ENGINE_CANARIES
    if entry["class_label"] == CLASS_CONFIGURED_SECRET
)


def marker(class_label: str) -> str:
    return f"[REDACTED:{class_label}]"


def sha256_of(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def full_redactor() -> Redactor:
    return Redactor(deny_paths=DENY_PATHS, configured_secrets=CONFIGURED_SECRETS)


# ==========================================================================
# 1. the §12.4 replacement contract
# ==========================================================================
def test_returns_an_audit_redaction() -> None:
    result = redact_for_audit("nothing secret here")
    assert isinstance(result, AuditRedaction)
    assert result.text == "nothing secret here"
    assert result.hits == ()
    assert result.digest_only is False


def test_payload_digest_is_the_sha256_of_the_original() -> None:
    """§14.1's evidence field: the digest binds the record to the pre-redaction text."""
    original = "token sk-CANARYskDECOY00000000 trailing"
    result = redact_for_audit(original)
    assert result.payload_digest == sha256_of(original)
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", result.payload_digest)


def test_replacement_uses_the_class_marker() -> None:
    result = redact_for_audit("key=sk-CANARYskDECOY00000000;")
    assert result.text == f"key={marker(CLASS_SK)};"


def test_surrounding_text_is_preserved() -> None:
    result = redact_for_audit("before ghp_CANARYdecoyGITHUBpat0000000000000000 after")
    assert result.text == f"before {marker(CLASS_GITHUB_PAT)} after"


def test_empty_text_is_not_an_error() -> None:
    result = redact_for_audit("")
    assert result.text == ""
    assert result.digest_only is False
    assert result.payload_digest == sha256_of("")


# ==========================================================================
# 2. corpus-driven: 100% redaction, every §12.4 class
# ==========================================================================
@pytest.mark.parametrize(
    "entry", _CANARIES, ids=[f"{i}-{e['class_label']}" for i, e in enumerate(_CANARIES)]
)
def test_every_t1_10_canary_is_redacted(entry: dict[str, str]) -> None:
    result = full_redactor().redact(entry["value"])
    assert entry["value"] not in result.text
    assert marker(entry["class_label"]) in result.text


@pytest.mark.parametrize(
    "entry",
    _ENGINE_CANARIES,
    ids=[f"{i}-{e['class_label']}" for i, e in enumerate(_ENGINE_CANARIES)],
)
def test_every_engine_canary_is_redacted(entry: dict[str, str]) -> None:
    result = full_redactor().redact(entry["value"])
    assert entry["value"] not in result.text, entry["note"]
    assert marker(entry["class_label"]) in result.text, entry["note"]


@pytest.mark.parametrize(
    "entry",
    _ENGINE_CANARIES,
    ids=[f"{i}-{e['class_label']}" for i, e in enumerate(_ENGINE_CANARIES)],
)
def test_engine_canaries_leave_no_fragment(entry: dict[str, str]) -> None:
    """Not just "the whole value is gone" — no LINE of it may survive."""
    result = full_redactor().redact(f"prefix\n{entry['value']}\nsuffix")
    for line in entry["value"].splitlines():
        stripped = line.strip()
        if len(stripped) >= 8:
            assert stripped not in result.text, f"{stripped!r} survived: {entry['note']}"


#: The markers T1.10's own AC-12 guard looks for, mirrored here. The seam critic
#: reproduced the gap: T1.10 parametrizes `test_every_canary_value_is_marked_
#: synthetic` over `canaries` ONLY, so the `engine_canaries` array this task
#: added could have taken a REAL credential and no test anywhere would object.
_SYNTHETIC_MARKERS = ("CANARY", "DECOY", "SYNTHETIC", "FAKE", "INVALID", "EXAMPLE")


@pytest.mark.parametrize(
    "entry",
    _ENGINE_CANARIES,
    ids=[f"synthetic-{i}" for i in range(len(_ENGINE_CANARIES))],
)
def test_every_engine_canary_value_is_marked_synthetic(entry: dict[str, str]) -> None:
    """AC-12: the corpus is decoys. A real credential must never land here."""
    upper = entry["value"].upper()
    assert any(marker in upper for marker in _SYNTHETIC_MARKERS), (
        f"{entry['value'][:40]!r} carries no synthetic marker "
        f"{_SYNTHETIC_MARKERS} — a real secret must never enter the corpus"
    )


def test_the_corpus_covers_every_declared_class() -> None:
    """AC-12: no §12.4 class may be untested."""
    covered = {e["class_label"] for e in _CANARIES} | {e["class_label"] for e in _ENGINE_CANARIES}
    assert covered == {
        CLASS_KIMI,
        CLASS_SK,
        CLASS_GITHUB_PAT,
        CLASS_AWS_ACCESS_KEY,
        CLASS_PRIVATE_KEY,
        CLASS_CONFIGURED_SECRET,
        CLASS_DENY_PATH_CONTENT,
    }


def test_a_document_mixing_every_class_redacts_all_of_them() -> None:
    document = "\n".join(
        [
            "aws=AKIACANARYDECOY00000",
            "gh=ghp_CANARYdecoyGITHUBpat0000000000000000",
            "kimi=sk-CANARYkimiDECOY0000000000000000000000000000000000000000",
            "sk=sk-CANARYskDECOY00000000",
            "cfg=CANARY-CONFIGURED-SECRET-VALUE-0000",
            "path=/home/canary/.ssh/id_ed25519",
            "-----BEGIN RSA PRIVATE KEY-----",
            "U1lOVEhFVElDLUNBTkFSWS1ERUNPWQ==",
            "-----END RSA PRIVATE KEY-----",
            "tail",
        ]
    )
    result = full_redactor().redact(document)

    for label in (
        CLASS_AWS_ACCESS_KEY,
        CLASS_GITHUB_PAT,
        CLASS_KIMI,
        CLASS_SK,
        CLASS_CONFIGURED_SECRET,
        CLASS_DENY_PATH_CONTENT,
        CLASS_PRIVATE_KEY,
    ):
        assert marker(label) in result.text, label
    assert "U1lOVEhFVElD" not in result.text
    assert result.text.endswith("tail")


# ==========================================================================
# 3. ordering — specific before generic, no partially-unreplaced fragment
# ==========================================================================
def test_private_key_block_beats_the_generic_key_patterns() -> None:
    """The plan's ordering case: the block rule runs before anything generic."""
    block = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "sk-CANARYskDECOY00000000\n"
        "-----END RSA PRIVATE KEY-----"
    )
    result = full_redactor().redact(block)
    assert result.text == marker(CLASS_PRIVATE_KEY)
    assert marker(CLASS_SK) not in result.text, "the inner key must be swallowed by the block"


def test_a_long_sk_key_is_labelled_kimi_not_generic() -> None:
    """T1.10 orders the >=48-char Kimi rule ahead of the generic ``sk-`` rule."""
    result = redact_for_audit("sk-CANARYkimiDECOY0000000000000000000000000000000000000000")
    assert result.text == marker(CLASS_KIMI)


def test_engine_preserves_the_t1_10_rule_order() -> None:
    """The engine may EXTEND the table; it may not reorder it."""
    engine_order = [rule.name for rule in full_redactor().rules]
    data_order = [pattern.name for pattern in REDACTION_PATTERNS]
    assert [name for name in engine_order if name in set(data_order)] == data_order


def test_unterminated_private_key_block_redacts_to_end_of_text() -> None:
    """Over-redaction is the safe direction when the END line never arrives."""
    text = "-----BEGIN RSA PRIVATE KEY-----\nU1lOVEhFVElDLUNBTkFSWQ==\nstill secret"
    result = full_redactor().redact(text)
    assert result.text == marker(CLASS_PRIVATE_KEY)


def test_two_private_key_blocks_are_both_redacted_without_swallowing_between() -> None:
    """A greedy block rule would eat the text between two keys."""
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"
        "KEEP THIS LINE\n"
        "-----BEGIN EC PRIVATE KEY-----\nBBBB\n-----END EC PRIVATE KEY-----"
    )
    result = full_redactor().redact(text)
    assert "KEEP THIS LINE" in result.text
    assert result.text.count(marker(CLASS_PRIVATE_KEY)) == 2
    assert "AAAA" not in result.text
    assert "BBBB" not in result.text


def test_redaction_is_idempotent() -> None:
    """A marker must never be re-matched by a later or repeated rule."""
    text = "sk-CANARYskDECOY00000000 and AKIACANARYDECOY00000"
    once = full_redactor().redact(text).text
    twice = full_redactor().redact(once).text
    assert once == twice


# ==========================================================================
# 4. hits — §12.4 "audit records the fact of redaction"
# ==========================================================================
def test_hits_record_class_and_count() -> None:
    text = "AKIACANARYDECOY00000 AKIACANARYDECOY11111"
    result = redact_for_audit(text)
    assert result.hits == (RedactionHit(class_label=CLASS_AWS_ACCESS_KEY, count=2),)


def test_hits_are_sorted_by_class_for_determinism() -> None:
    text = "sk-CANARYskDECOY00000000 AKIACANARYDECOY00000 ghp_CANARYdecoyGITHUBpat0000000000000000"
    labels = [hit.class_label for hit in redact_for_audit(text).hits]
    assert labels == sorted(labels)


def test_no_hits_when_nothing_matches() -> None:
    assert redact_for_audit("plain prose, nothing to see").hits == ()


def test_hit_count_helper() -> None:
    result = redact_for_audit("AKIACANARYDECOY00000 AKIACANARYDECOY11111")
    assert result.hit_count(CLASS_AWS_ACCESS_KEY) == 2
    assert result.hit_count(CLASS_KIMI) == 0


def test_hits_are_immutable() -> None:
    result = redact_for_audit("AKIACANARYDECOY00000")
    assert isinstance(result.hits, tuple)
    with pytest.raises((AttributeError, TypeError)):
        result.hits[0].count = 99  # type: ignore[misc]


def test_redacted_flag_reports_whether_anything_happened() -> None:
    """§12.4: "audit records the FACT of redaction" — this is that flag."""
    assert redact_for_audit("nothing here").redacted is False
    assert redact_for_audit("AKIACANARYDECOY00000").redacted is True
    assert Redactor(patterns=(BROKEN,)).redact("x").redacted is True


def test_the_facade_honours_runtime_deny_paths_and_secrets() -> None:
    """The keyword form builds a per-call engine; the bare form reuses the default."""
    text = "cfg=CANARY-CONFIGURED-SECRET-VALUE-0000 path=/home/canary/.ssh/id_ed25519"
    assert redact_for_audit(text).text == text  # no runtime data supplied

    result = redact_for_audit(
        text, deny_paths=DENY_PATHS, configured_secrets=CONFIGURED_SECRETS
    )
    assert marker(CLASS_CONFIGURED_SECRET) in result.text
    assert marker(CLASS_DENY_PATH_CONTENT) in result.text


def test_hits_never_carry_the_secret() -> None:
    """A hit is evidence OF redaction, never a copy of what was redacted."""
    secret = "AKIACANARYDECOY00000"
    for hit in redact_for_audit(secret).hits:
        assert secret not in repr(hit)


# ==========================================================================
# 5. fail-closed on a pattern-engine error (§14.3)
# ==========================================================================
BROKEN = RedactionPattern(name="broken", class_label="broken", pattern_src="(unclosed")


def test_a_broken_rule_yields_digest_only_and_does_not_raise() -> None:
    original = "payload with sk-CANARYskDECOY00000000 inside"
    result = Redactor(patterns=(BROKEN,)).redact(original)

    assert result.digest_only is True
    assert result.text == "", "the digest-only branch must emit NO payload"
    assert result.payload_digest == sha256_of(original)


def test_the_engine_error_is_recorded_in_hits() -> None:
    result = Redactor(patterns=(BROKEN,)).redact("anything")
    assert any(hit.class_label == CLASS_ENGINE_ERROR for hit in result.hits)


def test_a_broken_rule_never_emits_partially_redacted_text() -> None:
    """The dangerous failure is "some rules ran": it LOOKS redacted and is not."""
    original = "AKIACANARYDECOY00000 and sk-CANARYskDECOY00000000"
    result = Redactor(patterns=(*REDACTION_PATTERNS, BROKEN)).redact(original)
    assert result.digest_only is True
    assert result.text == ""
    assert "AKIA" not in result.text


def test_a_rule_that_explodes_during_substitution_is_contained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not only compile-time: anything raising mid-apply must fail closed too.

    ``_marker`` is called once per rule inside the substitution loop, so making
    it explode is an exception raised in the middle of a real pass — the state
    in which a half-substituted payload would otherwise be produced.
    """
    from lsassist.audit import redactor as engine

    redactor = full_redactor()

    def boom(*args: object, **kwargs: object) -> str:
        raise RuntimeError("regex engine exploded")

    monkeypatch.setattr(engine, "_marker", boom)
    result = redactor.redact("AKIACANARYDECOY00000")
    assert result.digest_only is True
    assert result.text == ""
    assert any(hit.class_label == CLASS_ENGINE_ERROR for hit in result.hits)


def test_redact_for_audit_never_raises_for_any_corpus_value() -> None:
    for entry in [*_CANARIES, *_ENGINE_CANARIES]:
        assert isinstance(redact_for_audit(entry["value"]), AuditRedaction)


@pytest.mark.parametrize("bad", [None, 42, b"bytes", ["list"], object()])
def test_a_non_string_payload_fails_closed(bad: object) -> None:
    """A caller bug must not become an unredacted payload or a crash."""
    result = redact_for_audit(bad)  # type: ignore[arg-type]
    assert result.digest_only is True
    assert result.text == ""
    assert any(hit.class_label == CLASS_ENGINE_ERROR for hit in result.hits)


def test_redactor_error_is_the_engines_own_type() -> None:
    assert issubclass(RedactorError, Exception)


def test_compile_raises_a_typed_error_on_an_uncompilable_source() -> None:
    """Unreachable through ``_build`` today — tested directly, and here is why.

    ``_build`` runs T1.10's ``validate_patterns`` first, so a table entry that
    cannot compile is rejected before ``_compile`` sees it. The arm still earns
    its place: ``_compile`` performs a SECOND compilation for the private-key
    class (source + block tail) that ``validate_patterns`` never exercises, and
    it also compiles the runtime exact-match rules, which come from
    ``exact_match_pattern`` rather than from the validated table. Kept and
    tested rather than deleted (T2.13: never close a branch by removing
    defensive code) and never silenced with a pragma (§23.1 forbids it).
    """
    from lsassist.audit.redactor import _compile

    with pytest.raises(RedactorError) as excinfo:
        _compile(RedactionPattern(name="broken", class_label="x", pattern_src="(unclosed"))
    assert "broken" in str(excinfo.value)


def test_an_oversized_payload_is_stored_digest_only() -> None:
    """An unbounded regex sweep over an attacker-influenced body is a DoS surface."""
    from lsassist.audit.redactor import MAX_PAYLOAD_CHARS

    oversized = "x" * (MAX_PAYLOAD_CHARS + 1)
    result = redact_for_audit(oversized)
    assert result.digest_only is True
    assert result.text == ""
    assert result.payload_digest == sha256_of(oversized)


def test_a_payload_exactly_at_the_cap_is_still_redacted() -> None:
    """Off-by-one guard: the cap is a ceiling, not a threshold."""
    from lsassist.audit.redactor import MAX_PAYLOAD_CHARS

    at_cap = "x" * MAX_PAYLOAD_CHARS
    result = redact_for_audit(at_cap)
    assert result.digest_only is False
    assert result.text == at_cap


def test_an_empty_configured_secret_is_refused_not_silently_ignored() -> None:
    """T1.10 rejects it fail-closed: an empty exact match would redact everything."""
    result = Redactor(configured_secrets=("",)).redact("anything at all")
    assert result.digest_only is True


# ==========================================================================
# 5b. REGRESSION PINS — every defect the adversarial critic round reproduced
# ==========================================================================
def test_openpgp_armored_private_key_is_redacted() -> None:
    """CRITICAL, reproduced: T1.10's source ends in ``PRIVATE KEY-----`` and so
    never matched OpenPGP armor, which ends in ``PRIVATE KEY BLOCK-----``. A GPG
    secret key passed through completely unredacted while ``~/.gnupg`` is a §7.3
    DENY_ALWAYS subtree."""
    pgp = (
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
        "lQOYBGSYNTHETICCANARYDECOYKEYMATERIAL==\n"
        "-----END PGP PRIVATE KEY BLOCK-----"
    )
    result = full_redactor().redact(pgp)
    assert result.text == marker(CLASS_PRIVATE_KEY)
    assert "lQOYBG" not in result.text


def test_an_injected_end_line_cannot_truncate_a_private_key_block() -> None:
    """HIGH, reproduced: a lazy body stopped at the FIRST END, so content that
    merely CONTAINS an END line published the real key body verbatim."""
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
        "SECRETKEYBODYAAAABBBBCCCC\n"
        "-----END RSA PRIVATE KEY-----"
    )
    result = full_redactor().redact(text)
    assert result.text == marker(CLASS_PRIVATE_KEY)
    assert "SECRETKEYBODY" not in result.text


def test_a_key_revealed_by_an_earlier_replacement_is_still_redacted() -> None:
    """HIGH, reproduced: the generic ``sk-`` rule carries a ``(?<![A-Za-z0-9])``
    left boundary. Glued to an AWS key id the boundary failed, and by the time
    the AWS rule removed the prefix the ``sk-`` rule had already run — a single
    ordered pass emitted the key. The engine now iterates to a fixpoint."""
    result = redact_for_audit("AKIACANARYDECOY00000sk-ABCDEFGHIJKLMNOPQRSTUV")
    assert "sk-ABCDEFGHIJKLMNOPQRSTUV" not in result.text
    assert result.text == f"{marker(CLASS_AWS_ACCESS_KEY)}{marker(CLASS_SK)}"


def test_the_fixpoint_terminates_on_ordinary_text() -> None:
    """The counterweight to the loop: a clean payload still costs one pass."""
    assert redact_for_audit("no secrets at all").text == "no secrets at all"


@pytest.mark.parametrize(
    "table",
    [
        (),
        tuple(p for p in REDACTION_PATTERNS if p.class_label != CLASS_PRIVATE_KEY),
        tuple(p for p in REDACTION_PATTERNS if p.class_label != CLASS_AWS_ACCESS_KEY),
    ],
    ids=["empty", "no-private-key", "no-aws"],
)
def test_a_table_missing_a_class_fails_closed(table: tuple[object, ...]) -> None:
    """HIGH, reproduced: an empty or filtered table built a NO-OP redactor that
    returned the payload unchanged with digest_only=False and hits=() — a clean
    success report for zero redaction. The single degenerate input that failed
    OPEN rather than closed."""
    result = Redactor(patterns=table).redact(  # type: ignore[arg-type]
        "AKIACANARYDECOY00000 sk-ABCDEFGHIJKLMNOPQRSTUV"
    )
    assert result.digest_only is True
    assert result.text == ""
    assert "class" in result.error_detail


def test_deny_paths_with_nowhere_to_go_fail_closed() -> None:
    """MEDIUM, reproduced: deny_paths were silently DISCARDED when the table had
    no placeholder to expand at, leaking §7.3 path content with digest_only=False.

    Today the class-coverage check catches this table first — a table missing
    ``deny-path-content`` is missing a required §12.4 class. That is the FIRST
    lock; the placement check below is the second.
    """
    table = tuple(p for p in REDACTION_PATTERNS if p.class_label != CLASS_DENY_PATH_CONTENT)
    result = Redactor(patterns=table, deny_paths=("/home/u/.ssh/id_ed25519",)).redact(
        "path=/home/u/.ssh/id_ed25519"
    )
    assert result.digest_only is True
    assert result.text == ""


def test_the_deny_placement_check_is_the_second_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unreachable while the class-coverage check stands — tested by disabling it.

    ``_REQUIRED_CLASSES`` is derived from T1.10's shipped table, which contains
    ``deny-path-content``, so no caller-supplied table can both pass the coverage
    check AND leave the deny rules unplaced. Kept and exercised directly rather
    than deleted (T2.13: never close a branch by removing defensive code) and
    never silenced with a pragma (§23.1 forbids it in TCB packages). If the
    coverage check is ever narrowed, this lock still holds.
    """
    from lsassist.audit import redactor as engine

    monkeypatch.setattr(engine, "_REQUIRED_CLASSES", frozenset())
    table = tuple(p for p in REDACTION_PATTERNS if p.class_label != CLASS_DENY_PATH_CONTENT)
    result = Redactor(patterns=table, deny_paths=("/home/u/.ssh/id_ed25519",)).redact(
        "path=/home/u/.ssh/id_ed25519"
    )
    assert result.digest_only is True
    assert "slot to place them in" in result.error_detail


def test_an_object_whose_repr_raises_is_still_contained() -> None:
    """MEDIUM, reproduced: the non-str guard called ``repr(text)`` OUTSIDE the
    try, so a hostile object made the "total function" raise at the caller."""

    class Exploding:
        def __repr__(self) -> str:
            raise RuntimeError("repr exploded")

    result = redact_for_audit(Exploding())  # type: ignore[arg-type]
    assert result.digest_only is True
    assert result.text == ""
    assert "Exploding" in result.error_detail


def test_error_detail_says_what_went_wrong() -> None:
    """HIGH, reproduced: the detail string was computed at four call sites and
    then discarded, so every fail-closed outcome was one indistinguishable
    ``engine_error`` hit and the operator could not tell a broken pattern from
    an oversized payload."""
    from lsassist.audit.redactor import MAX_PAYLOAD_CHARS

    assert "cap" in redact_for_audit("x" * (MAX_PAYLOAD_CHARS + 1)).error_detail
    assert "str" in redact_for_audit(None).error_detail  # type: ignore[arg-type]
    assert "broken" in Redactor(patterns=(*REDACTION_PATTERNS, BROKEN)).redact("x").error_detail


def test_error_detail_is_empty_on_success() -> None:
    assert redact_for_audit("clean").error_detail == ""


def test_substitution_failures_record_only_the_exception_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``error_detail`` is journalled, so it must never quote the payload — and
    an arbitrary exception's ``str()`` can contain the input it choked on."""
    from lsassist.audit import redactor as engine

    def boom(*args: object, **kwargs: object) -> str:
        raise RuntimeError("the payload was AKIACANARYDECOY00000")

    monkeypatch.setattr(engine, "_marker", boom)
    result = full_redactor().redact("AKIACANARYDECOY00000")
    assert result.error_detail == "substitution raised RuntimeError"
    assert "payload" not in result.error_detail
    assert "AKIA" not in result.error_detail


def test_non_convergence_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fixpoint loop must not silently return a best-effort partial result."""
    from lsassist.audit import redactor as engine

    monkeypatch.setattr(engine, "MAX_PASSES", 0)
    result = full_redactor().redact("AKIACANARYDECOY00000")
    assert result.digest_only is True
    assert "converge" in result.error_detail


def test_the_rules_property_never_exposes_a_configured_secret() -> None:
    """LOW, reproduced: ``rules`` returned compiled patterns, and a
    configured-secret rule's source is ``re.escape(<the secret>)`` — undoing the
    care taken to keep secrets out of ``RedactionHit``."""
    secret = "CANARY-CONFIGURED-SECRET-VALUE-0000"
    rendered = repr(Redactor(configured_secrets=(secret,)).rules)
    assert secret not in rendered
    assert "CANARY" not in rendered


# ==========================================================================
# 6. false-positive guard (§12.4 must not eat ordinary text)
# ==========================================================================
@pytest.mark.parametrize(
    "sample", _FALSE_POSITIVES, ids=[f"fp-{i}" for i in range(len(_FALSE_POSITIVES))]
)
def test_benign_text_is_returned_unchanged(sample: str) -> None:
    result = full_redactor().redact(sample)
    assert result.text == sample
    assert result.hits == ()


def test_a_certificate_is_not_a_private_key() -> None:
    """The block rule keys on "PRIVATE KEY"; a public artifact must survive."""
    pem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
    assert full_redactor().redact(pem).text == pem


def test_a_deny_path_only_matches_when_it_is_configured() -> None:
    """Without the injected §7.3 list the path rule is the T1.10 never-match hook."""
    path = "/home/canary/.ssh/id_ed25519"
    assert Redactor().redact(path).text == path
    assert Redactor(deny_paths=(path,)).redact(path).text == marker(CLASS_DENY_PATH_CONTENT)


def test_a_configured_secret_containing_regex_metacharacters_is_literal() -> None:
    """T1.10's ``exact_match_pattern`` escapes; the engine must not undo that."""
    secret = "a.*b(c|d)+"
    redactor = Redactor(configured_secrets=(secret,))
    assert redactor.redact("aXXXbc").text == "aXXXbc"
    assert redactor.redact(f"x{secret}y").text == f"x{marker(CLASS_CONFIGURED_SECRET)}y"


# ==========================================================================
# 7. I8 ownership — the engine lives here and nowhere else
# ==========================================================================
def test_the_engine_consumes_the_t1_10_table_by_reference() -> None:
    from lsassist.audit import redactor as engine

    assert engine.REDACTION_PATTERNS is REDACTION_PATTERNS


def test_config_still_contains_no_substitution_engine() -> None:
    """I8 grep-gate: T1.10 is DATA; ``config/`` may not grow an engine."""
    config_dir = Path(__file__).resolve().parents[3] / "src" / "lsassist" / "config"
    forbidden = re.compile(r"\bdef (redact|apply|scan)\b|\bre\.sub\b|\bre\.subn\b")
    for module in sorted(config_dir.rglob("*.py")):
        source = module.read_text(encoding="utf-8")
        assert not forbidden.search(source), f"{module.name} grew redaction ENGINE code (I8)"


def test_the_redactor_is_the_only_engine_module() -> None:
    src = Path(__file__).resolve().parents[3] / "src" / "lsassist"
    engines = [
        module
        for module in sorted(src.rglob("*.py"))
        if re.search(r"\bdef redact_for_audit\b", module.read_text(encoding="utf-8"))
    ]
    assert [module.name for module in engines] == ["redactor.py"]


def test_audit_package_exports_the_facade() -> None:
    import lsassist.audit as audit_package

    assert audit_package.redact_for_audit is redact_for_audit
