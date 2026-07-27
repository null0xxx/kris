"""T4.01 RED (property): redactor fuzz — 0 leaks (SPEC §14.3, AC-12, I8).

§14.3: "Tested by canary suite (AC-12) და fuzz (random secrets-shaped strings →
100% redacted)."

Two properties, in tension on purpose:

* **No leak.** A generated secret-shaped string is never present in the output.
  This is the I8 property, and it is the one that must never bend.
* **No over-redaction.** Generated benign text is returned byte-identical.
  Without it, ``return AuditRedaction(text="")`` would satisfy the first
  property perfectly — a redactor that redacts everything passes a leak test
  and destroys the audit journal.

The generators build values from the §12.4 shapes rather than from the patterns
themselves. Deriving them from ``REDACTION_PATTERNS`` would make the test a
tautology: it would only ever prove that the engine applies whatever the data
says, never that the data covers the shapes a real key takes.
"""

from __future__ import annotations

import string

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lsassist.audit.redactor import redact_for_audit

# §12.4 secret shapes. Alphabets are deliberately WIDER than the corpus values
# (mixed case, digits, `_`, `-`) so a pattern that silently truncates at the
# first separator — the T1.10 critic's `sk-proj-…` finding — reappears as a leak.
_B62 = string.ascii_letters + string.digits
_KEY_BODY = _B62 + "_-"
_UPPER36 = string.ascii_uppercase + string.digits


def _body(alphabet: str, min_size: int, max_size: int) -> st.SearchStrategy[str]:
    return st.text(alphabet=alphabet, min_size=min_size, max_size=max_size)


kimi_keys = _body(_KEY_BODY, 48, 96).map(lambda body: f"sk-{body}")
sk_keys = _body(_KEY_BODY, 20, 47).map(lambda body: f"sk-{body}")
github_pats = _body(_B62, 36, 36).map(lambda body: f"ghp_{body}")
aws_key_ids = _body(_UPPER36, 16, 16).map(lambda body: f"AKIA{body}")

_PEM_KINDS = st.sampled_from(["RSA", "EC", "DSA", "OPENSSH", ""])
private_keys = st.builds(
    lambda kind, body: (
        f"-----BEGIN {kind + ' ' if kind else ''}PRIVATE KEY-----\n"
        f"{body}\n"
        f"-----END {kind + ' ' if kind else ''}PRIVATE KEY-----"
    ),
    _PEM_KINDS,
    _body(_B62 + "+/=", 16, 200),
)

secret_shaped = st.one_of(kimi_keys, sk_keys, github_pats, aws_key_ids, private_keys)

# Benign text: printable, no `sk-`/`ghp_`/`AKIA`/PEM header, no control chars.
# Built by exclusion rather than by an allowlist so the strategy keeps finding
# ordinary strings the engine might over-match on.
benign = st.text(
    alphabet=st.characters(
        min_codepoint=32, max_codepoint=126, blacklist_characters="-_"
    ),
    min_size=0,
    max_size=120,
).filter(lambda s: not any(token in s for token in ("sk", "ghp", "AKIA", "PRIVATE KEY")))

_FUZZ = settings(
    max_examples=2500,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)


@_FUZZ
@given(secret_shaped)
def test_a_secret_shaped_string_never_survives(secret: str) -> None:
    result = redact_for_audit(secret)
    assert secret not in result.text
    assert result.hits, "a redaction must be RECORDED, not just performed (§12.4)"


@_FUZZ
@given(secret_shaped)
def test_a_secret_embedded_in_prose_never_survives(secret: str) -> None:
    result = redact_for_audit(f"log line: {secret} <- end")
    assert secret not in result.text
    assert result.text.startswith("log line: ")


@_FUZZ
@given(secret_shaped, secret_shaped)
def test_two_secrets_in_one_payload_both_go(first: str, second: str) -> None:
    result = redact_for_audit(f"{first}\n{second}")
    assert first not in result.text
    assert second not in result.text


@_FUZZ
@given(benign)
def test_benign_text_is_byte_identical(text: str) -> None:
    """The counterweight: redacting everything would pass every leak test."""
    result = redact_for_audit(text)
    assert result.text == text
    assert result.hits == ()
    assert result.digest_only is False


@_FUZZ
@given(st.text(max_size=200))
def test_redaction_never_raises_and_never_grows_unboundedly(text: str) -> None:
    """Total function: any ``str`` in, an ``AuditRedaction`` out (§14.3)."""
    result = redact_for_audit(text)
    assert result.payload_digest.startswith("sha256:")
    if not result.digest_only:
        assert len(result.text) <= len(text) + 64 * max(1, len(result.hits))


@_FUZZ
@given(secret_shaped)
def test_redaction_is_idempotent_on_secrets(secret: str) -> None:
    once = redact_for_audit(secret).text
    assert redact_for_audit(once).text == once
