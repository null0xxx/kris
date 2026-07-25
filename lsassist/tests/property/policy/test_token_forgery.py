"""§23.1 PT: the approval token is forgery-resistant (I5/I6, threat class T-12).

Positive control: an UNMUTATED mint→verify (at ``issued_at``, within TTL and
uses) is ALWAYS ``VALID`` — so the forgery property below is not vacuous.

Forgery property: across a broad family of adversarial mutations — token-value
hex corruption, splicing another record's value, tampering ANY canonical field
(args, cwd, paths, env, session, class, ttl_s, max_uses, token_id), swapping the
struct ``token_id``, and presenting a never-minted (but correctly-HMAC'd)
token — NO mutation ever verifies ``VALID``. The HMAC input is always
``record.canonical_bytes()`` (never re-serialized here). Run with
``--hypothesis-profile=ci`` for >=200 examples (see ``tests/property/conftest``).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from hypothesis import assume, given
from hypothesis import strategies as st

from lsassist.contracts.approval import ApprovalClass, ApprovalRecord
from lsassist.policy.canonical import action_hash, env_digest
from lsassist.policy.token import ApprovalToken, TokenService, TokenVerdict

_HEX = "0123456789abcdef"


@st.composite
def _records(draw: st.DrawFn, *, token_id: str | None = None) -> ApprovalRecord:
    tool = draw(st.sampled_from(["proc.exec", "fs.write", "net.fetch", "git.commit"]))
    argv = draw(st.lists(st.text(min_size=0, max_size=6), max_size=4))
    args = {"argv": argv}
    session_id = draw(st.text(min_size=1, max_size=10))
    cwd = draw(st.sampled_from(["/home/null/Desktop/LinuxSec", "/tmp/ws", "/srv/app"]))
    paths = draw(st.lists(st.sampled_from(["/a", "/b", "/home/null/x"]), max_size=3))
    env = draw(st.dictionaries(st.text(min_size=1, max_size=5), st.text(max_size=8), max_size=4))
    max_uses = draw(st.integers(min_value=1, max_value=5))
    ttl_s = draw(st.integers(min_value=1, max_value=100_000))
    cls = draw(st.sampled_from(list(ApprovalClass)))
    edigest = env_digest(env)
    ahash = action_hash(tool, args, paths, cwd, edigest)
    kwargs: dict[str, Any] = {
        "session_id": session_id,
        "tool": tool,
        "args_normalized": args,
        "canonical_paths": paths,
        "cwd_real": cwd,
        "env_digest": edigest,
        "action_hash": ahash,
        "max_uses": max_uses,
        "ttl_s": ttl_s,
        "policy_class": cls,
    }
    if token_id is not None:
        kwargs["token_id"] = token_id
    return ApprovalRecord(**kwargs)


_SECRETS = st.binary(min_size=16, max_size=48)
_HEX64 = st.text(alphabet=_HEX, min_size=64, max_size=64)


@given(secret=_SECRETS, record=_records())
def test_unmutated_token_verifies_valid(secret: bytes, record: ApprovalRecord) -> None:
    """Positive control — the property below is meaningful only if this holds."""
    service = TokenService(secret)
    token = service.mint(record)
    assert service.verify(token, record, now=record.issued_at) is TokenVerdict.VALID


# Corrupt values include hex noise AND arbitrary unicode (non-ASCII must fail
# CLOSED to a verdict, never raise — see S1 / the bytes value-compare).
_CORRUPT_VALUES = st.one_of(_HEX64, st.text(), st.text(min_size=1))


@given(secret=_SECRETS, record=_records(), corrupt=_CORRUPT_VALUES)
def test_corrupted_value_never_valid(secret: bytes, record: ApprovalRecord, corrupt: str) -> None:
    service = TokenService(secret)
    token = service.mint(record)
    assume(corrupt != token.value)
    forged = ApprovalToken(token_id=token.token_id, value=corrupt)
    # Must return a verdict (never raise) and never VALID.
    assert service.verify(forged, record, now=record.issued_at) is not TokenVerdict.VALID


@given(secret=_SECRETS, data=st.data())
def test_value_spliced_from_other_record_never_valid(secret: bytes, data: st.DataObject) -> None:
    service = TokenService(secret)
    record = data.draw(_records())
    other = data.draw(_records())
    token = service.mint(record)
    other_token = service.mint(other)
    assume(other_token.value != token.value)
    # Present another record's HMAC while claiming this record's identity.
    forged = ApprovalToken(token_id=record.token_id, value=other_token.value)
    assert service.verify(forged, record, now=record.issued_at) is not TokenVerdict.VALID


@given(
    secret=_SECRETS,
    record=_records(),
    field_value=st.sampled_from(
        [
            ("args_normalized", {"argv": ["TAMPERED"]}),
            ("cwd_real", "/evil"),
            ("canonical_paths", ["/evil/path"]),
            ("session_id", "hijacked-session"),
            ("policy_note", "injected note"),
            ("rollback_hint", "injected hint"),
            ("action_hash", "sha256:" + "0" * 64),
            ("env_digest", "sha256:" + "1" * 64),
            ("ttl_s", 10_000_000),
            ("max_uses", 9_999),
            ("policy_class", ApprovalClass.CONFIRM_EXACT),
        ]
    ),
)
def test_any_field_tamper_never_valid(
    secret: bytes, record: ApprovalRecord, field_value: tuple[str, Any]
) -> None:
    service = TokenService(secret)
    token = service.mint(record)
    field, value = field_value
    mutated = record.model_copy(update={field: value})
    assume(mutated.canonical_bytes() != record.canonical_bytes())
    assert service.verify(token, mutated, now=record.issued_at) is not TokenVerdict.VALID


@given(secret=_SECRETS, record=_records(), other_id=st.text(min_size=1, max_size=36))
def test_struct_token_id_swap_never_valid(
    secret: bytes, record: ApprovalRecord, other_id: str
) -> None:
    service = TokenService(secret)
    token = service.mint(record)
    assume(other_id != record.token_id)
    # HMAC still matches the record, but the struct id is swapped.
    forged = ApprovalToken(token_id=other_id, value=token.value)
    assert service.verify(forged, record, now=record.issued_at) is not TokenVerdict.VALID


@given(secret=_SECRETS, record=_records(), other_id=st.text(min_size=1, max_size=36))
def test_record_token_id_swap_never_valid(
    secret: bytes, record: ApprovalRecord, other_id: str
) -> None:
    service = TokenService(secret)
    token = service.mint(record)
    assume(other_id != record.token_id)
    mutated = record.model_copy(update={"token_id": other_id})
    assert service.verify(token, mutated, now=record.issued_at) is not TokenVerdict.VALID


@given(secret=_SECRETS, record=_records())
def test_never_minted_valid_hmac_never_valid(secret: bytes, record: ApprovalRecord) -> None:
    # A correctly-HMAC'd token for a record the service never minted.
    service = TokenService(secret)
    value = hmac.new(secret, record.canonical_bytes(), hashlib.sha256).hexdigest()
    token = ApprovalToken(token_id=record.token_id, value=value)
    assert service.verify(token, record, now=record.issued_at) is not TokenVerdict.VALID
