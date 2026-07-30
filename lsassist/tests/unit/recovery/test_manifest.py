"""T4.04 — the §14.4 checkpoint manifest: what a snapshot claims about itself.

A checkpoint's whole purpose is to be trusted LATER, by a rollback that has no
independent way to know what the workspace looked like. The manifest is that
claim, so every property worth testing here is about the claim being unforgeable,
unambiguous and reproducible:

* **Frozen and closed.** A mutable manifest is one whose digest can go stale
  between computing and writing it; an open one has room for a field nobody's
  contract fixes. `audit/schema.py` makes exactly this argument for
  :class:`AuditRecord` and it applies unchanged here.
* **Canonical bytes are the hash input, so the serialization is pinned.** Same
  spelling as §14.1's: ``sort_keys=True``, ``separators=(",", ":")``,
  ``ensure_ascii=False``, and the U+2028/U+2029 translation T4.02 added after
  measuring that `json.dumps` leaves them raw while a line-oriented reader treats
  them as line breaks. A manifest carries FILE PATHS, which is user-controlled
  text, so that trap is live here rather than theoretical.
* **Excluded and stored are mutually exclusive.** §14.4 excludes files over
  50 MB. An entry that carried both a digest and an exclusion marker would let a
  rollback restore something the snapshot never actually stored.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from lsassist.recovery.manifest import (
    CheckpointEntry,
    CheckpointManifest,
    ExclusionReason,
    TriggerKind,
    canonical_bytes,
    manifest_digest,
)

WORKSPACE = "/home/u/proj"
STAMP = datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC)
TREE = "a" * 40


def entry(**over: Any) -> CheckpointEntry:
    base: dict[str, Any] = {
        "path": "src/a.py",
        "size": 12,
        "mtime_ns": 1_700_000_000_000_000_000,
        "sha256": "b" * 64,
    }
    base.update(over)
    return CheckpointEntry(**base)


def manifest(**over: Any) -> CheckpointManifest:
    base: dict[str, Any] = {
        "checkpoint_id": "cp-0001",
        "workspace": WORKSPACE,
        "trigger": TriggerKind.PRE_WRITE,
        "created_at": STAMP,
        "entries": (entry(),),
        "tree": TREE,
    }
    base.update(over)
    return CheckpointManifest(**base)


# ---------------------------------------------------------------------------
# The record is closed and immutable
# ---------------------------------------------------------------------------


def test_a_manifest_cannot_be_mutated_after_it_is_built() -> None:
    with pytest.raises(ValidationError):
        manifest().checkpoint_id = "cp-0002"  # type: ignore[misc]


def test_an_entry_cannot_be_mutated_after_it_is_built() -> None:
    with pytest.raises(ValidationError):
        entry().sha256 = "c" * 64  # type: ignore[misc]


@pytest.mark.parametrize("model", ["manifest", "entry"])
def test_an_undeclared_field_is_refused(model: str) -> None:
    """Room for an undeclared field is room for a meaning the SPEC never fixed."""
    with pytest.raises(ValidationError):
        manifest(surprise=1) if model == "manifest" else entry(surprise=1)


# ---------------------------------------------------------------------------
# §14.4 trigger vocabulary
# ---------------------------------------------------------------------------


def test_the_trigger_vocabulary_is_exactly_the_four_14_4_names() -> None:
    """§14.4: before fs.write/fs.patch, before test.run, and manual."""
    assert {t.value for t in TriggerKind} == {"pre_write", "pre_patch", "pre_test", "manual"}


def test_an_unknown_trigger_is_refused() -> None:
    with pytest.raises(ValidationError):
        manifest(trigger="pre_deploy")


# ---------------------------------------------------------------------------
# Stored vs excluded — the distinction a rollback depends on
# ---------------------------------------------------------------------------


def test_an_excluded_entry_carries_a_reason_and_no_digest() -> None:
    """§14.4 excludes files over 50 MB; the manifest must SAY so, not omit them.

    Omitting an excluded file entirely would make the manifest indistinguishable
    from one taken before that file existed — and a rollback would then delete it
    as "not present at checkpoint time".
    """
    big = entry(sha256=None, excluded_because=ExclusionReason.OVERSIZE, size=60 * 1024 * 1024)
    assert big.sha256 is None
    assert big.excluded_because is ExclusionReason.OVERSIZE


def test_an_entry_may_not_be_both_stored_and_excluded() -> None:
    """Both would let a rollback restore bytes the snapshot never stored."""
    with pytest.raises(ValidationError):
        entry(sha256="b" * 64, excluded_because=ExclusionReason.OVERSIZE)


def test_an_entry_must_be_either_stored_or_excluded() -> None:
    with pytest.raises(ValidationError):
        entry(sha256=None, excluded_because=None)


@pytest.mark.parametrize("bad", ["", "xyz", "B" * 64, "sha256:" + "b" * 64, "b" * 63])
def test_a_malformed_digest_is_refused(bad: str) -> None:
    """Bare lowercase hex, 64 chars — the same spelling §6.5's evidence uses."""
    with pytest.raises(ValidationError):
        entry(sha256=bad)


# ---------------------------------------------------------------------------
# Paths — the part an attacker controls
# ---------------------------------------------------------------------------


def test_the_workspace_must_be_an_absolute_path() -> None:
    with pytest.raises(ValidationError):
        manifest(workspace="proj")


@pytest.mark.parametrize("bad", ["/etc/passwd", "../escape", "a/../../b", ""])
def test_an_entry_path_must_be_relative_and_may_not_climb(bad: str) -> None:
    """A manifest path is joined to the workspace at restore time.

    An absolute or climbing path would make the manifest itself the instrument
    of the escape — the rollback would faithfully restore to wherever it pointed.
    """
    with pytest.raises(ValidationError):
        entry(path=bad)


def test_a_nul_byte_in_a_path_is_refused() -> None:
    with pytest.raises(ValidationError):
        entry(path="src/a\x00.py")


def test_entries_are_stored_in_sorted_order_whatever_order_they_arrive() -> None:
    """Two snapshots of the same tree must produce the same bytes."""
    unsorted = (entry(path="z.py"), entry(path="a.py"), entry(path="m.py"))
    assert [e.path for e in manifest(entries=unsorted).entries] == ["a.py", "m.py", "z.py"]


def test_a_duplicate_path_is_refused() -> None:
    """Two claims about one file leave a rollback with no way to choose."""
    with pytest.raises(ValidationError):
        manifest(entries=(entry(path="a.py"), entry(path="a.py", sha256="c" * 64)))


@pytest.mark.parametrize("bad", [-1, -1000])
def test_a_negative_size_or_mtime_is_refused(bad: int) -> None:
    with pytest.raises(ValidationError):
        entry(size=bad)
    with pytest.raises(ValidationError):
        entry(mtime_ns=bad)


# ---------------------------------------------------------------------------
# Canonical bytes — the hash input, pinned like §14.1's
# ---------------------------------------------------------------------------


def test_canonical_bytes_are_compact_sorted_and_utf8() -> None:
    raw = canonical_bytes(manifest())
    assert b", " not in raw and b": " not in raw
    decoded = json.loads(raw)
    assert list(decoded) == sorted(decoded)


def test_canonical_bytes_keep_utf8_as_utf8() -> None:
    """`ensure_ascii=False`, for the same reason §14.1 gives: readability."""
    raw = canonical_bytes(manifest(entries=(entry(path="src/ქართული.py"),)))
    assert "ქართული".encode() in raw


def test_the_same_manifest_always_produces_the_same_bytes() -> None:
    assert canonical_bytes(manifest()) == canonical_bytes(manifest())
    assert manifest_digest(manifest()) == manifest_digest(manifest())


def test_the_digest_changes_when_any_field_changes() -> None:
    """A field outside the digest is a field an attacker may rewrite freely."""
    base = manifest_digest(manifest())
    assert manifest_digest(manifest(checkpoint_id="cp-0002")) != base
    assert manifest_digest(manifest(trigger=TriggerKind.MANUAL)) != base
    assert manifest_digest(manifest(tree="c" * 40)) != base
    assert manifest_digest(manifest(created_at=datetime(2026, 7, 30, tzinfo=UTC))) != base
    assert manifest_digest(manifest(entries=(entry(sha256="c" * 64),))) != base


@pytest.mark.parametrize("breaker", ["\u2028", "\u2029", "\u0085"])
def test_a_line_breaking_codepoint_in_a_path_cannot_split_the_record(breaker: str) -> None:
    """T4.02 measured this: `json.dumps` leaves these three RAW.

    Every ASCII control character is already escaped by `json.dumps`; exactly
    U+0085, U+2028 and U+2029 come through. A line-oriented reader then sees one
    manifest as two, and the second half is unparseable. A manifest carries file
    PATHS — attacker-influenced text — so this is the live case, not a
    theoretical one. Written as escapes rather than literals so the test says
    which codepoint it means.
    """
    raw = canonical_bytes(manifest(entries=(entry(path=f"src/a{breaker}b.py"),)))
    assert raw.count(b"\n") == 0
    assert breaker.encode() not in raw
    assert json.loads(raw)


def test_the_digest_is_a_prefixed_sha256() -> None:
    digest = manifest_digest(manifest())
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64


@pytest.mark.parametrize(
    "bad", ["", "z" * 40, "A" * 40, "a" * 39, "a" * 41, "a" * 50, "sha256:" + "a" * 40]
)
def test_a_malformed_tree_hash_is_refused(bad: str) -> None:
    """The tree is what a rollback resolves objects through.

    A manifest whose tree id is unparseable is a checkpoint that cannot be
    restored, and finding that out at restore time — when the workspace has
    already been mutated — is the worst moment to find it out.
    """
    with pytest.raises(ValidationError):
        manifest(tree=bad)


def test_a_sha256_length_git_tree_hash_is_accepted() -> None:
    """A future SHA-256 git repository must not require a schema change."""
    assert manifest(tree="a" * 64).tree == "a" * 64


def test_a_backslash_rooted_path_is_refused() -> None:
    """`posixpath.isabs` says False for `\\windows\\style`, so it is checked apart.

    A path this module accepted but a restore later treated as rooted would put
    the write outside the workspace — the same escape the `..` rule closes,
    arriving through a different spelling.
    """
    with pytest.raises(ValidationError):
        entry(path="\\etc\\passwd")
