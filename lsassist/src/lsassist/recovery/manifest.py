"""§14.4 checkpoint manifest — what a snapshot claims about the workspace.

A checkpoint exists to be trusted LATER, by a rollback that has no independent
way to know what the workspace looked like when it was taken. The manifest IS
that claim, so the properties that matter are the ones that keep the claim
unforgeable, unambiguous and reproducible.

**THE SERIALIZATION IS NOT REINVENTED HERE.** :func:`canonical_bytes` and
:func:`manifest_digest` delegate to :mod:`lsassist.audit.schema`, whose spelling
(``sort_keys=True``, ``separators=(",", ":")``, ``ensure_ascii=False``, then the
U+0085/U+2028/U+2029 escape table) is already pinned as the §14.1 hash input. Two
canonical forms in one system is two ways for the same object to hash, and the
one that drifts is the one nobody re-reads. That table is load-bearing here
rather than inherited politeness: a manifest carries FILE PATHS, which is
attacker-influenced text, and T4.02 measured that ``json.dumps`` leaves those
three codepoints RAW — one of them inside a path would split one manifest into
two lines for any line-oriented reader.

**STORED AND EXCLUDED ARE MUTUALLY EXCLUSIVE, AND EXCLUDED IS NOT OMITTED.**
§14.4 excludes files over 50 MB. Dropping them from the manifest entirely would
make a snapshot taken WITH a large file indistinguishable from one taken before
that file existed — and a rollback reading it would delete the file as "not
present at checkpoint time". So an excluded file is RECORDED, with a reason and
without a digest; carrying both would instead let a rollback try to restore bytes
the store never held.
"""

from __future__ import annotations

import posixpath
import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lsassist.audit.schema import canonical_bytes as _audit_canonical_bytes
from lsassist.audit.schema import record_hash as _audit_record_hash

__all__ = [
    "CheckpointEntry",
    "CheckpointManifest",
    "ExclusionReason",
    "TriggerKind",
    "canonical_bytes",
    "manifest_digest",
]

#: Bare lowercase hex, 64 characters — the same spelling §6.5's evidence uses,
#: deliberately WITHOUT the ``sha256:`` prefix that §14.1's chain values carry.
#: Mixing the two conventions in one system is how a comparison silently fails.
_SHA256_HEX: Final = re.compile(r"\A[0-9a-f]{64}\Z")

#: A git tree hash: 40 hex characters. Widened deliberately to 64 as well, so a
#: future SHA-256 git repository does not require a schema change.
_TREE_HASH: Final = re.compile(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


class TriggerKind(StrEnum):
    """§14.4's four snapshot triggers, and no fifth.

    "before ``fs.write``/``fs.patch`` on existing file; before ``test.run``
    (lightweight: manifest of mtimes); manual ``checkpoint create``". The
    enumeration is closed because an unrecognised trigger in a stored manifest is
    a checkpoint nobody can explain the existence of.
    """

    PRE_WRITE = "pre_write"
    PRE_PATCH = "pre_patch"
    PRE_TEST = "pre_test"
    MANUAL = "manual"


class ExclusionReason(StrEnum):
    """Why a file present in the workspace was not stored.

    §14.4 names the size rule ("Large binaries > 50 MB excluded by default"); the
    binary case is separated because the two have different remedies — a size
    limit is tunable, an unstorable file is not.
    """

    OVERSIZE = "oversize"
    BINARY = "binary"


class CheckpointEntry(BaseModel):
    """One file the snapshot has something to say about."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: Workspace-RELATIVE, POSIX separators. Relative because the manifest is
    #: joined to the workspace at restore time: an absolute or climbing path
    #: would make the manifest itself the instrument of an escape, and the
    #: rollback would faithfully restore to wherever it pointed.
    path: str = Field(min_length=1, max_length=4096)
    size: int = Field(ge=0)
    mtime_ns: int = Field(ge=0)
    #: ``None`` exactly when the file was excluded.
    sha256: str | None = None
    #: ``None`` exactly when the file was stored.
    excluded_because: ExclusionReason | None = None

    @field_validator("path")
    @classmethod
    def _relative_and_contained(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("path contains a NUL byte")
        if posixpath.isabs(value) or value.startswith("\\"):
            raise ValueError(f"path {value!r} must be workspace-relative")
        if any(segment == ".." for segment in value.replace("\\", "/").split("/")):
            raise ValueError(f"path {value!r} contains a '..' component")
        return value

    @field_validator("sha256")
    @classmethod
    def _bare_lowercase_hex(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256_HEX.match(value):
            raise ValueError("sha256 must be 64 lowercase hex characters, unprefixed")
        return value

    @model_validator(mode="after")
    def _stored_xor_excluded(self) -> CheckpointEntry:
        stored = self.sha256 is not None
        excluded = self.excluded_because is not None
        if stored and excluded:
            raise ValueError("an entry carrying a digest was stored; it cannot also be excluded")
        if not stored and not excluded:
            raise ValueError("an entry with no digest must say why it was excluded")
        return self


class CheckpointManifest(BaseModel):
    """The complete §14.4 claim for one snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    checkpoint_id: str = Field(min_length=1, max_length=128)
    #: Canonical absolute path of the workspace this snapshot covers.
    workspace: str = Field(min_length=1)
    trigger: TriggerKind
    created_at: datetime
    entries: tuple[CheckpointEntry, ...]
    #: The shadow-git tree the objects live under.
    tree: str

    @field_validator("workspace")
    @classmethod
    def _absolute(cls, value: str) -> str:
        if not posixpath.isabs(value):
            raise ValueError(f"workspace {value!r} must be an absolute path")
        return value

    @field_validator("tree")
    @classmethod
    def _tree_hash(cls, value: str) -> str:
        if not _TREE_HASH.match(value):
            raise ValueError("tree must be a lowercase hex git object id")
        return value

    @field_validator("entries")
    @classmethod
    def _sorted_and_unique(
        cls, value: tuple[CheckpointEntry, ...]
    ) -> tuple[CheckpointEntry, ...]:
        """Sorted by path, one entry per path.

        Sorting here rather than trusting the caller makes the bytes a property
        of the CONTENT: two snapshots of the same tree must serialize identically
        or the digest stops meaning "this tree". A duplicate path is refused
        rather than de-duplicated because two claims about one file leave a
        rollback with no principled way to choose between them.
        """
        seen = [e.path for e in value]
        if len(set(seen)) != len(seen):
            raise ValueError("entries contain a duplicate path")
        return tuple(sorted(value, key=lambda e: e.path))

    def as_canonical_dict(self) -> dict[str, Any]:
        """The hashed shape: every field, nothing derived, nothing omitted.

        A field outside the digest is a field an attacker may rewrite without
        breaking it — the same argument §14.1 makes about its own records.
        """
        return {
            "checkpoint_id": self.checkpoint_id,
            "workspace": self.workspace,
            "trigger": self.trigger.value,
            "created_at": self.created_at.isoformat(),
            "tree": self.tree,
            "entries": [
                {
                    "path": e.path,
                    "size": e.size,
                    "mtime_ns": e.mtime_ns,
                    "sha256": e.sha256,
                    "excluded_because": (
                        e.excluded_because.value if e.excluded_because is not None else None
                    ),
                }
                for e in self.entries
            ],
        }


def canonical_bytes(manifest: CheckpointManifest) -> bytes:
    """Byte-stable serialization, delegated to §14.1's pinned spelling."""
    return _audit_canonical_bytes(manifest.as_canonical_dict())


def manifest_digest(manifest: CheckpointManifest) -> str:
    """``sha256:<hex>`` over :func:`canonical_bytes`."""
    return _audit_record_hash(manifest.as_canonical_dict())
