"""audit/ — hash-chained JSONL journal, redactor, rotation, reader (SPEC §14).

Today this package holds the §14.3 redactor engine, which is THE single
redactor in the codebase (I8): every sink that can carry a secret — audit
events, UI logs, prompt assembly, error messages, memory writes (§12.4) — goes
through :func:`~lsassist.audit.redactor.redact_for_audit`, and the §14.1
append-only hash-chained journal that carries them (T4.02). The reader and the
``lsassist audit show`` surface arrive in T4.03.
"""

from lsassist.audit.redactor import (
    CLASS_ENGINE_ERROR,
    AuditRedaction,
    RedactionHit,
    Redactor,
    RedactorError,
    redact_for_audit,
)
from lsassist.audit.schema import AuditEvent, AuditRecord, canonical_bytes, record_hash
from lsassist.audit.writer import (
    AuditRefusedError,
    AuditWriteError,
    AuditWriter,
    ChainStatus,
    ChainVerdict,
    verify_chain,
)

__all__ = [
    "CLASS_ENGINE_ERROR",
    "AuditEvent",
    "AuditRecord",
    "AuditRedaction",
    "AuditRefusedError",
    "AuditWriteError",
    "AuditWriter",
    "ChainStatus",
    "ChainVerdict",
    "RedactionHit",
    "Redactor",
    "RedactorError",
    "canonical_bytes",
    "record_hash",
    "redact_for_audit",
    "verify_chain",
]
