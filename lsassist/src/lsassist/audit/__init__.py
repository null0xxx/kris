"""audit/ — hash-chained JSONL journal, redactor, rotation, reader (SPEC §14).

Today this package holds the §14.3 redactor engine, which is THE single
redactor in the codebase (I8): every sink that can carry a secret — audit
events, UI logs, prompt assembly, error messages, memory writes (§12.4) — goes
through :func:`~lsassist.audit.redactor.redact_for_audit`. The writer, schema,
rotation and reader arrive in T4.02/T4.03.
"""

from lsassist.audit.redactor import (
    CLASS_ENGINE_ERROR,
    AuditRedaction,
    RedactionHit,
    Redactor,
    RedactorError,
    redact_for_audit,
)

__all__ = [
    "CLASS_ENGINE_ERROR",
    "AuditRedaction",
    "RedactionHit",
    "Redactor",
    "RedactorError",
    "redact_for_audit",
]
