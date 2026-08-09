"""SQLite-backed durable memory primitives (SPEC §10)."""

from lsassist.memory.migrations import (
    CURRENT_SCHEMA_VERSION,
    MIGRATIONS,
    UnknownSchemaVersionError,
    get_schema_version,
    migrate,
)
from lsassist.memory.store import (
    MemoryCorruptedError,
    MemorySecurityError,
    MemoryStoreError,
    open_memory,
)

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "MIGRATIONS",
    "MemoryCorruptedError",
    "MemorySecurityError",
    "MemoryStoreError",
    "UnknownSchemaVersionError",
    "get_schema_version",
    "migrate",
    "open_memory",
]
