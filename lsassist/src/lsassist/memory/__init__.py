"""SQLite-backed durable memory primitives (SPEC §10)."""

from lsassist.memory.fetch_body import (
    FETCH_BODY_LIMIT,
    FetchBody,
    FetchBodyStore,
    FetchBodyStoreError,
)
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
    "FETCH_BODY_LIMIT",
    "MIGRATIONS",
    "FetchBody",
    "FetchBodyStore",
    "FetchBodyStoreError",
    "MemoryCorruptedError",
    "MemorySecurityError",
    "MemoryStoreError",
    "UnknownSchemaVersionError",
    "get_schema_version",
    "migrate",
    "open_memory",
]
