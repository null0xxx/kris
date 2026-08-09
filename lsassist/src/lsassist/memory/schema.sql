PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;

CREATE TABLE prefs (
  id INTEGER PRIMARY KEY,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  provenance TEXT NOT NULL CHECK (provenance IN ('user','model_confirmed')),
  confidence REAL NOT NULL DEFAULT 1.0,
  sensitivity TEXT NOT NULL DEFAULT 'normal' CHECK (sensitivity IN ('normal','sensitive')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  ttl TEXT,
  UNIQUE (key)
);

CREATE TABLE episodic (
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL,
  task_summary TEXT NOT NULL,          -- redacted summary, never raw secrets
  verdict TEXT,
  evidence_refs TEXT,                   -- JSON array
  provenance TEXT NOT NULL DEFAULT 'kernel',
  created_at TEXT NOT NULL,
  archived INTEGER NOT NULL DEFAULT 0
);

CREATE VIRTUAL TABLE episodic_fts USING fts5(
  task_summary, content='episodic', content_rowid='id'
);

CREATE TABLE sessions (
  session_id TEXT PRIMARY KEY,
  state_json TEXT NOT NULL,             -- kernel state snapshot (no secrets)
  journal_seq INTEGER NOT NULL,
  checkpoint_ref TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT
);
