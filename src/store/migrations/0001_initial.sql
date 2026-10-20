CREATE TABLE latchkey_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    password_hash TEXT,
    active INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX latchkey_users_one_owner ON latchkey_users (role) WHERE role = 'owner';

CREATE TABLE latchkey_tokens (
    hash BLOB PRIMARY KEY,
    kind TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES latchkey_users (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX latchkey_tokens_user ON latchkey_tokens (user_id, kind, created_at);

CREATE TABLE latchkey_sessions (
    id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES latchkey_users (id) ON DELETE CASCADE,
    stage TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    method TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    authenticated_at INTEGER,
    ip TEXT,
    user_agent TEXT
);

CREATE INDEX latchkey_sessions_user ON latchkey_sessions (user_id, expires_at);

CREATE TABLE latchkey_totp (
    user_id TEXT PRIMARY KEY REFERENCES latchkey_users (id) ON DELETE CASCADE,
    secret BLOB,
    pending_secret BLOB,
    last_step INTEGER
);

CREATE TABLE latchkey_passkeys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES latchkey_users (id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,
    name TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);

CREATE INDEX latchkey_passkeys_user ON latchkey_passkeys (user_id);

CREATE TABLE latchkey_recovery_codes (
    user_id TEXT NOT NULL REFERENCES latchkey_users (id) ON DELETE CASCADE,
    hash BLOB NOT NULL,
    used_at INTEGER,
    PRIMARY KEY (user_id, hash)
);

CREATE TABLE latchkey_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    user_id TEXT,
    kind TEXT NOT NULL,
    detail TEXT,
    ip TEXT
);

CREATE INDEX latchkey_audit_user ON latchkey_audit (user_id, id);

CREATE TRIGGER latchkey_audit_no_update BEFORE UPDATE ON latchkey_audit
BEGIN
    SELECT RAISE(ABORT, 'latchkey_audit is append-only');
END;

CREATE TRIGGER latchkey_audit_no_delete BEFORE DELETE ON latchkey_audit
BEGIN
    SELECT RAISE(ABORT, 'latchkey_audit is append-only');
END;
