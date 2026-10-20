CREATE TABLE latchkey_devices (
    user_id TEXT NOT NULL REFERENCES latchkey_users (id) ON DELETE CASCADE,
    hash BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, hash)
);

CREATE INDEX latchkey_devices_seen ON latchkey_devices (last_seen_at);
