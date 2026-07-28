CREATE TABLE IF NOT EXISTS relay_connection_history (
    relay_id TEXT PRIMARY KEY,
    last_ipv4 TEXT,
    last_ipv6 TEXT,
    last_port INTEGER NOT NULL,
    last_success_family INTEGER,
    last_connected_at INTEGER,
    last_disconnected_at INTEGER,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    retry_after INTEGER,
    descriptor_generation INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS presence_discovery_cache (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL,
    valid_until INTEGER NOT NULL,
    canonical_json BLOB NOT NULL,
    signature BLOB NOT NULL,
    fetched_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS processed_commands (
    command_id BLOB PRIMARY KEY,
    content_digest BLOB NOT NULL,
    result_code INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_processed_commands_expires_at
    ON processed_commands (expires_at);
