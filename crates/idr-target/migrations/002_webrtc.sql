CREATE TABLE IF NOT EXISTS webrtc_session_history (
    session_id TEXT PRIMARY KEY,
    result TEXT NOT NULL,
    turn_node_id TEXT,
    started_at INTEGER NOT NULL,
    ended_at INTEGER
);

CREATE TABLE IF NOT EXISTS turn_probe_cache (
    probe_generation INTEGER PRIMARY KEY,
    probed_at INTEGER NOT NULL,
    json_blob TEXT NOT NULL
);
