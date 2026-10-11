CREATE TABLE email_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    api_key BLOB NOT NULL,
    last_four TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
