-- SQLite cannot add a NOT NULL UNIQUE column without a default to a table that
-- has rows, so the table is rebuilt. Each existing note gets a request id made
-- from its own id, which no client sends, since clients send UUIDs.
CREATE TABLE notes_rebuilt (
    id INTEGER PRIMARY KEY,
    text TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE
);
INSERT INTO notes_rebuilt (id, text, created_by, created_at, updated_by, updated_at, request_id)
SELECT id, text, created_by, created_at, updated_by, updated_at, 'before-request-ids-' || id FROM notes;
DROP TABLE notes;
ALTER TABLE notes_rebuilt RENAME TO notes;
