ALTER TABLE notes RENAME COLUMN author_subject TO created_by;
ALTER TABLE notes ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';
ALTER TABLE notes ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
UPDATE notes SET updated_by = created_by, updated_at = created_at;
