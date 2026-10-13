ALTER TABLE email_settings ADD COLUMN created_by TEXT NOT NULL DEFAULT '';
ALTER TABLE email_settings ADD COLUMN created_at TEXT NOT NULL DEFAULT '';
UPDATE email_settings SET created_by = updated_by, created_at = updated_at;
