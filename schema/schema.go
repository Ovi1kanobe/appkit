// Package schema applies a system's embedded SQL migrations. Each system owns
// its migrations and records them in its own <system>_migrations table.
package schema

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var systemName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Migrate applies the files in files named migrations/NNN_description.sql that
// are newer than the version recorded for system, in order, each in its own
// transaction. It refuses a database migrated by a newer binary.
func Migrate(ctx context.Context, database *sql.DB, system string, files fs.FS) error {
	if !systemName.MatchString(system) {
		return fmt.Errorf("schema: system name %q must be lowercase letters, digits, and underscores", system)
	}
	migrations, err := read(files)
	if err != nil {
		return fmt.Errorf("schema: %s: %w", system, err)
	}
	table := system + "_migrations"
	if _, err := database.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+table+` (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("schema: %s: create %s: %w", system, table, err)
	}
	var current int
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM `+table).Scan(&current); err != nil {
		return fmt.Errorf("schema: %s: read version: %w", system, err)
	}
	latest := 0
	if len(migrations) > 0 {
		latest = migrations[len(migrations)-1].version
	}
	if current > latest {
		return fmt.Errorf("schema: %s: database is at version %d but this binary only knows %d; roll back the binary and database together", system, current, latest)
	}
	for _, migration := range migrations {
		if migration.version <= current {
			continue
		}
		if err := apply(ctx, database, table, migration); err != nil {
			return fmt.Errorf("schema: %s: %s: %w", system, migration.name, err)
		}
	}
	return nil
}

type migration struct {
	version int
	name    string
	script  string
}

// read returns the migrations sorted by version, rejecting unnumbered or duplicate files.
func read(files fs.FS) ([]migration, error) {
	names, err := fs.Glob(files, "migrations/*.sql") // sorted by name
	if err != nil {
		return nil, err
	}
	var migrations []migration
	seen := make(map[int]string)
	for _, path := range names {
		name := strings.TrimPrefix(path, "migrations/")
		version, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil || version < 1 {
			return nil, fmt.Errorf("migration %s needs a positive numeric prefix such as 001_", name)
		}
		if previous, exists := seen[version]; exists {
			return nil, fmt.Errorf("migrations %s and %s share version %d", previous, name, version)
		}
		seen[version] = name
		script, err := fs.ReadFile(files, path)
		if err != nil {
			return nil, err
		}
		migrations = append(migrations, migration{version: version, name: name, script: string(script)})
	}
	for index := 1; index < len(migrations); index++ {
		if migrations[index].version < migrations[index-1].version {
			return nil, fmt.Errorf("migration %s must be zero-padded to sort after %s", migrations[index-1].name, migrations[index].name)
		}
	}
	return migrations, nil
}

func apply(ctx context.Context, database *sql.DB, table string, migration migration) error {
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, migration.script); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO `+table+` (version, applied_at) VALUES (?, ?)`, migration.version, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	return transaction.Commit()
}
