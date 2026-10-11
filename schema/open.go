package schema

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"

	"modernc.org/sqlite"
)

// connectionSettings apply to every new connection, so they survive reconnects.
var connectionSettings = []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL"}

// Open opens the application database at path with the settings every AppKit
// application uses: foreign keys, a five-second busy timeout, WAL, and one
// connection.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") || strings.ContainsAny(path, "?\x00") {
		return nil, errors.New("schema: the database needs a plain file path")
	}
	database := sql.OpenDB(connector{path: path})
	database.SetMaxOpenConns(1)
	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, err
	}
	return database, nil
}

type connector struct{ path string }

func (connector connector) Driver() driver.Driver { return &sqlite.Driver{} }

func (connector connector) Connect(ctx context.Context) (driver.Conn, error) {
	connection, err := (&sqlite.Driver{}).Open(connector.path)
	if err != nil {
		return nil, err
	}
	execer, ok := connection.(driver.ExecerContext)
	if !ok {
		connection.Close()
		return nil, errors.New("schema: the SQLite driver must support ExecContext")
	}
	for _, setting := range connectionSettings {
		if _, err := execer.ExecContext(ctx, setting, nil); err != nil {
			connection.Close()
			return nil, err
		}
	}
	return connection, nil
}
