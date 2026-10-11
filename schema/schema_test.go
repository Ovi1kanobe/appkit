package schema_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Ovi1kanobe/appkit/schema"
)

// TestSchema checks Open's settings, that migrations apply once, and that
// unsafe sets are refused.
func TestSchema(t *testing.T) {
	ctx := context.Background()
	database, err := schema.Open(ctx, filepath.Join(t.TempDir(), "app.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for pragma, want := range map[string]string{"foreign_keys": "1", "busy_timeout": "5000", "journal_mode": "wal"} {
		var value string
		if err := database.QueryRow("PRAGMA " + pragma).Scan(&value); err != nil || value != want {
			t.Fatalf("%s = %q, want %q (%v)", pragma, value, want, err)
		}
	}
	if _, err := schema.Open(ctx, "file:x.sqlite?mode=memory"); err == nil {
		t.Fatal("Open accepted a URI")
	}
	first := fstest.MapFS{"migrations/001_initial.sql": {Data: []byte(`CREATE TABLE things (id INTEGER PRIMARY KEY)`)}}
	second := fstest.MapFS{
		"migrations/001_initial.sql": first["migrations/001_initial.sql"],
		"migrations/002_name.sql":    {Data: []byte(`ALTER TABLE things ADD COLUMN name TEXT`)},
	}
	for _, files := range []fstest.MapFS{first, first, second, second} {
		if err := schema.Migrate(ctx, database, "things", files); err != nil {
			t.Fatal(err)
		}
	}
	for name, test := range map[string]struct {
		system string
		files  fstest.MapFS
		want   string
	}{
		"newer database": {"things", first, "only knows 1"},
		"duplicate":      {"other", fstest.MapFS{"migrations/001_a.sql": {}, "migrations/001_b.sql": {}}, "share version"},
		"unnumbered":     {"other", fstest.MapFS{"migrations/initial.sql": {}}, "numeric prefix"},
		"unsafe name":    {"x; DROP", first, "lowercase"},
	} {
		if err := schema.Migrate(ctx, database, test.system, test.files); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}
