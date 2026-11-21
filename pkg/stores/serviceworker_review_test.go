package stores

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestServiceWorkerWebKitStoredScopeAndOrigin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ServiceWorkerRegistrations-8.sqlite3")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE Records (key TEXT, origin TEXT, scopeURL TEXT, topOrigin TEXT, scriptURL TEXT);
	INSERT INTO Records VALUES ('key', 'https://example.test', '/app/', 'https_example.test_0', 'https://example.test/sw.js');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err := ParseServiceWorkers(path)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	r := rows[0]
	if r.ScopeURL != "https://example.test/app/" || r.TopOrigin != r.Origin || r.ScopePathRaw != "/app/" || r.TopOriginRaw != "https_example.test_0" {
		t.Fatalf("incorrect normalization: %+v", r)
	}
	for raw, want := range map[string]string{
		"https_example.test_8443": "https://example.test:8443",
		"https_example.test_443":  "https://example.test",
		"https_example.test_":     "https://example.test",
		"https_[%3A%3A1]_8443":    "https://[::1]:8443",
		"https://example.test":    "https://example.test",
		"invalid":                 "invalid",
	} {
		if got := workerTopOrigin(raw); got != want {
			t.Errorf("%q: got %q want %q", raw, got, want)
		}
	}
	if got := resolveWorkerScope("https://example.test", "//app/path"); got != "https://example.test//app/path" {
		t.Errorf("incorrect double-slash scope: %q", got)
	}
}

func TestServiceWorkerInvalidSchemaAndRowAreErrors(t *testing.T) {
	for _, schema := range []string{
		`CREATE TABLE Records (unrelated TEXT); INSERT INTO Records VALUES ('x');`,
		`CREATE TABLE Records (origin TEXT, scopeURL TEXT, scriptURL TEXT, lastUpdateCheckTime TEXT);
   INSERT INTO Records VALUES ('https://example.test', '/', 'https://example.test/sw.js', 'not-a-time');`,
	} {
		path := filepath.Join(t.TempDir(), "ServiceWorkerRegistrations-8.sqlite3")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(schema); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := ParseServiceWorkers(path); err == nil {
			t.Fatal("malformed worker database silently accepted")
		}
	}
}
