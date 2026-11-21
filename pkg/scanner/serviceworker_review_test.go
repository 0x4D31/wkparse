package scanner

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/0x4d31/wkparse/pkg/stores"
)

func TestGraphIncludesSameOriginWorkers(t *testing.T) {
	r := &Report{Containers: []ContainerReport{{Owner: "app", ServiceWorkers: []stores.ServiceWorkerRecord{{Origin: "https://example.test", TopOrigin: "https://example.test", ScriptURL: "https://example.test/sw.js"}}}}}
	finalizeReport(r)
	if len(r.Graph) != 1 || r.Graph[0].From != "https://example.test" || r.Graph[0].To != "https://example.test/sw.js" {
		t.Fatalf("missing registration: %+v", r.Graph)
	}
}

func TestScanRetainsServiceWorkersWithRowErrors(t *testing.T) {
	root := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(root, "ServiceWorkerRegistrations-8.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE Records (origin TEXT, scopeURL TEXT, scriptURL TEXT, lastUpdateCheckTime TEXT);
		INSERT INTO Records VALUES
		('https://first.test', '/', 'https://first.test/sw.js', '1'),
		('https://bad.test', '/', 'https://bad.test/sw.js', 'invalid'),
		('https://last.test', '/', 'https://last.test/sw.js', '2');`)
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("create fixture: %v, close: %v", err, closeErr)
	}
	report, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.ServiceWorkers != 2 || len(report.Anomalies) != 1 || report.Anomalies[0].Code != "artifact_parse_error" {
		t.Fatalf("workers=%d anomalies=%+v", report.Summary.ServiceWorkers, report.Anomalies)
	}
}
