package stores

import (
	"os"
	"path/filepath"
	"testing"

	"howett.net/plist"
)

func TestHSTSPreservesSeparateSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "HSTS.plist")
	data, err := plist.Marshal(map[string]any{
		"session-a": map[string]any{"example.test": map[string]any{"Expiry": 100.0, "Include Subdomains": true}},
		"session-b": map[string]any{"example.test": map[string]any{"Expiry": 200.0, "Include Subdomains": false}},
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := ParseHSTS(path)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	if rows[0].Session != "session-a" || rows[1].Session != "session-b" || !rows[0].IncludeSubdomains || rows[1].IncludeSubdomains || rows[0].Expiry.Equal(*rows[1].Expiry) {
		t.Fatalf("lost session policy: %+v", rows)
	}
}
