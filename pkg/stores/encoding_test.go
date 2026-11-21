package stores

import (
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	_ "modernc.org/sqlite"
)

func TestSnapshotRejectsUnreadableSidecar(t *testing.T) {
	p := filepath.Join(t.TempDir(), "store")
	if err := os.WriteFile(p, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p+"-wal", 0700); err != nil {
		t.Fatal(err)
	}
	if _, closeDB, err := OpenSQLiteSnapshot(p); err == nil {
		closeDB()
		t.Fatal("missing snapshot coverage error")
	}
}

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

// WebKit's SQLiteStatement::bindBlob(String) always writes UTF-16 code units, so non-Latin
// values (no zero high bytes) must still decode as text rather than hex.
func TestLocalStorageNonLatinAndTextValues(t *testing.T) {
	p := filepath.Join(t.TempDir(), "localstorage.sqlite3")
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec(`CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB NOT NULL ON CONFLICT FAIL)`)
	_, _ = db.Exec(`INSERT INTO ItemTable VALUES ('cjk', ?), ('fa', ?), ('txt', 'plain utf8 text'), ('odd', X'010203')`,
		utf16LE("日本語テキスト"), utf16LE("سلام دنیا"))
	_ = db.Close()

	entries, err := ParseLocalStorage(p)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Key] = e.Value
	}
	want := map[string]string{"cjk": "日本語テキスト", "fa": "سلام دنیا", "txt": "plain utf8 text", "odd": "\x01\x02\x03"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestITPSchemaDriftAndEmptyStore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "observations.db")
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	// Older schema without several optional columns.
	_, _ = db.Exec(`CREATE TABLE ObservedDomains (domainID INTEGER PRIMARY KEY, registrableDomain TEXT, lastSeen REAL, hadUserInteraction INTEGER)`)
	_ = db.Close()

	st, err := ParseITPDatabase(p)
	if err != nil {
		t.Fatalf("schema drift should not fail the store: %v", err)
	}
	if st.Domains == nil || len(st.Domains) != 0 {
		t.Fatalf("empty store should have a non-nil empty Domains slice, got %#v", st.Domains)
	}
	if len(st.Warnings) == 0 {
		t.Fatal("expected a warning listing missing columns")
	}
}
