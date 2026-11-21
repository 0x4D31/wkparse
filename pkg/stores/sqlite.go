// Package stores reads WebKit SQLite databases and Apple plist metadata
// in a strictly read-only, WAL-preserving forensic manner.
package stores

import (
	"database/sql"
	"github.com/0x4d31/wkparse/internal/evidence"
	"io"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// openForensicSQLite copies dbPath (and sibling -wal/-shm files if present) into a private
// temporary directory before opening so evidence files are never modified while uncheckpointed
// WAL transactions remain fully visible.
func openForensicSQLite(dbPath string) (*sql.DB, func(), error) {
	return OpenSQLiteSnapshot(dbPath)
}

// OpenSQLiteSnapshot opens a private copy, including available WAL sidecars.
func OpenSQLiteSnapshot(dbPath string) (*sql.DB, func(), error) {
	tmpDir, err := os.MkdirTemp("", "wkparse-sql-*")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }

	base := filepath.Base(dbPath)
	dst := filepath.Join(tmpDir, base)
	if err := copyFile(dbPath, dst); err != nil {
		cleanup()
		return nil, nil, err
	}
	for _, suf := range []string{"-wal", "-shm"} {
		src := dbPath + suf
		if _, err := os.Lstat(src); os.IsNotExist(err) {
			continue
		} else if err != nil {
			cleanup()
			return nil, nil, err
		}
		if err := copyFile(src, dst+suf); err != nil {
			cleanup()
			return nil, nil, err
		}
	}

	db, err := sql.Open("sqlite", dst)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return db, func() {
		_ = db.Close()
		cleanup()
	}, nil
}

func copyFile(src, dst string) error {
	in, err := evidence.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	cerr := out.Close()
	if err != nil {
		return err
	}
	return cerr
}

func tableExists(db *sql.DB, name string) bool {
	var found string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&found)
	return err == nil && found == name
}

func tableColumns(db *sql.DB, table string) map[string]bool {
	cols := make(map[string]bool)
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return cols
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err == nil {
			cols[name] = true
		}
	}
	return cols
}
