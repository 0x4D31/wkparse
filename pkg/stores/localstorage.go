package stores

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// LocalStorageEntry represents one key/value row in WebKit LocalStorage ItemTable.
type LocalStorageEntry struct {
	Path   string `json:"path"`
	Origin string `json:"origin,omitempty"`
	Key    string `json:"key"`
	Value  string `json:"value"`
}

// ParseLocalStorage parses WebKit localstorage.sqlite3 or legacy *.localstorage databases.
func ParseLocalStorage(dbPath string) ([]LocalStorageEntry, error) {
	db, closeFn, err := openForensicSQLite(dbPath)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	if !tableExists(db, "ItemTable") {
		return nil, fmt.Errorf("ItemTable not found in %s", dbPath)
	}
	rows, err := db.Query(`SELECT key, value, typeof(value) FROM ItemTable`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []LocalStorageEntry
	var rowError error
	var skipped int
	for rows.Next() {
		var k, typ sql.NullString
		var raw []byte
		if err := rows.Scan(&k, &raw, &typ); err != nil {
			skipped++
			if rowError == nil {
				rowError = err
			}
			continue
		}
		val := decodeWebKitStorageValue(raw)
		if typ.String == "text" {
			val = decodeTextValue(raw)
		}
		out = append(out, LocalStorageEntry{
			Path:  dbPath,
			Key:   k.String,
			Value: val,
		})
	}
	if rowError != nil {
		rowError = fmt.Errorf("skipped %d LocalStorage rows after decode errors (first: %w)", skipped, rowError)
	}
	return out, errors.Join(rowError, rows.Err())
}

func decodeTextValue(raw []byte) string {
	if utf8.Valid(raw) {
		return string(raw)
	}
	return fmt.Sprintf("hex:%x", raw)
}

// decodeWebKitStorageValue decodes an ItemTable BLOB value. WebKit binds values with
// SQLiteStatement::bindBlob(String), which always writes the string's UTF-16 code units in host
// byte order (little-endian on Apple platforms), without a BOM, including for Latin-1 strings.
// Odd-length blobs cannot be UTF-16 and fall back to UTF-8 or hex.
func decodeWebKitStorageValue(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if len(raw)%2 == 0 {
		u16 := make([]uint16, len(raw)/2)
		for i := range u16 {
			u16[i] = binary.LittleEndian.Uint16(raw[i*2:])
		}
		return string(utf16.Decode(u16))
	}
	return decodeTextValue(raw)
}
