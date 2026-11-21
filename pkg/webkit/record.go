package webkit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0x4d31/wkparse/internal/evidence"
)

// ErrParserPanic is wrapped by errors returned when a parser hits an unexpected runtime panic.
// Callers should treat it as "this artifact could not be parsed", not as a fatal scan error.
var ErrParserPanic = errors.New("parser panic")

// recoverAsError converts a panic in a parser into an ErrParserPanic-wrapped error so that one
// malformed or hostile artifact cannot abort an entire scan.
func recoverAsError(errp *error, path string) {
	if r := recover(); r != nil {
		*errp = fmt.Errorf("%w while decoding %s: %v", ErrParserPanic, filepath.Base(path), r)
	}
}

// headerBounds returns [start,end) of the record header using overflow-safe arithmetic.
func headerBounds(fileLen, offset int, size uint64) (int, int, bool) {
	if offset < 0 || offset > fileLen {
		return 0, 0, false
	}
	if size > uint64(fileLen-offset) {
		return 0, 0, false
	}
	return offset, offset + int(size), true
}

// inlineBodyEnd returns the end offset of an inline body that starts at hdrEnd.
func inlineBodyEnd(fileLen, hdrEnd int, size uint64) (int, bool) {
	if hdrEnd < 0 || hdrEnd > fileLen || size > uint64(fileLen-hdrEnd) {
		return 0, false
	}
	return hdrEnd + int(size), true
}

func truncatedBodyAnomaly(bi *BodyInfo, path string) *Anomaly {
	if bi == nil || !bi.DecodeTruncated {
		return nil
	}
	return &Anomaly{
		Code:   "decompression_cap_reached",
		Detail: fmt.Sprintf("decoded output stopped at %d bytes (MaxDecompress); hash, snippet, matches and export cover only this prefix", bi.DecodedSize),
		Path:   path,
	}
}

func appendExportError(dst *[]Anomaly, bi BodyInfo, path string) {
	if bi.ExportError != "" {
		*dst = append(*dst, Anomaly{Code: "export_error", Detail: bi.ExportError, Path: path})
	}
}

func readExternal(path, hash string) ([]byte, error) {
	b, err := evidence.ReadFile(path + "-blob")
	if err == nil {
		return b, nil
	}
	root := findNetworkCacheRoot(path)
	if root != "" && hash != "" {
		dir := filepath.Join(root, "Blobs")
		fi, derr := os.Lstat(dir)
		if derr == nil && !fi.IsDir() {
			return nil, fmt.Errorf("%s is not a regular directory", dir)
		}
		if derr != nil && !os.IsNotExist(derr) {
			return nil, derr
		}
		if derr == nil {
			v, e := evidence.ReadFile(filepath.Join(dir, hash))
			if e == nil || !os.IsNotExist(e) {
				return v, e
			}
		}
	}
	return nil, err
}

func blobError(err error, path string) Anomaly {
	code := "blob_read_error"
	if os.IsNotExist(err) {
		code = "missing_blob"
	}
	return Anomaly{Code: code, Detail: err.Error(), Path: path}
}
