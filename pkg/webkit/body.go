package webkit

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
)

const (
	defaultMaxDecompress int64 = 32 << 20 // 32 MiB cap against decompression bombs
	defaultSnippetBytes  int   = 256
)

// ComputeSaltedSHA1 matches WebKit NetworkCache/CacheStorage SHA1(salt || data).
func ComputeSaltedSHA1(salt, data []byte) [20]byte {
	h := sha1.New()
	h.Write(salt)
	h.Write(data)
	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out
}

// AnalyzeBody hashes, safely decompresses, sniffs MIME, optionally regex-matches and exports a body.
func AnalyzeBody(storage string, raw []byte, contentEncoding, declaredMIME string, opts BodyOptions) BodyInfo {
	maxOut := opts.MaxDecompress
	if maxOut <= 0 {
		maxOut = defaultMaxDecompress
	}
	snipLen := opts.SnippetBytes
	if snipLen <= 0 {
		snipLen = defaultSnippetBytes
	}

	rawSum := sha256.Sum256(raw)
	info := BodyInfo{
		Storage:         storage,
		RawSize:         int64(len(raw)),
		ContentEncoding: contentEncoding,
		RawSHA256:       hex.EncodeToString(rawSum[:]),
	}

	payload := raw
	if len(raw) > 0 {
		if dec, ok, truncated := tryDecompress(raw, contentEncoding, maxOut); ok {
			payload = dec
			info.Decompressed = true
			info.DecodedSize = int64(len(dec))
			decSum := sha256.Sum256(dec)
			if truncated {
				// The hash covers only the first maxOut bytes; never present it as the full payload hash.
				info.DecodeTruncated = true
				info.DecodedPrefixSHA256 = hex.EncodeToString(decSum[:])
			} else {
				info.DecodedSHA256 = hex.EncodeToString(decSum[:])
			}
		} else {
			info.DecodedSize = int64(len(raw))
			info.DecodedSHA256 = info.RawSHA256
		}
	}

	if len(payload) > 0 {
		info.DetectedMIME = sniffMIME(payload, declaredMIME)
		if isTextLike(info.DetectedMIME, payload) {
			info.Snippet = makeSnippet(payload, snipLen)
		}
		if opts.Match != nil {
			hits := opts.Match.FindAllString(string(payload), 10)
			if len(hits) > 0 {
				info.Matches = uniqueStrings(hits)
			}
		}
		if opts.ExportDir != "" && (!opts.ExportMatchesOnly || len(info.Matches) > 0) {
			var err error
			info.ExportPath, err = exportPayload(opts.ExportDir, info, payload)
			if err != nil {
				info.ExportError = err.Error()
			}
		}
	}

	return info
}

// exportPayload writes a recovered body to dir and returns its path, or "" on failure.
// Files are named <sha256>.<type>.bin to reduce accidental opening of recovered HTML/JS.
// Files are written owner-only (0600).
func exportPayload(dir string, info BodyInfo, payload []byte) (string, error) {
	name := info.DecodedSHA256
	if info.DecodeTruncated {
		name = info.DecodedPrefixSHA256 + ".partial"
	}
	if name == "" {
		return "", fmt.Errorf("missing export digest")
	}
	ext := extForMIME(info.DetectedMIME)
	if ext == ".bin" {
		ext = ""
	}
	target := filepath.Join(dir, name+ext+".bin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() || (runtime.GOOS != "windows" && fi.Mode().Perm()&0002 != 0) {
		return "", fmt.Errorf("export directory must be a real directory not world-writable: %s", dir)
	}
	tmp, err := os.CreateTemp(dir, ".wkparse-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	_, writeErr := tmp.Write(payload)
	closeErr := tmp.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	// Link publishes a complete file without following or replacing an existing destination.
	if err := os.Link(tmp.Name(), target); err != nil {
		if !os.IsExist(err) {
			return "", err
		}
		fi, err := os.Lstat(target)
		if err != nil {
			return "", err
		}
		if !fi.Mode().IsRegular() || fi.Size() != int64(len(payload)) || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0600) {
			return "", fmt.Errorf("refusing conflicting export: %s", target)
		}
		f, err := os.Open(target)
		if err != nil {
			return "", err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", err
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != strings.TrimSuffix(name, ".partial") {
			return "", fmt.Errorf("existing export has a different digest: %s", target)
		}
	}
	return target, nil
}

// tryDecompress returns (decoded, ok, truncated). truncated is true when output hit maxBytes.
func tryDecompress(raw []byte, encoding string, maxBytes int64) ([]byte, bool, bool) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if enc == "" && len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		enc = "gzip"
	}
	switch enc {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, false, false
		}
		defer gr.Close()
		out, trunc, err := readBounded(gr, maxBytes)
		return out, err == nil, trunc
	case "br":
		// WebKit/CFNetwork often stores bodies already decoded while keeping the
		// original Content-Encoding header; avoid feeding plaintext into magicless Brotli.
		if looksAlreadyText(raw) {
			return nil, false, false
		}
		out, trunc, err := readBounded(brotli.NewReader(bytes.NewReader(raw)), maxBytes)
		return out, err == nil, trunc
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			defer zr.Close()
			if out, trunc, err := readBounded(zr, maxBytes); err == nil {
				return out, true, trunc
			}
		}
		if looksAlreadyText(raw) {
			return nil, false, false
		}
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		out, trunc, err := readBounded(fr, maxBytes)
		return out, err == nil, trunc
	default:
		return nil, false, false
	}
}

// readBounded reads at most limit bytes and reports whether more data was available.
func readBounded(r io.Reader, limit int64) ([]byte, bool, error) {
	if limit < 0 {
		return nil, false, fmt.Errorf("negative decompression limit")
	}
	readCap := limit
	if readCap < math.MaxInt64 {
		readCap++
	}
	out, err := io.ReadAll(io.LimitReader(r, readCap))
	if err != nil {
		return nil, false, err
	}
	if int64(len(out)) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

func looksAlreadyText(b []byte) bool {
	sample := b
	if len(sample) > 512 {
		sample = sample[:512]
		// Back off if the 512-byte cut landed mid-UTF-8 rune.
		for len(sample) > 0 && !utf8.Valid(sample) && 512-len(sample) < 4 {
			sample = sample[:len(sample)-1]
		}
	}
	if len(sample) == 0 || !utf8.Valid(sample) {
		return false
	}
	printable, total := 0, 0
	for _, r := range string(sample) {
		total++
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			printable++
		}
	}
	return total > 0 && printable*100 >= total*95
}

func sniffMIME(b []byte, declared string) string {
	if len(b) >= 4 && bytes.Equal(b[:4], []byte{0x00, 'a', 's', 'm'}) {
		return "application/wasm"
	}
	if declared != "" {
		return strings.ToLower(strings.TrimSpace(strings.Split(declared, ";")[0]))
	}
	return strings.Split(http.DetectContentType(b), ";")[0]
}

func isTextLike(mime string, b []byte) bool {
	if strings.HasPrefix(mime, "text/") ||
		strings.Contains(mime, "javascript") ||
		strings.Contains(mime, "json") ||
		strings.Contains(mime, "xml") ||
		strings.Contains(mime, "ecmascript") {
		return true
	}
	sample := b
	if len(sample) > 512 {
		sample = sample[:512]
	}
	return utf8.Valid(sample) && !bytes.ContainsRune(sample, 0)
}

func makeSnippet(b []byte, maxLen int) string {
	if len(b) > maxLen {
		b = b[:maxLen]
	}
	s := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, string(b))
	return strings.TrimSpace(s)
}

func extForMIME(mime string) string {
	switch mime {
	case "application/javascript", "text/javascript", "application/x-javascript":
		return ".js"
	case "text/html":
		return ".html"
	case "application/json":
		return ".json"
	case "application/wasm":
		return ".wasm"
	case "text/css":
		return ".css"
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "image/webp":
		return ".webp"
	case "image/gif":
		return ".gif"
	default:
		return ".bin"
	}
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
