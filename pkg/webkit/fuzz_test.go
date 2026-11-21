package webkit

import (
	"errors"
	"testing"

	"github.com/0x4d31/wkparse/pkg/persist"
)

// Fuzz targets for every parser that consumes attacker-influenced bytes. The parsers must
// never panic; a recovered ErrParserPanic still counts as a bug.
//
//	go test ./pkg/webkit -run '^$' -fuzz FuzzParseNetworkCacheRecordBytes -fuzztime 60s

func networkCacheSeeds(f *testing.F) {
	salt := []byte("01234567")
	der := makeSelfSignedDER(f, "seed.test", []string{"seed.test"})
	for _, v := range []uint32{16, 17, 18} {
		data, _ := buildNetworkCacheFile(f, v, salt, "https://seed.test/a.js", []byte("var a=1;"), true, "https://seed.test/b", der, true)
		f.Add(data)
		blob, _ := buildNetworkCacheFile(f, v, salt, "https://seed.test/c.js", []byte("var c=1;"), false, "", nil, false)
		f.Add(blob)
	}
	f.Add(buildMetaOnly("Resource", func(off int) uint64 { return ^uint64(0) - uint64(off) + 2 }, 0, true))
	f.Add(buildMetaOnly("SubResources", func(int) uint64 { return 0 }, ^uint64(0), true))
	f.Add([]byte{})
}

func FuzzParseNetworkCacheRecordBytes(f *testing.F) {
	networkCacheSeeds(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, err := ParseNetworkCacheRecordBytes("fuzz/record", raw, []byte("01234567"), BodyOptions{MaxDecompress: 1 << 16})
		if errors.Is(err, ErrParserPanic) {
			t.Fatalf("parser panicked: %v", err)
		}
	})
}

func FuzzParseCacheStorageRecordBytes(f *testing.F) {
	networkCacheSeeds(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, err := ParseCacheStorageRecordBytes("fuzz/record", raw, []byte("01234567"), BodyOptions{MaxDecompress: 1 << 16})
		if errors.Is(err, ErrParserPanic) {
			t.Fatalf("parser panicked: %v", err)
		}
	})
}

func FuzzDecodeClientOrigin(f *testing.F) {
	e := persist.NewEncoder()
	e.String("https")
	e.String("top.test")
	e.Bool(false)
	e.String("https")
	e.String("frame.test")
	e.Bool(true)
	e.Uint16(8443)
	f.Add(e.Bytes())
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeClientOrigin(raw)
	})
}

func FuzzAnalyzeBody(f *testing.F) {
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}, "gzip")
	f.Add([]byte("plain text"), "br")
	f.Add([]byte{0x78, 0x9c, 0x01}, "deflate")
	f.Fuzz(func(t *testing.T, raw []byte, enc string) {
		bi := AnalyzeBody("inline", raw, enc, "", BodyOptions{MaxDecompress: 1 << 16})
		if bi.DecodedSize > 1<<16 && bi.Decompressed {
			t.Fatalf("decoded size %d exceeds cap", bi.DecodedSize)
		}
	})
}
