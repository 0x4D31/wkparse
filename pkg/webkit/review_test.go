package webkit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0x4d31/wkparse/pkg/persist"
)

func TestExternalBodySizeWithoutSalt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record")
	if err := os.WriteFile(path+"-blob", []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	raw := buildMetaOnly("Resource", func(int) uint64 { return 0 }, 100, false)
	nc, err := ParseNetworkCacheRecordBytes(path, raw, nil, BodyOptions{})
	if err != nil || !hasCode(nc.Anomalies, "body_size_mismatch") {
		t.Fatalf("NetworkCache did not flag wrong-size blob: %+v, %v", nc, err)
	}
	cs, err := ParseCacheStorageRecordBytes(path, raw, nil, BodyOptions{})
	if err != nil || !hasCode(cs.Anomalies, "body_size_mismatch") {
		t.Fatalf("CacheStorage did not flag wrong-size blob: %+v, %v", cs, err)
	}
}

func TestSubresourcesRejectsTrailingHeaderBytes(t *testing.T) {
	e := persist.NewEncoder()
	e.Uint64(0)
	e.EncodeChecksum()
	if _, ok, err := decodeSubresourcesHeader(e.Bytes()); err != nil || !ok {
		t.Fatalf("clean header: %v", err)
	}
	if _, ok, err := decodeSubresourcesHeader(append(e.Bytes(), 1)); err != nil || ok {
		t.Fatalf("trailing byte accepted: ok=%v err=%v", ok, err)
	}
}

// A UTF-8 rune cut by the sniffing window must not hide an already decoded body.
func TestAlreadyTextSplitRune(t *testing.T) {
	body := make([]byte, 0, 1024)
	for i := 0; i < 511; i++ {
		body = append(body, 'a')
	}
	body = append(body, []byte("€")...)
	for len(body) < 1024 {
		body = append(body, 'b')
	}
	if !looksAlreadyText(body) {
		t.Fatal("text with a split UTF-8 rune was classified as compressed data")
	}
}
