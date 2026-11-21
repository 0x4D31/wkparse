package persist

import (
	"math"
	"testing"
	"time"
)

func TestRoundTripAndChecksum(t *testing.T) {
	enc := NewEncoder()
	enc.Bool(true)
	enc.Uint8(0xAB)
	enc.Uint16(0x1234)
	enc.Int16(200)
	enc.Uint32(18)
	enc.Int32(-42)
	enc.Uint64(999999999)
	enc.Int64(-1)
	enc.Float64(1750000000.5)
	enc.String("https://cdn.example.test/rce_loader.js")
	enc.String("café") // Latin-1 (>0x7F, <=0xFF)
	enc.String("日本語🚀") // UTF-16LE with surrogate pair
	enc.NullString()
	enc.FixedBytes([]byte{1, 2, 3, 4})
	enc.EncodeChecksum()

	dec := NewDecoder(enc.Bytes())
	if v, err := dec.Bool(); err != nil || !v {
		t.Fatalf("Bool: got %v, %v", v, err)
	}
	if v, err := dec.Uint8(); err != nil || v != 0xAB {
		t.Fatalf("Uint8: got %x, %v", v, err)
	}
	if v, err := dec.Uint16(); err != nil || v != 0x1234 {
		t.Fatalf("Uint16: got %x, %v", v, err)
	}
	if v, err := dec.Int16(); err != nil || v != 200 {
		t.Fatalf("Int16: got %d, %v", v, err)
	}
	if v, err := dec.Uint32(); err != nil || v != 18 {
		t.Fatalf("Uint32: got %d, %v", v, err)
	}
	if v, err := dec.Int32(); err != nil || v != -42 {
		t.Fatalf("Int32: got %d, %v", v, err)
	}
	if v, err := dec.Uint64(); err != nil || v != 999999999 {
		t.Fatalf("Uint64: got %d, %v", v, err)
	}
	if v, err := dec.Int64(); err != nil || v != -1 {
		t.Fatalf("Int64: got %d, %v", v, err)
	}
	if ts, raw, err := dec.WallTime(); err != nil || raw != 1750000000.5 || ts.Year() != 2025 {
		t.Fatalf("WallTime: got %v (%v), %v", ts, raw, err)
	}
	for _, want := range []string{"https://cdn.example.test/rce_loader.js", "café", "日本語🚀"} {
		got, isNull, err := dec.String()
		if err != nil || isNull || got != want {
			t.Fatalf("String: got %q (null=%v, err=%v), want %q", got, isNull, err, want)
		}
	}
	if got, isNull, err := dec.String(); err != nil || !isNull || got != "" {
		t.Fatalf("NullString: got %q, null=%v, err=%v", got, isNull, err)
	}
	if got, err := dec.FixedBytes(4); err != nil || len(got) != 4 || got[3] != 4 {
		t.Fatalf("FixedBytes: got %x, %v", got, err)
	}
	ok, err := dec.VerifyChecksum()
	if err != nil || !ok {
		t.Fatalf("VerifyChecksum: ok=%v, err=%v", ok, err)
	}
	if dec.Remaining() != 0 {
		t.Fatalf("Remaining = %d, want 0", dec.Remaining())
	}

	// Tamper a single byte and confirm checksum fails.
	tampered := append([]byte(nil), enc.Bytes()...)
	tampered[0] ^= 0x01
	bad := NewDecoder(tampered)
	_, _ = bad.Bool()
	_, _ = bad.Uint8()
	_, _ = bad.Uint16()
	_, _ = bad.Int16()
	_, _ = bad.Uint32()
	_, _ = bad.Int32()
	_, _ = bad.Uint64()
	_, _ = bad.Int64()
	_, _, _ = bad.WallTime()
	_, _, _ = bad.String()
	_, _, _ = bad.String()
	_, _, _ = bad.String()
	_, _, _ = bad.String()
	_, _ = bad.FixedBytes(4)
	if ok, err := bad.VerifyChecksum(); err != nil || ok {
		t.Fatalf("expected checksum mismatch on tampered buffer, got ok=%v err=%v", ok, err)
	}
}

func TestHostileStringLengthDoesNotPanic(t *testing.T) {
	enc := NewEncoder()
	enc.Uint32(0x7FFFFFFF)
	enc.Bool(true)
	dec := NewDecoder(enc.Bytes())
	if _, _, err := dec.String(); err == nil {
		t.Fatal("expected truncation error for huge string length")
	}
}

func TestWallTimeZero(t *testing.T) {
	if got := WallTimeFromSeconds(0); !got.Equal(time.Time{}) {
		t.Fatalf("expected zero time, got %v", got)
	}
	if got := WallTimeFromSeconds(1e30); !got.IsZero() {
		t.Fatalf("expected out-of-range WallTime to return zero, got %v", got)
	}
	if got := SanitizeFloat(math.NaN()); got != 0 {
		t.Fatalf("expected SanitizeFloat(NaN) == 0, got %v", got)
	}
}
