// Package persist implements WebKit's WTF::Persistence binary codec
// (Source/WTF/wtf/persistence/Persistent{Encoder,Decoder,Coders}.cpp).
package persist

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// Type salts from WebKit Source/WTF/wtf/persistence/PersistentEncoder.h.
const (
	saltBool    uint32 = 3
	saltUint8   uint32 = 5
	saltUint16  uint32 = 7
	saltUint32  uint32 = 11
	saltUint64  uint32 = 13
	saltInt32   uint32 = 17
	saltInt64   uint32 = 19
	saltFloat32 uint32 = 23
	saltFloat64 uint32 = 29
	saltBytes   uint32 = 101
	saltInt16   uint32 = 103
)

const nullStringLen uint32 = 0xFFFFFFFF

var (
	ErrTruncated = errors.New("persist: unexpected end of buffer")
	ErrChecksum  = errors.New("persist: checksum mismatch")
)

// Decoder reads WTF::Persistence streams and maintains the running typed SHA-1 checksum.
type Decoder struct {
	buf  []byte
	pos  int
	sha1 hash.Hash
}

// NewDecoder creates a Decoder over raw bytes.
func NewDecoder(data []byte) *Decoder {
	return &Decoder{buf: data, sha1: sha1.New()}
}

func (d *Decoder) Offset() int    { return d.pos }
func (d *Decoder) Remaining() int { return len(d.buf) - d.pos }

func (d *Decoder) readRaw(n int) ([]byte, error) {
	if n < 0 || n > len(d.buf)-d.pos {
		return nil, ErrTruncated
	}
	b := d.buf[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}

func (d *Decoder) hashTyped(salt uint32, raw []byte) {
	var s [4]byte
	binary.LittleEndian.PutUint32(s[:], salt)
	d.sha1.Write(s[:])
	d.sha1.Write(raw)
}

func (d *Decoder) Bool() (bool, error) {
	b, err := d.readRaw(1)
	if err != nil {
		return false, err
	}
	d.hashTyped(saltBool, b)
	return b[0] != 0, nil
}

func (d *Decoder) Uint8() (uint8, error) {
	b, err := d.readRaw(1)
	if err != nil {
		return 0, err
	}
	d.hashTyped(saltUint8, b)
	return b[0], nil
}

func (d *Decoder) Uint16() (uint16, error) {
	b, err := d.readRaw(2)
	if err != nil {
		return 0, err
	}
	d.hashTyped(saltUint16, b)
	return binary.LittleEndian.Uint16(b), nil
}

func (d *Decoder) Int16() (int16, error) {
	b, err := d.readRaw(2)
	if err != nil {
		return 0, err
	}
	d.hashTyped(saltInt16, b)
	return int16(binary.LittleEndian.Uint16(b)), nil
}

func (d *Decoder) Uint32() (uint32, error) {
	b, err := d.readRaw(4)
	if err != nil {
		return 0, err
	}
	d.hashTyped(saltUint32, b)
	return binary.LittleEndian.Uint32(b), nil
}

func (d *Decoder) Int32() (int32, error) {
	b, err := d.readRaw(4)
	if err != nil {
		return 0, err
	}
	d.hashTyped(saltInt32, b)
	return int32(binary.LittleEndian.Uint32(b)), nil
}

func (d *Decoder) Uint64() (uint64, error) {
	b, err := d.readRaw(8)
	if err != nil {
		return 0, err
	}
	d.hashTyped(saltUint64, b)
	return binary.LittleEndian.Uint64(b), nil
}

func (d *Decoder) Int64() (int64, error) {
	b, err := d.readRaw(8)
	if err != nil {
		return 0, err
	}
	d.hashTyped(saltInt64, b)
	return int64(binary.LittleEndian.Uint64(b)), nil
}

func (d *Decoder) Float32() (float32, error) {
	b, err := d.readRaw(4)
	if err != nil {
		return 0, err
	}
	d.hashTyped(saltFloat32, b)
	return math.Float32frombits(binary.LittleEndian.Uint32(b)), nil
}

func (d *Decoder) Float64() (float64, error) {
	b, err := d.readRaw(8)
	if err != nil {
		return 0, err
	}
	d.hashTyped(saltFloat64, b)
	return math.Float64frombits(binary.LittleEndian.Uint64(b)), nil
}

// Enum reads any C++ enum encoded via WTF::Persistence (always uint64).
func (d *Decoder) Enum() (uint64, error) {
	return d.Uint64()
}

// FixedBytes reads n raw bytes and updates the checksum with saltBytes.
func (d *Decoder) FixedBytes(n int) ([]byte, error) {
	b, err := d.readRaw(n)
	if err != nil {
		return nil, err
	}
	d.hashTyped(saltBytes, b)
	out := make([]byte, n)
	copy(out, b)
	return out, nil
}

// SHA1Digest reads a 20-byte SHA1::Digest.
func (d *Decoder) SHA1Digest() ([20]byte, error) {
	var out [20]byte
	b, err := d.readRaw(20)
	if err != nil {
		return out, err
	}
	d.hashTyped(saltBytes, b)
	copy(out[:], b)
	return out, nil
}

// String decodes a WTF::String (Latin-1 or UTF-16LE). Returns isNull=true for 0xFFFFFFFF.
func (d *Decoder) String() (string, bool, error) {
	length, err := d.Uint32()
	if err != nil {
		return "", false, err
	}
	if length == nullStringLen {
		return "", true, nil
	}
	is8Bit, err := d.Bool()
	if err != nil {
		return "", false, err
	}
	if is8Bit {
		if uint64(length) > uint64(d.Remaining()) {
			return "", false, fmt.Errorf("%w: 8-bit string len %d > remaining %d", ErrTruncated, length, d.Remaining())
		}
		raw, err := d.readRaw(int(length))
		if err != nil {
			return "", false, err
		}
		d.hashTyped(saltBytes, raw)
		return latin1ToUTF8(raw), false, nil
	}
	byteLen := uint64(length) * 2
	if byteLen > uint64(d.Remaining()) {
		return "", false, fmt.Errorf("%w: 16-bit string bytes %d > remaining %d", ErrTruncated, byteLen, d.Remaining())
	}
	raw, err := d.readRaw(int(byteLen))
	if err != nil {
		return "", false, err
	}
	d.hashTyped(saltBytes, raw)
	u16 := make([]uint16, length)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return string(utf16.Decode(u16)), false, nil
}

// StringValue decodes a WTF::String, mapping null strings to "".
func (d *Decoder) StringValue() (string, error) {
	s, _, err := d.String()
	return s, err
}

// WallTime decodes a WTF::WallTime (seconds since Unix epoch as float64).
func (d *Decoder) WallTime() (time.Time, float64, error) {
	secs, err := d.Float64()
	if err != nil {
		return time.Time{}, 0, err
	}
	return WallTimeFromSeconds(secs), secs, nil
}

// WallTimeFromSeconds converts Unix float seconds to UTC time.Time (zero if invalid/zero/out of RFC3339 range).
func WallTimeFromSeconds(secs float64) time.Time {
	if math.IsNaN(secs) || math.IsInf(secs, 0) || secs == 0 {
		return time.Time{}
	}
	// Keep within Go JSON-marshalable [0001-01-01, 9999-12-31] bounds.
	if secs < -62135596800 || secs > 253402300799 {
		return time.Time{}
	}
	sec, frac := math.Modf(secs)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC()
}

// SanitizeFloat returns 0 for NaN/Inf so JSON serialization never fails on corrupted floats.
func SanitizeFloat(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

// VerifyChecksum checks the trailing 20-byte WTF::Persistence SHA-1 checksum.
func (d *Decoder) VerifyChecksum() (bool, error) {
	computed := d.sha1.Sum(nil)
	saved, err := d.SHA1Digest()
	if err != nil {
		return false, err
	}
	return bytes.Equal(computed, saved[:]), nil
}

func latin1ToUTF8(b []byte) string {
	// Fast path for pure ASCII.
	ascii := true
	for _, c := range b {
		if c >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return string(b)
	}
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = utf8.AppendRune(out, rune(c))
	}
	return string(out)
}

// Encoder writes WTF::Persistence streams matching WebKit's PersistentEncoder.
type Encoder struct {
	buf  []byte
	sha1 hash.Hash
}

func NewEncoder() *Encoder {
	return &Encoder{sha1: sha1.New()}
}

func (e *Encoder) Bytes() []byte { return e.buf }

func (e *Encoder) writeTyped(salt uint32, raw []byte) {
	var s [4]byte
	binary.LittleEndian.PutUint32(s[:], salt)
	e.sha1.Write(s[:])
	e.sha1.Write(raw)
	e.buf = append(e.buf, raw...)
}

func (e *Encoder) Bool(v bool) {
	b := byte(0)
	if v {
		b = 1
	}
	e.writeTyped(saltBool, []byte{b})
}

func (e *Encoder) Uint8(v uint8) { e.writeTyped(saltUint8, []byte{v}) }

func (e *Encoder) Uint16(v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	e.writeTyped(saltUint16, b[:])
}

func (e *Encoder) Int16(v int16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], uint16(v))
	e.writeTyped(saltInt16, b[:])
}

func (e *Encoder) Uint32(v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	e.writeTyped(saltUint32, b[:])
}

func (e *Encoder) Int32(v int32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	e.writeTyped(saltInt32, b[:])
}

func (e *Encoder) Uint64(v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	e.writeTyped(saltUint64, b[:])
}

func (e *Encoder) Int64(v int64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(v))
	e.writeTyped(saltInt64, b[:])
}

func (e *Encoder) Float64(v float64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], math.Float64bits(v))
	e.writeTyped(saltFloat64, b[:])
}

func (e *Encoder) Enum(v uint64)       { e.Uint64(v) }
func (e *Encoder) FixedBytes(b []byte) { e.writeTyped(saltBytes, b) }
func (e *Encoder) NullString()         { e.Uint32(nullStringLen) }

// String encodes s as 8-bit Latin-1 if all runes <= 0xFF, otherwise UTF-16LE.
func (e *Encoder) String(s string) {
	latin1 := true
	for _, r := range s {
		if r > 0xFF {
			latin1 = false
			break
		}
	}
	if latin1 {
		raw := make([]byte, 0, len(s))
		for _, r := range s {
			raw = append(raw, byte(r))
		}
		e.Uint32(uint32(len(raw)))
		e.Bool(true)
		e.FixedBytes(raw)
		return
	}
	u16 := utf16.Encode([]rune(s))
	raw := make([]byte, len(u16)*2)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(raw[i*2:], c)
	}
	e.Uint32(uint32(len(u16)))
	e.Bool(false)
	e.FixedBytes(raw)
}

func (e *Encoder) EncodeChecksum() {
	sum := e.sha1.Sum(nil)
	e.FixedBytes(sum)
}
