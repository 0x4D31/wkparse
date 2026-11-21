package webkit

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/0x4d31/wkparse/internal/evidence"
	"github.com/0x4d31/wkparse/pkg/persist"
	"howett.net/plist"
)

// ParseOriginFile reads and decodes a WebKit Unified Origin Storage `origin` sidecar file.
func ParseOriginFile(path string) (*ClientOrigin, error) {
	data, err := evidence.ReadFile(path)
	if err != nil {
		return nil, err
	}
	co, err := DecodeClientOrigin(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	co.Path = path
	return co, nil
}

// DecodeClientOrigin decodes WebCore::ClientOrigin (topOrigin + clientOrigin).
func DecodeClientOrigin(data []byte) (*ClientOrigin, error) {
	dec := persist.NewDecoder(data)
	top, err := decodeSecurityOrigin(dec)
	if err != nil {
		return nil, fmt.Errorf("topOrigin: %w", err)
	}
	client, err := decodeSecurityOrigin(dec)
	if err != nil {
		return nil, fmt.Errorf("clientOrigin: %w", err)
	}
	return &ClientOrigin{
		TopOrigin:    top,
		ClientOrigin: client,
		CrossOrigin:  top.String() != client.String(),
	}, nil
}

func decodeSecurityOrigin(dec *persist.Decoder) (SecurityOrigin, error) {
	proto, err := dec.StringValue()
	if err != nil {
		return SecurityOrigin{}, err
	}
	host, err := dec.StringValue()
	if err != nil {
		return SecurityOrigin{}, err
	}
	hasPort, err := dec.Bool()
	if err != nil {
		return SecurityOrigin{}, err
	}
	var port *uint16
	if hasPort {
		p, err := dec.Uint16()
		if err != nil {
			return SecurityOrigin{}, err
		}
		port = &p
	}
	return SecurityOrigin{Protocol: proto, Host: host, Port: port}, nil
}

// decodeOptionalCertificateInfo decodes std::optional<WebCore::CertificateInfo> for Cocoa.
// WebKit <= v16 prefixed CertificateInfo with LegacyCertificateInfoType (None=0, Chain=1, Trust=2);
// v17+ removed that prefix and encodes SecTrustRef directly.
func decodeOptionalCertificateInfo(dec *persist.Decoder, legacyTypePrefix bool) ([]CertSummary, error) {
	engaged, err := dec.Bool()
	if err != nil || !engaged {
		return nil, err
	}
	if legacyTypePrefix {
		kind, err := dec.Enum()
		if err != nil {
			return nil, err
		}
		switch kind {
		case 0: // None
			return nil, nil
		case 1: // CertificateChain: uint64 count + N CFData (raw DER certs)
			count, err := dec.Uint64()
			if err != nil {
				return nil, err
			}
			if count > 64 {
				return nil, fmt.Errorf("unreasonable certificate chain length %d", count)
			}
			var out []CertSummary
			for i := uint64(0); i < count; i++ {
				der, err := decodeCFData(dec)
				if err != nil {
					return nil, err
				}
				if c, ok := summarizeDERCert(der); ok {
					out = append(out, c)
				}
			}
			return out, nil
		case 2: // Trust: falls through to SecTrustRef
		default:
			return nil, fmt.Errorf("unknown legacy certificate type %d", kind)
		}
	}

	hasTrust, err := dec.Bool()
	if err != nil || !hasTrust {
		return nil, err
	}
	trustBytes, err := decodeCFData(dec)
	if err != nil {
		return nil, err
	}
	return extractCertsFromSecTrust(trustBytes), nil
}

func decodeCFData(dec *persist.Decoder) ([]byte, error) {
	n, err := dec.Uint64()
	if err != nil {
		return nil, err
	}
	if n > uint64(dec.Remaining()) {
		return nil, fmt.Errorf("%w: CFData size %d > remaining %d", persist.ErrTruncated, n, dec.Remaining())
	}
	return dec.FixedBytes(int(n))
}

// extractCertsFromSecTrust extracts DER X.509 certificates from a Cocoa SecTrustSerialize blob.
// Real Apple SecTrustSerialize output is ASN.1 DER (SET of key/value SEQUENCEs with OCTET STRING certs);
// raw DER certificates and plist-wrapped blobs are also handled as fallbacks.
func extractCertsFromSecTrust(blob []byte) []CertSummary {
	if c, ok := summarizeDERCert(blob); ok {
		return []CertSummary{c}
	}

	var out []CertSummary
	seen := make(map[string]struct{})
	addCert := func(der []byte) {
		if c, ok := summarizeDERCert(der); ok {
			if _, dup := seen[c.SHA256]; !dup {
				seen[c.SHA256] = struct{}{}
				out = append(out, c)
			}
		}
	}

	// Primary path: Apple SecTrustSerialize ASN.1 DER container (starts with SET 0x31 or SEQUENCE 0x30).
	if len(blob) > 4 && (blob[0] == 0x31 || blob[0] == 0x30) {
		walkASN1DER(blob, 0, addCert)
		if len(out) > 0 {
			return out
		}
	}

	// Fallback: binary/XML plist containing DER cert data.
	var root any
	if _, err := plist.Unmarshal(blob, &root); err != nil {
		return nil
	}
	var walkPlist func(v any)
	walkPlist = func(v any) {
		switch x := v.(type) {
		case []byte:
			addCert(x)
		case []any:
			for _, item := range x {
				walkPlist(item)
			}
		case map[string]any:
			for _, val := range x {
				walkPlist(val)
			}
		}
	}
	walkPlist(root)
	return out
}

// walkASN1DER traverses ASN.1 DER TLV structures (bounded depth) and passes OCTET STRING values to fn.
func walkASN1DER(b []byte, depth int, fn func([]byte)) {
	if depth > 16 {
		return
	}
	for p := 0; p < len(b); {
		tag := b[p]
		p++
		if p >= len(b) {
			return
		}
		length := int(b[p])
		p++
		if length&0x80 != 0 {
			numBytes := length & 0x7f
			if numBytes == 0 || numBytes > 4 || p+numBytes > len(b) {
				return
			}
			length = 0
			for i := 0; i < numBytes; i++ {
				length = (length << 8) | int(b[p+i])
			}
			p += numBytes
		}
		if length < 0 || length > len(b)-p {
			return
		}
		val := b[p : p+length]
		p += length

		switch tag {
		case 0x04: // OCTET STRING
			fn(val)
		case 0x30, 0x31: // SEQUENCE, SET
			walkASN1DER(val, depth+1, fn)
		default:
			if tag&0x20 != 0 { // constructed context-specific tag
				walkASN1DER(val, depth+1, fn)
			}
		}
	}
}

func summarizeDERCert(der []byte) (CertSummary, bool) {
	if len(der) < 64 || der[0] != 0x30 {
		return CertSummary{}, false
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CertSummary{}, false
	}
	sum := sha256.Sum256(der)
	return CertSummary{
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		SANs:      cert.DNSNames,
		NotBefore: cert.NotBefore.UTC(),
		NotAfter:  cert.NotAfter.UTC(),
		SHA256:    hex.EncodeToString(sum[:]),
	}, true
}
