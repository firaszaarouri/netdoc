package main

import (
	"crypto/rand"
	"net"
	"strconv"
	"time"
)

// TLS extension posture — two RFC-defined extensions that crypto/tls negotiates
// silently but doesn't expose to callers:
//
//   • Extended Master Secret (RFC 7627, extension type 0x0017). Closes a
//     class of triple-handshake / cross-protocol attacks by binding the
//     master_secret to the handshake transcript. Modern servers MUST
//     advertise it; old/misconfigured servers don't.
//
//   • renegotiation_info (RFC 5746, extension type 0xff01). Without this,
//     the server is vulnerable to the 2009 Marsh-Ray TLS renegotiation
//     attack (CVE-2009-3555). Patched servers always include the extension
//     in the initial ServerHello, even if the value is empty.
//
// We learn both by sending one TLS 1.2 ClientHello that advertises both
// extensions and parsing the resulting ServerHello extension list.

// tlsExtensionPosture holds the verdict for the two RFC-extension checks.
type tlsExtensionPosture struct {
	ExtendedMasterSecret bool `json:"extended_master_secret"`
	SecureRenegotiation  bool `json:"secure_renegotiation"`
	// Determined records whether we got far enough to make a verdict. If false,
	// the probe failed and callers should suppress the per-extension fields.
	Determined bool `json:"-"`
}

// probeTLSExtensions runs the single-handshake extension-detection probe and
// returns ems + secure-renegotiation verdicts. Timeout-bounded.
func probeTLSExtensions(host string, port int, timeout time.Duration) tlsExtensionPosture {
	var out tlsExtensionPosture
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return out
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	hello := extensionAdvertisingClientHello(host)
	if _, err := conn.Write(hello); err != nil {
		return out
	}
	body := readServerHelloBody(conn)
	if body == nil {
		return out
	}
	ext := serverHelloExtensions(body)
	out.Determined = true
	out.ExtendedMasterSecret = extensionPresent(ext, 0x0017)
	out.SecureRenegotiation = extensionPresent(ext, 0xff01)
	return out
}

// extensionAdvertisingClientHello builds a TLS 1.2 ClientHello carrying both
// extended_master_secret (0x0017) and renegotiation_info (0xff01, empty value)
// extensions alongside SNI/supported_groups/signature_algorithms. We need to
// *advertise* these for a compliant server to mirror them in its ServerHello.
func extensionAdvertisingClientHello(host string) []byte {
	cipherSuites := []uint16{
		0xc02f, 0xc030, 0xc02b, 0xc02c,
		0xcca8, 0xcca9,
		0xc013, 0xc014, 0xc009, 0xc00a,
		0x009c, 0x009d, 0x002f, 0x0035,
	}
	cipherBytes := make([]byte, 0, len(cipherSuites)*2)
	for _, c := range cipherSuites {
		cipherBytes = append(cipherBytes, byte(c>>8), byte(c&0xff))
	}
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)

	extensions := buildSNIExtension(host)
	extensions = append(extensions, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18)
	extensions = append(extensions, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
		0x04, 0x03, 0x05, 0x03,
		0x08, 0x04, 0x08, 0x05, 0x08, 0x07,
		0x04, 0x01, 0x05, 0x01,
		0x02, 0x01, 0x02, 0x03,
	)
	// extended_master_secret (type 0x0017, length 0)
	extensions = append(extensions, 0x00, 0x17, 0x00, 0x00)
	// renegotiation_info (type 0xff01, length 1, empty client_verify_data)
	extensions = append(extensions, 0xff, 0x01, 0x00, 0x01, 0x00)

	extLen := len(extensions)

	body := []byte{0x03, 0x03}
	body = append(body, rnd...)
	body = append(body, 0x00)
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(extLen>>8), byte(extLen&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)
	hsLen := len(hs)
	rec := []byte{0x16, 0x03, 0x03, byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// extensionPresent walks an extension list and returns true iff an extension
// with the given type is present.
func extensionPresent(ext []byte, wantType uint16) bool {
	for i := 0; i+4 <= len(ext); {
		extType := uint16(ext[i])<<8 | uint16(ext[i+1])
		extDataLen := int(ext[i+2])<<8 | int(ext[i+3])
		end := i + 4 + extDataLen
		if end > len(ext) {
			return false
		}
		if extType == wantType {
			return true
		}
		i = end
	}
	return false
}
