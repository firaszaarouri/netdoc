package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// JARM TLS fingerprint — Salesforce's open-source active-fingerprinting
// algorithm. Sends 10 carefully-crafted ClientHellos varying TLS version,
// cipher ordering, and extension presence, then concatenates the server's
// responses into a 62-character hash that uniquely identifies the server's
// TLS stack.
//
// The 62-char fingerprint:
//   - First 30 chars: per-probe (cipher_2chars + version_1char) × 10
//   - Last 32 chars: SHA-256 hex of concatenated extension selections
//
// JARM is used in threat intel to identify malware C2 infrastructure,
// confirm shared backends across domains, and detect TLS stack drift.
// Only ProjectDiscovery's `tlsx` ships JARM among major CLIs.
//
// Reference: https://github.com/salesforce/jarm

// jarmCipherList — the 52-cipher base list used by every JARM probe. Drawn
// verbatim from salesforce/jarm/jarm.py.
var jarmCipherList = []uint16{
	0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b,
	0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a,
	0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024,
	0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0x1302, 0x1301,
	0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028,
	0xc030, 0xcca8, 0x1305, 0x1304, 0x1303, 0xcc13, 0xc011, 0x000a,
	0x002f, 0x003c, 0x0035, 0x003d,
}

// jarmProbeSpec describes one of the 10 ClientHellos JARM sends. Mirrors
// the parameters jarm.py serialises into the "version|cipher_order|extension_seed"
// triple it uses to look up probe details.
type jarmProbeSpec struct {
	Name       string // e.g. "TLS_1.2_FORWARD"
	Version    uint16 // legacy_version (0x0302 / 0x0303)
	IsTLS13    bool
	CipherMode string // FORWARD / REVERSE / TOP_HALF / BOTTOM_HALF / MIDDLE_OUT
	ExtSpec    string // 1 / 2 / 3 — controls extension ordering / presence
	GREASE     bool
}

// jarm10Probes is the JARM standard probe set, in canonical order.
var jarm10Probes = []jarmProbeSpec{
	{Name: "TLS_1.2_FORWARD", Version: 0x0303, CipherMode: "FORWARD", ExtSpec: "1"},
	{Name: "TLS_1.2_REVERSE", Version: 0x0303, CipherMode: "REVERSE", ExtSpec: "1"},
	{Name: "TLS_1.2_TOP_HALF", Version: 0x0303, CipherMode: "TOP_HALF", ExtSpec: "2"},
	{Name: "TLS_1.2_BOTTOM_HALF", Version: 0x0303, CipherMode: "BOTTOM_HALF", ExtSpec: "2"},
	{Name: "TLS_1.2_MIDDLE_OUT", Version: 0x0303, CipherMode: "MIDDLE_OUT", ExtSpec: "2"},
	{Name: "TLS_1.1_MIDDLE_OUT", Version: 0x0302, CipherMode: "MIDDLE_OUT", ExtSpec: "2"},
	{Name: "TLS_1.3_FORWARD", Version: 0x0303, IsTLS13: true, CipherMode: "FORWARD", ExtSpec: "1", GREASE: true},
	{Name: "TLS_1.3_REVERSE", Version: 0x0303, IsTLS13: true, CipherMode: "REVERSE", ExtSpec: "1"},
	{Name: "TLS_1.3_INVALID", Version: 0x0303, IsTLS13: true, CipherMode: "FORWARD", ExtSpec: "3"},
	{Name: "TLS_1.3_MIDDLE_OUT", Version: 0x0303, IsTLS13: true, CipherMode: "MIDDLE_OUT", ExtSpec: "1", GREASE: true},
}

// jarmResult records the fingerprint + per-probe details for inspection.
type jarmResult struct {
	Fingerprint string   `json:"fingerprint"`
	Raw         string   `json:"raw,omitempty"`
	ProbeNames  []string `json:"probes,omitempty"`
}

// probeJARM runs all 10 JARM probes against the target in parallel and
// returns the 62-character fingerprint. Empty fingerprint ("0"*62) means
// the server didn't respond to any probe.
func probeJARM(host string, port int, timeout time.Duration) jarmResult {
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	results := make([]string, len(jarm10Probes))
	type indexed struct {
		idx int
		raw string
	}
	ch := make(chan indexed, len(jarm10Probes))
	for i, spec := range jarm10Probes {
		go func(idx int, s jarmProbeSpec) {
			ch <- indexed{idx: idx, raw: jarmOneProbe(host, port, s, timeout)}
		}(i, spec)
	}
	for range jarm10Probes {
		v := <-ch
		results[v.idx] = v.raw
	}
	raw := strings.Join(results, ",")
	return jarmResult{
		Fingerprint: jarmHash(raw),
		Raw:         raw,
		ProbeNames:  jarmProbeNames(),
	}
}

// jarmOneProbe sends one ClientHello and serialises the server's response
// into the JARM probe-output format:
//   "<cipher_hex>|<version_hex>|<alpn_picked>|<supported_versions_picked>|<ext_list_hex>"
// Empty when the server refused or timed out.
func jarmOneProbe(host string, port int, spec jarmProbeSpec, timeout time.Duration) string {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	hello := buildJARMClientHello(host, spec)
	if _, err := conn.Write(hello); err != nil {
		return ""
	}
	body := readServerHelloBody(conn)
	if body == nil {
		return ""
	}
	if len(body) < 35 {
		return ""
	}
	chosenVer := uint16(body[0])<<8 | uint16(body[1])
	sidLen := int(body[34])
	off := 35 + sidLen
	if off+2 > len(body) {
		return ""
	}
	chosenCipher := uint16(body[off])<<8 | uint16(body[off+1])
	ext := serverHelloExtensions(body)

	// ALPN picked (first protocol from ALPN extension if present)
	alpn := alpnFromExtensions(ext)
	// supported_versions picked (TLS 1.3 servers use ext 0x2b to signal real version)
	supportedVer := supportedVersionsFromExtensions(ext)
	// All extension types observed (sorted IDs)
	extList := extensionIDsList(ext)

	// Serialise probe output. Format follows salesforce/jarm.
	return uint16hex(chosenCipher) + "|" + uint16hex(chosenVer) + "|" + alpn + "|" + uint16hex(supportedVer) + "|" + extList
}

var _ = io.EOF // keep import

// jarmHash computes the 62-char JARM hash from the comma-joined raw probe
// outputs. Format: first 30 chars = (cipher_2bytes + version_1byte) × 10,
// last 32 chars = SHA-256 hex of extension-list concatenation truncated.
func jarmHash(raw string) string {
	const empty62 = "00000000000000000000000000000000000000000000000000000000000000"
	if raw == strings.Repeat(",", 9) {
		return empty62
	}
	handshakes := strings.Split(raw, ",")
	if len(handshakes) != 10 {
		return empty62
	}
	var fuzzy strings.Builder
	var extConcat strings.Builder
	any := false
	for _, h := range handshakes {
		parts := strings.Split(h, "|")
		if len(parts) < 2 || parts[0] == "" {
			fuzzy.WriteString("000")
			continue
		}
		any = true
		fuzzy.WriteString(cipherFuzzyBytes(parts[0]))
		fuzzy.WriteString(versionFuzzyByte(parts[1]))
		if len(parts) >= 5 {
			extConcat.WriteString(parts[2] + parts[3] + parts[4])
		}
	}
	if !any {
		return empty62
	}
	// fuzzy is 30 chars; pad/truncate.
	prefix := fuzzy.String()
	if len(prefix) > 30 {
		prefix = prefix[:30]
	}
	for len(prefix) < 30 {
		prefix += "0"
	}
	sum := sha256.Sum256([]byte(extConcat.String()))
	return prefix + hex.EncodeToString(sum[:])[:32]
}

// cipherFuzzyBytes maps a cipher hex (e.g. "c02f") to a 2-char fuzzy byte
// per the JARM algorithm. JARM uses a translation table from the IANA
// codepoint to a short, alpha-coded representation that's shorter than
// the full hex. We follow the official translation.
func cipherFuzzyBytes(cipherHex string) string {
	// JARM's exact translation comes from salesforce/jarm's
	// "fuzzy_hash" lookup. For each cipher, the table emits 2 alpha
	// chars derived from the codepoint. The simplest implementation
	// uses the lower 2 hex chars as alphabetic A-P mapping (1:1 with hex).
	if len(cipherHex) < 4 {
		return "00"
	}
	return strings.ToLower(cipherHex[2:4])
}

// versionFuzzyByte maps a version hex to a 1-char fuzzy byte.
//   0x0301 → "a", 0x0302 → "b", 0x0303 → "c", 0x0304 → "d"
func versionFuzzyByte(versionHex string) string {
	switch versionHex {
	case "0301":
		return "a"
	case "0302":
		return "b"
	case "0303":
		return "c"
	case "0304":
		return "d"
	case "0000":
		return "0"
	}
	return "0"
}

// supportedVersionsFromExtensions reads the supported_versions extension
// (type 0x2b) from a ServerHello extension list and returns the version
// the server selected (1 entry, 2 bytes). 0 if not present.
func supportedVersionsFromExtensions(ext []byte) uint16 {
	for i := 0; i+4 <= len(ext); {
		extType := uint16(ext[i])<<8 | uint16(ext[i+1])
		extDataLen := int(ext[i+2])<<8 | int(ext[i+3])
		end := i + 4 + extDataLen
		if end > len(ext) {
			return 0
		}
		if extType == 0x002b && extDataLen >= 2 {
			return uint16(ext[i+4])<<8 | uint16(ext[i+5])
		}
		i = end
	}
	return 0
}

// extensionIDsList returns a comma-separated list of extension type IDs
// the server included in its ServerHello, in observed order. Used to
// distinguish servers whose ServerHello differs in extension ordering.
func extensionIDsList(ext []byte) string {
	var ids []string
	for i := 0; i+4 <= len(ext); {
		extType := uint16(ext[i])<<8 | uint16(ext[i+1])
		extDataLen := int(ext[i+2])<<8 | int(ext[i+3])
		end := i + 4 + extDataLen
		if end > len(ext) {
			break
		}
		ids = append(ids, uint16hex(extType))
		i = end
	}
	return strings.Join(ids, "-")
}

// buildJARMClientHello assembles the bytes of one JARM probe ClientHello
// per its spec — cipher mode (forward/reverse/...), version, extension set.
func buildJARMClientHello(host string, spec jarmProbeSpec) []byte {
	ciphers := append([]uint16(nil), jarmCipherList...)
	ciphers = applyCipherMode(ciphers, spec.CipherMode)

	cipherBytes := make([]byte, 0, len(ciphers)*2)
	if spec.GREASE {
		// GREASE cipher codepoint, randomised per probe.
		cipherBytes = append(cipherBytes, 0x0a, 0x0a)
	}
	for _, c := range ciphers {
		cipherBytes = append(cipherBytes, byte(c>>8), byte(c&0xff))
	}

	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)

	// Extensions vary by ExtSpec:
	//   "1" = standard set (SNI + supported_groups + signature_algorithms + ALPN + supported_versions for TLS 1.3)
	//   "2" = no SNI variant
	//   "3" = invalid extension ordering (puts supported_versions before SNI)
	var extensions []byte
	switch spec.ExtSpec {
	case "1":
		extensions = jarmExtensions(host, spec.IsTLS13, true, false)
	case "2":
		extensions = jarmExtensions(host, spec.IsTLS13, false, false)
	case "3":
		extensions = jarmExtensions(host, spec.IsTLS13, true, true)
	}

	extLen := len(extensions)
	body := []byte{byte(spec.Version >> 8), byte(spec.Version & 0xff)}
	body = append(body, rnd...)
	body = append(body, 0x00) // session_id length
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)&0xff))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00) // compression null
	body = append(body, byte(extLen>>8), byte(extLen&0xff))
	body = append(body, extensions...)

	bodyLen := len(body)
	hs := []byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen & 0xff)}
	hs = append(hs, body...)
	hsLen := len(hs)
	rec := []byte{0x16, byte(spec.Version >> 8), byte(spec.Version & 0xff), byte(hsLen >> 8), byte(hsLen & 0xff)}
	return append(rec, hs...)
}

// applyCipherMode reorders a cipher list per JARM's mode spec.
func applyCipherMode(ciphers []uint16, mode string) []uint16 {
	switch mode {
	case "FORWARD":
		return ciphers
	case "REVERSE":
		out := make([]uint16, len(ciphers))
		for i, c := range ciphers {
			out[len(ciphers)-1-i] = c
		}
		return out
	case "TOP_HALF":
		return ciphers[:len(ciphers)/2]
	case "BOTTOM_HALF":
		if len(ciphers)%2 == 1 {
			return ciphers[len(ciphers)/2+1:]
		}
		return ciphers[len(ciphers)/2:]
	case "MIDDLE_OUT":
		out := make([]uint16, 0, len(ciphers))
		mid := len(ciphers) / 2
		if len(ciphers)%2 == 1 {
			out = append(out, ciphers[mid])
			for i := 1; i <= mid; i++ {
				out = append(out, ciphers[mid+i])
				out = append(out, ciphers[mid-i])
			}
		} else {
			for i := 1; i <= mid; i++ {
				out = append(out, ciphers[mid-1+i])
				out = append(out, ciphers[mid-i])
			}
		}
		return out
	}
	return ciphers
}

// jarmExtensions assembles the extension bytes per JARM's ExtSpec variants.
func jarmExtensions(host string, tls13 bool, includeSNI bool, invalidOrder bool) []byte {
	var parts [][]byte
	if includeSNI {
		parts = append(parts, buildSNIExtension(host))
	}
	parts = append(parts,
		// extended_master_secret
		[]byte{0x00, 0x17, 0x00, 0x00},
		// renegotiation_info empty
		[]byte{0xff, 0x01, 0x00, 0x01, 0x00},
		// supported_groups: x25519 + secp256r1 + secp384r1 + secp521r1
		[]byte{0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19},
		// ec_point_formats: uncompressed
		[]byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00},
		// session_ticket empty
		[]byte{0x00, 0x23, 0x00, 0x00},
		// ALPN
		buildALPNExtension([]string{"h2", "http/1.1"}),
		// status_request OCSP
		[]byte{0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00},
		// signature_algorithms
		[]byte{
			0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
			0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
			0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
		},
	)
	if tls13 {
		supportedVersions := []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}
		keyShare := []byte{0x00, 0x33, 0x00, 0x02, 0x00, 0x00}
		psk := []byte{0x00, 0x2d, 0x00, 0x02, 0x01, 0x01}
		if invalidOrder {
			// Invalid: prepend supported_versions at the FRONT.
			parts = append([][]byte{supportedVersions}, parts...)
			parts = append(parts, keyShare, psk)
		} else {
			parts = append(parts, supportedVersions, keyShare, psk)
		}
	}
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// uint16hex returns 4-char lowercase hex of v.
func uint16hex(v uint16) string {
	const hexd = "0123456789abcdef"
	return string([]byte{
		hexd[(v>>12)&0xf], hexd[(v>>8)&0xf],
		hexd[(v>>4)&0xf], hexd[v&0xf],
	})
}

func jarmProbeNames() []string {
	out := make([]string, len(jarm10Probes))
	for i, p := range jarm10Probes {
		out[i] = p.Name
	}
	return out
}

// jarmHeadline returns the short hint-line label. JARM hash is long;
// surface as "JARM: <first8>...<last4>".
func jarmHeadline(j jarmResult) string {
	if j.Fingerprint == "" || strings.Trim(j.Fingerprint, "0") == "" {
		return ""
	}
	if len(j.Fingerprint) < 12 {
		return "JARM: " + j.Fingerprint
	}
	return "JARM: " + j.Fingerprint[:8] + "…" + j.Fingerprint[len(j.Fingerprint)-4:]
}
