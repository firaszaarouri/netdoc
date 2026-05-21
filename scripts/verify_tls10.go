//go:build ignore

// Quick verification: does Go 1.24's crypto/tls really pin to TLS 1.0
// when MinVersion=MaxVersion=tls.VersionTLS10, or does it silently
// negotiate up?

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	target := "github.com:443"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	for name, ver := range map[string]uint16{
		"TLS 1.0": tls.VersionTLS10,
		"TLS 1.1": tls.VersionTLS11,
		"TLS 1.2": tls.VersionTLS12,
		"TLS 1.3": tls.VersionTLS13,
	} {
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         ver,
			MaxVersion:         ver,
		})
		if err != nil {
			fmt.Printf("%s pinned: FAIL — %v\n", name, err)
			continue
		}
		st := conn.ConnectionState()
		negotiated := versionString(st.Version)
		match := negotiated == name
		fmt.Printf("%s pinned → negotiated %s (match=%v) cipher=%s\n",
			name, negotiated, match, tls.CipherSuiteName(st.CipherSuite))
		conn.Close()
	}
}

func versionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}
