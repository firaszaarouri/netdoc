package main

import (
	"net"
	"time"
)

// Service-ID active-probe dispatcher. For protocols that DON'T greet on
// TCP-connect (Memcached, Redis, Postgres, MongoDB, Elasticsearch) we have
// to send a protocol-specific probe before we can extract a version. The
// passive banner-grab in scanPort can't help here.
//
// For SSH the server DOES greet, but we additionally want the host-key
// fingerprint + KEX algorithm enumeration — which require driving an SSH
// transport handshake. So SSH is also in the active-probe map.
//
// Each probe is self-contained: opens its own TCP connection(s), times
// itself out, and returns ServiceInfo with whatever it extracted. The
// dispatcher passes only `addr` (host:port) so probes that need multiple
// conns (SSH does — one for KEXINIT, one for host-key via crypto/ssh)
// can manage their own connection lifecycle.

// serviceInfo is the result of an active service probe — what the dispatcher
// returned that we then fold into the portResult.
type serviceInfo struct {
	Product string            // e.g. "Redis", "Memcached", "OpenSSH"
	Version string            // e.g. "7.4.0", "1.6.21", "9.6p1"
	Banner  string            // human-friendly one-liner banner
	Extra   map[string]string // protocol-specific: auth posture, host-key fp, etc.
}

// serviceProbeFunc is the signature of every protocol-aware probe.
// Probes own all I/O — open their own conn, set their own deadlines, close
// before returning. `addr` is host:port, `host` is just the host (for SNI/
// Host headers), `timeout` caps the whole probe.
type serviceProbeFunc func(addr string, host string, timeout time.Duration) serviceInfo

// servicePortMap routes well-known ports to their active TCP probe.
var servicePortMap = map[int]serviceProbeFunc{
	22:    probeSSH,           // SSH host-key + KEX algorithms
	23:    probeTelnet,        // Telnet IAC negotiation + ASCII banner
	389:   probeLDAP,          // LDAP rootDSE (anonymous bind + search)
	445:   probeSMB2,          // SMB2 NEGOTIATE — dialect, signing, server GUID, uptime
	636:   probeLDAP,          // LDAPS (TLS-wrapped; still answers BER over the wire pre-TLS)
	3389:  probeRDP,           // RDP X.224 + nego — TLS/NLA/CredSSP selection
	5432:  probePostgreSQL,    // PostgreSQL SSLRequest + ErrorResponse parse
	6379:  probeRedis,         // Redis INFO + auth posture
	9200:  probeElasticsearch, // ES HTTP /
	9300:  probeElasticsearch, // ES transport-on-HTTP fallback
	11211: probeMemcached,     // memcached `version`
	27017: probeMongoDB,       // MongoDB OP_MSG hello
	27018: probeMongoDB,
	27019: probeMongoDB,
}

// udpServicePortMap routes well-known UDP ports to their active UDP probe.
// Each probe opens its own UDP socket via net.DialTimeout("udp", ...) and
// returns a serviceInfo with product/version/banner extracted from the
// application-layer response. The dispatcher (scanUDPPort) runs these
// probes alongside the Linux IP_RECVERR classifier for open/closed/
// filtered determination.
var udpServicePortMap = map[int]serviceProbeFunc{
	53:  probeDNSUDP, // DNS server CHAOS version.bind / hostname.bind / id.server
	123: probeNTP,    // NTP mode-6 readvar control message
}

// dialProbe opens a TCP conn with the given timeout and applies a read/write
// deadline equal to `timeout`. Probes call this rather than net.DialTimeout
// directly to ensure they always have a deadline.
func dialProbe(addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}
