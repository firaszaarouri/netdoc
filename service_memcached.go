package main

import (
	"bufio"
	"strings"
	"time"
)

// Memcached version probe. Memcached's ASCII protocol exposes a `version\r\n`
// command that any unauthenticated server responds to with `VERSION x.y.z\r\n`.
// SASL-only deployments (rare) reject it, but the vast majority of Memcached
// servers we'd find on a port scan still answer.
//
// Reference: https://github.com/memcached/memcached/blob/master/doc/protocol.txt

func probeMemcached(addr, _ string, timeout time.Duration) serviceInfo {
	info := serviceInfo{Product: "memcached"}
	conn, err := dialProbe(addr, timeout)
	if err != nil {
		return serviceInfo{}
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return info
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return info
	}
	line = strings.TrimRight(line, "\r\n")
	if strings.HasPrefix(line, "VERSION ") {
		info.Version = strings.TrimSpace(strings.TrimPrefix(line, "VERSION"))
		info.Banner = line
		info.Extra = map[string]string{"auth": "open"}
		return info
	}
	if strings.HasPrefix(line, "ERROR") || strings.HasPrefix(line, "CLIENT_ERROR") {
		info.Banner = line
		info.Extra = map[string]string{"auth": "restricted"}
	}
	return info
}
