package main

import (
	"bufio"
	"io"
	"strings"
	"time"
)

// Redis INFO probe. Speaks RESP-2, which any Redis 2.4+ server understands.
// We send PING first as a connectivity sanity check (anonymous-allowed in
// most configs), then INFO. If INFO returns -NOAUTH/-ERR we still know the
// service is Redis but auth-protected — useful posture signal.
//
// Reference: https://redis.io/docs/latest/develop/reference/protocol-spec/

func probeRedis(addr, _ string, timeout time.Duration) serviceInfo {
	info := serviceInfo{Product: "Redis"}
	conn, err := dialProbe(addr, timeout)
	if err != nil {
		return serviceInfo{}
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		return info
	}
	br := bufio.NewReader(conn)
	pingResp, err := br.ReadString('\n')
	if err != nil {
		return info
	}
	pingResp = strings.TrimRight(pingResp, "\r\n")
	if !strings.HasPrefix(pingResp, "+PONG") {
		if strings.HasPrefix(pingResp, "-NOAUTH") {
			info.Extra = map[string]string{"auth": "required"}
			info.Banner = pingResp
		}
		return info
	}

	if _, err := conn.Write([]byte("*1\r\n$4\r\nINFO\r\n")); err != nil {
		return info
	}
	header, err := br.ReadString('\n')
	if err != nil {
		return info
	}
	header = strings.TrimRight(header, "\r\n")
	if strings.HasPrefix(header, "-NOAUTH") || strings.HasPrefix(header, "-ERR") {
		info.Extra = map[string]string{"auth": "required"}
		info.Banner = "+PONG  ·  " + header
		return info
	}
	if !strings.HasPrefix(header, "$") {
		info.Banner = pingResp + "  ·  " + header
		return info
	}
	body, err := io.ReadAll(br)
	if err != nil && err != io.EOF {
		return info
	}
	info.Banner = "+PONG  ·  INFO ok"
	info.Extra = map[string]string{"auth": "open"}
	for _, line := range strings.Split(string(body), "\r\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		k, v, _ := strings.Cut(line, ":")
		switch k {
		case "redis_version":
			info.Version = strings.TrimSpace(v)
		case "redis_mode":
			info.Extra["mode"] = strings.TrimSpace(v)
		case "os":
			info.Extra["os"] = strings.TrimSpace(v)
		case "redis_build_id":
			info.Extra["build"] = strings.TrimSpace(v)
		case "tcp_port":
			info.Extra["tcp_port"] = strings.TrimSpace(v)
		case "role":
			info.Extra["role"] = strings.TrimSpace(v)
		}
	}
	return info
}
