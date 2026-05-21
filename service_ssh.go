package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH service probe. Returns:
//   • Product + Version parsed from the SSH banner (OpenSSH 9.6p1, libssh
//     0.10.4, dropbear 2022.83, AsyncSSH, etc.)
//   • host_key_type / host_key_bits / host_key_sha256 / host_key_md5
//   • kex_algorithms, host_key_algorithms, ciphers_s2c, macs_s2c
//
// We use two connections in sequence:
//   1. Hand-rolled SSH KEXINIT exchange (RFC 4253 §7). Reads server banner,
//      sends our banner, exchanges KEXINIT messages, extracts the 10 name-
//      lists the server advertises. No DH / key exchange — we close after
//      reading server's KEXINIT.
//   2. Full ssh.Dial via golang.org/x/crypto/ssh with a HostKeyCallback that
//      captures the public key (then returns an error to abort before auth).
//      This gets us the actual key bytes for fingerprinting.
//
// References:
//   RFC 4253 — SSH Transport Layer Protocol
//   https://datatracker.ietf.org/doc/html/rfc4253

func probeSSH(addr, _ string, timeout time.Duration) serviceInfo {
	info := serviceInfo{}

	// Phase 1: KEXINIT exchange on a dedicated connection.
	conn, err := dialProbe(addr, timeout)
	if err != nil {
		return info
	}
	banner, kexInfo := exchangeSSHIdentAndKEX(conn)
	conn.Close()
	if banner == "" {
		return info
	}
	info.Banner = banner
	info.Product, info.Version = parseSSHBanner(banner)
	if info.Product == "" {
		info.Product = "SSH"
	}
	info.Extra = map[string]string{
		"banner": banner,
	}
	if kexInfo != nil {
		if v := strings.Join(kexInfo.KexAlgorithms, ","); v != "" {
			info.Extra["kex_algorithms"] = v
		}
		if v := strings.Join(kexInfo.HostKeyAlgorithms, ","); v != "" {
			info.Extra["host_key_algorithms"] = v
		}
		if v := strings.Join(kexInfo.CiphersServerToClient, ","); v != "" {
			info.Extra["ciphers_s2c"] = v
		}
		if v := strings.Join(kexInfo.MACsServerToClient, ","); v != "" {
			info.Extra["macs_s2c"] = v
		}
		if v := strings.Join(kexInfo.CompressionServerToClient, ","); v != "" && v != "none" {
			info.Extra["compression_s2c"] = v
		}
	}

	// Phase 2: host-key capture via crypto/ssh. Aborts after KEX succeeds.
	if hk := captureSSHHostKey(addr, timeout); hk != nil {
		info.Extra["host_key_type"] = hk.Type
		info.Extra["host_key_sha256"] = "SHA256:" + hk.SHA256
		info.Extra["host_key_md5"] = "MD5:" + hk.MD5
	}
	return info
}

// parseSSHBanner extracts product and version from an SSH banner. Examples:
//   SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13   → ("OpenSSH", "9.6p1")
//   SSH-2.0-libssh_0.10.4                    → ("libssh", "0.10.4")
//   SSH-2.0-dropbear_2022.83                 → ("dropbear", "2022.83")
//   SSH-2.0-AsyncSSH_2.13.2                  → ("AsyncSSH", "2.13.2")
//   SSH-2.0-8ad108e                          → ("", "") — GitHub obfuscation
func parseSSHBanner(banner string) (string, string) {
	rest := strings.TrimPrefix(banner, "SSH-2.0-")
	if rest == banner {
		return "", ""
	}
	// "<product>_<version>[ <comment>]"
	rest = strings.SplitN(rest, " ", 2)[0]
	parts := strings.SplitN(rest, "_", 2)
	if len(parts) != 2 {
		return "", ""
	}
	prod, ver := parts[0], parts[1]
	// Guard against weird products: must start with a letter, version must
	// start with a digit. Eliminates GitHub's hash-banner false-positive.
	if len(prod) == 0 || (prod[0] < 'A' || prod[0] > 'z') {
		return "", ""
	}
	if len(ver) == 0 || ver[0] < '0' || ver[0] > '9' {
		return "", ""
	}
	return prod, ver
}

// sshKexInfo is the parsed contents of the server's SSH_MSG_KEXINIT message.
type sshKexInfo struct {
	KexAlgorithms             []string
	HostKeyAlgorithms         []string
	CiphersClientToServer     []string
	CiphersServerToClient     []string
	MACsClientToServer        []string
	MACsServerToClient        []string
	CompressionClientToServer []string
	CompressionServerToClient []string
}

// exchangeSSHIdentAndKEX reads the server's SSH banner, sends ours, exchanges
// KEXINIT, and returns the parsed banner + algorithm lists. Returns empty
// banner on any I/O or protocol failure.
func exchangeSSHIdentAndKEX(conn net.Conn) (string, *sshKexInfo) {
	br := bufio.NewReader(conn)
	banner, err := br.ReadString('\n')
	if err != nil {
		return "", nil
	}
	banner = strings.TrimRight(banner, "\r\n")
	if !strings.HasPrefix(banner, "SSH-") {
		return "", nil
	}

	if _, err := conn.Write([]byte("SSH-2.0-netdoc_probe\r\n")); err != nil {
		return banner, nil
	}

	// Send our minimal KEXINIT. The server's KEXINIT is independent — it'll
	// come back regardless of what we offered.
	if _, err := conn.Write(buildSSHKexInit()); err != nil {
		return banner, nil
	}

	// Read the server's KEXINIT. Pre-KEX-completion SSH packets are unencrypted:
	//   packet_length(4) + padding_length(1) + payload + padding
	pkt, err := readSSHPacket(br)
	if err != nil {
		return banner, nil
	}
	if len(pkt) < 1 || pkt[0] != 20 { // SSH_MSG_KEXINIT
		return banner, nil
	}
	kex, err := parseSSHKexInit(pkt[1:])
	if err != nil {
		return banner, nil
	}
	return banner, kex
}

// readSSHPacket reads one unencrypted SSH binary packet and returns its
// payload bytes.
func readSSHPacket(br *bufio.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, err
	}
	pktLen := int(binary.BigEndian.Uint32(hdr[0:4]))
	padLen := int(hdr[4])
	if pktLen < 1 || pktLen > 1<<18 {
		return nil, errors.New("bogus SSH packet length")
	}
	rest := make([]byte, pktLen-1)
	if _, err := io.ReadFull(br, rest); err != nil {
		return nil, err
	}
	if padLen > len(rest) {
		return nil, errors.New("padding longer than payload")
	}
	return rest[:len(rest)-padLen], nil
}

// parseSSHKexInit parses a KEXINIT payload (after the 1-byte msg type).
// Layout: 16-byte cookie + 10 name-lists + 1-byte first_kex_packet_follows
// + 4-byte reserved.
func parseSSHKexInit(payload []byte) (*sshKexInfo, error) {
	if len(payload) < 16 {
		return nil, errors.New("KEXINIT payload too short")
	}
	p := payload[16:] // skip cookie
	lists := make([][]string, 0, 10)
	for i := 0; i < 10; i++ {
		if len(p) < 4 {
			return nil, errors.New("truncated KEXINIT name-list")
		}
		l := int(binary.BigEndian.Uint32(p[0:4]))
		p = p[4:]
		if l > len(p) {
			return nil, errors.New("name-list overruns packet")
		}
		names := splitCSV(string(p[:l]))
		lists = append(lists, names)
		p = p[l:]
	}
	return &sshKexInfo{
		KexAlgorithms:             lists[0],
		HostKeyAlgorithms:         lists[1],
		CiphersClientToServer:     lists[2],
		CiphersServerToClient:     lists[3],
		MACsClientToServer:        lists[4],
		MACsServerToClient:        lists[5],
		CompressionClientToServer: lists[6],
		CompressionServerToClient: lists[7],
	}, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// buildSSHKexInit assembles our SSH_MSG_KEXINIT packet. We offer a broad set
// of common algorithms so any modern server picks at least one (even though
// we don't actually proceed to KEX). The packet is wrapped in the standard
// SSH binary-packet framing with random padding.
func buildSSHKexInit() []byte {
	const (
		kexAlgos    = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256"
		hostKeyAlgs = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss"
		ciphers     = "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr"
		macs        = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
		compress    = "none"
		langs       = ""
	)
	cookie := make([]byte, 16)
	// Cookie is supposed to be random; "netdoc kex prober" is a stable marker
	// that won't affect anything since we don't complete KEX.
	copy(cookie, []byte("netdoc-prober-rev"))

	payload := []byte{20} // SSH_MSG_KEXINIT
	payload = append(payload, cookie...)
	for _, list := range []string{
		kexAlgos, hostKeyAlgs, ciphers, ciphers, macs, macs, compress, compress, langs, langs,
	} {
		b := []byte(list)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
		payload = append(payload, lenBuf[:]...)
		payload = append(payload, b...)
	}
	payload = append(payload, 0)             // first_kex_packet_follows
	payload = append(payload, 0, 0, 0, 0)    // reserved

	// Compute padding. Block-align to 8 bytes; padding length must be >= 4.
	pad := 8 - ((4 + 1 + len(payload)) % 8)
	if pad < 4 {
		pad += 8
	}
	padding := make([]byte, pad)
	totalLen := 1 + len(payload) + pad

	out := make([]byte, 0, 4+totalLen)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(totalLen))
	out = append(out, lenBuf[:]...)
	out = append(out, byte(pad))
	out = append(out, payload...)
	out = append(out, padding...)
	return out
}

// sshHostKeyInfo records what we learned about the server's host public key.
type sshHostKeyInfo struct {
	Type   string // "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa", ...
	SHA256 string // base64-encoded sha256 of the key blob, sans "SHA256:"
	MD5    string // colon-separated hex MD5 of the key blob, sans "MD5:"
}

// captureSSHHostKey opens a second TCP conn, drives a full SSH transport
// handshake via crypto/ssh, captures the host-key public key in the callback
// (which then returns a sentinel error so the auth phase is skipped), and
// returns the key's type + fingerprints. Returns nil on any failure.
func captureSSHHostKey(addr string, timeout time.Duration) *sshHostKeyInfo {
	var captured ssh.PublicKey
	var captureErr = errors.New("netdoc: captured host key")
	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		captured = key
		return captureErr
	}
	cfg := &ssh.ClientConfig{
		User:            "netdoc-probe",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: cb,
		Timeout:         timeout,
	}
	// ssh.Dial does the transport handshake then auth. It'll return our sentinel
	// error from the callback before auth — we ignore the error and inspect
	// the captured key instead.
	_, _ = ssh.Dial("tcp", addr, cfg)
	if captured == nil {
		return nil
	}
	blob := captured.Marshal()
	sha := sha256.Sum256(blob)
	md := md5.Sum(blob)
	return &sshHostKeyInfo{
		Type:   captured.Type(),
		SHA256: strings.TrimRight(base64.StdEncoding.EncodeToString(sha[:]), "="),
		MD5:    colonHex(md[:]),
	}
}

// colonHex formats raw bytes as a colon-separated lowercase hex string.
// Standard SSH MD5 fingerprint format: "16:27:ac:a5:..."
func colonHex(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3)
	for i, x := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexd[x>>4], hexd[x&0xf])
	}
	return string(out)
}
