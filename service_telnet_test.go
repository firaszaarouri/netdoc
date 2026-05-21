package main

import (
	"strings"
	"testing"
)

// Tests for the Telnet IAC-stripping logic. We don't probe a real Telnet
// server in tests; instead we exercise stripTelnetIAC against canned
// inputs covering: WILL/WONT/DO/DONT negotiation, SB subnegotiation,
// escaped 0xFF, and plain ASCII passthrough.

func TestStripTelnetIAC_WillWontDoDont(t *testing.T) {
	// IAC WILL ECHO (0xff 0xfb 0x01) + IAC DO ECHO + ASCII "hi"
	in := []byte{0xff, 0xfb, 0x01, 0xff, 0xfd, 0x01, 'h', 'i'}
	got := stripTelnetIAC(in)
	if got != "hi" {
		t.Errorf("got %q want %q", got, "hi")
	}
}

func TestStripTelnetIAC_EscapedFF(t *testing.T) {
	// 0xff 0xff is an escaped literal 0xff (which is non-printable and
	// gets filtered, so result is empty string but no crash).
	in := []byte{'a', 0xff, 0xff, 'b'}
	got := stripTelnetIAC(in)
	if got != "ab" {
		t.Errorf("got %q want %q", got, "ab")
	}
}

func TestStripTelnetIAC_SubNegotiation(t *testing.T) {
	// IAC SB TERMINAL-TYPE IS "xterm" IAC SE
	// = 0xff 0xfa 0x18 0x00 'x' 't' 'e' 'r' 'm' 0xff 0xf0
	// Followed by ASCII "ok".
	in := []byte{0xff, 0xfa, 0x18, 0x00, 'x', 't', 'e', 'r', 'm', 0xff, 0xf0, 'o', 'k'}
	got := stripTelnetIAC(in)
	if got != "ok" {
		t.Errorf("got %q want %q (subnegotiation should be stripped)", got, "ok")
	}
}

func TestStripTelnetIAC_PlainASCII(t *testing.T) {
	in := []byte("login: ")
	got := stripTelnetIAC(in)
	if got != "login:" {
		t.Errorf("got %q want %q", got, "login:")
	}
}

func TestStripTelnetIAC_FullBanner(t *testing.T) {
	// Realistic banner: negotiation + banner text + login prompt.
	in := []byte{
		0xff, 0xfb, 0x01, // IAC WILL ECHO
		0xff, 0xfb, 0x03, // IAC WILL SUPPRESS-GA
		0xff, 0xfd, 0x18, // IAC DO TERMINAL-TYPE
	}
	in = append(in, []byte("Cisco IOS Software, Version 15.4\r\nUser Access Verification\r\nUsername: ")...)
	got := stripTelnetIAC(in)
	if !strings.Contains(got, "Cisco IOS") {
		t.Errorf("got %q — expected Cisco banner", got)
	}
	if strings.ContainsRune(got, 0xff) {
		t.Errorf("got %q — IAC bytes leaked into output", got)
	}
}

func TestStripTelnetIAC_DanglingIAC(t *testing.T) {
	// Truncated IAC at end-of-buffer must not panic or read out of bounds.
	in := []byte{'h', 'i', 0xff}
	got := stripTelnetIAC(in)
	if got != "hi" {
		t.Errorf("got %q — dangling IAC mishandled", got)
	}
}
