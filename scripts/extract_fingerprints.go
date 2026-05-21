//go:build ignore

// Helper script: parse Mozilla NSS certdata.txt, extract every cert's DER
// from CKA_VALUE MULTILINE_OCTAL blocks, SHA-256 each, print CA-name +
// SHA-256 fingerprint pairs. Run: go run scripts/extract_fingerprints.go /tmp/certdata.txt
//
// Used to populate tls_distrust.go's FingerprintSHA256 field with verified
// authoritative hashes.

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: extract_fingerprints <certdata.txt>")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)

	var (
		curLabel        string
		readingValue    bool
		valueBytes      []byte
		distrustedAfter bool
	)
	results := []string{}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "CKA_LABEL UTF8 \""):
			// Beginning of a new cert entry — flush previous if any.
			if curLabel != "" && len(valueBytes) > 0 {
				sum := sha256.Sum256(valueBytes)
				tag := "trusted"
				if distrustedAfter {
					tag = "DISTRUSTED-AFTER"
				}
				results = append(results, fmt.Sprintf("%s | %s | %q",
					hex.EncodeToString(sum[:]), tag, curLabel))
			}
			start := strings.Index(line, "\"") + 1
			end := strings.LastIndex(line, "\"")
			curLabel = line[start:end]
			valueBytes = nil
			distrustedAfter = false
			readingValue = false
		case line == "CKA_VALUE MULTILINE_OCTAL":
			readingValue = true
		case line == "END" && readingValue:
			readingValue = false
		case readingValue:
			// Octal-encoded multiline body. Each line: \nnn\nnn\nnn...
			body := strings.ReplaceAll(line, "\\", " ")
			body = strings.TrimSpace(body)
			if body == "" {
				continue
			}
			for _, tok := range strings.Fields(body) {
				n, err := strconv.ParseUint(tok, 8, 8)
				if err != nil {
					continue
				}
				valueBytes = append(valueBytes, byte(n))
			}
		case strings.HasPrefix(line, "CKA_NSS_SERVER_DISTRUST_AFTER MULTILINE_OCTAL"):
			distrustedAfter = true
		}
	}
	// Flush the last entry.
	if curLabel != "" && len(valueBytes) > 0 {
		sum := sha256.Sum256(valueBytes)
		tag := "trusted"
		if distrustedAfter {
			tag = "DISTRUSTED-AFTER"
		}
		results = append(results, fmt.Sprintf("%s | %s | %q",
			hex.EncodeToString(sum[:]), tag, curLabel))
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, r := range results {
		fmt.Println(r)
	}
}
