package main

import "crypto/sha256"

// sha256ForTLS is the package-internal SHA-256 wrapper used by the
// Finished-message transcript hashing. Pulled out so tls_reneg.go doesn't
// have to import crypto/sha256 (which it does transitively via
// tls_crypto.go anyway, but the explicit name makes the call site read
// well at the use site).
func sha256ForTLS(b []byte) [32]byte {
	return sha256.Sum256(b)
}
