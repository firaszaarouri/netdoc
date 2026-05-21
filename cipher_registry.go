package main

// Curated subset of the IANA TLS Cipher Suite registry
// (https://www.iana.org/assignments/tls-parameters/tls-parameters.xml).
// Covers what's actually been deployed in the wild: TLS 1.3 AEAD,
// TLS 1.2 ECDHE/DHE/RSA, legacy RC4/3DES/DES/EXPORT, NULL, anonymous DH,
// PSK/SRP, Kerberos, and the obscure families (GOST, Camellia, SEED,
// ARIA, IDEA). Each entry carries a severity label so the cipher
// enumerator can grade a hit on a broken cipher as fail vs informational.

// cipherSpec is one entry in the netdoc cipher catalog.
type cipherSpec struct {
	Code     uint16
	Name     string // IANA name (TLS_xxx_WITH_yyy_zzz)
	Family   string // "TLS13", "ECDHE", "DHE", "RSA", "PSK", "SRP", "KRB5", "ANON", "EXPORT", "GOST", "Camellia", "SEED", "ARIA", "IDEA", "NULL"
	Severity string // "modern", "weak", "broken", "policy", "info"
}

// cipherRegistry is the netdoc-curated catalog. Entries are ordered by
// codepoint so binary search / linear scan are predictable.
var cipherRegistry = []cipherSpec{
	// === NULL family (RFC 5246 §A.5) — encryption disabled, ALWAYS fail.
	{0x0000, "TLS_NULL_WITH_NULL_NULL", "NULL", "broken"},
	{0x0001, "TLS_RSA_WITH_NULL_MD5", "NULL", "broken"},
	{0x0002, "TLS_RSA_WITH_NULL_SHA", "NULL", "broken"},
	{0x003b, "TLS_RSA_WITH_NULL_SHA256", "NULL", "broken"},
	{0xc001, "TLS_ECDH_ECDSA_WITH_NULL_SHA", "NULL", "broken"},
	{0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", "NULL", "broken"},
	{0xc00b, "TLS_ECDH_RSA_WITH_NULL_SHA", "NULL", "broken"},
	{0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA", "NULL", "broken"},
	{0xc015, "TLS_ECDH_anon_WITH_NULL_SHA", "ANON", "broken"},

	// === EXPORT (40-bit/56-bit, broken by design — RFC 2246 §A.5).
	{0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "EXPORT", "broken"},
	{0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "EXPORT", "broken"},
	{0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXPORT", "broken"},
	{0x000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", "EXPORT", "broken"},
	{0x000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXPORT", "broken"},
	{0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "EXPORT", "broken"},
	{0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXPORT", "broken"},
	{0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", "EXPORT", "broken"},
	{0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", "EXPORT", "broken"},
	{0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", "EXPORT", "broken"},
	{0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", "EXPORT", "broken"},
	{0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA", "EXPORT", "broken"},
	{0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", "EXPORT", "broken"},
	{0x002a, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", "EXPORT", "broken"},
	{0x002b, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5", "EXPORT", "broken"},
	{0x0060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5", "EXPORT", "broken"},
	{0x0061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5", "EXPORT", "broken"},
	{0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", "EXPORT", "broken"},
	{0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", "EXPORT", "broken"},
	{0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", "EXPORT", "broken"},
	{0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA", "EXPORT", "broken"},

	// === Plain DES (56-bit single-DES, broken).
	{0x0009, "TLS_RSA_WITH_DES_CBC_SHA", "RSA", "broken"},
	{0x000c, "TLS_DH_DSS_WITH_DES_CBC_SHA", "RSA", "broken"},
	{0x000f, "TLS_DH_RSA_WITH_DES_CBC_SHA", "RSA", "broken"},
	{0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA", "DHE", "broken"},
	{0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA", "DHE", "broken"},
	{0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA", "ANON", "broken"},

	// === 3DES (Sweet32 family — weak; collide on 64-bit blocks).
	{0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "weak"},
	{0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", "DHE", "weak"},
	{0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", "DHE", "weak"},
	{0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "DHE", "weak"},
	{0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE", "weak"},
	{0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "ANON", "weak"},
	{0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "weak"},
	{0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "weak"},
	{0xc00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "weak"},
	{0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "weak"},
	{0xc017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", "ANON", "weak"},

	// === RC4 (BEAST/RC4-NOMORE, broken).
	{0x0004, "TLS_RSA_WITH_RC4_128_MD5", "RSA", "broken"},
	{0x0005, "TLS_RSA_WITH_RC4_128_SHA", "RSA", "broken"},
	{0x0018, "TLS_DH_anon_WITH_RC4_128_MD5", "ANON", "broken"},
	{0xc002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "ECDHE", "broken"},
	{0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDHE", "broken"},
	{0xc00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA", "ECDHE", "broken"},
	{0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE", "broken"},
	{0xc016, "TLS_ECDH_anon_WITH_RC4_128_SHA", "ANON", "broken"},

	// === Kerberos (RFC 2712 — niche; can negotiate alongside Active Directory).
	{0x001e, "TLS_KRB5_WITH_DES_CBC_SHA", "KRB5", "broken"},
	{0x001f, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", "KRB5", "weak"},
	{0x0020, "TLS_KRB5_WITH_RC4_128_SHA", "KRB5", "broken"},
	{0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA", "IDEA", "broken"},
	{0x0022, "TLS_KRB5_WITH_DES_CBC_MD5", "KRB5", "broken"},
	{0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5", "KRB5", "weak"},
	{0x0024, "TLS_KRB5_WITH_RC4_128_MD5", "KRB5", "broken"},
	{0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5", "IDEA", "broken"},

	// === AES_CBC family — TLS 1.0+ baseline. Vulnerable to BEAST in TLS 1.0,
	// CBC oracles (Lucky13, Goldendoodle, etc) in TLS 1.1+. Mark as weak.
	{0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "weak"},
	{0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA", "DHE", "weak"},
	{0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA", "DHE", "weak"},
	{0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "DHE", "weak"},
	{0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", "weak"},
	{0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", "ANON", "broken"},
	{0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", "weak"},
	{0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA", "DHE", "weak"},
	{0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA", "DHE", "weak"},
	{0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "DHE", "weak"},
	{0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", "weak"},
	{0x003a, "TLS_DH_anon_WITH_AES_256_CBC_SHA", "ANON", "broken"},
	{0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", "weak"},
	{0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", "weak"},
	{0x003e, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "DHE", "weak"},
	{0x003f, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", "DHE", "weak"},
	{0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "DHE", "weak"},
	{0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", "weak"},
	{0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "DHE", "weak"},
	{0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "DHE", "weak"},
	{0x006a, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "DHE", "weak"},
	{0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE", "weak"},
	{0x006c, "TLS_DH_anon_WITH_AES_128_CBC_SHA256", "ANON", "broken"},
	{0x006d, "TLS_DH_anon_WITH_AES_256_CBC_SHA256", "ANON", "broken"},

	// === IDEA (RFC 5469 — historically present; weak by 2026 standards).
	{0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA", "IDEA", "broken"},

	// === Anonymous DH families — no peer auth, broken for HTTPS.
	{0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA", "ANON", "broken"},

	// === SEED (Korean, RFC 4162 — KISA-mandated for some Korean services).
	{0x0096, "TLS_RSA_WITH_SEED_CBC_SHA", "SEED", "policy"},
	{0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA", "SEED", "policy"},
	{0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA", "SEED", "policy"},
	{0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA", "SEED", "policy"},
	{0x009a, "TLS_DHE_RSA_WITH_SEED_CBC_SHA", "SEED", "policy"},
	{0x009b, "TLS_DH_anon_WITH_SEED_CBC_SHA", "ANON", "broken"},

	// === GCM/AEAD — TLS 1.2 AEAD baseline (modern).
	{0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", "weak"},
	{0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", "weak"},
	{0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", "modern"},
	{0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", "modern"},
	{0x00a0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", "DHE", "weak"},
	{0x00a1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", "DHE", "weak"},
	{0x00a2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "DHE", "weak"},
	{0x00a3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "DHE", "weak"},
	{0x00a4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "DHE", "weak"},
	{0x00a5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "DHE", "weak"},
	{0x00a6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256", "ANON", "broken"},
	{0x00a7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384", "ANON", "broken"},

	// === PSK (RFC 4279, RFC 5489) — pre-shared key, niche; usually IoT.
	{0x008a, "TLS_PSK_WITH_RC4_128_SHA", "PSK", "broken"},
	{0x008b, "TLS_PSK_WITH_3DES_EDE_CBC_SHA", "PSK", "weak"},
	{0x008c, "TLS_PSK_WITH_AES_128_CBC_SHA", "PSK", "weak"},
	{0x008d, "TLS_PSK_WITH_AES_256_CBC_SHA", "PSK", "weak"},
	{0x008e, "TLS_DHE_PSK_WITH_RC4_128_SHA", "PSK", "broken"},
	{0x008f, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", "PSK", "weak"},
	{0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA", "PSK", "weak"},
	{0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA", "PSK", "weak"},
	{0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA", "PSK", "broken"},
	{0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", "PSK", "weak"},
	{0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA", "PSK", "weak"},
	{0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA", "PSK", "weak"},

	// === ECDHE — TLS 1.2 modern, what most production servers prefer.
	{0xc001, "TLS_ECDH_ECDSA_WITH_NULL_SHA", "NULL", "broken"},
	{0xc002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "ECDHE", "broken"},
	{0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "weak"},
	{0xc004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE", "weak"},
	{0xc005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE", "weak"},
	{0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE", "weak"},
	{0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE", "weak"},
	{0xc00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "weak"},
	{0xc00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", "ECDHE", "weak"},
	{0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "weak"},
	{0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", "weak"},
	{0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "ANON", "broken"},
	{0xc019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "ANON", "broken"},
	{0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE", "weak"},
	{0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE", "weak"},
	{0xc025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE", "weak"},
	{0xc026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE", "weak"},
	{0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "weak"},
	{0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "weak"},
	{0xc029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "weak"},
	{0xc02a, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "weak"},
	{0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "modern"},
	{0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "modern"},
	{0xc02d, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "weak"},
	{0xc02e, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "weak"},
	{0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "modern"},
	{0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "modern"},
	{0xc031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "weak"},
	{0xc032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "weak"},

	// === SRP (RFC 5054 — Secure Remote Password, niche).
	{0xc01a, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", "SRP", "weak"},
	{0xc01b, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", "SRP", "weak"},
	{0xc01c, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", "SRP", "weak"},
	{0xc01d, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA", "SRP", "weak"},
	{0xc01e, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", "SRP", "weak"},
	{0xc01f, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", "SRP", "weak"},
	{0xc020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA", "SRP", "weak"},
	{0xc021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", "SRP", "weak"},
	{0xc022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", "SRP", "weak"},

	// === Camellia (Japanese standard; RFC 5932 / 6367).
	{0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "Camellia", "info"},
	{0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "Camellia", "info"},
	{0x00ba, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", "Camellia", "info"},
	{0x00c0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", "Camellia", "info"},
	{0xc072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "Camellia", "info"},
	{0xc073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "Camellia", "info"},
	{0xc076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "Camellia", "info"},
	{0xc077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", "Camellia", "info"},
	{0xc09c, "TLS_RSA_WITH_AES_128_CCM", "RSA", "modern"},
	{0xc09d, "TLS_RSA_WITH_AES_256_CCM", "RSA", "modern"},
	{0xc09e, "TLS_DHE_RSA_WITH_AES_128_CCM", "DHE", "modern"},
	{0xc09f, "TLS_DHE_RSA_WITH_AES_256_CCM", "DHE", "modern"},
	{0xc0a0, "TLS_RSA_WITH_AES_128_CCM_8", "RSA", "modern"},
	{0xc0a1, "TLS_RSA_WITH_AES_256_CCM_8", "RSA", "modern"},
	{0xc0a4, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", "Camellia", "info"},
	{0xc0a5, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", "Camellia", "info"},
	{0xc0ac, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", "ECDHE", "modern"},
	{0xc0ad, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", "ECDHE", "modern"},
	{0xc0ae, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", "ECDHE", "modern"},
	{0xc0af, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", "ECDHE", "modern"},

	// === ARIA (Korean; RFC 6209).
	{0xc03c, "TLS_RSA_WITH_ARIA_128_CBC_SHA256", "ARIA", "info"},
	{0xc03d, "TLS_RSA_WITH_ARIA_256_CBC_SHA384", "ARIA", "info"},
	{0xc050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256", "ARIA", "info"},
	{0xc051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384", "ARIA", "info"},
	{0xc052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", "ARIA", "info"},
	{0xc053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", "ARIA", "info"},
	{0xc05c, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", "ARIA", "info"},
	{0xc05d, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", "ARIA", "info"},
	{0xc060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", "ARIA", "info"},
	{0xc061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", "ARIA", "info"},

	// === ChaCha20-Poly1305 (RFC 7905).
	{0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "modern"},
	{0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "modern"},
	{0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "DHE", "modern"},
	{0xccab, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256", "PSK", "modern"},
	{0xccac, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", "PSK", "modern"},
	{0xccad, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", "PSK", "modern"},
	{0xccae, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256", "PSK", "modern"},

	// === TLS 1.3 (RFC 8446 §B.4) — modern AEAD baseline.
	{0x1301, "TLS_AES_128_GCM_SHA256", "TLS13", "modern"},
	{0x1302, "TLS_AES_256_GCM_SHA384", "TLS13", "modern"},
	{0x1303, "TLS_CHACHA20_POLY1305_SHA256", "TLS13", "modern"},
	{0x1304, "TLS_AES_128_CCM_SHA256", "TLS13", "modern"},
	{0x1305, "TLS_AES_128_CCM_8_SHA256", "TLS13", "modern"},

	// === GOST (Russian government cipher).
	{0x0080, "TLS_GOSTR341094_WITH_28147_CNT_IMIT", "GOST", "policy"},
	{0x0081, "TLS_GOSTR341001_WITH_28147_CNT_IMIT", "GOST", "policy"},
	{0xc100, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC", "GOST", "policy"},
	{0xc101, "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC", "GOST", "policy"},
	{0xc102, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT", "GOST", "policy"},

	// === Cisco Anyconnect / signaling pseudo-ciphers (RFC 7507 / 8701).
	{0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "RSA", "info"},
	{0x5600, "TLS_FALLBACK_SCSV", "RSA", "info"},
}

// cipherRegistryByCode returns the cipherSpec for a codepoint, or nil if
// not in our catalog. Used by the --each-cipher reporter to label
// accepted ciphers; unknown codes still get probed but show as "0x????".
func cipherRegistryByCode(code uint16) *cipherSpec {
	for i := range cipherRegistry {
		if cipherRegistry[i].Code == code {
			return &cipherRegistry[i]
		}
	}
	return nil
}

// cipherRegistryAllCodes returns every codepoint in our catalog, used by
// the --each-cipher elimination algorithm.
func cipherRegistryAllCodes() []uint16 {
	out := make([]uint16, 0, len(cipherRegistry))
	seen := make(map[uint16]bool)
	for _, c := range cipherRegistry {
		if seen[c.Code] {
			continue
		}
		seen[c.Code] = true
		out = append(out, c.Code)
	}
	return out
}
