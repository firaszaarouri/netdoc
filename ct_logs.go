package main

import (
	"encoding/hex"
	"strings"
)

// Certificate Transparency log database. Curated from Google's canonical
// log_list.json (https://www.gstatic.com/ct/log_list/v3/log_list.json) on
// 2026-05-20. The list rotates each year as logs expire and new annual
// shards come online; refresh by re-running the fetch script in the commit
// that adds this file.
//
// Each entry maps a 32-byte log_id (SHA-256 of the log's SubjectPublicKeyInfo
// per RFC 6962 §3.2) to the human-readable log name.

var ctLogs = map[string]string{
	"0e5794bcf3aea93e331b2c9907b3f790df9bc23d713225dd21a925ac61c54e21": "Google Argon2026h1",
	"d76d7d10d1a7f577c2c7e95fd700bff982c9335a65e1d0b3017317c0c8c56977": "Google Argon2026h2",
	"d6d58da9d01753f36a4aa0c7574902afebc7dc2cd38cd9f764c80c89191e9f02": "Google Argon2027h1",
	"969764bf555897adf743876837084277e9f03ad5f6a4f3366e46a43f0fcaa9c6": "Google Xenon2026h1",
	"d809553b944f7affc816196f944f85abb0f8fc5e8755260f15d12e72bb454b14": "Google Xenon2026h2",
	"44c2bd0ce9140e64a5c94a01930a5aa1bb35970e00ee111689682a1c44d7b566": "Google Xenon2027h1",
	"cb38f715897c84a1445f5bc1ddfbc96ef29a59cd470a690585b0cb14c31458e7": "Cloudflare Nimbus2026",
	"4c63dc98e59c1dab88f61e8a3ddeae8fab44a3377b5f9b94c3fba19cfcc1be26": "Cloudflare Nimbus2027",
	"6411c46ca412eca7891ca2022e00bcab4f2807d41e3527abeafed503c97dcdf0": "DigiCert Wyvern2026h1",
	"c2317e574519a345ee7f38deb29041ebc7c2215a22bf7fd5b5ad769ad90e52cd": "DigiCert Wyvern2026h2",
	"001a5d1a1c2d9375b6485578f82f71a1ae6eef397d297c8ae3157bcadee1a01e": "DigiCert Wyvern2027h1",
	"37aa07cc216f2e6d919c709d24d8f731b00f2b147c621cc091a5fa1a84d816dd": "DigiCert Wyvern2027h2",
	"499c9b69de1d7cecfc36decd8764a6b85baf0a878019d15552fbe9eb29ddf8c3": "DigiCert Sphinx2026h1",
	"944e4387faecc1ef81f3192426a8186501c7d35f3802013f72677d55372e19d8": "DigiCert Sphinx2026h2",
	"46a23967c60db64687c66f3df999947693a6a611208457d555e7e3d0a1d9b646": "DigiCert Sphinx2027h1",
	"1fb0f8a92d8adda121776c05e2aa2e15bacbc62b65393695576aaab52e11d11d": "DigiCert Sphinx2027h2",
	"252f94c22b29e96e9f411a72072b695c5b52ff97a90d2540bbfcdc51ec4dee0b": "Sectigo Mammoth2026h1",
	"94b1c18ab0d057c47be0ac040e1f2cbc8dc375727bc951f20a526126863ba73c": "Sectigo Mammoth2026h2",
	"566cd5a376be83dfe342b675c49c232498a769bac382cbab49a3877d9ab32d01": "Sectigo Sabre2026h1",
	"1f56d1ab94704a41dd3feafdf4699355302c1431bfe61346089fffae795dcc2f": "Sectigo Sabre2026h2",
	"d16ea9a568077e6635a03f37a5ddbc03a53c411214d48818f5e931b323cb9504": "Sectigo Elephant2026h1",
	"af67883b57b04edd8fa6d97ef62ea8eb810ac77160f0245e55d60c2fe785873a": "Sectigo Elephant2026h2",
	"604c9aaf7a7f775f01d406fc920dc899eb0b1c7df8c9521bfafa17773b978bc9": "Sectigo Elephant2027h1",
	"a2490cdcdb8e33a400321760d6d4d51a2036191ea77d968be26a8a00f6fffff7": "Sectigo Elephant2027h2",
	"16832dabf0a9250f0ff03aa545ffc8bfc823d0874bf6042927f8e71f3313f5fa": "Sectigo Tiger2026h1",
	"c8a3c47fc7b3adb9356b013f6a7a126de33a4e43a5c646f997ad3975991dcf9a": "Sectigo Tiger2026h2",
	"1c9f682ce9faf0456950f81b968a87dddb3210d84ce6c8b2e382524ac4cf599f": "Sectigo Tiger2027h1",
	"03802ac262f6e05e03f8bc6f7b9851324fd76a3df5b7595175e222fb8e9bd5f6": "Sectigo Tiger2027h2",
	"74db9d58f7d47e9dfd787a162a991c18cf698da7c729918c9a18b0450dba44bc": "TrustAsia log2026a",
	"25b7efdea1130193ed93079770aa322a26620de35ac8aa7c75197de0b1a9e065": "TrustAsia log2026b",
	"eddaeb815c63213449b47be5077905abd0d93147c27ac5146b3bc58e43e9b6c7": "TrustAsia HETU2027",
}

// ctLogName returns the human-readable log name for the given 32-byte log_id,
// or an abbreviated hex representation when we don't recognise it. We keep
// the unknown-log fallback short so the hint line doesn't overflow.
func ctLogName(logID []byte) string {
	if len(logID) != 32 {
		return ""
	}
	key := hex.EncodeToString(logID)
	if name, ok := ctLogs[strings.ToLower(key)]; ok {
		return name
	}
	return "unknown log (" + key[:12] + ")"
}

// listSCTLogs walks the X.509 SCT extension on a cert and returns the
// per-SCT log names. Empty when the extension isn't present or the bytes
// don't parse cleanly. Caller uses this for the hint line; SCT counting
// still lives in countEmbeddedSCTs.
func listSCTLogs(extValue []byte) []string {
	body := extValue
	if len(body) >= 2 && body[0] == 0x04 {
		switch {
		case body[1] < 0x80:
			body = body[2:]
		case body[1] == 0x81 && len(body) >= 3:
			body = body[3:]
		case body[1] == 0x82 && len(body) >= 4:
			body = body[4:]
		}
	}
	if len(body) < 2 {
		return nil
	}
	listLen := int(body[0])<<8 | int(body[1])
	rest := body[2:]
	if listLen > len(rest) {
		return nil
	}
	rest = rest[:listLen]

	var names []string
	for i := 0; i+2 <= len(rest); {
		sctLen := int(rest[i])<<8 | int(rest[i+1])
		i += 2
		if i+sctLen > len(rest) {
			break
		}
		sct := rest[i : i+sctLen]
		// SCT v1 layout (RFC 6962 §3.2):
		//   1 byte version (0)
		//   32 bytes log_id
		//   8 bytes timestamp
		//   2 bytes extensions_length + extensions
		//   2 bytes signature_algorithm
		//   2 bytes signature_length + signature
		if len(sct) >= 33 {
			logID := sct[1:33]
			if name := ctLogName(logID); name != "" {
				names = append(names, name)
			}
		}
		i += sctLen
	}
	return names
}
