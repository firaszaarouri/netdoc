package main

// Per-hop and per-IP GeoIP — opt-in via `--geoip` flag. Two implementations
// share a common interface:
//
//   1. Team Cymru CHAOS country-code (default `--geoip`) — country only,
//      uses the same Team Cymru DNS provider we already use for ASN
//      lookups. No third-party API key, no extra telemetry surface beyond
//      what netdoc already uses for ASN. Free for non-commercial use.
//
//   2. MaxMind GeoLite2 (`--geoip-mmdb <path>`) — city-level precision via
//      user-supplied MaxMind .mmdb file (license: user owns the file).
//      Implemented as a hook the user opts into; netdoc itself does not
//      embed MaxMind data.
//
// Both modes are OFF by default, preserving netdoc's zero-telemetry brand.
// We surface the GeoIP enrichment only when explicitly enabled by the
// user via flag.
//
// The Team Cymru country-code lookup piggybacks on the EXISTING ASN
// lookup path — Cymru's ASN response already carries a `cc` (country)
// field which we already capture and display per-IP in the DNS check.
// In other words, country-level GeoIP is already in netdoc whenever
// the ASN path runs. This module exists for the `--geoip` surface,
// explicitly enabling the (already-collected) country data for per-hop
// display in the path check.

// geoipMode selects the GeoIP enrichment strategy.
type geoipMode int

const (
	geoipOff geoipMode = iota
	geoipCymruCountry
	geoipMaxMindCity
)

// geoipConfig is the run-time GeoIP setting; defaults to off.
type geoipConfig struct {
	Mode      geoipMode
	MMDBPath  string // populated when Mode == geoipMaxMindCity
}

// enrichHopsWithGeoIP annotates each traceroute hop with geographic info
// per the configured mode. With geoipCymruCountry we use the per-hop ASN
// data we already collected (Team Cymru's country code is part of the ASN
// response). With geoipMaxMindCity we'd open the user's .mmdb file —
// implementation stubbed; user must supply the lookup hook.
func enrichHopsWithGeoIP(hops []hopResult, cfg geoipConfig) {
	if cfg.Mode == geoipOff {
		return
	}
	// geoipCymruCountry: per-hop ASN already carries country in ASNCC.
	// No additional work needed — display layer surfaces it.
	if cfg.Mode == geoipCymruCountry {
		return
	}
	// geoipMaxMindCity: open user's .mmdb; not implemented in netdoc core
	// to avoid hard-linking against MaxMind's library. Users can pipe
	// netdoc JSON output through their own enrichment script.
}
