package main

import (
	"fmt"
	"runtime"
	"time"
)

// bannerLines is the six-line ANSI-Shadow ASCII-art wordmark spelling
// "netdoc". Each row is exactly 52 visible characters wide (10 + 8 + 9 + 8 +
// 9 + 8) so callers can append suffix text at a consistent column.
var bannerLines = []string{
	"███╗   ██╗███████╗████████╗██████╗  ██████╗  ██████╗",
	"████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██╔════╝",
	"██╔██╗ ██║█████╗     ██║   ██║  ██║██║   ██║██║     ",
	"██║╚██╗██║██╔══╝     ██║   ██║  ██║██║   ██║██║     ",
	"██║ ╚████║███████╗   ██║   ██████╔╝╚██████╔╝╚██████╗",
	"╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═════╝  ╚═════╝  ╚═════╝",
}

// bannerGradient: one truecolor SGR per banner row, top-to-bottom from
// cyan-300 (lightest) to cyan-800 (darkest). On terminals that don't speak
// 24-bit color the escapes show up as literal text — modern terminals
// (Windows Terminal, iTerm2, kitty, alacritty, recent VS Code) all do.
var bannerGradient = []string{
	"\x1b[38;2;103;232;249m", // cyan-300
	"\x1b[38;2;34;211;238m",  // cyan-400
	"\x1b[38;2;6;182;212m",   // cyan-500
	"\x1b[38;2;8;145;178m",   // cyan-600
	"\x1b[38;2;14;116;144m",  // cyan-700
	"\x1b[38;2;21;94;117m",   // cyan-800
}

// renderBanner prints the wordmark with the given info lines lined up to its
// right, one per row. Used for both the per-run header and --help.
func renderBanner(infoLines []string) {
	for i, line := range bannerLines {
		art := line
		if useColor {
			art = bannerGradient[i] + line + cReset
		}
		info := ""
		if i < len(infoLines) {
			info = "    " + infoLines[i]
		}
		fmt.Println("  " + art + info)
	}
}

// runInfo returns the six right-column lines for a real diagnostic run.
func runInfo(host string) []string {
	return []string{
		col(cBold, "netdoc "+version),
		col(cGray, "──────────────────────────────"),
		col(cGray, "target   ") + col(cCyan, host),
		col(cGray, "started  ") + time.Now().Format("2006-01-02 15:04:05"),
		col(cGray, "system   ") + prettyOS() + " " + runtime.GOARCH,
		col(cGray, "runtime  ") + runtime.Version(),
	}
}

// helpInfo returns the six right-column lines for --help.
func helpInfo() []string {
	return []string{
		col(cBold, "netdoc "+version),
		col(cGray, "──────────────────────────────"),
		col(cGray, "diagnose what's wrong with a connection,"),
		col(cGray, "in one command."),
		"",
		col(cGray, "system   ") + prettyOS() + " " + runtime.GOARCH,
	}
}

// prettyOS turns runtime.GOOS into a nicer label for display.
func prettyOS() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "macos"
	case "linux":
		return "linux"
	default:
		return runtime.GOOS
	}
}
