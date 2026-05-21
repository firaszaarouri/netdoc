//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// enableANSI turns on virtual-terminal processing so ANSI color codes
// render correctly in the Windows console, AND sets the console output
// code page to UTF-8 (CP 65001) so the wordmark gradient and · / →
// glyphs render correctly instead of being mojibake'd into ?'s.
//
// Without the code-page fix, PowerShell 5.x (the default on Windows 10
// and Server 2019) ships CP1252 (Western European), which mangles the
// UTF-8-encoded box-drawing and bullet glyphs in our banner. Setting
// the OutputCP affects only this process — the user's surrounding
// shell is unchanged.
//
// On Windows 11 / PowerShell 7+ / Windows Terminal, UTF-8 is already
// the default; SetConsoleOutputCP(65001) is a no-op there. Harmless.
func enableANSI() {
	const enableVirtualTerminalProcessing = 0x0004
	const codePageUTF8 = 65001

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	setConsoleOutputCP := kernel32.NewProc("SetConsoleOutputCP")

	handle := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	ret, _, _ := getConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if ret != 0 {
		setConsoleMode.Call(uintptr(handle), uintptr(mode|enableVirtualTerminalProcessing))
	}

	// Set CP 65001 — return value ignored; the call is best-effort. On
	// older Windows where SetConsoleOutputCP isn't available the
	// LazyProc.Call returns a non-zero error code which we don't surface.
	setConsoleOutputCP.Call(uintptr(codePageUTF8))
}
