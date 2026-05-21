//go:build !windows

package main

// enableANSI is a no-op on non-Windows platforms, which support ANSI natively.
func enableANSI() {}
