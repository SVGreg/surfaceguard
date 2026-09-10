//go:build !unix

package main

import "os"

// terminalWidth reports "unknown" everywhere the TIOCGWINSZ ioctl is not
// available; the renderer then uses its fixed default width.
func terminalWidth(f *os.File) int { return 0 }
