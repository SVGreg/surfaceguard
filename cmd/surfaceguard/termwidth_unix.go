//go:build unix

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// terminalWidth returns the width in columns of the terminal behind f, or 0
// when f is not a terminal (a pipe, a file named with --out, CI). Reports that
// are not going to a terminal keep the renderer's fixed default width, so
// redirected output stays byte-stable whatever window it was produced in.
//
// This is an ioctl rather than golang.org/x/term because the project's
// dependencies are deliberately cobra + yaml.v3 and stdlib.
func terminalWidth(f *os.File) int {
	var ws struct{ row, col, xpixel, ypixel uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return 0
	}
	return int(ws.col)
}
