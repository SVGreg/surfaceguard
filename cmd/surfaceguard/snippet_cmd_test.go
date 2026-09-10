package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runScan executes the scan command against the malicious fixture, writing the
// text report to a temp file so stdout stays out of the test.
func runScan(t *testing.T, extra ...string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.txt")
	cmd := scanCmd()
	cmd.SetOut(os.NewFile(0, os.DevNull))
	cmd.SetErr(os.NewFile(0, os.DevNull))
	cmd.SetArgs(append([]string{filepath.Join("..", "..", "testdata", "malicious"),
		"--out", out, "--quiet", "--no-color"}, extra...))
	// The fixture fails the gate by design, so a non-nil exitErr is expected.
	_ = cmd.Execute()
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	return string(b)
}

// TestScanSnippetFlagRendersTheSourceFrame covers the wiring: presence of the
// flag (not its value) turns the frame on, and the frame reaches the file the
// user named with --out.
func TestScanSnippetFlagRendersTheSourceFrame(t *testing.T) {
	plain := runScan(t)
	if strings.Contains(plain, "╵") {
		t.Errorf("source frame rendered without --snippet:\n%s", firstLines(plain, 6))
	}

	framed := runScan(t, "--snippet")
	if !strings.Contains(framed, "╵") || !strings.Contains(framed, "│") {
		t.Fatalf("--snippet produced no source frame:\n%s", firstLines(framed, 12))
	}
	// The header gains the column, so a reviewer can jump straight to it.
	if !strings.Contains(framed, "SKILL.md:29:8") {
		t.Errorf("header lost file:line:column:\n%s", firstLines(framed, 12))
	}
	// Bare --snippet means two context lines either side.
	if !strings.Contains(framed, " 27 │") || !strings.Contains(framed, " 31 │") {
		t.Errorf("bare --snippet did not default to 2 context lines:\n%s", firstLines(framed, 20))
	}
}

func TestScanSnippetZeroDropsContextLines(t *testing.T) {
	out := runScan(t, "--snippet=0")
	if !strings.Contains(out, "╵") {
		t.Fatalf("--snippet=0 dropped the frame entirely:\n%s", firstLines(out, 10))
	}
	// With no context, every frame is exactly one source line, so the source
	// rows and the marker rows must come out one for one.
	if src, marks := strings.Count(out, "│"), strings.Count(out, "╵"); src != marks {
		t.Errorf("--snippet=0 printed %d source lines for %d markers (context leaked):\n%s",
			src, marks, firstLines(out, 10))
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
