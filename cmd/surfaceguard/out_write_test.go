package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestScanOutReportsAFailedWrite pins the --out write path: a report that
// could not be written in full is exit 4, not a truncated file and success.
// /dev/full fails every write with ENOSPC, the "full disk" case, without
// needing a quota or a tiny filesystem. Text is the format that used to be
// silent (report.Text returns nothing); JSON is the control.
func TestScanOutReportsAFailedWrite(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("/dev/full not available on this platform")
	}
	benign := filepath.Join("..", "..", "testdata", "benign")
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			cmd := scanCmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{benign, "--format", format, "--out", "/dev/full", "--quiet", "--no-color"})
			err := cmd.Execute()
			var ee exitErr
			if !errors.As(err, &ee) || ee.code != 4 {
				t.Fatalf("scan --format %s --out /dev/full: got %v, want exit 4", format, err)
			}
		})
	}
	t.Run("folder", func(t *testing.T) {
		cmd := scanCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{filepath.Join("..", "..", "testdata"), "--out", "/dev/full", "--quiet", "--no-color"})
		err := cmd.Execute()
		var ee exitErr
		if !errors.As(err, &ee) || ee.code != 4 {
			t.Fatalf("folder scan --out /dev/full: got %v, want exit 4", err)
		}
	})
}

// TestScanOutSucceedsOnAWritableFile is the other side of the boundary: a
// normal --out still exits on the verdict alone.
func TestScanOutSucceedsOnAWritableFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "r.txt")
	cmd := scanCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{filepath.Join("..", "..", "testdata", "benign"), "--out", out, "--quiet", "--no-color"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("benign scan --out: %v", err)
	}
	if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
		t.Fatalf("report not written: %v", err)
	}
}
