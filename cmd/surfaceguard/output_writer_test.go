package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOutputWriterReturnsAnExitErr pins that a bad --out path is reported the
// way every other usage error is — by returning an exitErr the caller can
// propagate — rather than by calling os.Exit from inside a helper.
//
// Before this change outputWriter printed to stderr and exited 3 directly,
// which bypassed the exit-code contract in main.go, skipped the caller's
// deferred closeWriter, and made this path impossible to test at all: a test
// that reached it terminated the test binary.
func TestOutputWriterReturnsAnExitErr(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "no-such-dir", "out.json")

	f, err := outputWriter(bad)
	if err == nil {
		if f != nil && f != os.Stdout {
			_ = f.Close()
		}
		t.Fatal("outputWriter succeeded on a path whose parent directory does not exist")
	}
	if f != nil {
		t.Errorf("outputWriter returned a non-nil file alongside an error: %v", f)
	}

	var ee exitErr
	if !errors.As(err, &ee) {
		t.Fatalf("error is %T, want exitErr so main.go can map it to an exit code", err)
	}
	if ee.code != 3 {
		t.Errorf("exit code = %d, want 3 (usage error)", ee.code)
	}
	// The sibling usage errors all say what to do next; a bare OS error does not.
	if !strings.Contains(ee.msg, bad) {
		t.Errorf("message does not name the offending path: %q", ee.msg)
	}
	if !strings.Contains(ee.msg, "must already exist") {
		t.Errorf("message gives no guidance, unlike every other usage error: %q", ee.msg)
	}
}

// TestOutputWriterDefaultsToStdout: the common path must stay allocation-free
// and must not hand back a file the caller would then close.
func TestOutputWriterDefaultsToStdout(t *testing.T) {
	f, err := outputWriter("")
	if err != nil {
		t.Fatalf("outputWriter(\"\") = %v, want stdout", err)
	}
	if f != os.Stdout {
		t.Errorf("outputWriter(\"\") = %v, want os.Stdout", f)
	}
}
