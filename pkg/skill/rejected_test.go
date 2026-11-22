//go:build unix

package skill

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestLoadRejectionsAreErrRejected (#396): every structure the loader refuses
// because it is hostile carries ErrRejected, so a gate can deny it instead of
// treating it like a mistyped path. A missing path and a directory with no
// SKILL.md are caller mistakes and must not carry it.
func TestLoadRejectionsAreErrRejected(t *testing.T) {
	orig := maxBundleSize
	defer func() { maxBundleSize = orig }()

	symlinked := writeBundle(t)
	mkSymlink(t, "/etc/hostname", filepath.Join(symlinked, "link"))

	fifo := writeBundle(t)
	if err := syscall.Mkfifo(filepath.Join(fifo, "pipe"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	big := writeBundle(t)
	if err := os.WriteFile(filepath.Join(big, "pad.bin"), make([]byte, 8192), 0o644); err != nil {
		t.Fatal(err)
	}

	noSkill := t.TempDir()

	linkedDir := filepath.Join(t.TempDir(), "linked")
	mkSymlink(t, writeBundle(t), linkedDir)

	cases := []struct {
		name     string
		src      string
		cap      int64
		rejected bool
	}{
		{"symlink inside bundle", symlinked, orig, true},
		{"fifo inside bundle", fifo, orig, true},
		{"bundle over total cap", big, 4096, true},
		{"missing path", filepath.Join(noSkill, "nope"), orig, false},
		{"no SKILL.md", noSkill, orig, false},
		// A skills dir linking to a checkout is an ordinary dev setup; whether
		// to deny or follow it is a separate decision, so it stays unmarked.
		{"top-level symlinked dir", linkedDir, orig, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			maxBundleSize = c.cap
			_, err := LoadBundle(c.src)
			if err == nil {
				t.Fatal("loaded; want an error")
			}
			if got := errors.Is(err, ErrRejected); got != c.rejected {
				t.Errorf("errors.Is(%q, ErrRejected) = %v, want %v", err, got, c.rejected)
			}
		})
	}
}
