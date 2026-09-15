package main

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSignRejectsTTLThatExpiresImmediately pins the --ttl-days bound found in
// the cycle-136 review of pkg/attest.
//
// BuildStatement computes time.Duration(ttlDays) * 24 * time.Hour. Duration is
// int64 nanoseconds, so the product overflows above 106,751 days (~292 years):
// at 106752 it wraps negative and expires_at lands in 1734. Both ends of the
// range produced an attestation that was *born expired* while `sign` reported
// success, leaving `verify` to blame the artifact (SG-PRV-004) rather than the
// flag that made it.
func TestSignRejectsTTLThatExpiresImmediately(t *testing.T) {
	cases := []struct {
		name string
		days int
		ok   bool
	}{
		{"default", 365, true},
		{"one day", 1, true},
		{"at the documented maximum", maxTTLDays, true},
		{"zero expires at issue time", 0, false},
		{"negative expires in the past", -1, false},
		{"just past the maximum", maxTTLDays + 1, false},
		// The value where the int64 nanosecond product actually wraps.
		{"the overflow point", 106752, false},
		{"far past the overflow point", 200000, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := signCmd()
			cmd.SetArgs([]string{"--ttl-days", strconv.Itoa(c.days), "--key", "missing.key", "some-bundle"})
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			err := cmd.Execute()
			mentionsTTL := err != nil && strings.Contains(err.Error(), "--ttl-days")
			if c.ok && mentionsTTL {
				t.Errorf("ttl-days=%d rejected, want accepted: %v", c.days, err)
			}
			if !c.ok && !mentionsTTL {
				t.Errorf("ttl-days=%d accepted, want rejected (got %v)", c.days, err)
			}
		})
	}
}

// TestTTLOverflowIsRealArithmetic documents *why* the bound exists, so a future
// widening has to contend with the number rather than the opinion.
//
// The days values go through a variable on purpose. Written as constants, Go
// refuses to compile `time.Duration(106752) * 24 * time.Hour` — "overflows
// int64" — which is exactly why the bug was invisible: the compiler catches the
// constant form, and `sign` only ever computes it from a runtime flag.
func TestTTLOverflowIsRealArithmetic(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	ttlOf := func(days int) time.Time { return now.Add(time.Duration(days) * 24 * time.Hour) }

	safe := maxTTLDays
	if exp := ttlOf(safe); !exp.After(now) {
		t.Fatalf("maxTTLDays=%d already overflows: expires_at=%s", safe, exp)
	}
	lastGood := 106751
	if exp := ttlOf(lastGood); !exp.After(now) {
		t.Fatalf("%d days should still be positive, got expires_at=%s", lastGood, exp)
	}
	wrap := 106752
	if exp := ttlOf(wrap); exp.After(now) {
		t.Fatalf("expected %d days to overflow int64 nanoseconds, got expires_at=%s", wrap, exp)
	} else if exp.Year() > 1800 {
		t.Errorf("overflow should land expires_at deep in the past, got %s", exp.Format(time.RFC3339))
	}
}
