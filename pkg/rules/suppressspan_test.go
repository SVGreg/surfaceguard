package rules

import "testing"

const spanSuppressPack = `
apiVersion: surfaceguard.svgreg.net/rulepack.v1
name: t
version: 1.0.0
rules:
  - id: SG-T-001
    title: t
    ast: [AST01]
    severity: high
    engine: static
    layer: code
    confidence: 0.9
    targets: [scripts]
    match:
      any:
        - regex: 'CALL\([^)]*FLAG'
    suppress:
      - 'SAFE'
      - '^\s*//'
`

// TestSuppressCoversEveryLineOfTheMatch pins the scope of a rule's carve-outs:
// every line a match touches, and no other. A leaf whose gap crosses a newline
// matches a pretty-printed call starting on its bare `CALL(` line; testing the
// suppress list against that line alone left a carve-out written for the
// call's argument blind to the multi-line form of the same call.
func TestSuppressCoversEveryLineOfTheMatch(t *testing.T) {
	p, err := LoadPack([]byte(spanSuppressPack))
	if err != nil {
		t.Fatal(err)
	}
	r := p.Rules[0]
	cases := []struct {
		name, text string
		lines      []int
	}{
		{"one-line call", "CALL(x, FLAG)\n", []int{1}},
		{"one-line call, carve-out on its line", "CALL(SAFE, FLAG)\n", nil},
		{"multi-line call", "CALL(\n  x,\n  FLAG)\n", []int{1}},
		{"carve-out on a continuation line", "CALL(\n  SAFE,\n  FLAG)\n", nil},
		{"carve-out on the last matched line", "CALL(\n  x, FLAG, SAFE)\n", nil},
		// Each line is tested on its own, so an anchored pattern keeps its
		// meaning instead of seeing only the start of a joined span.
		{"anchored carve-out on a continuation line", "CALL(\n// note\n  FLAG)\n", nil},
		// Lines outside the match are not the match's business.
		{"carve-out on the line before", "SAFE\nCALL(\n  FLAG)\n", []int{2}},
		{"carve-out on the line after", "CALL(\n  FLAG)\nSAFE\n", []int{1}},
		{"carve-out past the gap's end", "CALL(\n  FLAG) x\n  SAFE\n", []int{1}},
	}
	for _, c := range cases {
		var lines []int
		for _, f := range r.Evaluate("scripts", c.text) {
			lines = append(lines, f.StartLine)
		}
		if len(lines) != len(c.lines) {
			t.Errorf("%s: findings on lines %v, want %v", c.name, lines, c.lines)
			continue
		}
		for i := range lines {
			if lines[i] != c.lines[i] {
				t.Errorf("%s: findings on lines %v, want %v", c.name, lines, c.lines)
				break
			}
		}
	}
}

// TestMultiLineShellCallStillFires guards the other direction on a shipped
// rule: widening the carve-out scope must not quiet a pretty-printed sink
// whose lines carry no carve-out.
func TestMultiLineShellCallStillFires(t *testing.T) {
	r := ruleByID(t, "SG-EXE-001")
	got := r.Evaluate("scripts", "subprocess.run(\n    cmd,\n    shell=True,\n)\n")
	if len(got) != 1 || got[0].StartLine != 1 {
		t.Fatalf("want one finding on line 1, got %+v", got)
	}
}
