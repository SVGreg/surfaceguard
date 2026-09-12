package rules

import "testing"

// TestUnpinnedDependencyIgnoresIAMPolicyWildcards: SG-DEP-001's quoted-wildcard
// leaf is a generic "JSON key with a wildcard value", which an IAM statement
// satisfies as readily as a dependency manifest. A cloud policy wildcard is a
// real risk — over-privilege (AST03) — but reported here it cites AST02 supply
// chain and offers lockfile advice that cannot be acted on. 8 of the 10 hits
// the leaf produces across the corpus are IAM statements (#263).
func TestUnpinnedDependencyIgnoresIAMPolicyWildcards(t *testing.T) {
	r := ruleByID(t, "SG-DEP-001")
	cases := []struct {
		text string
		want bool
	}{
		// IAM policy documents — verbatim corpus shapes, both spacings.
		{`      "Resource": "*"`, false},
		{`"Resource":"*"`, false},
		{`      "Principal": "*"`, false},
		{`      "Action": "*",`, false},
		{`      "NotResource": "*"`, false},

		// Genuine floating dependency specs must keep firing.
		{`    "version": "latest"`, true},
		{`    "left-pad": "*"`, true},
		{`    "typescript": "latest"`, true},
	}
	for _, c := range cases {
		if got := len(r.Evaluate("configs", c.text)) > 0; got != c.want {
			t.Errorf("%q: match=%v, want %v", c.text, got, c.want)
		}
	}
}
