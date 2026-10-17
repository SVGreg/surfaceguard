package attest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SVGreg/surfaceguard/pkg/skill"
)

// TestReservedLineCannotHideSignedLines is the attack: two inserted reserved
// lines with open quotes turn the signed line between them into the inside of
// a string. Before the fix both lines were stripped from the Merkle leaf, so
// the root was unchanged and the signature verified, while the parsed manifest
// had lost `disable-model-invocation: true`.
func TestReservedLineCannotHideSignedLines(t *testing.T) {
	signed := "---\nname: demo\ndescription: Formats CSV files.\ndisable-model-invocation: true\n---\nBody.\n"
	tampered := "---\nname: demo\ndescription: Formats CSV files.\nsignature: \"\ndisable-model-invocation: true\ncontent_hash: \"\n---\nBody.\n"

	rootOf := func(s string) (string, *skill.Bundle) {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, "SKILL.md"), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		b, err := skill.LoadBundle(d)
		if err != nil {
			t.Fatal(err)
		}
		return MerkleRoot(BundleLeaves(b)), b
	}
	r1, b1 := rootOf(signed)
	r2, b2 := rootOf(tampered)
	if _, ok := b1.Manifest.Extra["disable-model-invocation"]; !ok {
		t.Fatal("precondition: the signed manifest should carry disable-model-invocation")
	}
	if _, ok := b2.Manifest.Extra["disable-model-invocation"]; ok {
		t.Fatal("precondition: the tampered manifest should have lost disable-model-invocation to the string")
	}
	if r1 == r2 {
		t.Fatalf("tampered manifest kept the signed root %s: the reserved lines hid a signed line", r1)
	}
}

// TestNormalizeKeepsUnsafeReservedLines pins each shape that must stay in the
// leaf, and each well-formed shape that must still be dropped.
func TestNormalizeKeepsUnsafeReservedLines(t *testing.T) {
	const plain = "---\nname: x\ndescription: y\n---\n\nbody\n"
	cases := []struct {
		name     string
		in       string
		stripped bool // true: normalizes to plain; false: must differ from plain
	}{
		{"writer form, double-quoted", "---\nname: x\ncontent_hash: \"sha256:abc\"\nsignature: \"ed25519:zzz\"\ndescription: y\n---\n\nbody\n", true},
		{"plain scalar", "---\nname: x\ncontent_hash: sha256:abc\ndescription: y\n---\n\nbody\n", true},
		{"single-quoted with escaped quote", "---\nname: x\nsignature: 'ed25519:a''b'\ndescription: y\n---\n\nbody\n", true},
		{"double-quoted with escaped quote", "---\nname: x\nsignature: \"ed25519:a\\\"b\"\ndescription: y\n---\n\nbody\n", true},
		{"CRLF line", "---\nname: x\ncontent_hash: \"sha256:abc\"\r\ndescription: y\n---\n\nbody\n", true},

		{"open double quote", "---\nname: x\nsignature: \"\ndescription: y\n---\n\nbody\n", false},
		{"open single quote", "---\nname: x\nsignature: 'abc\ndescription: y\n---\n\nbody\n", false},
		{"block scalar", "---\nname: x\nsignature: |\n  abc\ndescription: y\n---\n\nbody\n", false},
		{"folded scalar", "---\nname: x\ncontent_hash: >\n  abc\ndescription: y\n---\n\nbody\n", false},
		{"flow mapping", "---\nname: x\nsignature: {a: b}\ndescription: y\n---\n\nbody\n", false},
		{"anchor", "---\nname: x\nsignature: &a abc\ndescription: y\n---\n\nbody\n", false},
		{"empty value (nested map follows)", "---\nname: x\nsignature:\n  description: y\n---\n\nbody\n", false},
		{"well-formed but next line indented", "---\nname: x\nsignature: \"ed25519:zzz\"\n  description: y\n---\n\nbody\n", false},
		{"duplicate key", "---\nname: x\ncontent_hash: \"sha256:abc\"\ndescription: y\ncontent_hash: \"sha256:def\"\n---\n\nbody\n", false},
	}
	for _, c := range cases {
		got := string(NormalizeSkillMD([]byte(c.in)))
		if c.stripped && got != plain {
			t.Errorf("%s: want the reserved line dropped, normalized to %q", c.name, got)
		}
		if !c.stripped && got == plain {
			t.Errorf("%s: an unsafe reserved line was dropped from the leaf", c.name)
		}
	}
}
