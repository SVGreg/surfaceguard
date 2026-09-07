package rules

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// pack returns a minimal, valid pack body carrying the given apiVersion line.
func pack(apiVersion string) []byte {
	head := ""
	if apiVersion != "" {
		head = "apiVersion: " + apiVersion + "\n"
	}
	return []byte(head + `name: t
version: 1.0.0
rules:
  - id: SG-T-001
    title: t
    severity: low
    targets: [body]
    match:
      any:
        - regex: 'x'
`)
}

// The gate is fail-closed by design: a pack written against a schema this build
// does not know would otherwise load and run under today's semantics, which is
// the same class of bug as an unknown `engine:` (design §8.1) with a wider blast
// radius. Both the current id and the pre-0.5 one are accepted; nothing else is.
func TestAPIVersionGate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		apiVersion string
		wantErr    bool
	}{
		{"current", APIVersion, false},
		{"legacy pre-0.5", LegacyAPIVersion, false},
		{"future major", "surfaceguard.svgreg.net/rulepack.v2", true},
		{"foreign namespace", "example.com/rulepack.v1", true},
		{"nonsense", "potato", true},
		{"missing", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := LoadPack(pack(tc.apiVersion))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("apiVersion %q: loaded, want refusal", tc.apiVersion)
				}
				if !errors.Is(err, ErrAPIVersion) {
					t.Fatalf("apiVersion %q: err = %v, want ErrAPIVersion", tc.apiVersion, err)
				}
				// The message has to name what this build does understand, or the
				// author of an external pack cannot act on it.
				if !strings.Contains(err.Error(), APIVersion) {
					t.Errorf("error does not name the supported id: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("apiVersion %q: %v", tc.apiVersion, err)
			}
			if p.APIVersion != tc.apiVersion {
				t.Errorf("APIVersion = %q, want %q", p.APIVersion, tc.apiVersion)
			}
		})
	}
}

// Every built-in pack must carry the current id — a legacy one shipping inside
// the binary would mean the rename missed a file.
func TestBuiltinPacksDeclareCurrentAPIVersion(t *testing.T) {
	packs, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	if len(packs) == 0 {
		t.Fatal("no built-in packs")
	}
	for _, p := range packs {
		if p.APIVersion != APIVersion {
			t.Errorf("pack %s: apiVersion %q, want %q", p.Name, p.APIVersion, APIVersion)
		}
	}
}

func ExampleLoadPack_unsupportedAPIVersion() {
	_, err := LoadPack(pack("example.com/rulepack.v1"))
	fmt.Println(err)
	// Output: unsupported rule-pack apiVersion: "example.com/rulepack.v1" in pack "t" (this build understands "surfaceguard.svgreg.net/rulepack.v1")
}
