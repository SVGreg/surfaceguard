package rules

import "testing"

// TestLoadDotenvBindsToItsArgument pins issue #339. `load_dotenv` used to share
// the free {0,120} verb window, so documentation of the SDK's precedence —
// "`load_dotenv(override=False)`, so an existing process environment value wins
// over `.env`" (microsoft/azure-skills) — was a critical sensitive-path read:
// the window ran past the call's closing paren to a `.env` later in the
// sentence. The call now binds only to a path inside its own argument list.
func TestLoadDotenvBindsToItsArgument(t *testing.T) {
	var r *Rule
	packs, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	for _, p := range packs {
		for _, x := range p.Rules {
			if x.ID == "SG-SEC-001" {
				r = x
			}
		}
	}
	if r == nil {
		t.Fatal("SG-SEC-001 not found")
	}
	cases := []struct {
		text string
		want bool
	}{
		// The reported false positive and its siblings: the path is prose after
		// the call, not the call's argument.
		{"`load_dotenv(override=False)`, so an existing process environment value wins over `.env`", false},
		{"load_dotenv() reads the values from your .env file", false},
		{"from dotenv import load_dotenv; load_dotenv()  # picks up ./.env and ~/.ssh is untouched", false},
		{"dotenv.load_dotenv(dotenv.find_dotenv(usecwd=True))", false},

		// A credential path as the argument is still a credential read.
		{`load_dotenv(os.path.expanduser("~/.aws/credentials"))`, true},
		{`load_dotenv(Path.home() / ".aws" / "credentials")`, true},
		{`load_dotenv(dotenv_path="/home/user/.ssh/id_rsa")`, true},
		{`load_dotenv("../other-skill/.env")`, true},

		// The other verbs keep the free window: removing load_dotenv from the
		// verb list must not have narrowed them.
		{"cat ~/.aws/credentials", true},
		{`open("/home/user/.config/app/.env")`, true},
	}
	for _, c := range cases {
		if got := len(r.Evaluate("scripts", c.text)) > 0; got != c.want {
			t.Errorf("%q: got match=%v want %v", c.text, got, c.want)
		}
	}
}
