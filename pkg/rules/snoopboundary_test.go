package rules

import "testing"

// TestSnoopingStopsAtCommandBoundaries pins the cycle-132 polish of SG-AS-001.
//
// Three separate false-positive mechanisms, all measured on real corpora:
//
//  1. the verb->path window spanned a shell command boundary, so a read verb in
//     one command was joined to a path in the next;
//  2. `cat > path` is a *write*, which this rule's own spec assigns to
//     SG-INJ-004, and the read-verb leaf claimed it anyway;
//  3. #272 carved out install instructions by keying on a directional
//     preposition, which the command form does not have (#294).
//
// Every `false` row below is a verbatim line from a scanned corpus.
func TestSnoopingStopsAtCommandBoundaries(t *testing.T) {
	r := ruleByID(t, "SG-AS-001")
	cases := []struct {
		name string
		text string
		want bool
	}{
		// --- (1) the window must not cross a command boundary ---
		// Note: a negative row here must contain exactly ONE read verb. The
		// first draft used `cat … ; open .claude/settings.json`, which fails
		// correctly — `open` is itself a read verb sitting next to the path, so
		// the row tested nothing about boundaries.
		// skillject/skill-developer-diet103, 5 hits. cat reads a HEREDOC; the
		// .claude/ path is tsx's argument, in the next command.
		{"fp: heredoc piped to another command", "cat <<'EOF' | npx tsx .claude/hooks/skill-verification-guard.ts\n", false},
		{"fp: verb and path split by a semicolon", "cat notes.txt ; npx tsx .claude/hooks/guard.ts\n", false},
		{"fp: verb and path split by &&", "grep -q ok build.log && npx tsx .claude/agents/run.ts\n", false},

		// --- (2) a redirect is a write, and belongs to SG-INJ-004 ---
		// orgs/trailofbits chrome-mcp-troubleshooting:136 — the regression anchor.
		{"fp: cat > into .claude is a write", "cat > ~/.claude/chrome/chrome-native-host << 'EOF'\n", false},

		// --- (3) an install writes INTO the skills dir (#294) ---
		// clawhub sweep 2026-09-13, 4 hits.
		{"fp: upgrade copies skills dir to skills dir", "cp -Rf ~/.claude/skills/gstack .claude/skills/gstack && rm -rf .claude/skills/gstack/.git\n", false},
		{"fp: install copies a built artifact in", "cp browse/dist/browse ~/.claude/skills\n", false},
		{"fp: install via mv", "mv dist/tool ~/.claude/skills\n", false},
		// #272's prose form must keep working.
		{"fp: prose install instruction", "Copy it to `~/.claude/skills`.\n", false},

		// --- the rule's actual job, all still caught ---
		{"config read", "cat ~/.claude/mcp.json\n", true},
		{"settings read", "less ~/.claude/settings.json\n", true},
		{"jq into cursor config", "jq '.mcpServers' ~/.cursor/mcp.json\n", true},
		{"macOS desktop config (the #179 window)", "cat ~/Library/Application Support/Claude/claude_desktop_config.json\n", true},
		{"peer enumeration", "ls ~/.claude/skills/\n", true},
		// A separator AFTER the path is untouched — the bound is on the gap,
		// not on the line. Both are verbatim corpus lines.
		{"read then pipe to jq", "cat .claude/settings.json | jq '.hooks.UserPromptSubmit'\n", true},
		{"read skills registry then pipe", "cat .claude/skills/skill-rules.json | jq .\n", true},
		{"read with stderr redirect after the path", "cat ~/.claude/chrome/host 2>/dev/null || echo none\n", true},
		// The skills path as the *source* is exactly what the rule is for, and
		// the install carve-out must not reach it.
		{"copy a peer's file OUT", "cp ~/.claude/skills/other-skill/secrets.env .\n", true},
		{"listing peers has no destination", "ls -la .claude/skills\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := len(r.Evaluate("scripts", c.text)) > 0; got != c.want {
				t.Errorf("match=%v, want %v", got, c.want)
			}
		})
	}
}
