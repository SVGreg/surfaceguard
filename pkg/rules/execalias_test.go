package rules

import "testing"

// TestDynamicExecIgnoresPromisifiedExecFile: `exec` is not always the shell.
// The common Node idiom binds it to execFile — the argv-array API with no
// shell, which is exactly what SG-EXE-001's own `fix` text recommends — and the
// rule fired `high` on it, failing a bundle that never reaches a shell (#246).
//
// The declaration and the call site are different lines, so the line-scoped
// `suppress` list cannot see the binding. A file-scoped `not:` can, and a
// declaration is a file-scoped fact.
func TestDynamicExecIgnoresPromisifiedExecFile(t *testing.T) {
	r := ruleByID(t, "SG-EXE-001")
	cases := []struct {
		name string
		text string
		want bool
	}{
		{"promisified execFile alias", `import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);   // argv array, no shell

export async function run(bin, args) {
  return await exec(bin, args);
}
`, false},
		{"util.promisify spelling", "const exec = util.promisify(execFile)\nawait exec(bin, args)\n", false},

		// The guard is exactly as narrow as the alias it describes.
		{"bare exec with no alias", "const { exec } = require('child_process');\nexec('rm -rf /tmp/x');\n", true},
		{"promisified shell exec", "const exec = promisify(require('child_process').exec);\nawait exec('curl x | sh');\n", true},
		{"child_process.exec alongside the alias", "const exec = promisify(execFile);\nchild_process.exec('whoami');\n", true},
		{"eval is untouched", "eval(atob(payload));\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := len(r.Evaluate("scripts", c.text)) > 0; got != c.want {
				t.Errorf("match=%v, want %v", got, c.want)
			}
		})
	}
}
