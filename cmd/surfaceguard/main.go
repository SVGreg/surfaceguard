// Command surfaceguard is the CLI over the surfaceguard library (design §10).
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is the binary version (set via -ldflags at release).
var Version = "0.1.0-dev"

func main() {
	root := &cobra.Command{
		Use:   "surfaceguard <command> <path>",
		Short: "Security, signing & provenance toolchain for Agent Skills (SKILL.md)",
		Long: `surfaceguard scans, signs, and verifies Agent Skills (SKILL.md bundles)
against the OWASP Agentic Skills Top 10.

A skill <path> is either:
  • a bundle directory containing a SKILL.md (plus scripts/config), or
  • a single SKILL.md file.

COMMANDS:
  scan     find injection/exfiltration/exec/secret/metadata risks
  guard    decide whether a skill may be loaded: allow, warn, or deny
  sign     Merkle-hash + DSSE-sign a bundle (writes SKILL.md.skillsig)
  verify   check a signature, Merkle root, and trust
  keygen   create an Ed25519 signing key
  version  print version and built-in rule-pack versions

Run 'surfaceguard <command> --help' for input formats, flags, and examples.

EXIT CODES: 0 ok · 1 scan verdict fail · 2 verification failed · 3 usage · 4 internal.`,
		Example: `  surfaceguard scan ./my-skill
  surfaceguard keygen --out publisher.key
  surfaceguard sign ./my-skill --key publisher.key --identity oidc:you@example.com
  surfaceguard verify ./my-skill --policy .surfaceguard.yaml
  surfaceguard guard ./my-skill --format json`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(scanCmd(), guardCmd(), signCmd(), verifyCmd(), keygenCmd(), versionCmd())

	if err := root.Execute(); err != nil {
		// Cobra usage/flag errors → exit 3; command errors set their own code
		// via exitErr.
		if ee, ok := err.(exitErr); ok {
			fmt.Fprintln(os.Stderr, "error:", ee.msg)
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(3)
	}
}

// exitErr carries a specific process exit code (design §10.5).
type exitErr struct {
	code int
	msg  string
}

func (e exitErr) Error() string { return e.msg }

func fail(code int, format string, a ...any) error {
	return exitErr{code: code, msg: fmt.Sprintf(format, a...)}
}

// fileMode returns path's permission bits, or def if they cannot be read. Used
// to report the mode a file actually has instead of the one that was requested.
func fileMode(path string, def os.FileMode) os.FileMode {
	fi, err := os.Stat(path)
	if err != nil {
		return def
	}
	return fi.Mode().Perm()
}
