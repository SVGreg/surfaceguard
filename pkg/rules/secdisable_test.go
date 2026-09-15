package rules

import "testing"

// TestSecurityDisablementNamesTheControl pins SG-EXE-010.
//
// The rule's precision rests entirely on every leaf naming a *specific*
// security control. Measured over 1,036 bundles, all thirteen spellings below
// appear in 0 files, while a bare `systemctl` appears in 23 — so the `false`
// rows here are not decoration, they are the argument for the narrow list.
func TestSecurityDisablementNamesTheControl(t *testing.T) {
	r := ruleByID(t, "SG-EXE-010")
	cases := []struct {
		name string
		text string
		want bool
	}{
		// (a) mandatory access control
		{"setenforce 0", "setenforce 0\n", true},
		{"sudo setenforce 0", "sudo setenforce 0\n", true},
		{"SELINUX=disabled in a config", "SELINUX=disabled\n", true},
		{"systemctl stop apparmor", "systemctl stop apparmor\n", true},
		{"systemctl disable --now apparmor", "sudo systemctl disable --now apparmor\n", true},
		{"aa-teardown", "aa-teardown\n", true},
		// (b) host firewall
		{"ufw disable", "sudo ufw disable\n", true},
		{"iptables flush", "iptables -F\n", true},
		{"systemctl mask firewalld", "systemctl mask firewalld\n", true},
		{"netsh advfirewall off", "netsh advfirewall set allprofiles state off\n", true},
		// (c) Defender
		{"defender realtime off", "Set-MpPreference -DisableRealtimeMonitoring $true\n", true},
		{"defender exclusion", "Add-MpPreference -ExclusionPath C:\\Users\\Public\\stage\n", true},
		// (d) macOS
		{"gatekeeper off", "spctl --master-disable\n", true},
		{"SIP off", "csrutil disable\n", true},
		// (e) audit
		{"mask auditd", "systemctl mask auditd\n", true},
		{"auditctl disabled", "auditctl -e 0\n", true},
		{"service auditd stop", "service auditd stop\n", true},

		// --- the narrow list is the rule: generic service management must not match ---
		// `systemctl` is in 23 corpus files; a leaf on it would be unusable.
		{"restart an app service", "systemctl restart myapp\n", false},
		{"stop an app service", "sudo systemctl stop nginx\n", false},
		{"enable the skill's own unit", "systemctl enable --now my-skill.service\n", false},
		{"ufw allow is not disable", "sudo ufw allow 8080/tcp\n", false},
		{"iptables list is not flush", "iptables -L -n\n", false},
		{"defender status query", "Get-MpPreference | Select-Object DisableRealtimeMonitoring\n", false},
		{"csrutil status is a query", "csrutil status\n", false},
		{"spctl assess is not a disable", "spctl --assess --type execute /Applications/Foo.app\n", false},
		// launchctl unload is deliberately absent — 3/3 corpus hits are a skill
		// unloading its OWN LaunchAgent in its uninstall instructions.
		{"launchctl unload own agent", "launchctl unload ~/Library/LaunchAgents/com.vendor.my-skill.plist\n", false},
		// The gap must not join a `stop` to a service name in a later command.
		{"service name in a later command", "systemctl stop myapp && systemctl status apparmor\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := len(r.Evaluate("scripts", c.text)) > 0; got != c.want {
				t.Errorf("match=%v, want %v", got, c.want)
			}
		})
	}
}
