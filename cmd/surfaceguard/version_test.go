package main

import (
	"runtime/debug"
	"testing"
)

// TestVersionFrom pins what the binary claims to be. The string is not
// cosmetic: it reaches a skill card's surfaceguard_version and SARIF's
// tool.driver.version, both of which are provenance, so a build that cannot
// establish its version must say so rather than name one that never shipped.
//
// Only GoReleaser passes -X main.Version. Before this, `go install <mod>@v0.4.0`
// produced a binary reporting "0.1.0-dev" — a version that has never been
// released — in every one of those places.
func TestVersionFrom(t *testing.T) {
	info := func(version string, settings ...debug.BuildSetting) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Version: version}, Settings: settings}
	}
	rev := func(v string) debug.BuildSetting { return debug.BuildSetting{Key: "vcs.revision", Value: v} }
	mod := func(v string) debug.BuildSetting { return debug.BuildSetting{Key: "vcs.modified", Value: v} }

	cases := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		// The bug this fixes: installed by tag, so report the tag.
		{"go install @v0.4.0", info("v0.4.0"), "0.4.0"},
		{"prerelease tag", info("v1.0.0-rc.1"), "1.0.0-rc.1"},

		// A pseudo-version's leading component is derived from the *previous*
		// tag, so reporting it would name an unreleased version (v0.3.1 here).
		// The dev marker plus the commit is both honest and traceable.
		{"pseudo-version, clean", info("v0.3.1-0.20260907131511-7426ae32609e",
			rev("7426ae32609ebc5bf85f8b2e1fdab45102aa0ebb")), "0.1.0-dev+7426ae32609e"},
		{"pseudo-version, dirty", info("v0.3.1-0.20260907131511-7426ae32609e+dirty",
			rev("7426ae32609ebc5bf85f8b2e1fdab45102aa0ebb"), mod("true")),
			"0.1.0-dev+7426ae32609e-dirty"},
		{"pseudo-version, no base tag", info("v0.0.0-20260907131511-7426ae32609e",
			rev("7426ae32609ebc5bf85f8b2e1fdab45102aa0ebb")), "0.1.0-dev+7426ae32609e"},

		{"devel build with a commit", info("(devel)", rev("abcdef0123456789")), "0.1.0-dev+abcdef012345"},
		{"devel build, modified tree", info("(devel)", rev("abcdef0123456789"), mod("true")),
			"0.1.0-dev+abcdef012345-dirty"},

		// Nothing to go on: keep the placeholder rather than invent detail.
		{"devel build, no vcs info", info("(devel)"), devVersion},
		{"empty version", info(""), devVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := versionFrom(devVersion, tc.info); got != tc.want {
				t.Errorf("versionFrom(%q) = %q, want %q", tc.info.Main.Version, got, tc.want)
			}
		})
	}
}

// TestResolveVersionKeepsLdflags: a release build already knows its version and
// must not have it second-guessed by build info.
func TestResolveVersionKeepsLdflags(t *testing.T) {
	if got := resolveVersion("0.4.0"); got != "0.4.0" {
		t.Errorf("resolveVersion(%q) = %q; a release version must be returned unchanged", "0.4.0", got)
	}
}

// TestResolveVersionNeverReportsThePlaceholderAlone guards the actual defect:
// this test binary is built by `go test`, which stamps VCS info, so a build
// that can identify itself must not fall back to the bare placeholder.
func TestResolveVersionResolvesInThisBuild(t *testing.T) {
	got := resolveVersion(devVersion)
	if got == devVersion {
		if info, ok := debug.ReadBuildInfo(); ok {
			var hasRev bool
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					hasRev = true
				}
			}
			if hasRev {
				t.Errorf("build info carries a revision but the version stayed %q", got)
			}
		}
	}
}
