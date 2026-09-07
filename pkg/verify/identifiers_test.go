package verify

import (
	"testing"

	"github.com/SVGreg/surfaceguard/pkg/attest"
	"github.com/SVGreg/surfaceguard/pkg/scan"
)

// The accepted payload type is a set of exactly one. Anything else — a foreign
// protocol, a pre-rename spelling, or the USF type — is refused before the
// crypto runs.
//
// The USF entries are the security-relevant half: that signature is published
// in plaintext in SKILL.md front-matter, so an envelope shaped like an
// attestation can always be assembled around it. The payload-type gate is what
// makes that replay fail.
func TestOnlyTheCurrentPayloadTypeIsAccepted(t *testing.T) {
	for _, pt := range []string{
		attest.USFPayloadType,
		"application/vnd.surfaceguard.attestation.v2+json",
		"application/vnd.in-toto+json",
		"text/plain",
		"",
	} {
		b, env, _, roster := signedFixture(t)
		env.PayloadType = pt
		res := Verify(b, env, roster)
		if res.SignatureValid || res.Trusted {
			t.Fatalf("payloadType %q accepted as an attestation: %+v", pt, res)
		}
		if !hasFinding(res, "Unexpected attestation payload type") {
			t.Fatalf("payloadType %q: missing rejection finding: %+v", pt, res.Findings)
		}
	}
}

func TestCurrentPayloadTypeVerifiesCleanly(t *testing.T) {
	b, env, _, roster := signedFixture(t)
	if env.PayloadType != attest.PayloadType {
		t.Fatalf("fixture payloadType = %q, want %q", env.PayloadType, attest.PayloadType)
	}
	res := Verify(b, env, roster)
	if !res.SignatureValid || !res.Trusted {
		t.Fatalf("round trip did not verify: %+v", res.Findings)
	}
	for _, f := range res.Findings {
		if f.RuleID == "SG-PRV-002" {
			t.Fatalf("payload-type finding on a current attestation: %+v", f)
		}
	}
}

// A card carrying any other schema id is a document this build cannot check.
func TestParseCardAcceptsOnlyTheCurrentSchemaID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     string
		wantErr bool
	}{
		{"current", scan.CardType, false},
		{"future major", "https://surfaceguard.svgreg.net/skill-card/v2", true},
		{"foreign", "example.com/skill-card/v1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCard([]byte(`{"_type":"` + tc.typ + `","content_hash":"sha256:aa"}`))
			if tc.wantErr != (err != nil) {
				t.Fatalf("_type %q: err = %v, wantErr = %v", tc.typ, err, tc.wantErr)
			}
		})
	}
}
