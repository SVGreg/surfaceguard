package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/SVGreg/surfaceguard/pkg/attest"
	"github.com/SVGreg/surfaceguard/pkg/attest/oms"
	"github.com/SVGreg/surfaceguard/pkg/model"
	"github.com/SVGreg/surfaceguard/pkg/policy"
	"github.com/SVGreg/surfaceguard/pkg/skill"
)

// coSigned builds an envelope over the benign bundle signed by `first`, then
// attaches a second valid signature from `second`. DSSE envelopes carry a list
// of signatures, so this is a well-formed document, not a malformed one.
func coSigned(t *testing.T, first, second *attest.LocalSigner, identity string) (*skill.Bundle, *attest.Envelope) {
	t.Helper()
	b, err := skill.LoadBundle("../../testdata/benign")
	if err != nil {
		t.Fatal(err)
	}
	st := attest.BuildStatement(b, &attest.ScanSummary{Verdict: "pass", MaxSeverity: "low", Version: "t"},
		first, identity, 24*time.Hour)
	env, err := attest.SignWith(context.Background(), st, first)
	if err != nil {
		t.Fatal(err)
	}
	if second != nil {
		raw, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := second.Sign(context.Background(), attest.PAE(attest.PayloadType, raw))
		if err != nil {
			t.Fatal(err)
		}
		env.Signatures = append(env.Signatures, attest.Signature{
			KeyID: second.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig),
		})
	}
	return b, env
}

func rosterKey(s *attest.LocalSigner, identity string) policy.Key {
	return policy.Key{KeyID: s.KeyID(), Algorithm: "ed25519", PublicKey: s.PublicKeyBase64(), Identity: identity}
}

func findingIDs(res *Result) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, f := range res.Findings {
		m[f.RuleID] = f.Severity
	}
	return m
}

// TestRevocationIsNotMaskedByIdentityRejection is the regression for the
// cycle-143 review finding.
//
// A DSSE envelope may carry several signatures. When one is from a revoked key
// and another from a roster key whose identity no trust.identities rule admits,
// both states are true at once. The arms used to be ordered identity-first, so
// the identity arm swallowed the revocation and the result carried only
// SG-PRV-005 (medium) — which verificationFailed does *not* treat as failure,
// while SG-PRV-004 is. A bundle signed by a revoked key therefore verified
// without failing, as long as a second scoped-out signature was attached.
func TestRevocationIsNotMaskedByIdentityRejection(t *testing.T) {
	revoked, err := attest.GenerateKey("revoked-key")
	if err != nil {
		t.Fatal(err)
	}
	scopedOut, err := attest.GenerateKey("scoped-out-key")
	if err != nil {
		t.Fatal(err)
	}
	b, env := coSigned(t, revoked, scopedOut, "evil@example.com")

	roster := policy.Trust{
		Keys: []policy.Key{
			rosterKey(revoked, "evil@example.com"),
			rosterKey(scopedOut, "someone@elsewhere.test"),
		},
		Identities: []policy.IdentityRule{{Pattern: "repo:acme/*"}}, // admits neither
		Revoked:    []string{revoked.KeyID()},
	}

	res := Verify(b, env, roster)
	ids := findingIDs(res)

	if _, ok := ids["SG-PRV-004"]; !ok {
		t.Errorf("revocation masked: no SG-PRV-004 among %v", ids)
	}
	if sev := ids["SG-PRV-004"]; sev != model.SevHigh {
		t.Errorf("SG-PRV-004 severity = %s, want high", sev)
	}
	// Both problems are real and have different fixes, so both are reported.
	if _, ok := ids["SG-PRV-005"]; !ok {
		t.Errorf("identity rejection dropped: no SG-PRV-005 among %v", ids)
	}
	if !res.Revoked || !res.IdentityRejected || res.Trusted {
		t.Errorf("flags wrong: Revoked=%v IdentityRejected=%v Trusted=%v",
			res.Revoked, res.IdentityRejected, res.Trusted)
	}
}

// TestSingleStateReportingUnchanged pins that the reorder did not disturb the
// one-signature cases, which are the overwhelmingly common ones.
func TestSingleStateReportingUnchanged(t *testing.T) {
	t.Run("revoked only", func(t *testing.T) {
		k, err := attest.GenerateKey("k")
		if err != nil {
			t.Fatal(err)
		}
		b, env := coSigned(t, k, nil, "pub@example.com")
		res := Verify(b, env, policy.Trust{
			Keys:    []policy.Key{rosterKey(k, "pub@example.com")},
			Revoked: []string{k.KeyID()},
		})
		ids := findingIDs(res)
		if _, ok := ids["SG-PRV-004"]; !ok {
			t.Errorf("want SG-PRV-004, got %v", ids)
		}
		if _, ok := ids["SG-PRV-005"]; ok {
			t.Errorf("SG-PRV-005 emitted with no identity rejection: %v", ids)
		}
		if !res.Revoked {
			t.Error("Revoked flag not set")
		}
	})

	t.Run("identity rejected only", func(t *testing.T) {
		k, err := attest.GenerateKey("k")
		if err != nil {
			t.Fatal(err)
		}
		b, env := coSigned(t, k, nil, "pub@example.com")
		res := Verify(b, env, policy.Trust{
			Keys:       []policy.Key{rosterKey(k, "pub@example.com")},
			Identities: []policy.IdentityRule{{Pattern: "repo:acme/*"}},
		})
		ids := findingIDs(res)
		if _, ok := ids["SG-PRV-005"]; !ok {
			t.Errorf("want SG-PRV-005, got %v", ids)
		}
		if _, ok := ids["SG-PRV-004"]; ok {
			t.Errorf("revocation claimed with nothing revoked: %v", ids)
		}
		// The old code set Revoked in this arm's sibling; nothing was revoked here.
		if res.Revoked {
			t.Error("Revoked flag set although the roster revokes nothing")
		}
	})

	t.Run("trusted stays trusted", func(t *testing.T) {
		k, err := attest.GenerateKey("k")
		if err != nil {
			t.Fatal(err)
		}
		b, env := coSigned(t, k, nil, "pub@example.com")
		res := Verify(b, env, policy.Trust{Keys: []policy.Key{rosterKey(k, "pub@example.com")}})
		if !res.Trusted || res.Revoked || res.IdentityRejected {
			t.Errorf("clean case disturbed: %+v", findingIDs(res))
		}
	})
}

// TestOMSRevocationIsNotMaskedByIdentityRejection is the same regression on the
// OMS path. An OMS DSSE envelope carries a list of signatures and
// verifyKeyBound tries every roster key against every one, so the two states
// co-occur the same way. OMS is the format other tools verify and the one
// keyless signing uses, which is why the arm could not be left as it was.
func TestOMSRevocationIsNotMaskedByIdentityRejection(t *testing.T) {
	revoked, err := attest.GenerateKeyAlg("sg-revoked-oms", attest.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	scopedOut, err := attest.GenerateKeyAlg("sg-scoped-oms", attest.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	b := &skill.Bundle{Root: "/tmp/demo", Files: []skill.File{
		{Path: "SKILL.md", Content: []byte("---\nname: demo\n---\nbody\n")},
	}}
	signed, err := oms.SignBundle(context.Background(), b, revoked, oms.EnumOptions{})
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	// Attach a second valid signature over the same PAE.
	raw, err := base64.StdEncoding.DecodeString(signed.DSSEEnvelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := scopedOut.Sign(context.Background(),
		attest.PAE(signed.DSSEEnvelope.PayloadType, raw))
	if err != nil {
		t.Fatal(err)
	}
	signed.DSSEEnvelope.Signatures = append(signed.DSSEEnvelope.Signatures,
		oms.Signature{Sig: base64.StdEncoding.EncodeToString(sig2)})
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}

	roster := policy.Trust{
		Keys: []policy.Key{
			{KeyID: revoked.KeyID(), Algorithm: attest.AlgECDSAP256, PublicKey: revoked.PublicKeyBase64(), Identity: "oidc:evil@example.com"},
			{KeyID: scopedOut.KeyID(), Algorithm: attest.AlgECDSAP256, PublicKey: scopedOut.PublicKeyBase64(), Identity: "oidc:other@elsewhere.test"},
		},
		Identities: []policy.IdentityRule{{Pattern: "repo:acme/*"}},
		Revoked:    []string{revoked.KeyID()},
	}

	res := VerifyOMS(b, data, roster)
	ids := findingIDs(res)
	if _, ok := ids["SG-PRV-004"]; !ok {
		t.Errorf("OMS revocation masked: no SG-PRV-004 among %v", ids)
	}
	if !res.Revoked {
		t.Error("Revoked flag not set on the OMS result")
	}
}
