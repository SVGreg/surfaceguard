package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/SVGreg/surfaceguard/pkg/attest"
	"github.com/SVGreg/surfaceguard/pkg/model"
	"github.com/SVGreg/surfaceguard/pkg/policy"
	"github.com/SVGreg/surfaceguard/pkg/scan"
	"github.com/SVGreg/surfaceguard/pkg/skill"
)

// An attestation issued before the 0.5 identifier rename still verifies: the PAE
// is rebuilt from the envelope's own payloadType, so the bytes checked are the
// bytes that were signed. It reports SG-PRV-008 so the holder knows to re-sign,
// and it must NOT report SG-PRV-002, which would say the signature is bad.
func TestVerifyAcceptsLegacyPayloadTypeWithDeprecationFinding(t *testing.T) {
	b, err := skill.LoadBundle("../../testdata/benign")
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	signer, err := attest.GenerateKey("legacy-test")
	if err != nil {
		t.Fatal(err)
	}
	st := attest.BuildStatement(b, &attest.ScanSummary{Verdict: "pass", MaxSeverity: "low", Version: "test"},
		signer, "test@example.com", 24*time.Hour)
	st.Type = attest.LegacyStatementType

	// Sign the legacy way — PAE over the legacy payloadType, exactly as a pre-0.5
	// build would have. Re-labelling a current envelope would test nothing: the
	// payloadType is inside the PAE, so the signature has to be made over it.
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(context.Background(), attest.PAE(attest.LegacyPayloadType, raw))
	if err != nil {
		t.Fatal(err)
	}
	env := &attest.Envelope{
		PayloadType: attest.LegacyPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(raw),
		Signatures: []attest.Signature{{
			KeyID: signer.KeyID(),
			Sig:   base64.StdEncoding.EncodeToString(sig),
		}},
	}

	roster := policy.Trust{Keys: []policy.Key{{
		KeyID:     signer.KeyID(),
		Algorithm: "ed25519",
		PublicKey: signer.PublicKeyBase64(),
		Identity:  "test@example.com",
	}}}
	res := Verify(b, env, roster)

	if !res.SignatureValid {
		t.Fatalf("legacy attestation did not verify: %+v", res.Findings)
	}
	if !res.Trusted {
		t.Fatalf("legacy attestation not trusted: %+v", res.Findings)
	}
	if !hasFinding(res, "Legacy attestation payload type") {
		t.Fatalf("missing SG-PRV-008 deprecation finding: %+v", res.Findings)
	}
	if hasFinding(res, "Unexpected attestation payload type") {
		t.Fatalf("legacy type reported as foreign: %+v", res.Findings)
	}
	for _, f := range res.Findings {
		if f.RuleID == "SG-PRV-008" && f.Severity != model.SevMedium {
			t.Errorf("SG-PRV-008 severity = %q, want medium", f.Severity)
		}
	}
}

// A signature made today carries no deprecation finding.
func TestVerifyCurrentPayloadTypeIsClean(t *testing.T) {
	b, env, _, roster := signedFixture(t)
	res := Verify(b, env, roster)
	if hasFinding(res, "Legacy attestation payload type") {
		t.Fatalf("current attestation reported as legacy: %+v", res.Findings)
	}
}

// The USF payload type stays outside the accepted set. This is the property that
// makes accepting a legacy attestation type safe at all: the USF signature is
// published in plaintext in SKILL.md front-matter, so widening the set to
// anything but attestation types would hand an attacker a replay.
func TestLegacyAcceptanceDoesNotAdmitUSFTypes(t *testing.T) {
	for _, pt := range []string{attest.USFPayloadType, attest.LegacyUSFPayloadType} {
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

// A card written before the rename is still readable — it is a published
// artifact someone else may be holding, and only its identifier changed.
func TestParseCardAcceptsLegacySchemaID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     string
		wantErr bool
	}{
		{"current", scan.CardType, false},
		{"legacy pre-0.5", scan.LegacyCardType, false},
		{"future major", "https://surfaceguard.svgreg.net/skill-card/v2", true},
		{"foreign", "example.com/skill-card/v1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"_type":"` + tc.typ + `","content_hash":"sha256:aa"}`
			_, err := ParseCard([]byte(body))
			if tc.wantErr != (err != nil) {
				t.Fatalf("_type %q: err = %v, wantErr = %v", tc.typ, err, tc.wantErr)
			}
		})
	}
}
