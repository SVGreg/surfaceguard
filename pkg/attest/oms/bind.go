package oms

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Binding a transparency-log entry to the bundle it travels in (#333, step 2).
//
// An inclusion proof shows that *some* entry is in the log. It does not show
// that the entry is about *this* signature: Rekor is public, so any genuine
// entry, proof and checkpoint can be copied out of it and pasted into an
// unrelated bundle. What ties an entry to a bundle is its canonicalized body,
// which records the payload hash, the signature and the signing certificate.
// BindsTo decodes that body and requires all three to match.
//
// Only the entry kinds a DSSE bundle is logged as are understood: `dsse`
// 0.0.1 and `intoto` 0.0.2. Any other kind is reported as unbound rather than
// accepted unread — an entry whose meaning cannot be checked proves nothing.

var (
	ErrEntryUnbound   = errors.New("oms: log entry is not bound to this bundle")
	ErrEntryKindUnsup = errors.New("oms: unsupported log entry kind")
)

type rekorBody struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Spec       json.RawMessage `json:"spec"`
}

type rekorHash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// dsse 0.0.1: spec.payloadHash + spec.signatures[{signature, verifier}], where
// signature is base64 signature bytes and verifier is base64 PEM.
type dsseSpec struct {
	PayloadHash *rekorHash `json:"payloadHash"`
	Signatures  []struct {
		Signature string `json:"signature"`
		Verifier  string `json:"verifier"`
	} `json:"signatures"`
}

// intoto 0.0.2: spec.content.payloadHash + spec.content.envelope.signatures
// [{sig, publicKey}], where publicKey is base64 PEM and sig is the envelope's
// base64 signature, itself base64-encoded once more by Rekor's strfmt.Base64.
type intotoSpec struct {
	Content struct {
		PayloadHash *rekorHash `json:"payloadHash"`
		Envelope    struct {
			Signatures []struct {
				Sig       string `json:"sig"`
				PublicKey string `json:"publicKey"`
			} `json:"signatures"`
		} `json:"envelope"`
	} `json:"content"`
}

type loggedSig struct {
	sig      string // base64 as stored in the body
	verifier string // base64 PEM as stored in the body
}

// BindsTo reports whether the entry's canonicalized body records this
// bundle's DSSE payload, one of its signatures, and the given signing
// certificate. A nil error means all three match.
func (e TlogEntry) BindsTo(b *Bundle, leaf *x509.Certificate) error {
	if b == nil || b.DSSEEnvelope == nil {
		return ErrNoEnvelope
	}
	if leaf == nil {
		return fmt.Errorf("%w: no signing certificate to compare", ErrEntryUnbound)
	}
	var body rekorBody
	if err := json.Unmarshal(e.CanonicalizedBody, &body); err != nil {
		return fmt.Errorf("%w: body is not a Rekor entry: %v", ErrEntryUnbound, err)
	}

	var hash *rekorHash
	var logged []loggedSig
	switch {
	case body.Kind == "dsse" && body.APIVersion == "0.0.1":
		var s dsseSpec
		if err := json.Unmarshal(body.Spec, &s); err != nil {
			return fmt.Errorf("%w: dsse spec: %v", ErrEntryUnbound, err)
		}
		hash = s.PayloadHash
		for _, x := range s.Signatures {
			logged = append(logged, loggedSig{x.Signature, x.Verifier})
		}
	case body.Kind == "intoto" && body.APIVersion == "0.0.2":
		var s intotoSpec
		if err := json.Unmarshal(body.Spec, &s); err != nil {
			return fmt.Errorf("%w: intoto spec: %v", ErrEntryUnbound, err)
		}
		hash = s.Content.PayloadHash
		for _, x := range s.Content.Envelope.Signatures {
			logged = append(logged, loggedSig{x.Sig, x.PublicKey})
		}
	default:
		return fmt.Errorf("%w: %s %s", ErrEntryKindUnsup, body.Kind, body.APIVersion)
	}

	payload, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
	if err != nil {
		return fmt.Errorf("oms: DSSE payload is not valid base64: %w", err)
	}
	if hash == nil || !strings.EqualFold(hash.Algorithm, "sha256") {
		return fmt.Errorf("%w: entry carries no sha256 payload hash", ErrEntryUnbound)
	}
	want, err := hex.DecodeString(hash.Value)
	if err != nil {
		return fmt.Errorf("%w: payload hash is not hex", ErrEntryUnbound)
	}
	got := sha256.Sum256(payload)
	if !bytes.Equal(want, got[:]) {
		return fmt.Errorf("%w: entry records payload %x, bundle carries %x", ErrEntryUnbound, want, got)
	}

	sigs, err := Signatures(b)
	if err != nil {
		return err
	}
	for _, l := range logged {
		if !certMatches(l.verifier, leaf) {
			continue
		}
		for _, cand := range sigCandidates(l.sig) {
			for _, s := range sigs {
				if bytes.Equal(cand, s) {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%w: no logged signature matches the bundle's signature and certificate", ErrEntryUnbound)
}

// certMatches decodes a body's base64 PEM verifier and compares it with the
// leaf certificate byte for byte. A public-key verifier never matches: a
// keyless bundle is bound to its certificate, not just to the key in it.
func certMatches(verifier string, leaf *x509.Certificate) bool {
	raw, err := base64.StdEncoding.DecodeString(verifier)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	return bytes.Equal(block.Bytes, leaf.Raw)
}

// sigCandidates returns the signature bytes a body field may denote: one
// base64 layer (dsse) or two (intoto 0.0.2 stores the envelope's base64 sig as
// strfmt.Base64). Both are compared against the raw envelope signature, so a
// field only ever matches the exact bytes the bundle carries.
func sigCandidates(field string) [][]byte {
	once, err := base64.StdEncoding.DecodeString(field)
	if err != nil {
		return nil
	}
	out := [][]byte{once}
	if twice, err := base64.StdEncoding.DecodeString(string(once)); err == nil {
		out = append(out, twice)
	}
	return out
}
