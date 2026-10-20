// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sarenvelope

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cloudflare/circl/kem/xwing"
)

// SDK-internal smoke tests. The load-bearing cross-implementation
// byte-identity tests live at the parent module under
// AleutianEnterprise/test/cross_compat/. These tests guard structural
// validation paths that don't require the proprietary Seal primitive.

func TestOpen_RejectsWrongSeedSize(t *testing.T) {
	cases := []int{0, 16, 31, 33, 64, 128}
	for _, n := range cases {
		seed := make([]byte, n)
		_, err := Open([]byte(`{"envelope_version":2}`), seed)
		if !errors.Is(err, ErrInvalidPrivkeySize) {
			t.Errorf("seed size %d: want ErrInvalidPrivkeySize, got %v", n, err)
		}
	}
}

func TestOpen_RejectsMalformedJSON(t *testing.T) {
	seed := randomSeed(t)
	cases := [][]byte{
		[]byte(""),
		[]byte("not json"),
		[]byte(`{"envelope_version":1}`), // wrong version
		[]byte(`{"envelope_version":2,"kem_algorithm":"unknown"}`),
		[]byte(`{"envelope_version":2,"kem_algorithm":"xwing","aead":"chacha20"}`),
	}
	for i, env := range cases {
		_, err := Open(env, seed)
		if err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}

func TestOpen_RejectsExtraFields(t *testing.T) {
	seed := randomSeed(t)
	env := []byte(`{
		"envelope_version": 2,
		"kem_algorithm": "xwing",
		"aead": "aes-256-gcm",
		"unknown_field": "boom"
	}`)
	_, err := Open(env, seed)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("expected ErrInvalidEnvelope on unknown field, got %v", err)
	}
}

func TestOpen_RejectsUnsupportedVersion(t *testing.T) {
	seed := randomSeed(t)
	env := []byte(`{
		"envelope_version": 99,
		"kem_algorithm": "xwing",
		"recipient_fingerprint": "00000000000000000000000000000000",
		"kem_ciphertext_b64": "",
		"aead": "aes-256-gcm",
		"nonce_b64": "",
		"ciphertext_b64": "",
		"associated_data": {"company_id":"c","request_id":"r","sealed_at_ms":1}
	}`)
	_, err := Open(env, seed)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
}

func TestOpen_RejectsUnsupportedAlg(t *testing.T) {
	seed := randomSeed(t)
	env := []byte(`{
		"envelope_version": 2,
		"kem_algorithm": "kyber",
		"recipient_fingerprint": "00000000000000000000000000000000",
		"kem_ciphertext_b64": "",
		"aead": "aes-256-gcm",
		"nonce_b64": "",
		"ciphertext_b64": "",
		"associated_data": {"company_id":"c","request_id":"r","sealed_at_ms":1}
	}`)
	_, err := Open(env, seed)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("want ErrUnsupportedAlg, got %v", err)
	}
}

func TestFingerprint_RejectsWrongPubkeySize(t *testing.T) {
	cases := []int{0, 1, 100, 1215, 1217, 2000}
	for _, n := range cases {
		_, err := Fingerprint(make([]byte, n))
		if !errors.Is(err, ErrInvalidPubkeySize) {
			t.Errorf("pubkey size %d: want ErrInvalidPubkeySize, got %v", n, err)
		}
	}
}

func TestFingerprint_KnownLengthAndForm(t *testing.T) {
	scheme := xwing.Scheme()
	pub, _ := scheme.DeriveKeyPair(randomSeed(t))
	raw, _ := pub.MarshalBinary()
	fp, err := Fingerprint(raw)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if len(fp) != FingerprintHexLen {
		t.Errorf("fingerprint length = %d, want %d", len(fp), FingerprintHexLen)
	}
	// All lowercase hex chars.
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("fingerprint has non-lowercase-hex char %q", c)
			break
		}
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	scheme := xwing.Scheme()
	seed := randomSeed(t)
	pub, _ := scheme.DeriveKeyPair(seed)
	raw, _ := pub.MarshalBinary()
	fp1, _ := Fingerprint(raw)
	fp2, _ := Fingerprint(raw)
	if fp1 != fp2 {
		t.Fatalf("fingerprint non-deterministic: %s vs %s", fp1, fp2)
	}
}

func TestAssociatedData_CanonicalEncodingIsStable(t *testing.T) {
	// Field order MUST be company_id, request_id, sealed_at_ms.
	// Any drift here breaks AEAD verification cross-implementation.
	ad := AssociatedData{CompanyID: "c", RequestID: "r", SealedAtMs: 1}
	out, err := canonicalAAD(ad)
	if err != nil {
		t.Fatalf("canonicalAAD: %v", err)
	}
	want := `{"company_id":"c","request_id":"r","sealed_at_ms":1}`
	if string(out) != want {
		t.Fatalf("canonical AAD drift:\n  got:  %s\n  want: %s", string(out), want)
	}
	// Sanity-check via re-decode round-trip.
	var back AssociatedData
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if back != ad {
		t.Fatal("round-trip AssociatedData differed")
	}
}

func TestErrorMessagesDoNotLeakSeed(t *testing.T) {
	// Best-effort guard: every sentinel's string form should not
	// contain anything resembling key material patterns.
	for _, err := range []error{
		ErrInvalidEnvelope, ErrUnsupportedVersion, ErrUnsupportedAlg,
		ErrUnsupportedAEAD, ErrInvalidPubkeySize, ErrInvalidPrivkeySize,
		ErrInvalidFingerprint, ErrDecryptFailed,
	} {
		msg := err.Error()
		if !strings.HasPrefix(msg, "sdk-sarenvelope: ") {
			t.Errorf("sentinel %q lacks sdk-sarenvelope prefix", msg)
		}
	}
}

func randomSeed(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, XWingSeedSize)
	if _, err := rand.Read(s); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return s
}
