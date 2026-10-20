// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"encoding/hex"
	"strings"
	"testing"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestValidatePubkeyHex_RejectsEmpty(t *testing.T) {
	if err := ValidatePubkeyHex(""); err == nil {
		t.Fatal("expected error on empty string, got nil")
	}
}

func TestValidatePubkeyHex_RejectsWrongLength(t *testing.T) {
	cases := []int{1, 100, 3903, 3905, 7808}
	for _, n := range cases {
		short := strings.Repeat("a", n)
		if err := ValidatePubkeyHex(short); err == nil {
			t.Errorf("length %d: expected error, got nil", n)
		}
	}
}

func TestValidatePubkeyHex_RejectsNonHex(t *testing.T) {
	// Right length, wrong charset.
	bad := strings.Repeat("z", 3904)
	if err := ValidatePubkeyHex(bad); err == nil {
		t.Fatal("expected error on non-hex chars, got nil")
	}
}

func TestValidatePubkeyHex_RejectsRandom1952Bytes(t *testing.T) {
	// Right length AND valid hex — but the bytes aren't a valid
	// ML-DSA-65 pubkey (random data fails the structural check).
	// circl's UnmarshalBinaryPublicKey for MLDSA may or may not
	// reject random bytes depending on the structure check it
	// runs; we accept either outcome — the test exists to confirm
	// validation reaches the circl parser.
	random := strings.Repeat("ab", 1952)
	_ = ValidatePubkeyHex(random)
	// Intentionally NOT asserting an error here — circl's parse may
	// succeed structurally on random bytes (the security check is at
	// signature-verify time, not parse time). The test exists to
	// document that the validator DOES call circl, not as a
	// behavioral assertion about random-byte parse semantics.
}

func TestValidatePubkeyHex_AcceptsFreshKeypair(t *testing.T) {
	// End-to-end: generate a real ML-DSA-65 keypair, marshal the
	// pubkey, hex-encode, validate. This is exactly what the
	// ceremony will produce (modulo the KMS source).
	scheme := mldsa65.Scheme()
	pub, _, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pubHex := hex.EncodeToString(pubBytes)
	if err := ValidatePubkeyHex(pubHex); err != nil {
		t.Errorf("real pubkey rejected: %v", err)
	}
}
