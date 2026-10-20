// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// generateMLDSAKeyPair generates a circl ML-DSA-65 key pair for testing.
// Returns the raw 1952-byte public key and the private key.
func generateMLDSAKeyPair(t *testing.T) ([]byte, *mldsa65.PrivateKey) {
	t.Helper()
	scheme := mldsa65.Scheme()
	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("generate ML-DSA-65 key: %v", err)
	}
	concretePub, ok := pub.(*mldsa65.PublicKey)
	if !ok {
		t.Fatalf("pub is not *mldsa65.PublicKey")
	}
	concretePriv, ok := priv.(*mldsa65.PrivateKey)
	if !ok {
		t.Fatalf("priv is not *mldsa65.PrivateKey")
	}
	rawPub, err := concretePub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return rawPub, concretePriv
}

// signAnchorMLDSA signs canonical anchor JSON with ML-DSA-65 and returns base64.
// Pass an anchor with Signature = "" to canonicalize (signature is excluded).
func signAnchorMLDSA(t *testing.T, priv *mldsa65.PrivateKey, anchor Anchor) string {
	t.Helper()
	canonical, err := canonicalizeAnchor(anchor)
	if err != nil {
		t.Fatalf("canonicalize anchor: %v", err)
	}
	scheme := mldsa65.Scheme()
	rawSig := scheme.Sign(priv, canonical, nil)
	return base64.StdEncoding.EncodeToString(rawSig)
}

// makeTestAnchor creates a flat test anchor and signs it with priv.
// The resulting anchor has a valid ML-DSA-65 signature over the canonical JSON.
func makeTestAnchor(t *testing.T, priv *mldsa65.PrivateKey, signingKeyID string) Anchor {
	t.Helper()
	base := Anchor{
		Version:   2,
		AnchorID:  "anc_test123",
		CompanyID: "comp_abc",
		ChainHash: "abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
		Range: EntryRange{
			StartEntryID: "entry_001",
			EndEntryID:   "entry_xyz",
		},
		EntryCount:       100,
		Signature:        "", // Set below after signing.
		SigningKeyID:     signingKeyID,
		CreatedAtMs:      1737374400000, // 2026-01-20T12:00:00Z in ms
		PreviousAnchorID: "anc_prev",
	}
	base.Signature = signAnchorMLDSA(t, priv, base)
	return base
}

func TestCanonicalizeAnchor(t *testing.T) {
	anchor := Anchor{
		Version:   2,
		AnchorID:  "anc_test123",
		CompanyID: "comp_abc",
		ChainHash: "abc123def456",
		Range: EntryRange{
			StartEntryID: "entry_001",
			EndEntryID:   "entry_xyz",
		},
		EntryCount:       100,
		Signature:        "base64signature", // Excluded from canonical form.
		SigningKeyID:     "aleutian-ml-dsa-65-2026-v1",
		CreatedAtMs:      1737374400000,
		PreviousAnchorID: "anc_prev",
	}

	canonical, err := CanonicalizeAnchor(anchor)
	if err != nil {
		t.Fatalf("CanonicalizeAnchor error: %v", err)
	}

	// Verify it's valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal(canonical, &parsed); err != nil {
		t.Fatalf("canonical output is not valid JSON: %v", err)
	}

	// Verify signature is NOT included.
	if _, ok := parsed["signature"]; ok {
		t.Errorf("canonical output should not include signature field")
	}

	// Verify expected flat top-level fields are present.
	for _, field := range []string{"anchor_id", "chain_hash", "company_id", "created_at_ms", "entry_count", "previous_anchor_id", "range", "signing_key_id", "version"} {
		if _, ok := parsed[field]; !ok {
			t.Errorf("canonical output missing field %q", field)
		}
	}

	// Verify nested chain_state / metadata do NOT appear (SC-3).
	for _, field := range []string{"chain_state", "metadata", "region"} {
		if _, ok := parsed[field]; ok {
			t.Errorf("canonical output must not contain field %q (SC-3: flat schema only)", field)
		}
	}

	// Verify determinism.
	canonical2, _ := CanonicalizeAnchor(anchor)
	if string(canonical) != string(canonical2) {
		t.Errorf("canonicalization not deterministic")
	}

	// Verify key ordering is alphabetical — first key must be anchor_id.
	expectedPrefix := `{"anchor_id":`
	if len(canonical) < len(expectedPrefix) || string(canonical[:len(expectedPrefix)]) != expectedPrefix {
		t.Errorf("canonical JSON does not start with %q, got: %s", expectedPrefix, canonical[:min(50, len(canonical))])
	}
}

func TestVerifyAnchorLocally(t *testing.T) {
	ctx := context.Background()

	rawPub, priv := generateMLDSAKeyPair(t)
	anchor := makeTestAnchor(t, priv, "test-verify-key")

	t.Run("valid signature with provided key", func(t *testing.T) {
		err := VerifyAnchorLocally(ctx, anchor, rawPub)
		if err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("valid signature with embedded key", func(t *testing.T) {
		if err := AddPublicKey("test-verify-key", rawPub); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}
		if err := VerifyAnchorLocally(ctx, anchor, nil); err != nil {
			t.Errorf("verification with embedded key failed: %v", err)
		}
	})

	t.Run("tampered data fails verification", func(t *testing.T) {
		tampered := anchor
		tampered.EntryCount = 999
		err := VerifyAnchorLocally(ctx, tampered, rawPub)
		if !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("expected ErrInvalidSignature for tampered anchor, got %v", err)
		}
	})

	t.Run("wrong key fails verification", func(t *testing.T) {
		otherPub, _ := generateMLDSAKeyPair(t)
		err := VerifyAnchorLocally(ctx, anchor, otherPub)
		if !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("expected ErrInvalidSignature for wrong key, got %v", err)
		}
	})

	t.Run("unknown key ID", func(t *testing.T) {
		unknownAnchor := anchor
		unknownAnchor.SigningKeyID = "unknown-key"
		err := VerifyAnchorLocally(ctx, unknownAnchor, nil)
		if !errors.Is(err, ErrUnknownKeyID) {
			t.Errorf("expected ErrUnknownKeyID, got %v", err)
		}
	})

	t.Run("malformed signature base64", func(t *testing.T) {
		badSigAnchor := anchor
		badSigAnchor.Signature = "not-valid-base64!!!"
		err := VerifyAnchorLocally(ctx, badSigAnchor, rawPub)
		if !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("expected ErrInvalidSignature for bad base64, got %v", err)
		}
	})

	t.Run("wrong signature length", func(t *testing.T) {
		shortSigAnchor := anchor
		// A valid base64 string but decodes to wrong length.
		shortSigAnchor.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
		err := VerifyAnchorLocally(ctx, shortSigAnchor, rawPub)
		if !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("expected ErrInvalidSignature for short signature, got %v", err)
		}
	})
}

func TestCanonicalJSONKeyOrder(t *testing.T) {
	anchor := Anchor{
		Version:          2,
		AnchorID:         "test",
		CompanyID:        "test",
		ChainHash:        "test",
		Range:            EntryRange{StartEntryID: "s", EndEntryID: "e"},
		EntryCount:       1,
		SigningKeyID:     "test",
		CreatedAtMs:      0,
		PreviousAnchorID: "test",
	}

	canonical, err := canonicalizeAnchor(anchor)
	if err != nil {
		t.Fatalf("canonicalize error: %v", err)
	}

	// The standard Go encoding/json produces keys in struct field order,
	// which we've defined alphabetically.
	// Expected prefix: {"anchor_id":"test","chain_hash":"test",...}
	expectedPrefix := `{"anchor_id":"test","chain_hash":"test","company_id":"test",`
	if len(canonical) < len(expectedPrefix) || string(canonical[:len(expectedPrefix)]) != expectedPrefix {
		t.Errorf("unexpected canonical JSON start:\n  got:  %s\n  want: %s...",
			string(canonical[:min(80, len(canonical))]), expectedPrefix)
	}

	// Range sub-object: end_entry_id must come before start_entry_id (alphabetical).
	rangeStr := `"range":{"end_entry_id":"e","start_entry_id":"s"}`
	if !contains(string(canonical), rangeStr) {
		t.Errorf("range keys not in alphabetical order, got: %s", canonical)
	}
}

// TestCanonicalJSONVector verifies byte-exact canonical output against a known vector.
// AQ-3: This test vector must match the Python and JS SDK outputs exactly.
func TestCanonicalJSONVector(t *testing.T) {
	anchor := Anchor{
		Version:          2,
		AnchorID:         "anc_abc123",
		CompanyID:        "comp_xyz",
		ChainHash:        "deadbeef",
		Range:            EntryRange{StartEntryID: "entry_first", EndEntryID: "entry_last"},
		EntryCount:       42,
		SigningKeyID:     "aleutian-ml-dsa-65-2026-v1",
		CreatedAtMs:      1737388800000,
		PreviousAnchorID: "",
	}

	canonical, err := canonicalizeAnchor(anchor)
	if err != nil {
		t.Fatalf("canonicalize error: %v", err)
	}

	// AQ-3: Expected byte-exact output matching all three SDK implementations.
	expected := `{"anchor_id":"anc_abc123","chain_hash":"deadbeef","company_id":"comp_xyz","created_at_ms":1737388800000,"entry_count":42,"previous_anchor_id":"","range":{"end_entry_id":"entry_last","start_entry_id":"entry_first"},"signing_key_id":"aleutian-ml-dsa-65-2026-v1","version":2}`
	if string(canonical) != expected {
		t.Errorf("canonical JSON vector mismatch:\n  got:  %s\n  want: %s", canonical, expected)
	}
}

// contains is a simple substring check to avoid importing strings in test-only code.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
