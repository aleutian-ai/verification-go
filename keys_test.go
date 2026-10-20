// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// generateRawMLDSAPublicKey generates a random raw 1952-byte ML-DSA-65 public key for tests.
func generateRawMLDSAPublicKey(t *testing.T) []byte {
	t.Helper()
	scheme := mldsa65.Scheme()
	pub, _, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	concretePub, ok := pub.(*mldsa65.PublicKey)
	if !ok {
		t.Fatalf("pub is not *mldsa65.PublicKey")
	}
	raw, err := concretePub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return raw
}

func TestGetPublicKey(t *testing.T) {
	publicKey := generateRawMLDSAPublicKey(t)
	testKeyID := "test-get-key"
	if err := AddPublicKey(testKeyID, publicKey); err != nil {
		t.Fatalf("AddPublicKey failed: %v", err)
	}

	t.Run("existing key", func(t *testing.T) {
		key, err := GetPublicKey(testKeyID)
		if err != nil {
			t.Fatalf("GetPublicKey failed: %v", err)
		}
		if !bytes.Equal(key, publicKey) {
			t.Errorf("returned key does not match")
		}
	})

	t.Run("returns defensive copy", func(t *testing.T) {
		key1, _ := GetPublicKey(testKeyID)
		key2, _ := GetPublicKey(testKeyID)
		// Mutate key1 — key2 must be unaffected.
		key1[0] ^= 0xFF
		if bytes.Equal(key1, key2) {
			t.Errorf("GetPublicKey did not return a defensive copy")
		}
		// And the embedded copy must also be unaffected.
		key3, _ := GetPublicKey(testKeyID)
		if !bytes.Equal(key3, publicKey) {
			t.Errorf("embedded key was mutated through defensive copy")
		}
	})

	t.Run("unknown key", func(t *testing.T) {
		_, err := GetPublicKey("nonexistent-key")
		if !errors.Is(err, ErrUnknownKeyID) {
			t.Errorf("expected ErrUnknownKeyID, got %v", err)
		}
	})
}

func TestAddPublicKey(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		publicKey := generateRawMLDSAPublicKey(t)
		if err := AddPublicKey("test-add-valid", publicKey); err != nil {
			t.Errorf("AddPublicKey failed: %v", err)
		}

		retrieved, err := GetPublicKey("test-add-valid")
		if err != nil {
			t.Errorf("GetPublicKey failed: %v", err)
		}
		if !bytes.Equal(retrieved, publicKey) {
			t.Errorf("retrieved key does not match")
		}
	})

	t.Run("invalid key size", func(t *testing.T) {
		shortKey := make([]byte, 16)
		if err := AddPublicKey("test-add-short", shortKey); err == nil {
			t.Errorf("expected error for short key")
		}
	})

	t.Run("overwrite existing key", func(t *testing.T) {
		key1 := generateRawMLDSAPublicKey(t)
		key2 := generateRawMLDSAPublicKey(t)

		keyID := "test-overwrite"
		if err := AddPublicKey(keyID, key1); err != nil {
			t.Fatalf("AddPublicKey key1: %v", err)
		}
		if err := AddPublicKey(keyID, key2); err != nil {
			t.Fatalf("AddPublicKey key2: %v", err)
		}

		retrieved, _ := GetPublicKey(keyID)
		if !bytes.Equal(retrieved, key2) {
			t.Errorf("key was not overwritten")
		}
	})
}

func TestPublicKeySize(t *testing.T) {
	// SC-2: Use ListKeyIDs/GetPublicKey rather than iterating the unexported map.
	for _, keyID := range ListKeyIDs() {
		key, err := GetPublicKey(keyID)
		if err != nil {
			t.Fatalf("GetPublicKey(%s) failed: %v", keyID, err)
		}
		if len(key) != MLDSAPubKeySize {
			t.Errorf("key %s has wrong size: %d, want %d", keyID, len(key), MLDSAPubKeySize)
		}
	}
}

func TestPublicKeysEndpoint(t *testing.T) {
	if PublicKeysEndpoint == "" {
		t.Errorf("PublicKeysEndpoint should not be empty")
	}
	if !strings.HasPrefix(PublicKeysEndpoint, "https://") {
		t.Errorf("PublicKeysEndpoint should use HTTPS: %s", PublicKeysEndpoint)
	}
	if !strings.Contains(PublicKeysEndpoint, "aleutian.ai") {
		t.Errorf("PublicKeysEndpoint should contain aleutian.ai: %s", PublicKeysEndpoint)
	}
}

func TestListKeyIDs(t *testing.T) {
	ids := ListKeyIDs()
	if len(ids) < 2 {
		t.Errorf("expected at least 2 embedded keys, got %d", len(ids))
	}

	// Verify sorted order.
	for i := 1; i < len(ids); i++ {
		if ids[i] < ids[i-1] {
			t.Errorf("ListKeyIDs not sorted: %q < %q at index %d", ids[i], ids[i-1], i)
		}
	}

	// Verify key ID naming convention for Aleutian-embedded keys only.
	// (Test-added keys from other tests may also appear in the map.)
	for _, id := range ids {
		if strings.HasPrefix(id, "aleutian-") && !strings.Contains(id, "ml-dsa-65") {
			t.Errorf("aleutian key ID %q does not follow ml-dsa-65 naming convention", id)
		}
	}
}

func TestIsKnownKey(t *testing.T) {
	for _, id := range ListKeyIDs() {
		if !IsKnownKey(id) {
			t.Errorf("IsKnownKey(%q) returned false for known key", id)
		}
	}
	if IsKnownKey("not-a-real-key-id") {
		t.Errorf("IsKnownKey returned true for unknown key")
	}
	if IsKnownKey("") {
		t.Errorf("IsKnownKey returned true for empty string")
	}
}

func TestValidateEmbeddedKeys(t *testing.T) {
	// SC-1: The embedded placeholder keys are all-zero, so this should fail.
	err := ValidateEmbeddedKeys()
	if err == nil {
		t.Logf("ValidateEmbeddedKeys passed — production keys are embedded")
	} else {
		// Expected during development with placeholder keys.
		if !strings.Contains(err.Error(), "placeholder") {
			t.Errorf("unexpected ValidateEmbeddedKeys error: %v", err)
		}
	}
}
