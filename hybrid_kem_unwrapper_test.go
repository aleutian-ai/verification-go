// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/sha512"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/cloudflare/circl/kem/xwing"
)

// testWrapXWING generates a key pair using CIRCL, constructs a WrappedKeyV3
// blob manually, and returns the blob bytes, the expected shared secret, and
// the private key. Does not import internal/crypto.
func testWrapXWING(t *testing.T) (wrappedBlob []byte, expectedSS SharedSecret, priv *XWINGPrivateKey) {
	t.Helper()

	// Generate key pair via CIRCL.
	scheme := xwing.Scheme()
	circlPub, circlPriv, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Extract 32-byte seed from CIRCL private key.
	privBytes, err := circlPriv.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary priv: %v", err)
	}
	if len(privBytes) != 32 {
		t.Fatalf("unexpected CIRCL priv size: %d (want 32-byte seed)", len(privBytes))
	}
	priv, err = NewXWINGPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewXWINGPrivateKey: %v", err)
	}

	// Get public key bytes (1216 bytes: 1184 ML-KEM + 32 X25519).
	pubBytes, err := circlPub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary pub: %v", err)
	}
	if len(pubBytes) != 1216 {
		t.Fatalf("unexpected pub size: %d", len(pubBytes))
	}

	// Encapsulate using CIRCL directly.
	ctBytes, ssBytes, err := scheme.Encapsulate(circlPub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(ssBytes) != 32 {
		t.Fatalf("unexpected shared secret size: %d", len(ssBytes))
	}
	copy(expectedSS[:], ssBytes)

	// Build WrappedKeyV3 wire format manually:
	// version(1) | keyID(16) | mlkem_ct(1088) | x25519_epk(32) | mac(32)
	//
	// CIRCL ciphertext is 1120 bytes: mlkem_ct(1088) + x25519_epk(32)
	if len(ctBytes) != 1120 {
		t.Fatalf("unexpected ciphertext size: %d", len(ctBytes))
	}

	// Compute keyID = SHA-512(MLKEMPub || X25519Pub)[:16]
	// Must match internal/crypto/kem.go KeyID() — SHA-512 over full 1216-byte pub key.
	kidHash := sha512.New()
	kidHash.Write(pubBytes[:1184]) // ML-KEM pub
	kidHash.Write(pubBytes[1184:]) // X25519 pub
	kidDigest := kidHash.Sum(nil)
	var keyID [16]byte
	copy(keyID[:], kidDigest[:16])

	blob := make([]byte, 1169)
	blob[0] = 0x03 // version
	copy(blob[1:17], keyID[:])
	copy(blob[17:1105], ctBytes[:1088])   // mlkem_ct
	copy(blob[1105:1137], ctBytes[1088:]) // x25519_epk

	// Compute MAC over bytes [0:1137].
	macH := hmac.New(sha512.New, []byte("aleutian-kem-v3-mac"))
	macH.Write(blob[:1137])
	copy(blob[1137:], macH.Sum(nil))

	return blob, expectedSS, priv
}

// testGeneratePrivateKey creates a fresh private key for testing.
func testGeneratePrivateKey(t *testing.T) *XWINGPrivateKey {
	t.Helper()
	scheme := xwing.Scheme()
	_, circlPriv, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	privBytes, err := circlPriv.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	priv, err := NewXWINGPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewXWINGPrivateKey: %v", err)
	}
	return priv
}

// TestHybridKEMUnwrapperRoundTrip generates a key pair, wraps via CIRCL,
// unwraps via SDK, and asserts the shared secret matches.
func TestHybridKEMUnwrapperRoundTrip(t *testing.T) {
	wrappedBlob, expectedSS, priv := testWrapXWING(t)
	defer priv.Zeroize()

	unwrapper := &HybridKEMUnwrapper{}
	ss, err := unwrapper.Unwrap(context.Background(), wrappedBlob, priv)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	defer ss.Zeroize()

	if ss != expectedSS {
		t.Errorf("shared secret mismatch:\n  got:    %x\n  want:   %x", ss, expectedSS)
	}
}

// TestHybridKEMUnwrapperV1Rejection verifies that a v1 blob returns
// ErrLegacyRSAVersion.
func TestHybridKEMUnwrapperV1Rejection(t *testing.T) {
	priv := testGeneratePrivateKey(t)
	defer priv.Zeroize()

	// Build fake v1 blob with valid MAC.
	blob := make([]byte, 1169)
	blob[0] = 0x01
	macH := hmac.New(sha512.New, []byte("aleutian-kem-v3-mac"))
	macH.Write(blob[:1137])
	copy(blob[1137:], macH.Sum(nil))

	unwrapper := &HybridKEMUnwrapper{}
	_, err := unwrapper.Unwrap(context.Background(), blob, priv)
	if err == nil {
		t.Fatal("expected error for v1 blob, got nil")
	}
	if err != ErrLegacyRSAVersion {
		t.Errorf("error: got %v, want ErrLegacyRSAVersion", err)
	}
}

// TestHybridKEMUnwrapperMACTamper verifies that a flipped MAC byte returns
// ErrInvalidMAC.
func TestHybridKEMUnwrapperMACTamper(t *testing.T) {
	wrappedBlob, _, priv := testWrapXWING(t)
	defer priv.Zeroize()

	// Flip a byte in the MAC field.
	wrappedBlob[1140] ^= 0xFF

	unwrapper := &HybridKEMUnwrapper{}
	_, err := unwrapper.Unwrap(context.Background(), wrappedBlob, priv)
	if err == nil {
		t.Fatal("expected error for tampered MAC, got nil")
	}
	if err != ErrInvalidMAC {
		t.Errorf("error: got %v, want ErrInvalidMAC", err)
	}
}

// TestHybridKEMUnwrapperWrongKey verifies that decapsulating with the wrong
// private key returns a different (non-error) shared secret — this is
// IND-CCA2 implicit rejection per FIPS 203.
func TestHybridKEMUnwrapperWrongKey(t *testing.T) {
	wrappedBlob, expectedSS, priv := testWrapXWING(t)
	defer priv.Zeroize()

	// Generate a different key pair.
	wrongPriv := testGeneratePrivateKey(t)
	defer wrongPriv.Zeroize()

	unwrapper := &HybridKEMUnwrapper{}

	// Wrong key should succeed (implicit rejection) but produce different SS.
	wrongSS, err := unwrapper.Unwrap(context.Background(), wrappedBlob, wrongPriv)
	if err != nil {
		t.Fatalf("Unwrap with wrong key: %v (expected implicit rejection, not error)", err)
	}
	if wrongSS == expectedSS {
		t.Error("wrong key produced the same shared secret — implicit rejection failed")
	}

	// Correct key should produce the expected SS.
	correctSS, err := unwrapper.Unwrap(context.Background(), wrappedBlob, priv)
	if err != nil {
		t.Fatalf("Unwrap with correct key: %v", err)
	}
	if correctSS != expectedSS {
		t.Error("correct key did not produce the expected shared secret")
	}
}

// TestHybridKEMUnwrapperUnknownVersion verifies that an unknown version byte
// returns ErrUnsupportedVersion.
func TestHybridKEMUnwrapperUnknownVersion(t *testing.T) {
	priv := testGeneratePrivateKey(t)
	defer priv.Zeroize()

	// Build fake blob with version 0x04 and valid MAC.
	blob := make([]byte, 1169)
	blob[0] = 0x04
	macH := hmac.New(sha512.New, []byte("aleutian-kem-v3-mac"))
	macH.Write(blob[:1137])
	copy(blob[1137:], macH.Sum(nil))

	unwrapper := &HybridKEMUnwrapper{}
	_, err := unwrapper.Unwrap(context.Background(), blob, priv)
	if err == nil {
		t.Fatal("expected error for unknown version, got nil")
	}
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("error: got %v, want ErrUnsupportedVersion", err)
	}
}

// TestHybridKEMUnwrapperNilKey verifies that a nil private key returns an error.
func TestHybridKEMUnwrapperNilKey(t *testing.T) {
	// Build any valid-looking blob (doesn't matter, should fail before parsing).
	blob := make([]byte, 1169)
	blob[0] = 0x03
	macH := hmac.New(sha512.New, []byte("aleutian-kem-v3-mac"))
	macH.Write(blob[:1137])
	copy(blob[1137:], macH.Sum(nil))

	unwrapper := &HybridKEMUnwrapper{}
	_, err := unwrapper.Unwrap(context.Background(), blob, nil)
	if err == nil {
		t.Fatal("expected error for nil priv, got nil")
	}
}

// TestHybridKEMUnwrapperLabelBytes asserts the XWING label constant matches
// the expected hex value (regression guard against spec drift).
func TestHybridKEMUnwrapperLabelBytes(t *testing.T) {
	expected := []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}
	if len(xwingLabel) != len(expected) {
		t.Fatalf("label length: got %d, want %d", len(xwingLabel), len(expected))
	}
	for i := range expected {
		if xwingLabel[i] != expected[i] {
			t.Errorf("label[%d]: got 0x%02x, want 0x%02x", i, xwingLabel[i], expected[i])
		}
	}
}

// TestExpandDecapsulationKeySDK verifies SHAKE256 expansion determinism and
// that the output can be consumed by ML-KEM and X25519.
func TestExpandDecapsulationKeySDK(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	mlkemSeed1, x25519Priv1 := expandDecapsulationKeySDK(seed)
	mlkemSeed2, x25519Priv2 := expandDecapsulationKeySDK(seed)

	// Deterministic: same seed -> same output.
	if mlkemSeed1 != mlkemSeed2 {
		t.Error("SHAKE256 expansion is not deterministic for mlkemSeed")
	}
	if x25519Priv1 != x25519Priv2 {
		t.Error("SHAKE256 expansion is not deterministic for x25519Priv")
	}

	// Non-zero check.
	allZero := true
	for _, b := range mlkemSeed1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("mlkemSeed is all zeros")
	}

	// Verify output is valid for ML-KEM and X25519.
	_, err := mlkem.NewDecapsulationKey768(mlkemSeed1[:])
	if err != nil {
		t.Errorf("NewDecapsulationKey768 with expanded seed: %v", err)
	}
	_, err = curve25519.X25519(x25519Priv1[:], curve25519.Basepoint)
	if err != nil {
		t.Errorf("X25519 with expanded scalar: %v", err)
	}
}
