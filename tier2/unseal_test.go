// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package tier2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

// =============================================================================
// Test helpers: in-test producer that mirrors the internal sealer's primitives.
//
// The SDK's correctness contract is "byte-equivalent to the internal Tier-2
// producer." This test harness re-implements the producer-side flow using
// IDENTICAL primitives, so a roundtrip (seal here → OpenBundle) proves the
// SDK's algorithm is wire-compatible with anything else that uses the same
// spec. When the internal producer eventually emits golden vector fixtures
// (see ticket follow-up), those fixtures can be loaded here and the helper
// can be retired.
// =============================================================================

// testKeypair holds an X-Wing seed + its derived pubkey + fingerprint.
type testKeypair struct {
	seed        []byte
	pubkey      []byte // 1216-byte canonical X-Wing pubkey
	fingerprint string // 32-char lowercase hex
}

// genTestKeypair creates a fresh X-Wing keypair for testing.
func genTestKeypair(t *testing.T) testKeypair {
	t.Helper()
	seed := make([]byte, XWingSeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := derivePubkey(seed)
	if err != nil {
		t.Fatalf("derivePubkey: %v", err)
	}
	h := sha512.Sum512(pub)
	fp := hex.EncodeToString(h[:fingerprintHexLen/2])
	return testKeypair{seed: seed, pubkey: pub, fingerprint: fp}
}

// sealCEKToPubkey wraps a CEK to a recipient pubkey using the exact
// primitives from the spec, producing a CEKWrapEnvelope that
// OpenBundle should be able to open.
func sealCEKToPubkey(t *testing.T, cek []byte, kp testKeypair, bundleID string, envelopeIndex int64) CEKWrapEnvelope {
	t.Helper()
	if len(cek) != aesKeySize {
		t.Fatalf("cek must be %d bytes", aesKeySize)
	}

	// X-Wing encapsulate to the recipient pubkey.
	kemCT, ss := xwingEncapsulate(t, kp.pubkey)

	// Derive wrap key from the shared secret using the SDK's KDF.
	wrapKey, err := deriveCEKWrapKey(ss, bundleID, kp.fingerprint)
	if err != nil {
		t.Fatalf("deriveCEKWrapKey: %v", err)
	}

	// Build §2.2 AAD with envelope_kind="cek".
	aad, err := buildAAD(bundleID, "", envelopeKindCEK, 0, envelopeIndex)
	if err != nil {
		t.Fatalf("buildAAD: %v", err)
	}

	// AEAD-seal the CEK.
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	wrapCT := gcm.Seal(nil, nonce, cek, aad)

	return CEKWrapEnvelope{
		PubkeyFingerprint: kp.fingerprint,
		KEMCiphertext:     base64.StdEncoding.EncodeToString(kemCT),
		WrapNonce:         base64.StdEncoding.EncodeToString(nonce),
		WrapCiphertext:    base64.StdEncoding.EncodeToString(wrapCT),
		EncapsulatedAtMs:  time.Now().UTC().UnixMilli(),
	}
}

// xwingEncapsulate runs the X-Wing KEM encapsulation against a 1216-byte
// public key, returning the 1120-byte ciphertext + 32-byte shared secret.
// Mirrors the producer-side flow (internal/crypto.XWINGEncapsulate).
func xwingEncapsulate(t *testing.T, pub []byte) (ct, ss []byte) {
	t.Helper()
	if len(pub) != xwingPubkeySize {
		t.Fatalf("pub len %d, want %d", len(pub), xwingPubkeySize)
	}
	mlkemEKBytes := pub[:1184]
	x25519PK := pub[1184:]

	// ML-KEM-768 encapsulate.
	ek, err := mlkem.NewEncapsulationKey768(mlkemEKBytes)
	if err != nil {
		t.Fatalf("mlkem ek: %v", err)
	}
	mlkemSS, mlkemCT := ek.Encapsulate()

	// X25519 ephemeral keypair + DH.
	ephPriv := make([]byte, 32)
	if _, err := rand.Read(ephPriv); err != nil {
		t.Fatalf("eph: %v", err)
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("eph pub: %v", err)
	}
	x25519SS, err := curve25519.X25519(ephPriv, x25519PK)
	if err != nil {
		t.Fatalf("x25519 dh: %v", err)
	}

	// X-Wing combiner: SHA3-256(ss_M || ss_X || ct_X || pk_X || label).
	h := sha3.New256()
	h.Write(mlkemSS)
	h.Write(x25519SS)
	h.Write(ephPub)   // ct_X (ephemeral pub the producer sends as the "ciphertext" half)
	h.Write(x25519PK) // pk_X (recipient pub)
	h.Write(xwingLabel)
	ss = h.Sum(nil)

	ct = make([]byte, 0, xwingCiphertextWireSize)
	ct = append(ct, mlkemCT...)
	ct = append(ct, ephPub...)
	return ct, ss
}

// makeBundle assembles a Bundle from N CEKWrapEnvelopes.
func makeBundle(bundleID string, envs []CEKWrapEnvelope) *Bundle {
	return &Bundle{
		ID: bundleID,
		Manifest: Manifest{
			Tier2: Tier2Manifest{
				Mode:         tierModeStandard,
				CEKEnvelopes: envs,
				PubkeyCount:  len(envs),
			},
		},
	}
}

// =============================================================================
// Tests
// =============================================================================

// TestOpenBundle_DualRecipient_BothSeedsUnseal verifies the demo path:
// a bundle sealed under primary + backup pubkeys is opened by EITHER
// seed and returns the same CEK.
func TestOpenBundle_DualRecipient_BothSeedsUnseal(t *testing.T) {
	primary := genTestKeypair(t)
	backup := genTestKeypair(t)
	bundleID := "bundle_01HXTEST_DUAL"

	cek := make([]byte, aesKeySize)
	if _, err := rand.Read(cek); err != nil {
		t.Fatalf("cek: %v", err)
	}

	envP := sealCEKToPubkey(t, cek, primary, bundleID, 0)
	envB := sealCEKToPubkey(t, cek, backup, bundleID, 1)
	bundle := makeBundle(bundleID, []CEKWrapEnvelope{envP, envB})

	resP, err := OpenBundle(primary.seed, bundle)
	if err != nil {
		t.Fatalf("primary unseal: %v", err)
	}
	if !bytes.Equal(resP.CEK, cek) {
		t.Errorf("primary CEK mismatch")
	}
	if resP.MatchedEnvelopeIndex != 0 {
		t.Errorf("primary matched idx = %d; want 0", resP.MatchedEnvelopeIndex)
	}
	if resP.MatchedFingerprint != primary.fingerprint {
		t.Errorf("primary matched fp = %q; want %q", resP.MatchedFingerprint, primary.fingerprint)
	}

	resB, err := OpenBundle(backup.seed, bundle)
	if err != nil {
		t.Fatalf("backup unseal: %v", err)
	}
	if !bytes.Equal(resB.CEK, cek) {
		t.Errorf("backup CEK mismatch")
	}
	if resB.MatchedEnvelopeIndex != 1 {
		t.Errorf("backup matched idx = %d; want 1", resB.MatchedEnvelopeIndex)
	}
}

// TestOpenBundle_LegacySingleRecipient verifies pre-ADR-024-Amendment
// bundles with N=1 still open correctly. Backward compatibility.
func TestOpenBundle_LegacySingleRecipient(t *testing.T) {
	kp := genTestKeypair(t)
	bundleID := "bundle_01HXTEST_LEGACY"

	cek := make([]byte, aesKeySize)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}

	env := sealCEKToPubkey(t, cek, kp, bundleID, 0)
	bundle := makeBundle(bundleID, []CEKWrapEnvelope{env})

	res, err := OpenBundle(kp.seed, bundle)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if !bytes.Equal(res.CEK, cek) {
		t.Errorf("CEK mismatch")
	}
}

// TestOpenBundle_LegacySingleRecipient_WrongSeed verifies that a
// single-recipient bundle returns ErrNoMatchingRecipient when called
// with a seed for a different keypair.
func TestOpenBundle_LegacySingleRecipient_WrongSeed(t *testing.T) {
	bundleKp := genTestKeypair(t)
	otherKp := genTestKeypair(t)
	bundleID := "bundle_01HXTEST_WRONG"

	cek := make([]byte, aesKeySize)
	rand.Read(cek)

	env := sealCEKToPubkey(t, cek, bundleKp, bundleID, 0)
	bundle := makeBundle(bundleID, []CEKWrapEnvelope{env})

	_, err := OpenBundle(otherKp.seed, bundle)
	if !errors.Is(err, ErrNoMatchingRecipient) {
		t.Errorf("err = %v; want ErrNoMatchingRecipient", err)
	}
}

// TestOpenBundle_TamperedCiphertext verifies that a flipped byte in
// WrapCiphertext yields ErrOpenFailed (NOT ErrNoMatchingRecipient —
// the fingerprint still matches; only the AEAD fails).
func TestOpenBundle_TamperedCiphertext(t *testing.T) {
	kp := genTestKeypair(t)
	bundleID := "bundle_01HXTEST_TAMPER"

	cek := make([]byte, aesKeySize)
	rand.Read(cek)

	env := sealCEKToPubkey(t, cek, kp, bundleID, 0)
	// Flip the first byte of the base64-decoded wrap_ciphertext, then
	// re-encode.
	raw, _ := base64.StdEncoding.DecodeString(env.WrapCiphertext)
	raw[0] ^= 0x01
	env.WrapCiphertext = base64.StdEncoding.EncodeToString(raw)

	bundle := makeBundle(bundleID, []CEKWrapEnvelope{env})
	_, err := OpenBundle(kp.seed, bundle)
	if !errors.Is(err, ErrOpenFailed) {
		t.Errorf("err = %v; want ErrOpenFailed", err)
	}
}

// TestOpenBundle_WrongBundleID verifies that AAD binding is enforced —
// opening with a bundleID that doesn't match the seal-time value fails.
func TestOpenBundle_WrongBundleID(t *testing.T) {
	kp := genTestKeypair(t)
	cek := make([]byte, aesKeySize)
	rand.Read(cek)

	env := sealCEKToPubkey(t, cek, kp, "bundle_01_REAL", 0)
	bundle := makeBundle("bundle_02_FAKE", []CEKWrapEnvelope{env})

	_, err := OpenBundle(kp.seed, bundle)
	if !errors.Is(err, ErrOpenFailed) {
		t.Errorf("err = %v; want ErrOpenFailed", err)
	}
}

// TestOpenBundle_WrongEnvelopeIndex verifies that AAD binding to
// envelope_index is enforced. Manually swapping a bundle's envelope
// order without resealing breaks decryption.
func TestOpenBundle_WrongEnvelopeIndex(t *testing.T) {
	primary := genTestKeypair(t)
	backup := genTestKeypair(t)
	bundleID := "bundle_01HXTEST_SWAP"

	cek := make([]byte, aesKeySize)
	rand.Read(cek)

	envP := sealCEKToPubkey(t, cek, primary, bundleID, 0)
	envB := sealCEKToPubkey(t, cek, backup, bundleID, 1)

	// Swap the order — primary envelope now claims index 1 (where it
	// was sealed for index 0). OpenBundle will find primary via
	// fingerprint scan at index 1 and rebuild AAD with envelope_index=1,
	// which won't match the seal-time AAD (envelope_index=0). Fails.
	bundle := makeBundle(bundleID, []CEKWrapEnvelope{envB, envP})

	_, err := OpenBundle(primary.seed, bundle)
	if !errors.Is(err, ErrOpenFailed) {
		t.Errorf("err = %v; want ErrOpenFailed", err)
	}
}

// TestOpenBundle_InvalidSeedSize verifies the input-validation guard.
func TestOpenBundle_InvalidSeedSize(t *testing.T) {
	bundle := makeBundle("b1", []CEKWrapEnvelope{
		{PubkeyFingerprint: strings.Repeat("0", 32)},
	})
	cases := [][]byte{
		nil,
		make([]byte, 0),
		make([]byte, 31),
		make([]byte, 33),
		make([]byte, 64),
	}
	for _, seed := range cases {
		_, err := OpenBundle(seed, bundle)
		if !errors.Is(err, ErrSeedInvalid) {
			t.Errorf("seed len %d: err = %v; want ErrSeedInvalid", len(seed), err)
		}
	}
}

// TestOpenBundle_BundleMalformed verifies the structural rejection paths.
func TestOpenBundle_BundleMalformed(t *testing.T) {
	seed := make([]byte, XWingSeedSize)
	rand.Read(seed)

	tests := []struct {
		name   string
		bundle *Bundle
	}{
		{"nil", nil},
		{"empty id", &Bundle{ID: "", Manifest: Manifest{Tier2: Tier2Manifest{Mode: "standard", CEKEnvelopes: []CEKWrapEnvelope{{PubkeyFingerprint: strings.Repeat("0", 32)}}}}}},
		{"forensic mode", &Bundle{ID: "b1", Manifest: Manifest{Tier2: Tier2Manifest{Mode: "forensic", CEKEnvelopes: []CEKWrapEnvelope{{PubkeyFingerprint: strings.Repeat("0", 32)}}}}}},
		{"empty envelopes", &Bundle{ID: "b1", Manifest: Manifest{Tier2: Tier2Manifest{Mode: "standard"}}}},
		{"pubkey_count skew", &Bundle{ID: "b1", Manifest: Manifest{Tier2: Tier2Manifest{Mode: "standard", PubkeyCount: 5, CEKEnvelopes: []CEKWrapEnvelope{{PubkeyFingerprint: strings.Repeat("0", 32)}}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := OpenBundle(seed, tt.bundle)
			if !errors.Is(err, ErrBundleMalformed) {
				t.Errorf("err = %v; want ErrBundleMalformed", err)
			}
		})
	}
}

// TestDeriveFingerprint_DeterministicAndRoundtrips verifies fingerprint
// derivation is deterministic and matches what the test's own
// genTestKeypair produces via SHA-512.
func TestDeriveFingerprint_DeterministicAndRoundtrips(t *testing.T) {
	kp := genTestKeypair(t)

	fp1, err := DeriveFingerprint(kp.seed)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if fp1 != kp.fingerprint {
		t.Errorf("DeriveFingerprint = %q; want %q (test-harness derivation)", fp1, kp.fingerprint)
	}
	if len(fp1) != fingerprintHexLen {
		t.Errorf("len(fp) = %d; want %d", len(fp1), fingerprintHexLen)
	}

	fp2, _ := DeriveFingerprint(kp.seed)
	if fp1 != fp2 {
		t.Errorf("DeriveFingerprint not deterministic: %q vs %q", fp1, fp2)
	}
}

// TestDeriveFingerprint_InvalidSeed verifies size validation.
func TestDeriveFingerprint_InvalidSeed(t *testing.T) {
	cases := [][]byte{nil, make([]byte, 0), make([]byte, 31), make([]byte, 33)}
	for _, seed := range cases {
		_, err := DeriveFingerprint(seed)
		if !errors.Is(err, ErrSeedInvalid) {
			t.Errorf("seed len %d: err = %v; want ErrSeedInvalid", len(seed), err)
		}
	}
}

// TestOpenBundle_OpaqueErrorMessages verifies the security-critical
// property that ErrNoMatchingRecipient does NOT leak slot labels or
// fingerprints in its message. (Defends against a future change that
// adds debug info to the sentinel string.)
func TestOpenBundle_OpaqueErrorMessages(t *testing.T) {
	bundleKp := genTestKeypair(t)
	otherKp := genTestKeypair(t)

	cek := make([]byte, aesKeySize)
	rand.Read(cek)
	env := sealCEKToPubkey(t, cek, bundleKp, "b1", 0)
	bundle := makeBundle("b1", []CEKWrapEnvelope{env})

	_, err := OpenBundle(otherKp.seed, bundle)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if strings.Contains(msg, bundleKp.fingerprint) || strings.Contains(msg, otherKp.fingerprint) {
		t.Errorf("error leaks fingerprint: %q", msg)
	}
	if strings.Contains(msg, "primary") || strings.Contains(msg, "backup") {
		t.Errorf("error leaks slot label: %q", msg)
	}
}
