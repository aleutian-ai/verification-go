// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// dsar_chain_d: verifier tests. Each test signs a v3 entry with a
// freshly-generated ML-DSA-65 keypair, then asserts the verifier
// accepts the valid signature + rejects each documented tamper
// scenario.

const testV3SigningKeyID = "test-signer-2026-v1"

// signedV3Fixture builds a typed entry, signs it with a freshly-
// generated keypair, and returns everything the verifier needs
// to run end-to-end.
type signedV3Fixture struct {
	entry          ChainEntryV3
	contentHashHex string
	signatureB64   string
	publicKeyBytes []byte
	manifest       TrustManifestV3
	canonical      []byte
}

func mintSignedV3(t *testing.T, entry ChainEntryV3) signedV3Fixture {
	t.Helper()
	canonical, contentHashHex, err := EncodeAndHashV3(entry)
	if err != nil {
		t.Fatalf("EncodeAndHashV3: %v", err)
	}
	scheme := mldsa65.Scheme()
	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signingInput := append([]byte(DomainPrefixV3), canonical...)
	sig := scheme.Sign(priv, signingInput, nil)
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	manifest, err := NewTrustManifestFromMapV3(map[string][]byte{
		testV3SigningKeyID: pubBytes,
	})
	if err != nil {
		t.Fatalf("NewTrustManifestFromMapV3: %v", err)
	}
	return signedV3Fixture{
		entry:          entry,
		contentHashHex: contentHashHex,
		signatureB64:   base64.StdEncoding.EncodeToString(sig),
		publicKeyBytes: pubBytes,
		manifest:       manifest,
		canonical:      canonical,
	}
}

// emptyManifestV3 returns a valid (empty) manifest for "key not in
// manifest" tests.
func emptyManifestV3(t *testing.T) TrustManifestV3 {
	t.Helper()
	m, err := NewTrustManifestFromMapV3(nil)
	if err != nil {
		t.Fatalf("NewTrustManifestFromMapV3(nil): %v", err)
	}
	return m
}

// =============================================================================
// Happy path
// =============================================================================

func TestVerifyChainEntryV3_AcceptsValidEntry(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		entry ChainEntryV3
	}{
		{"sar_intent", testIntentForSigning()},
		{"sar_acknowledged", testAckForSigning()},
		{"sar_fulfilled", testFulfilledForSigning()},
		{"sar_rejected", testRejectedForSigning()},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			f := mintSignedV3(t, c.entry)
			if err := VerifyChainEntryV3(context.Background(), f.entry, f.contentHashHex, f.signatureB64, f.manifest); err != nil {
				t.Errorf("expected nil error on valid entry, got %v", err)
			}
		})
	}
}

// =============================================================================
// Typed failure modes
// =============================================================================

func TestVerifyChainEntryV3_NilEntry(t *testing.T) {
	t.Parallel()
	err := VerifyChainEntryV3(context.Background(), nil, strings.Repeat("0", 128), "AAAA", emptyManifestV3(t))
	if !errors.Is(err, ErrInvalidEntryV3) {
		t.Errorf("nil entry should return ErrInvalidEntryV3, got %v", err)
	}
}

func TestVerifyChainEntryV3_NilManifest(t *testing.T) {
	t.Parallel()
	err := VerifyChainEntryV3(context.Background(), testIntentForSigning(), strings.Repeat("0", 128), "AAAA", nil)
	if err == nil || !strings.Contains(err.Error(), "trust manifest is nil") {
		t.Errorf("nil manifest should error, got %v", err)
	}
}

func TestVerifyChainEntryV3_InvalidEntry(t *testing.T) {
	t.Parallel()
	e := testIntentForSigning()
	e.CompanyID = "garbage"
	err := VerifyChainEntryV3(context.Background(), e, strings.Repeat("0", 128), "AAAA", emptyManifestV3(t))
	if !errors.Is(err, ErrInvalidEntryV3) {
		t.Errorf("invalid entry should return ErrInvalidEntryV3, got %v", err)
	}
}

func TestVerifyChainEntryV3_ContentHashMismatch(t *testing.T) {
	t.Parallel()
	f := mintSignedV3(t, testIntentForSigning())
	badHash := strings.Repeat("0", 128)
	err := VerifyChainEntryV3(context.Background(), f.entry, badHash, f.signatureB64, f.manifest)
	if !errors.Is(err, ErrContentHashMismatchV3) {
		t.Errorf("wrong content_hash should return ErrContentHashMismatchV3, got %v", err)
	}
}

// chain_d H2 verification: error string MUST NOT echo claimed
// or computed hash values.
func TestVerifyChainEntryV3_ContentHashMismatchErrorDoesNotLeak(t *testing.T) {
	t.Parallel()
	f := mintSignedV3(t, testIntentForSigning())
	badHash := strings.Repeat("0", 128)
	err := VerifyChainEntryV3(context.Background(), f.entry, badHash, f.signatureB64, f.manifest)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), badHash) {
		t.Errorf("error message leaked claimed hash: %v", err)
	}
	if strings.Contains(err.Error(), f.contentHashHex) {
		t.Errorf("error message leaked computed hash: %v", err)
	}
}

// chain_d H2: invalid signature error MUST NOT echo signing_key_id.
func TestVerifyChainEntryV3_SignatureInvalidErrorDoesNotLeakKeyID(t *testing.T) {
	t.Parallel()
	f := mintSignedV3(t, testIntentForSigning())
	sigRaw, _ := base64.StdEncoding.DecodeString(f.signatureB64)
	sigRaw[0] ^= 0xFF
	err := VerifyChainEntryV3(context.Background(), f.entry, f.contentHashHex,
		base64.StdEncoding.EncodeToString(sigRaw), f.manifest)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), testV3SigningKeyID) {
		t.Errorf("error message leaked signing_key_id: %v", err)
	}
}

func TestVerifyChainEntryV3_SignatureMalformedBase64(t *testing.T) {
	t.Parallel()
	f := mintSignedV3(t, testIntentForSigning())
	err := VerifyChainEntryV3(context.Background(), f.entry, f.contentHashHex, "this is not base64!", f.manifest)
	if !errors.Is(err, ErrSignatureMalformedV3) {
		t.Errorf("bad base64 should return ErrSignatureMalformedV3, got %v", err)
	}
}

func TestVerifyChainEntryV3_SignatureOversizedRejected(t *testing.T) {
	t.Parallel()
	f := mintSignedV3(t, testIntentForSigning())
	huge := strings.Repeat("A", 1<<16) // way over ML-DSA-65 sig size
	err := VerifyChainEntryV3(context.Background(), f.entry, f.contentHashHex, huge, f.manifest)
	if !errors.Is(err, ErrSignatureMalformedV3) {
		t.Errorf("oversized sig should return ErrSignatureMalformedV3, got %v", err)
	}
}

func TestVerifyChainEntryV3_SignatureWrongLength(t *testing.T) {
	t.Parallel()
	f := mintSignedV3(t, testIntentForSigning())
	short := base64.StdEncoding.EncodeToString([]byte("too short"))
	err := VerifyChainEntryV3(context.Background(), f.entry, f.contentHashHex, short, f.manifest)
	if !errors.Is(err, ErrSignatureMalformedV3) {
		t.Errorf("short sig should return ErrSignatureMalformedV3, got %v", err)
	}
}

func TestVerifyChainEntryV3_SignatureInvalid(t *testing.T) {
	t.Parallel()
	f := mintSignedV3(t, testIntentForSigning())
	sigRaw, err := base64.StdEncoding.DecodeString(f.signatureB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sigRaw[0] ^= 0xFF
	badSig := base64.StdEncoding.EncodeToString(sigRaw)
	err = VerifyChainEntryV3(context.Background(), f.entry, f.contentHashHex, badSig, f.manifest)
	if !errors.Is(err, ErrSignatureInvalidV3) {
		t.Errorf("tampered sig should return ErrSignatureInvalidV3, got %v", err)
	}
}

func TestVerifyChainEntryV3_KeyNotInManifest(t *testing.T) {
	t.Parallel()
	f := mintSignedV3(t, testIntentForSigning())
	err := VerifyChainEntryV3(context.Background(), f.entry, f.contentHashHex, f.signatureB64, emptyManifestV3(t))
	if !errors.Is(err, ErrKeyNotInTrustManifestV3) {
		t.Errorf("missing key should return ErrKeyNotInTrustManifestV3, got %v", err)
	}
}

// chain_d_go_review_followup M4 mirror: MaxCanonicalBytesV3 must
// stay at 4096 bytes — divergence from Python's
// MAX_CANONICAL_BYTES_V3 silently becomes a per-tenant DoS vector
// against customers using the laxer SDK. Pin the value here so a
// drift surfaces in CI rather than at customer-incident time.
func TestMaxCanonicalBytesV3_LockedAtCrossLanguageValue(t *testing.T) {
	t.Parallel()
	const wantCrossLanguagePythonValue = 4096
	if MaxCanonicalBytesV3 != wantCrossLanguagePythonValue {
		t.Fatalf("MaxCanonicalBytesV3 = %d; want %d (must match Python SDK MAX_CANONICAL_BYTES_V3)",
			MaxCanonicalBytesV3, wantCrossLanguagePythonValue)
	}
}

// chain_d_go_review_followup H1 mirror: the v3 scope-regex error
// message MUST NOT echo the offending scope value (Privacy Inv 4 of
// sdk_privacy_invariants_spec).
func TestScopeRegexError_DoesNotEchoBadValue(t *testing.T) {
	t.Parallel()
	e := testIntentForSigning()
	bad := "grant_!!!THIS_VALUE_MUST_NOT_LEAK_INTO_ERROR_OUTPUT!!!"
	e.Scope = bad
	_, err := CanonicalBytesV3(e)
	if err == nil {
		t.Fatal("expected ErrInvalidEntryV3 for bad scope")
	}
	if !errors.Is(err, ErrInvalidEntryV3) {
		t.Errorf("want ErrInvalidEntryV3, got %v", err)
	}
	if strings.Contains(err.Error(), bad) {
		t.Errorf("error message leaked bad scope value: %v", err)
	}
}

// chain_d H3: constructor rejects malformed keys at construction
// time (used to be lazy per-verify).
func TestNewTrustManifestFromMapV3_RejectsMalformedKeyAtConstruction(t *testing.T) {
	t.Parallel()
	_, err := NewTrustManifestFromMapV3(map[string][]byte{
		testV3SigningKeyID: []byte("not a valid ML-DSA-65 public key"),
	})
	if !errors.Is(err, ErrPublicKeyMalformedV3) {
		t.Errorf("constructor should reject malformed key, got %v", err)
	}
}

func TestNewTrustManifestFromMapV3_RejectsEmptyKeyID(t *testing.T) {
	t.Parallel()
	// Build a real key first.
	scheme := mldsa65.Scheme()
	pub, _, _ := scheme.GenerateKey()
	pubBytes, _ := pub.MarshalBinary()
	_, err := NewTrustManifestFromMapV3(map[string][]byte{
		"": pubBytes,
	})
	if !errors.Is(err, ErrInvalidEntryV3) {
		t.Errorf("constructor should reject empty signing_key_id, got %v", err)
	}
}

// TestVerifyChainEntryV3_TamperedEntryRejected: re-sign with a
// genuine key, then verify against a SLIGHTLY-MUTATED entry. The
// mutation changes canonical_bytes; the signature was over the
// pre-mutation bytes. Verifier MUST return content_hash mismatch
// (the claimed hash was for the original).
func TestVerifyChainEntryV3_TamperedEntryRejected(t *testing.T) {
	t.Parallel()
	original := testIntentForSigning()
	f := mintSignedV3(t, original)
	mutated := original
	mutated.Scope = "grant_attackerscope"
	err := VerifyChainEntryV3(context.Background(), mutated, f.contentHashHex, f.signatureB64, f.manifest)
	if !errors.Is(err, ErrContentHashMismatchV3) {
		t.Errorf("tampered entry should return ErrContentHashMismatchV3, got %v", err)
	}
}

// TestVerifyChainEntryV3_CrossEntryReplayRejected: signature minted
// for SAR-intent must NOT verify for SAR-acknowledged even if both
// share the same SigningKeyID. The signing input includes the
// entry_type literal in canonical_bytes, so cross-type replay
// produces a signature-verify failure.
func TestVerifyChainEntryV3_CrossEntryReplayRejected(t *testing.T) {
	t.Parallel()
	intent := testIntentForSigning()
	fIntent := mintSignedV3(t, intent)
	ack := testAckForSigning()
	ack.SigningKeyID = intent.SigningKeyID
	_, ackContentHash, err := EncodeAndHashV3(ack)
	if err != nil {
		t.Fatalf("encode ack: %v", err)
	}
	err = VerifyChainEntryV3(context.Background(), ack, ackContentHash, fIntent.signatureB64, fIntent.manifest)
	if !errors.Is(err, ErrSignatureInvalidV3) {
		t.Errorf("cross-entry replay should return ErrSignatureInvalidV3, got %v", err)
	}
}

// =============================================================================
// Trust manifest tests
// =============================================================================

func TestTrustManifestFromMapV3_CopiesInput(t *testing.T) {
	t.Parallel()
	scheme := mldsa65.Scheme()
	pub, _, _ := scheme.GenerateKey()
	pubBytes, _ := pub.MarshalBinary()
	original := map[string][]byte{
		"key1": pubBytes,
	}
	m, err := NewTrustManifestFromMapV3(original)
	if err != nil {
		t.Fatalf("NewTrustManifestFromMapV3: %v", err)
	}
	// Mutate the caller's map post-construction.
	original["key1"][0] = 99
	original["key2"] = pubBytes
	got, err := m.PublicKeyForSigningKeyID(context.Background(), "key1")
	if err != nil || len(got) != len(pubBytes) || got[0] == 99 {
		t.Errorf("manifest should have isolated input copy: err=%v len=%d byte0=%d",
			err, len(got), got[0])
	}
	if _, err := m.PublicKeyForSigningKeyID(context.Background(), "key2"); !errors.Is(err, ErrKeyNotInTrustManifestV3) {
		t.Errorf("post-construction mutation leaked into manifest: err=%v", err)
	}
}

// =============================================================================
// Test entry builders (use the testV3SigningKeyID so manifest hits)
// =============================================================================

func testIntentForSigning() SARIntentEntryV3 {
	e := minimalSARIntentV3()
	e.SigningKeyID = testV3SigningKeyID
	return e
}

func testAckForSigning() SARAcknowledgedEntryV3 {
	e := minimalSARAcknowledgedV3()
	e.SigningKeyID = testV3SigningKeyID
	return e
}

func testFulfilledForSigning() SARFulfilledEntryV3 {
	e := minimalSARFulfilledV3()
	e.SigningKeyID = testV3SigningKeyID
	return e
}

func testRejectedForSigning() SARRejectedEntryV3 {
	e := minimalSARRejectedV3()
	e.SigningKeyID = testV3SigningKeyID
	return e
}

// testCaptureForSigning returns a valid signed-shape capture leaf (SigningKeyID
// == testV3SigningKeyID so mintSignedV3's manifest resolves it).
func testCaptureForSigning() CaptureRequestEntryV3 {
	return CaptureRequestEntryV3{
		CompanyID:           "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA",
		SigningKeyID:        testV3SigningKeyID,
		TimestampMs:         1751068800000,
		CaptureMethod:       "fetch_intercept",
		ContentHash:         strings.Repeat("a", 128),
		DLP:                 strings.Repeat("b", 128),
		EncryptionMode:      "aleutian-managed",
		Model:               "gpt-4o-2024-08-06",
		PIIAction:           "flagged",
		PIICategories:       strings.Repeat("c", 128),
		PIIDetected:         true,
		PIIDigestKeyVersion: "sm:v1",
		ProcessingMode:      "pii_inspection",
		Provider:            "openai",
		Region:              "us",
		SourceType:          "extension",
		TrustLevel:          "self-reported",
		UserID:              strings.Repeat("d", 128),
	}
}

// TestVerifyChainEntryV3_AcceptsCaptureLeaf proves chainlinker_modernization_01i:
// VerifyChainEntryV3 now verifies a signed capture leaf (previously
// ErrUnsupportedEntryTypeV3).
func TestVerifyChainEntryV3_AcceptsCaptureLeaf(t *testing.T) {
	t.Parallel()
	f := mintSignedV3(t, testCaptureForSigning())
	if err := VerifyChainEntryV3(context.Background(), f.entry, f.contentHashHex, f.signatureB64, f.manifest); err != nil {
		t.Fatalf("valid capture leaf must verify: %v", err)
	}
}

// TestVerifyChainEntryV3_CaptureLeafTamperBreaks is the tamper-evidence payoff:
// flipping ANY sealed metadata field changes the canonical → content_hash
// mismatch → verification break. This is the whole point of the V3 leaf.
func TestVerifyChainEntryV3_CaptureLeafTamperBreaks(t *testing.T) {
	t.Parallel()
	base := testCaptureForSigning()
	f := mintSignedV3(t, base)
	cases := []struct {
		name string
		mut  func(*CaptureRequestEntryV3)
	}{
		{"model", func(e *CaptureRequestEntryV3) { e.Model = "evil-model" }},
		{"user_id_pseudonym", func(e *CaptureRequestEntryV3) { e.UserID = strings.Repeat("f", 128) }},
		{"pii_detected", func(e *CaptureRequestEntryV3) { e.PIIDetected = false }},
		{"region", func(e *CaptureRequestEntryV3) { e.Region = "eu" }},
		{"processing_mode", func(e *CaptureRequestEntryV3) { e.ProcessingMode = "zk" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := base
			tc.mut(&tampered)
			err := VerifyChainEntryV3(context.Background(), tampered, f.contentHashHex, f.signatureB64, f.manifest)
			// Tampering MUST break verification. Pure metadata flips change the
			// canonical → content_hash mismatch; processing_mode→zk additionally
			// trips the encoder's zk-invariant (ErrInvalidEntryV3) — either way the
			// leaf no longer verifies, which is the guarantee.
			if err == nil {
				t.Errorf("flipping %s must break verification, got nil", tc.name)
			}
			if tc.name != "processing_mode" && !errors.Is(err, ErrContentHashMismatchV3) {
				t.Errorf("flipping metadata field %s should give content_hash mismatch, got %v", tc.name, err)
			}
		})
	}
}
