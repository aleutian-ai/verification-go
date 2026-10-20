// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dsar_chain_d: SDK-side v3 encoder tests. The golden vector
// fixtures are byte-identical copies of the producer-side
// fixtures from chain_b; this test asserts the SDK encoder
// produces the same bytes + content_hash. Any drift between SDK
// and producer surfaces here.
//
// NOTE on test scope: this file is the SDK MIRROR of
// `internal/consent/canonical_v3_test.go`. Many test cases are
// intentionally near-duplicates — they prove the SDK encoder
// matches the producer's behavior point-for-point. Drift between
// the two test sets is itself a regression signal.

// =============================================================================
// Domain-prefix lock + content-hash determinism
// =============================================================================

func TestDomainPrefixV3_LockedBytes(t *testing.T) {
	t.Parallel()
	if DomainPrefixV3 != "aleutian.chain.entry.v3:" {
		t.Errorf("DomainPrefixV3 = %q, want %q (DO NOT change — invalidates every signed v3 entry)",
			DomainPrefixV3, "aleutian.chain.entry.v3:")
	}
}

func TestContentHashV3_BindsPrefix(t *testing.T) {
	t.Parallel()
	canonical := []byte("test-canonical-bytes")
	got := ContentHashV3(canonical)
	if len(got) != 128 {
		t.Errorf("content_hash hex length = %d, want 128", len(got))
	}
	bareSum := sha512.Sum512(canonical)
	if got == hex.EncodeToString(bareSum[:]) {
		t.Errorf("content_hash equals bare SHA-512 — domain prefix not bound")
	}
}

// =============================================================================
// Golden vector tests — cross-language parity with producer-side
// =============================================================================

type v3VectorFile struct {
	Version        int    `json:"version"`
	DomainPrefixV3 string `json:"domain_prefix_v3"`
	EntryType      string `json:"entry_type"`
	Vectors        []struct {
		Name                         string                 `json:"name"`
		Input                        map[string]interface{} `json:"input"`
		ExpectedCanonicalBytesHex    string                 `json:"expected_canonical_bytes_hex"`
		ExpectedContentHashSHA512Hex string                 `json:"expected_content_hash_sha512_hex"`
	} `json:"vectors"`
}

func TestCanonicalBytesV3_GoldenVectors(t *testing.T) {
	t.Parallel()
	files := []string{
		"v3_golden_sar_intent.json",
		"v3_golden_sar_acknowledged.json",
		"v3_golden_sar_fulfilled.json",
		"v3_golden_sar_rejected.json",
	}
	for _, fname := range files {
		fname := fname
		t.Run(fname, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join("testdata", fname))
			if err != nil {
				t.Fatalf("read %s: %v", fname, err)
			}
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			var f v3VectorFile
			if err := dec.Decode(&f); err != nil {
				t.Fatalf("parse %s: %v", fname, err)
			}
			if f.Version != 3 {
				t.Fatalf("%s: version = %d, want 3", fname, f.Version)
			}
			if f.DomainPrefixV3 != DomainPrefixV3 {
				t.Errorf("%s: domain prefix mismatch: file=%q sdk=%q",
					fname, f.DomainPrefixV3, DomainPrefixV3)
			}
			for _, v := range f.Vectors {
				v := v
				t.Run(v.Name, func(t *testing.T) {
					entry, err := buildV3SAREntryFromInput(f.EntryType, v.Input)
					if err != nil {
						t.Fatalf("build entry: %v", err)
					}
					gotBytes, err := CanonicalBytesV3(entry)
					if err != nil {
						t.Fatalf("CanonicalBytesV3: %v", err)
					}
					gotHex := hex.EncodeToString(gotBytes)
					if gotHex != v.ExpectedCanonicalBytesHex {
						t.Errorf("canonical bytes mismatch\n got:  %s\n want: %s",
							gotHex, v.ExpectedCanonicalBytesHex)
					}
					gotHash := ContentHashV3(gotBytes)
					if gotHash != v.ExpectedContentHashSHA512Hex {
						t.Errorf("content_hash mismatch\n got:  %s\n want: %s",
							gotHash, v.ExpectedContentHashSHA512Hex)
					}
				})
			}
		})
	}
}

// buildV3SAREntryFromInput constructs the typed SDK entry from a
// JSON fixture's `input` object. Mirrors the producer-side test
// builder.
func buildV3SAREntryFromInput(entryType string, in map[string]interface{}) (ChainEntryV3, error) {
	companyID, _ := in["company_id"].(string)
	signingKID, _ := in["signing_key_id"].(string)
	requestID, _ := in["request_id"].(string)
	timestampMs, err := readJSONInt64(in, "timestamp_ms")
	if err != nil {
		return nil, err
	}
	switch entryType {
	case "sar_intent":
		reasonHash, _ := in["reason_hash"].(string)
		sarType, _ := in["sar_type"].(string)
		scope, _ := in["scope"].(string)
		channel, _ := in["source_channel"].(string)
		piiVer, _ := in["pii_digest_key_version"].(string)
		return SARIntentEntryV3{
			CompanyID:           companyID,
			EntryType:           EventTypeSARIntentV3,
			SigningKeyID:        signingKID,
			TimestampMs:         timestampMs,
			PIIDigestKeyVersion: piiVer,
			ReasonHash:          MustTenantHMACDigestFromHexV3(reasonHash),
			RequestID:           requestID,
			SARType:             SARTypeV3(sarType),
			Scope:               scope,
			SourceChannel:       SARSourceChannelV3(channel),
		}, nil
	case "sar_acknowledged":
		intentEID, _ := in["intent_entry_id"].(string)
		return SARAcknowledgedEntryV3{
			CompanyID:     companyID,
			EntryType:     EventTypeSARAcknowledgedV3,
			SigningKeyID:  signingKID,
			TimestampMs:   timestampMs,
			IntentEntryID: intentEID,
			RequestID:     requestID,
		}, nil
	case "sar_fulfilled":
		// certificate_id added 2026-05-16 by dsar_fulfill_b_pre_02e.
		// Empty for access-kind, cert_<32-hex> for erasure/both.
		certificateID, _ := in["certificate_id"].(string)
		fulfillKind, _ := in["fulfillment_kind"].(string)
		intentEID, _ := in["intent_entry_id"].(string)
		legalBasis, _ := in["legal_basis"].(string)
		manifestRoot, _ := in["manifest_root"].(string)
		tombstoneCount, err := readJSONInt64(in, "tombstone_count")
		if err != nil {
			return nil, err
		}
		return SARFulfilledEntryV3{
			CompanyID:       companyID,
			EntryType:       EventTypeSARFulfilledV3,
			SigningKeyID:    signingKID,
			TimestampMs:     timestampMs,
			CertificateID:   certificateID,
			FulfillmentKind: SARFulfillmentKindV3(fulfillKind),
			IntentEntryID:   intentEID,
			LegalBasis:      legalBasis,
			ManifestRoot:    manifestRoot,
			RequestID:       requestID,
			TombstoneCount:  tombstoneCount,
		}, nil
	case "sar_rejected":
		intentEID, _ := in["intent_entry_id"].(string)
		legalBasis, _ := in["legal_basis"].(string)
		rationaleHash, _ := in["rationale_hash"].(string)
		piiVer, _ := in["pii_digest_key_version"].(string)
		return SARRejectedEntryV3{
			CompanyID:           companyID,
			EntryType:           EventTypeSARRejectedV3,
			SigningKeyID:        signingKID,
			TimestampMs:         timestampMs,
			IntentEntryID:       intentEID,
			LegalBasis:          legalBasis,
			PIIDigestKeyVersion: piiVer,
			RationaleHash:       MustTenantHMACDigestFromHexV3(rationaleHash),
			RequestID:           requestID,
		}, nil
	}
	return nil, errors.New("unknown entry type: " + entryType)
}

// readJSONInt64 extracts an int64 from a JSON-decoded map without
// going through float64 (which loses precision > 2^53).
func readJSONInt64(in map[string]interface{}, key string) (int64, error) {
	switch v := in[key].(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, fmt.Errorf("readJSONInt64: %s: %w", key, err)
		}
		return n, nil
	case float64:
		n := int64(v)
		if float64(n) != v {
			return 0, fmt.Errorf("readJSONInt64: %s: %g lost precision via float64", key, v)
		}
		return n, nil
	case nil:
		return 0, fmt.Errorf("readJSONInt64: %s: missing", key)
	default:
		return 0, fmt.Errorf("readJSONInt64: %s: unexpected type %T", key, v)
	}
}

// =============================================================================
// Critical structural tests
// =============================================================================

func TestCanonicalBytesV3_HeaderFourFields(t *testing.T) {
	t.Parallel()
	entry := minimalSARIntentV3()
	got, err := CanonicalBytesV3(entry)
	if err != nil {
		t.Fatalf("CanonicalBytesV3: %v", err)
	}
	if !strings.Contains(string(got), string(entry.EntryType)) {
		t.Errorf("expected entry_type literal in canonical bytes")
	}
	// Confirm 'schema_version' (OQ-13: dropped) is absent.
	if strings.Contains(string(got), "schema_version") {
		t.Errorf("canonical bytes contain 'schema_version' — OQ-13 regression")
	}
}

func TestCanonicalBytesV3_CrossTypeNonCollision(t *testing.T) {
	t.Parallel()
	entries := []ChainEntryV3{
		minimalSARIntentV3(),
		minimalSARAcknowledgedV3(),
		minimalSARFulfilledV3(),
		minimalSARRejectedV3(),
	}
	seen := map[string]string{}
	for _, e := range entries {
		b, err := CanonicalBytesV3(e)
		if err != nil {
			t.Fatalf("%T: %v", e, err)
		}
		h := hex.EncodeToString(b)
		if prev, ok := seen[h]; ok {
			t.Errorf("collision: %T and %s produced identical canonical bytes", e, prev)
		}
		seen[h] = string(e.EntryTypeV3())
	}
}

// L4: regex boundary fixture for signing_key_id — exercises every
// charset edge character (`a`, `Z`, `0`, `9`, `_`, `.`, `/`, `-`)
// at the start, middle, and end of the string. Cross-language
// port authors who mis-escape `-` (creating a character range)
// or `.` (matching any byte) get a loud test failure.
func TestL4_SigningKeyIDRegexBoundaryCharsAccepted(t *testing.T) {
	t.Parallel()
	cases := []string{
		"a",                // single lowercase letter
		"Z",                // single uppercase letter
		"0",                // single digit
		"9",                // digit boundary
		"_",                // underscore
		"-",                // hyphen (last char of class — easy to mis-escape)
		".",                // dot (must NOT match "any char")
		"/",                // slash
		"-leading-hyphen",  // hyphen at start (range escape edge)
		"trailing-hyphen-", // hyphen at end
		"a.b/c-d_e",        // every char class member
		"A0-B1_C2.D3/E4",   // mix at every position
		"kms/projects/p/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", // realistic GCP KMS path (66 chars; within 128)
	}
	for _, s := range cases {
		s := s
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			e := minimalSARIntentV3()
			e.SigningKeyID = s
			if _, err := CanonicalBytesV3(e); err != nil {
				t.Errorf("signing_key_id %q should be accepted (charset boundary case), got %v", s, err)
			}
		})
	}
}

// L4: regex boundary REJECTIONS — characters outside the charset
// MUST fail, including ones a mis-escaped port might accept.
func TestL4_SigningKeyIDRegexBoundaryCharsRejected(t *testing.T) {
	t.Parallel()
	cases := []string{
		"with space",   // space (not in class)
		"with\ttab",    // tab (not in class)
		"semi;colon",   // semicolon
		"backslash\\",  // backslash
		"at@sign",      // @ (email-shape regression)
		"quote\"mark",  // quote
		"unicode🔑here", // multibyte UTF-8
	}
	for _, s := range cases {
		s := s
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			e := minimalSARIntentV3()
			e.SigningKeyID = s
			if _, err := CanonicalBytesV3(e); err == nil {
				t.Errorf("signing_key_id %q should be rejected (outside charset), got nil error", s)
			}
		})
	}
}

func TestCanonicalBytesV3_Idempotent(t *testing.T) {
	t.Parallel()
	for _, builder := range []func() ChainEntryV3{
		func() ChainEntryV3 { return minimalSARIntentV3() },
		func() ChainEntryV3 { return minimalSARAcknowledgedV3() },
		func() ChainEntryV3 { return minimalSARFulfilledV3() },
		func() ChainEntryV3 { return minimalSARRejectedV3() },
	} {
		e := builder()
		first, _ := CanonicalBytesV3(e)
		second, _ := CanonicalBytesV3(e)
		if !bytes.Equal(first, second) {
			t.Errorf("%T not idempotent", e)
		}
	}
}

// =============================================================================
// Test helpers
// =============================================================================

func minimalSARIntentV3() SARIntentEntryV3 {
	return SARIntentEntryV3{
		CompanyID:     "comp_01HK7AAAAAAAAAAAAAAAAAAAAA",
		EntryType:     EventTypeSARIntentV3,
		SigningKeyID:  "anchor-signer-2026-v1",
		TimestampMs:   1715000000000,
		RequestID:     "01HK7BBBBBBBBBBBBBBBBBBBBB",
		SARType:       SARTypeAccessV3,
		Scope:         "all",
		SourceChannel: SARSourceChannelPortalV3,
	}
}

func minimalSARAcknowledgedV3() SARAcknowledgedEntryV3 {
	return SARAcknowledgedEntryV3{
		CompanyID:     "comp_01HK7AAAAAAAAAAAAAAAAAAAAA",
		EntryType:     EventTypeSARAcknowledgedV3,
		SigningKeyID:  "anchor-signer-2026-v1",
		TimestampMs:   1715000000000,
		IntentEntryID: "018fa1b3-c4d5-7000-8000-1234567890ab",
		RequestID:     "01HK7BBBBBBBBBBBBBBBBBBBBB",
	}
}

func minimalSARFulfilledV3() SARFulfilledEntryV3 {
	return SARFulfilledEntryV3{
		CompanyID:       "comp_01HK7AAAAAAAAAAAAAAAAAAAAA",
		EntryType:       EventTypeSARFulfilledV3,
		SigningKeyID:    "anchor-signer-2026-v1",
		TimestampMs:     1715000000000,
		FulfillmentKind: SARFulfillmentKindAccessV3,
		IntentEntryID:   "018fa1b3-c4d5-7000-8000-1234567890ab",
		LegalBasis:      "art_15_access",
		ManifestRoot:    strings.Repeat("c", 128),
		RequestID:       "01HK7BBBBBBBBBBBBBBBBBBBBB",
	}
}

func minimalSARRejectedV3() SARRejectedEntryV3 {
	return SARRejectedEntryV3{
		CompanyID:     "comp_01HK7AAAAAAAAAAAAAAAAAAAAA",
		EntryType:     EventTypeSARRejectedV3,
		SigningKeyID:  "anchor-signer-2026-v1",
		TimestampMs:   1715000000000,
		IntentEntryID: "018fa1b3-c4d5-7000-8000-1234567890ab",
		LegalBasis:    "art_17_3_b_freedom_of_expression",
		RationaleHash: MustTenantHMACDigestFromHexV3(strings.Repeat("e", 128)),
		RequestID:     "01HK7BBBBBBBBBBBBBBBBBBBBB",
	}
}
