// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureGoldenFileSDK mirrors the neutral cross-language fixture schema baked by
// the producer (internal/captureentry). The SDK reads the SAME committed file and
// re-encodes each vector's input — the independent check that the public verifier
// reproduces the producer byte contract.
type captureGoldenFileSDK struct {
	DomainPrefixV3 string                   `json:"domain_prefix_v3"`
	EntryType      string                   `json:"entry_type"`
	Vectors        []captureGoldenVectorSDK `json:"vectors"`
}

type captureGoldenVectorSDK struct {
	Name                         string                `json:"name"`
	Input                        CaptureRequestEntryV3 `json:"input"`
	ExpectedCanonicalBytesHex    string                `json:"expected_canonical_bytes_hex"`
	ExpectedContentHashSHA512Hex string                `json:"expected_content_hash_sha512_hex"`
}

func loadCaptureGolden(t *testing.T) captureGoldenFileSDK {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "v3_golden_capture_request.json"))
	if err != nil {
		t.Fatalf("read capture golden: %v", err)
	}
	var f captureGoldenFileSDK
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("unmarshal capture golden: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("capture golden has no vectors")
	}
	return f
}

// TestCaptureV3_FixtureParity is the load-bearing cross-implementation check: the
// SDK encoder MUST reproduce the producer's baked canonical bytes + content hash
// for every vector, byte-for-byte. A failure here means the public verifier and
// the producer have diverged on the capture.request.v3 byte contract.
func TestCaptureV3_FixtureParity(t *testing.T) {
	f := loadCaptureGolden(t)

	if f.DomainPrefixV3 != DomainPrefixV3 {
		t.Errorf("domain prefix drift: fixture=%q const=%q", f.DomainPrefixV3, DomainPrefixV3)
	}
	if f.EntryType != string(EventTypeCaptureRequestV3) {
		t.Errorf("entry_type drift: fixture=%q const=%q", f.EntryType, EventTypeCaptureRequestV3)
	}

	for _, v := range f.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			canonical, contentHash, err := EncodeAndHashV3(v.Input)
			if err != nil {
				t.Fatalf("EncodeAndHashV3: %v", err)
			}
			if got := hex.EncodeToString(canonical); got != v.ExpectedCanonicalBytesHex {
				t.Errorf("canonical bytes diverge from producer:\n want %s\n  got %s", v.ExpectedCanonicalBytesHex, got)
			}
			if contentHash != v.ExpectedContentHashSHA512Hex {
				t.Errorf("content_hash diverges from producer:\n want %s\n  got %s", v.ExpectedContentHashSHA512Hex, contentHash)
			}
		})
	}
}

// TestCaptureV3_EntryType pins the entry-type tag + that the type satisfies the
// sealed ChainEntryV3 interface and dispatches through the shared encoder.
func TestCaptureV3_EntryType(t *testing.T) {
	var e ChainEntryV3 = CaptureRequestEntryV3{}
	if e.EntryTypeV3() != EventTypeCaptureRequestV3 {
		t.Fatalf("entry type = %q, want %q", e.EntryTypeV3(), EventTypeCaptureRequestV3)
	}
	if string(EventTypeCaptureRequestV3) != "capture.request.v3" {
		t.Fatalf("entry-type byte value drift: %q", EventTypeCaptureRequestV3)
	}
}

// TestCaptureV3_Rejections covers the validation paths most likely to mask a
// real divergence (mode vocab, zk invariant, hex shape, charsets).
func TestCaptureV3_Rejections(t *testing.T) {
	base := loadCaptureGolden(t).Vectors[0].Input // the full_pii_inspection vector

	cases := []struct {
		name   string
		mutate func(*CaptureRequestEntryV3)
	}{
		{"empty_company_id", func(e *CaptureRequestEntryV3) { e.CompanyID = "" }},
		{"bad_content_hash", func(e *CaptureRequestEntryV3) { e.ContentHash = "abc" }},
		{"empty_user_id", func(e *CaptureRequestEntryV3) { e.UserID = "" }},
		{"encryption_mode_is_processing_value", func(e *CaptureRequestEntryV3) { e.EncryptionMode = "zk" }},
		{"bad_processing_mode", func(e *CaptureRequestEntryV3) { e.ProcessingMode = "zero-knowledge" }},
		{"bad_pii_action", func(e *CaptureRequestEntryV3) { e.PIIAction = "deleted" }},
		{"model_with_colon", func(e *CaptureRequestEntryV3) { e.Model = "llama3:8b" }},
		{"zk_with_verdict", func(e *CaptureRequestEntryV3) { e.ProcessingMode = "zk" }}, // base has pii_detected=true
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			e := base
			tc.mutate(&e)
			if _, err := CanonicalBytesV3(e); err == nil {
				t.Fatalf("expected rejection for %s, got nil", tc.name)
			} else if !errors.Is(err, ErrInvalidEntryV3) {
				t.Fatalf("expected ErrInvalidEntryV3, got %v", err)
			}
		})
	}
}

// TestCaptureV3_ValidZK confirms a well-formed zk leaf (empty compliance surface)
// encodes — the positive counterpart to the zk-invariant rejections.
func TestCaptureV3_ValidZK(t *testing.T) {
	e := CaptureRequestEntryV3{
		CompanyID:      "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA",
		SigningKeyID:   "capture-leaf-signer-2026-v1",
		TimestampMs:    1751068800000,
		ContentHash:    strings.Repeat("e", 128),
		EncryptionMode: "zero-knowledge",
		PIIAction:      "none",
		ProcessingMode: "zk",
		UserID:         strings.Repeat("f", 128),
	}
	if _, _, err := EncodeAndHashV3(e); err != nil {
		t.Fatalf("valid zk leaf rejected: %v", err)
	}
}
