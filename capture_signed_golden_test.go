// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type captureSignedVector struct {
	SigningKeyID        string `json:"signing_key_id"`
	PublicKeyB64        string `json:"public_key_b64"`
	SignatureB64        string `json:"signature_b64"`
	ExpectedContentHash string `json:"expected_content_hash_hex"`
	Input               struct {
		CompanyID           string `json:"company_id"`
		SigningKeyID        string `json:"signing_key_id"`
		TimestampMs         int64  `json:"timestamp_ms"`
		CaptureMethod       string `json:"capture_method"`
		ContentHash         string `json:"content_hash"`
		DLP                 string `json:"dlp"`
		EncryptionMode      string `json:"encryption_mode"`
		Model               string `json:"model"`
		PIIAction           string `json:"pii_action"`
		PIICategories       string `json:"pii_categories"`
		PIIDetected         bool   `json:"pii_detected"`
		PIIDigestKeyVersion string `json:"pii_digest_key_version"`
		ProcessingMode      string `json:"processing_mode"`
		Provider            string `json:"provider"`
		Region              string `json:"region"`
		SourceType          string `json:"source_type"`
		TrustLevel          string `json:"trust_level"`
		UserID              string `json:"user_id"`
	} `json:"input"`
}

// TestVerifyCaptureSignedGoldenVector verifies the cross-language signed capture
// golden vector through VerifyChainEntryV3 — the same fixture Python + JS verify,
// proving cross-language signature parity for capture leaves (01i).
func TestVerifyCaptureSignedGoldenVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "v3_golden_capture_signed.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var v captureSignedVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	pub, err := base64.StdEncoding.DecodeString(v.PublicKeyB64)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	manifest, err := NewTrustManifestFromMapV3(map[string][]byte{v.SigningKeyID: pub})
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	entry := CaptureRequestEntryV3{
		CompanyID: v.Input.CompanyID, SigningKeyID: v.Input.SigningKeyID, TimestampMs: v.Input.TimestampMs,
		CaptureMethod: v.Input.CaptureMethod, ContentHash: v.Input.ContentHash, DLP: v.Input.DLP,
		EncryptionMode: v.Input.EncryptionMode, Model: v.Input.Model, PIIAction: v.Input.PIIAction,
		PIICategories: v.Input.PIICategories, PIIDetected: v.Input.PIIDetected, PIIDigestKeyVersion: v.Input.PIIDigestKeyVersion,
		ProcessingMode: v.Input.ProcessingMode, Provider: v.Input.Provider, Region: v.Input.Region,
		SourceType: v.Input.SourceType, TrustLevel: v.Input.TrustLevel, UserID: v.Input.UserID,
	}
	if err := VerifyChainEntryV3(context.Background(), entry, v.ExpectedContentHash, v.SignatureB64, manifest); err != nil {
		t.Fatalf("signed capture golden vector must verify: %v", err)
	}
}
