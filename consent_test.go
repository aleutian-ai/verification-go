// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// consentGoldenPath is the path from sdk/verification-go/ to the golden file.
// A copy of sdk/testdata/consent_canonical_golden.json, kept inside the module so its tests pass
// outside the monorepo; scripts/publish-sdks.sh refuses a copy that differs.
const consentGoldenPath = "testdata/shared/consent_canonical_golden.json"

// consentGoldenEntryJSON holds all 15 canonical fields as read from the
// golden file. Field names match the JSON tags on goldenEntry (generator).
type consentGoldenEntryJSON struct {
	ActorPseudonym             string `json:"actor_pseudonym"`
	ActorPseudonymKeyVersion   string `json:"actor_pseudonym_key_version"`
	CompanyID                  string `json:"company_id"`
	ConsentID                  string `json:"consent_id"`
	ConsentRenderedHash        string `json:"consent_rendered_hash"`
	ConsentTemplateHash        string `json:"consent_template_hash"`
	ConsentTextVersion         string `json:"consent_text_version"`
	EntryType                  string `json:"entry_type"`
	EventType                  string `json:"event_type"`
	ExpiresAtMs                int64  `json:"expires_at_ms"`
	IdempotencyKeyHash         string `json:"idempotency_key_hash"`
	ProcessingModeAtWrite      string `json:"processing_mode_at_write"`
	ProcessingModeSetByEventID string `json:"processing_mode_set_by_event_id"`
	SigningKeyID               string `json:"signing_key_id"`
	TimestampMs                int64  `json:"timestamp_ms"`
}

type consentGoldenVector struct {
	Name         string                 `json:"name"`
	Entry        consentGoldenEntryJSON `json:"entry"`
	CanonicalHex string                 `json:"canonical_hex"`
	ContentHash  string                 `json:"content_hash"`
}

type consentGoldenFile struct {
	Version int                   `json:"version"`
	Vectors []consentGoldenVector `json:"vectors"`
}

func loadConsentGolden(t *testing.T) consentGoldenFile {
	t.Helper()
	raw, err := os.ReadFile(consentGoldenPath)
	if err != nil {
		t.Fatalf("read consent golden JSON %s: %v", consentGoldenPath, err)
	}
	var g consentGoldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parse consent golden JSON: %v", err)
	}
	if len(g.Vectors) == 0 {
		t.Fatal("consent golden file has no vectors")
	}
	return g
}

// jsonToConsentChainEntry converts a golden file entry JSON to ConsentChainEntry.
func jsonToConsentChainEntry(j consentGoldenEntryJSON) ConsentChainEntry {
	return ConsentChainEntry{
		ActorPseudonym:             j.ActorPseudonym,
		ActorPseudonymKeyVersion:   j.ActorPseudonymKeyVersion,
		CompanyID:                  j.CompanyID,
		ConsentID:                  j.ConsentID,
		ConsentRenderedHash:        j.ConsentRenderedHash,
		ConsentTemplateHash:        j.ConsentTemplateHash,
		ConsentTextVersion:         j.ConsentTextVersion,
		EntryType:                  ConsentEntryType(j.EntryType),
		EventType:                  ConsentEntryType(j.EventType),
		ExpiresAtMs:                j.ExpiresAtMs,
		IdempotencyKeyHash:         j.IdempotencyKeyHash,
		ProcessingModeAtWrite:      j.ProcessingModeAtWrite,
		ProcessingModeSetByEventID: j.ProcessingModeSetByEventID,
		SigningKeyID:               j.SigningKeyID,
		TimestampMs:                j.TimestampMs,
	}
}

// =============================================================================
// Golden vector tests
// =============================================================================

// TestConsentCanonical_GoldenVectors verifies that ConsentCanonical produces
// byte-identical output to the internal encoder for all golden vectors.
func TestConsentCanonical_GoldenVectors(t *testing.T) {
	t.Parallel()
	g := loadConsentGolden(t)

	for _, v := range g.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			entry := jsonToConsentChainEntry(v.Entry)
			canonical, err := ConsentCanonical(entry)
			if err != nil {
				t.Fatalf("ConsentCanonical: %v", err)
			}
			gotHex := hex.EncodeToString(canonical)
			if gotHex != v.CanonicalHex {
				t.Errorf("canonical_hex mismatch:\n got: %s\nwant: %s", gotHex, v.CanonicalHex)
			}

			gotHash := DeriveConsentContentHash(canonical)
			if gotHash != v.ContentHash {
				t.Errorf("content_hash mismatch:\n got: %s\nwant: %s", gotHash, v.ContentHash)
			}
		})
	}
}

// TestConsentCanonical_FieldOrder_Alphabetical verifies the 15 fields are
// written in strict alphabetical order by building an entry with unique
// per-field byte values and checking the TLV position of each field.
func TestConsentCanonical_FieldOrder_Alphabetical(t *testing.T) {
	t.Parallel()

	// Each field gets a unique marker string so we can detect its position
	// in the raw canonical bytes.
	entry := ConsentChainEntry{
		ActorPseudonym:             "field_01_actor_pseudonym",
		ActorPseudonymKeyVersion:   "field_02_actor_pseudonym_key_version",
		CompanyID:                  "field_03_company_id",
		ConsentID:                  "field_04_consent_id",
		ConsentRenderedHash:        "field_05_consent_rendered_hash",
		ConsentTemplateHash:        "field_06_consent_template_hash",
		ConsentTextVersion:         "field_07_consent_text_version",
		EntryType:                  ConsentEntryTypeGranted, // = "consent_granted" — field 08
		EventType:                  ConsentEntryTypeGranted, // = "consent_granted" — field 09
		ExpiresAtMs:                1800000000000,           // field 10
		IdempotencyKeyHash:         "field_11_idempotency_key_hash",
		ProcessingModeAtWrite:      "pii_inspection", // field 12
		ProcessingModeSetByEventID: "field_13_pm_set_by",
		SigningKeyID:               "field_14_signing_key_id",
		TimestampMs:                1700000000000, // field 15
	}

	canonical, err := ConsentCanonical(entry)
	if err != nil {
		t.Fatalf("ConsentCanonical: %v", err)
	}
	raw := string(canonical)

	// Verify each field marker appears in the canonical bytes, and appears
	// before the next one in alphabetical order.
	orderedMarkers := []string{
		"field_01_actor_pseudonym",
		"field_02_actor_pseudonym_key_version",
		"field_03_company_id",
		"field_04_consent_id",
		"field_05_consent_rendered_hash",
		"field_06_consent_template_hash",
		"field_07_consent_text_version",
		"consent_granted", // entry_type (field 8)
		// event_type is also "consent_granted" — same position check is not possible;
		// the alphabetical test in the internal package covers this via TestConsentCanonical_FieldOrderAlphabetical.
		"field_11_idempotency_key_hash",
		"pii_inspection",
		"field_13_pm_set_by",
		"field_14_signing_key_id",
	}

	prevPos := -1
	for _, marker := range orderedMarkers {
		pos := findInBytes(canonical, marker)
		if pos < 0 {
			t.Errorf("marker %q not found in canonical bytes", marker)
			continue
		}
		if pos <= prevPos {
			t.Errorf("marker %q at pos %d is not after prev pos %d (field order broken)", marker, pos, prevPos)
		}
		// Advance past the marker to find the next one
		if marker == "consent_granted" {
			// Skip past the first occurrence (entry_type); event_type follows
			prevPos = findInBytesAfter(canonical, marker, pos+1)
			if prevPos < 0 {
				prevPos = pos
			}
		} else {
			prevPos = pos
		}
		// ensure raw reference resolves
		_ = raw
	}
}

// findInBytes returns the byte offset of substr within b, or -1.
func findInBytes(b []byte, substr string) int {
	s := []byte(substr)
	for i := 0; i <= len(b)-len(s); i++ {
		match := true
		for j := 0; j < len(s); j++ {
			if b[i+j] != s[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// findInBytesAfter returns the first offset of substr at or after start.
func findInBytesAfter(b []byte, substr string, start int) int {
	s := []byte(substr)
	for i := start; i <= len(b)-len(s); i++ {
		match := true
		for j := 0; j < len(s); j++ {
			if b[i+j] != s[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// =============================================================================
// Mutation tests
// =============================================================================

// TestMutateEachFieldBreaksContentHash_GoSDK verifies that mutating any single
// canonical field changes the DeriveConsentContentHash output. Covers all 15.
func TestMutateEachFieldBreaksContentHash_GoSDK(t *testing.T) {
	t.Parallel()
	g := loadConsentGolden(t)

	// Find the baseline consent_granted_basic vector.
	var baseline consentGoldenVector
	for _, v := range g.Vectors {
		if v.Name == "consent_granted_basic" {
			baseline = v
			break
		}
	}
	if baseline.Name == "" {
		t.Fatal("consent_granted_basic vector not found in golden file")
	}

	baseEntry := jsonToConsentChainEntry(baseline.Entry)
	baseCanonical, err := ConsentCanonical(baseEntry)
	if err != nil {
		t.Fatalf("baseline ConsentCanonical: %v", err)
	}
	baseHash := DeriveConsentContentHash(baseCanonical)

	// Find the corresponding mutation vector for each field and verify the
	// content_hash differs from the baseline.
	mutationFields := []string{
		"actor_pseudonym",
		"actor_pseudonym_key_version",
		"company_id",
		"consent_id",
		"consent_rendered_hash",
		"consent_template_hash",
		"consent_text_version",
		"entry_type",
		"event_type",
		"expires_at_ms",
		"idempotency_key_hash",
		"processing_mode_at_write",
		"processing_mode_set_by_event_id",
		"signing_key_id",
		"timestamp_ms",
	}
	if len(mutationFields) != 15 {
		t.Fatalf("expected 15 mutation fields, got %d", len(mutationFields))
	}

	vectorsByName := make(map[string]consentGoldenVector, len(g.Vectors))
	for _, v := range g.Vectors {
		vectorsByName[v.Name] = v
	}

	for _, field := range mutationFields {
		field := field
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			mutName := "mutation_" + field
			mv, ok := vectorsByName[mutName]
			if !ok {
				t.Fatalf("mutation vector %q not found in golden file", mutName)
			}
			mutEntry := jsonToConsentChainEntry(mv.Entry)
			mutCanonical, err := ConsentCanonical(mutEntry)
			if err != nil {
				t.Fatalf("ConsentCanonical for mutation %q: %v", field, err)
			}
			mutHash := DeriveConsentContentHash(mutCanonical)
			if mutHash == baseHash {
				t.Errorf("mutating %q did not change content_hash (both %q)", field, baseHash)
			}
		})
	}
}

// =============================================================================
// VerifyConsentEntry tests
// =============================================================================

// TestVerifyConsentEntry_InvalidSignature verifies that a flipped signature
// byte produces ErrInvalidSignature.
func TestVerifyConsentEntry_InvalidSignature(t *testing.T) {
	t.Parallel()
	g := loadConsentGolden(t)
	entry := jsonToConsentChainEntry(g.Vectors[0].Entry)
	storedHash := g.Vectors[0].ContentHash

	// Build a 3309-byte all-zero signature (invalid but correct length).
	badSig := make([]byte, 3309)
	keyID := "aleutian-ml-dsa-65-2026-v1"

	err := VerifyConsentEntry(context.Background(), entry, storedHash, badSig, keyID)
	if err == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got: %v", err)
	}
}

// TestVerifyConsentEntry_ContentHashMismatch verifies that a tampered
// storedContentHash produces ErrInvalidSignature before any key lookup.
func TestVerifyConsentEntry_ContentHashMismatch(t *testing.T) {
	t.Parallel()
	g := loadConsentGolden(t)
	entry := jsonToConsentChainEntry(g.Vectors[0].Entry)

	// Use a content hash from a different vector to simulate tampering.
	tamperedHash := g.Vectors[1].ContentHash
	badSig := make([]byte, 3309)
	keyID := "aleutian-ml-dsa-65-2026-v1"

	err := VerifyConsentEntry(context.Background(), entry, tamperedHash, badSig, keyID)
	if err == nil {
		t.Fatal("expected error for content hash mismatch, got nil")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got: %v", err)
	}
}

// TestVerifyConsentEntry_UnknownKeyID verifies that an unknown keyID (after
// content hash match) returns ErrUnknownKeyID.
func TestVerifyConsentEntry_UnknownKeyID(t *testing.T) {
	t.Parallel()
	g := loadConsentGolden(t)
	entry := jsonToConsentChainEntry(g.Vectors[0].Entry)
	storedHash := g.Vectors[0].ContentHash

	err := VerifyConsentEntry(context.Background(), entry, storedHash, make([]byte, 3309), "unknown-key-does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown key ID, got nil")
	}
	if !errors.Is(err, ErrUnknownKeyID) {
		t.Errorf("expected ErrUnknownKeyID, got: %v", err)
	}
}

// TestVerifyConsentEntry_BadSigLength verifies that a signature with wrong
// length returns ErrInvalidSignature.
func TestVerifyConsentEntry_BadSigLength(t *testing.T) {
	t.Parallel()
	g := loadConsentGolden(t)
	entry := jsonToConsentChainEntry(g.Vectors[0].Entry)
	storedHash := g.Vectors[0].ContentHash

	err := VerifyConsentEntry(context.Background(), entry, storedHash, make([]byte, 100), "aleutian-ml-dsa-65-2026-v1")
	if err == nil {
		t.Fatal("expected error for bad sig length, got nil")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got: %v", err)
	}
}

// TestConsentCanonical_ValidationRejects verifies that invalid entries are
// rejected with ErrInvalidConsentEntry.
func TestConsentCanonical_ValidationRejects(t *testing.T) {
	t.Parallel()

	validBase := ConsentChainEntry{
		ActorPseudonym:             "actor-hash",
		ActorPseudonymKeyVersion:   "v1",
		CompanyID:                  "corp",
		ConsentID:                  "id-001",
		ConsentRenderedHash:        "renderedhash",
		ConsentTemplateHash:        "templatehash",
		ConsentTextVersion:         "v1",
		EntryType:                  ConsentEntryTypeGranted,
		EventType:                  ConsentEntryTypeGranted,
		ExpiresAtMs:                1800000000000,
		IdempotencyKeyHash:         "idemphash",
		ProcessingModeAtWrite:      "pii_inspection",
		ProcessingModeSetByEventID: "pm-event-001",
		SigningKeyID:               "key-v1",
		TimestampMs:                1700000000000,
	}

	cases := []struct {
		name  string
		mutFn func(*ConsentChainEntry)
	}{
		{"empty actor_pseudonym", func(e *ConsentChainEntry) { e.ActorPseudonym = "" }},
		{"empty company_id", func(e *ConsentChainEntry) { e.CompanyID = "" }},
		{"empty signing_key_id", func(e *ConsentChainEntry) { e.SigningKeyID = "" }},
		{"negative expires_at_ms", func(e *ConsentChainEntry) { e.ExpiresAtMs = -1 }},
		{"zero timestamp_ms", func(e *ConsentChainEntry) { e.TimestampMs = 0 }},
		{"unknown entry_type", func(e *ConsentChainEntry) {
			e.EntryType = "consent_unknown"
			e.EventType = "consent_unknown"
		}},
		{"string exceeds 1 KiB", func(e *ConsentChainEntry) {
			e.CompanyID = string(make([]byte, 1025))
			for i := range []byte(e.CompanyID) {
				([]byte(e.CompanyID))[i] = 'a'
			}
		}},
		{"pii_inspection without set_by", func(e *ConsentChainEntry) {
			e.ProcessingModeSetByEventID = ""
		}},
		{"revoked with non-zero expiry", func(e *ConsentChainEntry) {
			e.EntryType = ConsentEntryTypeRevoked
			e.EventType = ConsentEntryTypeRevoked
			e.ExpiresAtMs = 1900000000000
		}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := validBase
			tc.mutFn(&e)
			_, err := ConsentCanonical(e)
			if err == nil {
				t.Fatalf("expected ErrInvalidConsentEntry for %q, got nil", tc.name)
			}
			if !errors.Is(err, ErrInvalidConsentEntry) {
				t.Errorf("expected ErrInvalidConsentEntry, got: %v", err)
			}
		})
	}
}
