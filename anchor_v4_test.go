// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"strings"
	"testing"
)

// validV3Anchor returns a sample Version=3 anchor (no VerifiedThrough).
func validV3Anchor() Anchor {
	return Anchor{
		Version:          3,
		AnchorID:         "anc_01HZZZZZZZZZZZZZZZZZZZZZ01",
		CompanyID:        "comp_01HZZZZZZZZZZZZZZZZZZZZZZZ",
		ChainHash:        strings.Repeat("a", 128),
		Range:            EntryRange{StartEntryID: "ent_start", EndEntryID: "ent_end"},
		EntryCount:       1000,
		Signature:        "",
		SigningKeyID:     "aleutian-anchor-2026-01-v2",
		CreatedAtMs:      1715789432000,
		PreviousAnchorID: "anc_prev",
		VerifiedThrough:  0, // v3 must be 0
	}
}

// validV4Anchor returns a sample Version=4 anchor.
func validV4Anchor() Anchor {
	a := validV3Anchor()
	a.Version = 4
	a.VerifiedThrough = 1000 // must equal entry_count semantically for first-cut
	return a
}

// ---------------------------------------------------------------------------
// Version-dispatch invariants (ui_chainops_18 C1/M5)
// ---------------------------------------------------------------------------

func TestVerifyAnchor_V3NonzeroVerifiedThroughRejected(t *testing.T) {
	a := validV3Anchor()
	a.VerifiedThrough = 1 // v3 forbids this
	err := VerifyAnchorLocally(context.Background(), a, []byte("fake-key"))
	if err == nil {
		t.Fatal("expected error: v3 anchor with VerifiedThrough!=0 must be rejected")
	}
	if !strings.Contains(err.Error(), "verified_through=0") {
		t.Errorf("expected v3-gate error; got: %v", err)
	}
}

func TestVerifyAnchor_V4ZeroVerifiedThroughRejected(t *testing.T) {
	a := validV4Anchor()
	a.VerifiedThrough = 0 // v4 requires positive
	err := VerifyAnchorLocally(context.Background(), a, []byte("fake-key"))
	if err == nil {
		t.Fatal("expected error: v4 anchor with VerifiedThrough==0 must be rejected")
	}
	if !strings.Contains(err.Error(), "positive verified_through") {
		t.Errorf("expected v4-gate error; got: %v", err)
	}
}

func TestVerifyAnchor_UnsupportedVersion(t *testing.T) {
	a := validV3Anchor()
	a.Version = 5 // unknown
	err := VerifyAnchorLocally(context.Background(), a, []byte("fake-key"))
	if err == nil || !strings.Contains(err.Error(), "unsupported anchor version") {
		t.Errorf("expected unsupported-version error; got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Canonical-form dispatch
// ---------------------------------------------------------------------------

func TestCanonicalize_V3DoesNotIncludeVerifiedThrough(t *testing.T) {
	a := validV3Anchor()
	bytes, err := canonicalizeAnchorForVersion(a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), "verified_through") {
		t.Errorf("v3 canonical must NOT include verified_through; got: %s", bytes)
	}
}

func TestCanonicalize_V4IncludesVerifiedThrough(t *testing.T) {
	a := validV4Anchor()
	bytes, err := canonicalizeAnchorForVersion(a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bytes), `"verified_through":1000`) {
		t.Errorf("v4 canonical must include verified_through; got: %s", bytes)
	}
}

func TestCanonicalize_V4DispatchedByVersion_NotFieldPresence(t *testing.T) {
	// A malicious anchor sets VerifiedThrough but lies about Version.
	// We expect canonicalize to dispatch on Version (=3), so VerifiedThrough
	// is excluded — verifier later will reject the inconsistency via
	// the version-dispatch invariant.
	a := validV3Anchor()
	a.VerifiedThrough = 999
	bytes, _ := canonicalizeAnchorForVersion(a)
	if strings.Contains(string(bytes), "verified_through") {
		t.Errorf("dispatch by Version=3 must exclude VerifiedThrough regardless of field value: %s", bytes)
	}
}

// ---------------------------------------------------------------------------
// Cross-language byte-stable canonical form
// ---------------------------------------------------------------------------

func TestCanonicalize_V4StableByteForm(t *testing.T) {
	// Fixed values → fixed bytes. If this test fails, the canonical form
	// drifted from the Python/JS SDK and signature verification breaks
	// cross-language.
	a := Anchor{
		Version:          4,
		AnchorID:         "anc_01ABC",
		CompanyID:        "comp_01XYZ",
		ChainHash:        "abc123",
		Range:            EntryRange{StartEntryID: "ent_a", EndEntryID: "ent_z"},
		EntryCount:       100,
		Signature:        "",
		SigningKeyID:     "aleutian-anchor-2026-01-v2",
		CreatedAtMs:      1715789432000,
		PreviousAnchorID: "anc_prev_01",
		VerifiedThrough:  100,
	}
	want := `{"anchor_id":"anc_01ABC","chain_hash":"abc123","company_id":"comp_01XYZ","created_at_ms":1715789432000,"entry_count":100,"previous_anchor_id":"anc_prev_01","range":{"end_entry_id":"ent_z","start_entry_id":"ent_a"},"signing_key_id":"aleutian-anchor-2026-01-v2","verified_through":100,"version":4}`
	got, err := canonicalizeAnchorV4(a)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("v4 canonical drift:\n want: %s\n got:  %s", want, got)
	}
}
