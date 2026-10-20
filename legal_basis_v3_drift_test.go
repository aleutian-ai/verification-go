// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"sort"
	"testing"
)

// dsar_chain_d_go_legal_basis_audit (2026-05-27): drift guards
// pinning the Go SDK's legal_basis vocabulary against the producer.
//
// # Cross-language drift posture
//
// Producer source of truth lives at `internal/sar/legal_basis.go`
// (rejection 7-value enum) and the access/erasure orchestrators'
// `LegalBasis{Access,Erasure}GreenPath` constants (fulfillment
// vocabulary). The SDK is in a SEPARATE Go module so we cannot
// import the producer constants directly; we pin the EXPECTED set
// here as plain-text fixtures. If the producer adds a value, this
// test fails — by design — so the SDK update is required at the
// test layer.

// TestLegalBasisV3_RejectionVocabularyPinned asserts the SDK's
// rejection vocabulary matches the producer enum byte-for-byte.
//
// Producer enum (audited 2026-05-27 from
// `internal/sar/legal_basis.go::LegalBasis` consts):
func TestLegalBasisV3_RejectionVocabularyPinned(t *testing.T) {
	t.Parallel()

	// Producer's closed 7-value enum, in producer's canonical
	// render order (allLegalBasesOrdered).
	producerVocab := []string{
		"art_12_5_manifestly_unfounded",
		"art_15_4_rights_of_others",
		"art_17_3_a_freedom_of_expression",
		"art_17_3_b_legal_obligation",
		"art_17_3_e_public_interest",
		"art_17_3_e_legal_claims",
		"other",
	}

	got := AllRejectionLegalBasesV3()

	if len(got) != len(producerVocab) {
		t.Fatalf("rejection vocab length drift: got %d, producer has %d (re-audit internal/sar/legal_basis.go)",
			len(got), len(producerVocab))
	}
	for i, want := range producerVocab {
		if got[i] != want {
			t.Errorf("rejection vocab[%d]: got %q, want %q (producer canonical order)",
				i, got[i], want)
		}
	}
}

// TestLegalBasisV3_RejectionVocabularySymmetric asserts no SDK
// constant exists without a matching producer value (catches
// SDK-side aspirational/orphan constants — exactly the class of
// drift this audit surfaced for the pre-2026-05-27 SDK).
func TestLegalBasisV3_RejectionVocabularySymmetric(t *testing.T) {
	t.Parallel()
	producerSet := map[string]struct{}{
		"art_12_5_manifestly_unfounded":    {},
		"art_15_4_rights_of_others":        {},
		"art_17_3_a_freedom_of_expression": {},
		"art_17_3_b_legal_obligation":      {},
		"art_17_3_e_public_interest":       {},
		"art_17_3_e_legal_claims":          {},
		"other":                            {},
	}
	for _, sdkVal := range AllRejectionLegalBasesV3() {
		if _, ok := producerSet[sdkVal]; !ok {
			t.Errorf("SDK has rejection value %q with no producer counterpart "+
				"(orphan SDK constant; re-audit internal/sar/legal_basis.go)", sdkVal)
		}
	}
}

// TestLegalBasisV3_FulfillmentVocabularyPinned asserts the
// fulfillment vocabulary matches what the producer ACTUALLY emits.
// Producer source: `internal/sar/access_fulfillment_orchestrator.go::LegalBasisAccessGreenPath`
// + `internal/sar/fulfillment_orchestrator.go::LegalBasisErasureGreenPath`.
//
// Distinct from the rejection enum — fulfillment has no closed
// `Parse` validator on the producer side; this is an audit-derived
// pin against what is observably emitted today.
func TestLegalBasisV3_FulfillmentVocabularyPinned(t *testing.T) {
	t.Parallel()
	wantSet := map[string]struct{}{
		"art_15_access":  {},
		"art_17_erasure": {},
	}
	got := AllFulfillmentLegalBasesV3()
	if len(got) != len(wantSet) {
		t.Fatalf("fulfillment vocab length drift: got %d, producer emits %d "+
			"(re-audit access_fulfillment_orchestrator + fulfillment_orchestrator)",
			len(got), len(wantSet))
	}
	gotSorted := make([]string, len(got))
	copy(gotSorted, got)
	sort.Strings(gotSorted)
	for _, sdkVal := range gotSorted {
		if _, ok := wantSet[sdkVal]; !ok {
			t.Errorf("SDK has fulfillment value %q with no producer counterpart", sdkVal)
		}
	}
}

// TestLegalBasisV3_CharsetCompliance asserts every constant in
// both vocabularies passes the v3 §6 `[a-z0-9_+]{1,64}` charset
// gate — defense-in-depth against a future SDK-side const that
// would silently fail producer validation.
func TestLegalBasisV3_CharsetCompliance(t *testing.T) {
	t.Parallel()
	check := func(label string, vals []string) {
		for _, v := range vals {
			if !v3LegalBasisReSDK.MatchString(v) {
				t.Errorf("%s constant %q violates v3 §6 charset "+
					"^[a-z0-9_+]{1,64}$", label, v)
			}
		}
	}
	check("rejection", AllRejectionLegalBasesV3())
	check("fulfillment", AllFulfillmentLegalBasesV3())
}

// TestLegalBasisV3_RegexParityWithProducer pins the SDK's regex
// pattern source against the producer's pattern as a hard string
// literal. This closes the "test against itself" gap surfaced by
// the chain_d_go_review_followup audit — if the producer tightens
// its regex (e.g., drops `+`), this test fails BEFORE any silent
// vocabulary drift can occur. Update both sides in lockstep, then
// update this literal.
//
// Producer source-of-truth: `internal/consent/canonical_v3.go::v3LegalBasisRe`
// (string is `^[a-z0-9_+]{1,64}$` as of audit 2026-05-27).
func TestLegalBasisV3_RegexParityWithProducer(t *testing.T) {
	t.Parallel()
	const producerPattern = `^[a-z0-9_+]{1,64}$`
	if got := v3LegalBasisReSDK.String(); got != producerPattern {
		t.Errorf("legal_basis regex drift: SDK=%q, producer=%q "+
			"(update both in lockstep, then update this test literal)",
			got, producerPattern)
	}
}

// TestCertificateIDV3_RegexParityWithProducer pins the SDK's
// certificate_id regex against the producer's pattern as a hard
// string literal. Same drift-guard rationale as
// TestLegalBasisV3_RegexParityWithProducer.
//
// Producer source-of-truth: `internal/consent/canonical_v3.go::v3CertificateIDPattern`
// (string is `^cert_[0-9a-f]{32}$` as of audit 2026-05-27).
func TestCertificateIDV3_RegexParityWithProducer(t *testing.T) {
	t.Parallel()
	const producerPattern = `^cert_[0-9a-f]{32}$`
	if got := v3CertificateIDReSDK.String(); got != producerPattern {
		t.Errorf("certificate_id regex drift: SDK=%q, producer=%q "+
			"(update both in lockstep, then update this test literal)",
			got, producerPattern)
	}
}
