// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

// dsar_chain_d M12: documented common-vocabulary constants for
// the `LegalBasis` field on SARFulfilledEntryV3 and
// SARRejectedEntryV3 per pqc_05c v3 §6.
//
// # Open vocabulary, closed charset
//
// `LegalBasis` is intentionally OPEN-VOCABULARY at the value
// level (verifiers MUST accept any string matching
// `^[a-z0-9_+]{1,64}$`) and CLOSED at the byte level (the
// charset regex prevents operator free-text injection — see
// chain_d H3 review fix).
//
// The constants below name the v3-launch vocabulary so customer
// dashboards / verifier UIs can switch on them ergonomically. A
// future ticket adds new values without bumping v4; verifiers
// recognizing only this list MUST warn-not-reject on unknown
// values.
//
// # Source of truth
//
// The producer-side `internal/sar/legal_basis.go` is the canonical
// REJECTION vocabulary; the access/erasure fulfillment-orchestrators
// (`internal/sar/access_fulfillment_orchestrator.go`,
// `internal/sar/fulfillment_orchestrator.go`) are the canonical
// FULFILLMENT vocabulary. This SDK file mirrors what those producer
// surfaces ACTUALLY emit today — a drift guard test
// (`legal_basis_v3_drift_test.go::TestLegalBasisV3_PinnedVocabulary`)
// asserts the SDK list is a superset of every value the producer
// actually mints.
//
// Audited 2026-05-27 (`dsar_chain_d_go_legal_basis_audit`).

// Fulfillment legal-basis values (pqc_05c v3 §6.1, used in
// SARFulfilledEntryV3.LegalBasis).
//
// What the producer emits today (2026-05-27):
//   - LegalBasisFulfillArt15AccessV3 — access fulfillment green path
//   - LegalBasisFulfillArt17ErasureV3 — erasure fulfillment green path
//
// Future producer fulfillment values will be added here as they
// land; the drift test asserts every producer-emitted value has a
// matching SDK constant.
const (
	LegalBasisFulfillArt15AccessV3  = "art_15_access"
	LegalBasisFulfillArt17ErasureV3 = "art_17_erasure"
)

// Rejection legal-basis values (pqc_05c v3 §6.2, used in
// SARRejectedEntryV3.LegalBasis). Mirror of the producer's closed
// vocabulary at `internal/sar/legal_basis.go::LegalBasis`. The
// 7-value enum below MUST stay in lockstep with the producer; the
// drift test enforces.
const (
	// Art. 12(5) — request manifestly unfounded or excessive.
	LegalBasisRejectArt12_5ManifestlyUnfoundedV3 = "art_12_5_manifestly_unfounded"

	// Art. 15(4) — third-party rights carve-out on access.
	LegalBasisRejectArt15_4RightsOfOthersV3 = "art_15_4_rights_of_others"

	// Art. 17(3)(a) — freedom of expression and information.
	LegalBasisRejectArt17_3aFreedomOfExpressionV3 = "art_17_3_a_freedom_of_expression"

	// Art. 17(3)(b) — compliance with a legal obligation. Used by
	// the fulfillment-orchestrator auto-rejection branch for active
	// retention holds.
	LegalBasisRejectArt17_3bLegalObligationV3 = "art_17_3_b_legal_obligation"

	// Art. 17(3)(e) — reasons of public interest in the area of
	// public health.
	LegalBasisRejectArt17_3ePublicInterestV3 = "art_17_3_e_public_interest"

	// Art. 17(3)(e) — establishment, exercise, or defence of legal
	// claims.
	LegalBasisRejectArt17_3eLegalClaimsV3 = "art_17_3_e_legal_claims"

	// "other" — operator-flagged catch-all. Display surfaces
	// should render "(see rationale)" so the data subject understands
	// the rationale is in the audit chain `rationale_hash` preimage.
	LegalBasisRejectOtherV3 = "other"
)

// AllRejectionLegalBasesV3 returns the closed 7-value rejection
// vocabulary in canonical render order. Used by the drift guard
// test and by verifier UIs building dropdowns.
//
// # Description
//
// Returns a fresh slice; callers may sort or mutate without
// affecting SDK state. Order mirrors `internal/sar/legal_basis.go::allLegalBasesOrdered`.
//
// # Inputs
//
//   - none
//
// # Outputs
//
//   - []string: the ordered allowlist (length == 7 today)
//
// # Example
//
//	for _, lb := range verification.AllRejectionLegalBasesV3() {
//	    fmt.Println(lb)
//	}
//
// # Limitations
//
//   - Fulfillment legal_basis values are NOT included; see
//     AllFulfillmentLegalBasesV3.
//
// # Assumptions
//
//   - Caller does not mutate the returned slice expecting other
//     goroutines to observe the change.
func AllRejectionLegalBasesV3() []string {
	return []string{
		LegalBasisRejectArt12_5ManifestlyUnfoundedV3,
		LegalBasisRejectArt15_4RightsOfOthersV3,
		LegalBasisRejectArt17_3aFreedomOfExpressionV3,
		LegalBasisRejectArt17_3bLegalObligationV3,
		LegalBasisRejectArt17_3ePublicInterestV3,
		LegalBasisRejectArt17_3eLegalClaimsV3,
		LegalBasisRejectOtherV3,
	}
}

// AllFulfillmentLegalBasesV3 returns the fulfillment-side
// vocabulary in canonical render order. Today this is the green-path
// pair (access + erasure); the producer doesn't enumerate a closed
// fulfillment vocabulary the way it does for rejection.
//
// # Description
//
// Returns a fresh slice; callers may sort or mutate without
// affecting SDK state.
//
// # Inputs
//
//   - none
//
// # Outputs
//
//   - []string: the ordered fulfillment list (length == 2 today)
//
// # Example
//
//	for _, lb := range verification.AllFulfillmentLegalBasesV3() {
//	    fmt.Println(lb)
//	}
//
// # Limitations
//
//   - Open at the producer side; this list mirrors what the
//     producer ACTUALLY emits today. Combined fulfillments
//     (e.g., access + erasure on the same SAR) currently emit
//     separate `sar_fulfilled` chain entries with distinct
//     legal_basis values, NOT a combined `art_15+art_17` string.
//     If that evolves, both this list AND the drift test must
//     update in lockstep.
//
// # Assumptions
//
//   - Caller does not mutate the returned slice expecting other
//     goroutines to observe the change.
func AllFulfillmentLegalBasesV3() []string {
	return []string{
		LegalBasisFulfillArt15AccessV3,
		LegalBasisFulfillArt17ErasureV3,
	}
}
