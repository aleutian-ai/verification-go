// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import "time"

// =============================================================================
// Anchor Types
// =============================================================================

// EntryRange identifies the first and last entries covered by an anchor.
//
// # Description
//
// Identifies the first and last entries in the chain segment this anchor
// attests to. Both IDs are entry_ids from the audit chain.
type EntryRange struct {
	// StartEntryID is the entry_id of the first entry covered by this anchor.
	StartEntryID string `json:"start_entry_id"`

	// EndEntryID is the entry_id of the last entry covered by this anchor.
	EndEntryID string `json:"end_entry_id"`
}

// Anchor represents a signed chain checkpoint.
//
// # Description
//
// An anchor is a cryptographically signed attestation of a company's
// audit chain state at a specific point in time. Anchors are generated
// periodically (typically daily) and can be used to verify chain
// integrity without network access.
//
// The Signature field is an ML-DSA-65 (FIPS 204) signature over the canonical
// JSON form of the anchor (all fields except Signature, alphabetical key order,
// no whitespace). See canonicalizeAnchor for the exact canonical form.
//
// This struct matches the storage.SignedAnchor flat format delivered by
// the Aleutian backend. It does NOT have nested chain_state or metadata
// sub-objects — those are internal-only backend fields.
//
// WARNING (M-5): CompanyID contains business-identifying information.
// Do not log anchors in production — use a redacted view if logging is needed.
type Anchor struct {
	// Version is the anchor format version. Currently 2 (ML-DSA-65 / FIPS 204).
	Version int `json:"version"`

	// AnchorID is the unique identifier for this anchor.
	AnchorID string `json:"anchor_id"`

	// CompanyID is the company this anchor belongs to.
	// WARNING: Contains business-identifying information.
	CompanyID string `json:"company_id"`

	// ChainHash is the anchor-of-anchors digest binding this anchor to its
	// covered chain segment. It is NOT byte-equal to the tip entry's
	// chain_hash — it is the output of ComputeAnchorChainHash, which
	// applies a distinct SHA-512 domain separator ("aleutian.anchor.v2:")
	// and folds in the previous anchor's hash, the company id, the entry
	// range, and the tip entry's chain_hash. Verifiers MUST recompute this
	// value (not byte-compare against the tip) to validate the binding.
	ChainHash string `json:"chain_hash"`

	// Range identifies the first and last entries covered by this anchor.
	Range EntryRange `json:"range"`

	// EntryCount is the number of entries covered by this anchor.
	EntryCount int64 `json:"entry_count"`

	// Signature is the base64-encoded ML-DSA-65 signature (3309 bytes decoded).
	// Excluded from the canonical JSON used to compute this signature.
	Signature string `json:"signature"`

	// SigningKeyID identifies which key signed this anchor. Corresponds to a
	// key in the embedded public keys. Format: "aleutian-ml-dsa-65-YYYY-vN".
	SigningKeyID string `json:"signing_key_id"`

	// CreatedAtMs is when this anchor was created, in milliseconds since the
	// Unix epoch (UTC).
	CreatedAtMs int64 `json:"created_at_ms"`

	// PreviousAnchorID is the anchor_id of the preceding anchor, or empty
	// string for the first anchor.
	PreviousAnchorID string `json:"previous_anchor_id"`

	// VerifiedThrough (ui_chainops_18 / Version=4): a signed claim that
	// the chain from (previous_anchor.EntryCount + 1) through this
	// anchor's EntryCount has been verified clean by the anchor-generator
	// at signing time. Verifiers may treat this as a trust shortcut: a
	// valid Version=4 anchor signature implies a valid verified_through
	// claim, so the segment need not be re-walked.
	//
	// # Version dispatch
	//
	//   - Version <= 3 anchors MUST carry VerifiedThrough == 0. Non-zero
	//     values on a Version<4 anchor invalidate verification (the field
	//     is not in those versions' canonical bytes, so non-zero means
	//     the anchor was forged).
	//   - Version == 4 anchors MUST carry VerifiedThrough > 0. A zero
	//     value on a Version=4 anchor invalidates verification.
	//
	// # Cross-language encoding
	//
	// Always present in JSON (NO `omitempty` tag) so Go and Python and JS
	// produce byte-identical canonical bytes for the same logical record.
	VerifiedThrough int64 `json:"verified_through"`
}

// =============================================================================
// Chain Verification Types
// =============================================================================

// ExportedEntry represents an entry from a data export.
//
// # Description
//
// Contains the fields needed to verify chain integrity for an exported
// audit entry. This matches the schema of Aleutian's data export format.
type ExportedEntry struct {
	// EntryID is the unique identifier for this entry.
	EntryID string `json:"entry_id"`

	// EntryType indicates the type of entry (e.g., "request", "tombstone").
	EntryType string `json:"entry_type"`

	// Timestamp is when this entry was created.
	// Format: RFC3339 with microsecond precision.
	Timestamp string `json:"timestamp"`

	// RunID is the batch run identifier that linked this entry.
	RunID string `json:"run_id"`

	// SequenceNum is the 0-indexed position within the batch run.
	SequenceNum int64 `json:"sequence_num"`

	// GlobalSeq is the global sequence number across all runs.
	GlobalSeq int64 `json:"global_seq"`

	// ContentHash is the SHA-512 hash of the entry content, or
	// a tombstone content hash if this is a tombstone entry.
	ContentHash string `json:"content_hash"`

	// ChainHash is the chain hash linking this entry to its predecessor.
	ChainHash string `json:"chain_hash"`
}

// OfflineBreak represents a break found during offline verification.
//
// # Description
//
// Contains details about an inconsistency detected during chain
// verification, including the position, entry ID, and type of break.
//
// WARNING (M-4): OfflineBreak contains EntryID and hashes that may
// correlate to PII. Consider truncating hashes before logging:
// hash[:8] is sufficient for debugging.
type OfflineBreak struct {
	// Position is the 0-indexed position in the entries slice where
	// the break was detected.
	Position int `json:"position"`

	// EntryID is the entry_id of the entry where the break was detected.
	EntryID string `json:"entry_id"`

	// ExpectedHash is the expected chain hash (computed from inputs).
	ExpectedHash string `json:"expected_hash"`

	// ActualHash is the actual chain hash found in the entry.
	ActualHash string `json:"actual_hash"`

	// BreakType categorizes the break. Possible values:
	//   - "hash_mismatch": chain hash doesn't match computed value
	//   - "sequence_gap": global_seq is not consecutive
	//   - "invalid_tombstone": tombstone content hash format invalid
	//   - "anchor_mismatch": final hash doesn't match anchor
	BreakType string `json:"break_type"`

	// Context contains additional context about the break.
	Context map[string]string `json:"context"`
}

// OfflineVerificationResult contains the result of offline chain verification.
//
// # Description
//
// Summarizes the results of verifying a chain export against an anchor.
//
// WARNING (M-8): Do not log Duration in production - it can reveal chain
// size and business volume. Duration is excluded from JSON serialization.
type OfflineVerificationResult struct {
	// Valid is true if no breaks were found.
	Valid bool `json:"valid"`

	// EntriesVerified is the number of entries that were verified.
	EntriesVerified int `json:"entries_verified"`

	// TombstonesFound is the number of tombstone entries encountered.
	TombstonesFound int `json:"tombstones_found"`

	// Breaks contains details about any chain breaks found.
	Breaks []OfflineBreak `json:"breaks"`

	// Duration is how long verification took. Excluded from JSON to
	// prevent accidental logging that could reveal business volume.
	Duration time.Duration `json:"-"`
}

// ChainVerifyOptions configures chain verification behavior.
//
// # Description
//
// Allows customization of chain verification, including setting
// resource limits to prevent OOM on large chains.
type ChainVerifyOptions struct {
	// Anchor binds the verified chain to a signed Aleutian anchor.
	//
	// When non-nil, after walking the entries the verifier recomputes the
	// expected anchor chain hash via ComputeAnchorChainHash(
	//   PreviousAnchorHash, Anchor.CompanyID,
	//   Anchor.Range.StartEntryID, Anchor.Range.EndEntryID,
	//   <walked tip chain_hash>,
	// ) and compares it against Anchor.ChainHash. Mismatch emits an
	// anchor_mismatch OfflineBreak.
	//
	// nil skips anchor binding (per-entry chain integrity is still checked).
	Anchor *Anchor

	// PreviousAnchorHash is the chain_hash of the anchor immediately
	// preceding Anchor in the anchor-of-anchors chain. Required when
	// Anchor != nil.
	//
	// For genesis anchors (Anchor.PreviousAnchorID == SeedAnchorID), pass
	// SeedAnchorHash. For non-genesis anchors, callers must fetch the prior
	// anchor and supply its ChainHash here.
	//
	// Empty string + non-nil Anchor + Anchor.PreviousAnchorID == SeedAnchorID
	// is treated as SeedAnchorHash (convenience for genesis). Any other empty
	// value with a non-nil Anchor yields anchor_mismatch — callers MUST
	// supply the previous anchor's hash explicitly to verify a mid-chain
	// anchor, otherwise no trust can be established.
	PreviousAnchorHash string

	// ExpectedLastHash is deprecated and broken — it byte-compares the
	// walked tip chain_hash against the anchor's chain_hash, but the two
	// values live in DIFFERENT SHA-512 domain separators (chain.v2 vs
	// anchor.v2) and cannot match for real Aleutian-produced anchors. Use
	// the Anchor + PreviousAnchorHash fields instead. Kept temporarily for
	// backwards compatibility with prior 0.x callers; will be removed in
	// the next minor release.
	//
	// Deprecated: pass Anchor + PreviousAnchorHash for real anchor binding.
	ExpectedLastHash string

	// MaxEntries limits entries processed. 0 = unlimited.
	// Use this to prevent OOM on very large chain exports.
	MaxEntries int

	// MaxBreaks stops verification early if this many breaks are found.
	// 0 = unlimited.
	MaxBreaks int
}

// =============================================================================
// Webhook Types
// =============================================================================

// WebhookVerifyOptions configures webhook signature verification.
//
// # Description
//
// Allows customization of timestamp tolerance for webhook verification.
// Default values (5 min past, 30 sec future) match Aleutian's server-side
// enforcement.
type WebhookVerifyOptions struct {
	// TolerancePast is the maximum age of a valid signature.
	// Zero value means use default (5 minutes). Set to -1 to disable.
	TolerancePast time.Duration

	// ToleranceFuture is the maximum future drift allowed.
	// Zero value means use default (30 seconds). Set to -1 to disable.
	ToleranceFuture time.Duration

	// Now overrides current time (for testing only).
	Now time.Time
}

// DefaultWebhookVerifyOptions returns default verification options.
//
// # Description
//
// Returns options with server-enforced defaults:
//   - TolerancePast: 5 minutes
//   - ToleranceFuture: 30 seconds
//
// # Example
//
//	opts := verification.DefaultWebhookVerifyOptions()
//	err := verification.VerifyWebhookSignature(ctx, sig, body, secret, opts)
func DefaultWebhookVerifyOptions() WebhookVerifyOptions {
	return WebhookVerifyOptions{
		TolerancePast:   WebhookDefaultTolerancePast,
		ToleranceFuture: WebhookDefaultToleranceFuture,
	}
}
