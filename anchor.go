// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// =============================================================================
// Anchor Verification
// =============================================================================

// VerifyAnchorLocally verifies an anchor signature without network access.
//
// # Description
//
// Verifies the ML-DSA-65 (FIPS 204) signature of an anchor using embedded or
// provided public keys. This enables fully offline anchor verification.
//
// No pre-hashing is applied — ML-DSA-65 handles message hashing internally
// per FIPS 204, matching the signing path used by Cloud KMS.
//
// WARNING (M-5): anchor.CompanyID contains business-identifying information.
// Do not log anchors in production - use a redacted view if logging is needed.
//
// # Inputs
//
//   - ctx: Context for cancellation (reserved for future use)
//   - anchor: The anchor to verify
//   - publicKey: Optional raw 1952-byte ML-DSA-65 public key. If nil, uses
//     embedded keys based on anchor.SigningKeyID
//
// # Outputs
//
//   - error: nil if valid, ErrInvalidSignature or ErrUnknownKeyID otherwise
//
// # Security Considerations
//
//   - Uses cloudflare/circl ML-DSA-65 (FIPS 204 compliant)
//   - Signature is verified over canonical JSON directly (no pre-hash)
//   - Cannot check key revocation without network access
//
// # Example
//
//	anchor, _ := verification.LoadAnchor("anchor.json")
//	if err := verification.VerifyAnchorLocally(ctx, anchor, nil); err != nil {
//	    log.Fatalf("verification failed: %v", err)
//	}
//
// # Limitations
//
//   - Cannot check key revocation without network access
//   - Requires embedded keys to include the signing key
//
// # Assumptions
//
//   - Anchor JSON uses snake_case field names (flat format, no nesting)
//   - Signature field is base64-encoded 3309-byte ML-DSA-65 signature
func VerifyAnchorLocally(ctx context.Context, anchor Anchor, publicKey []byte) error {
	// Version-dispatch invariants (ui_chainops_18 review C1/M5).
	// MUST happen BEFORE canonicalization so a malicious anchor cannot
	// downgrade or upgrade the canonical form via the Version field.
	switch {
	case anchor.Version <= 3:
		if anchor.VerifiedThrough != 0 {
			return fmt.Errorf("%w: Version<=3 anchor must have verified_through=0", ErrInvalidSignature)
		}
	case anchor.Version == 4:
		if anchor.VerifiedThrough <= 0 {
			return fmt.Errorf("%w: Version=4 anchor must have positive verified_through", ErrInvalidSignature)
		}
	default:
		return fmt.Errorf("%w: unsupported anchor version %d", ErrInvalidSignature, anchor.Version)
	}

	// Get public key if not provided.
	if publicKey == nil {
		key, err := GetPublicKey(anchor.SigningKeyID)
		if err != nil {
			return err
		}
		publicKey = key
	}

	// Canonicalize anchor for signature verification.
	// Dispatched by Version — never probe; never branch on
	// VerifiedThrough!=0 (that branch is the downgrade oracle).
	canonical, err := canonicalizeAnchorForVersion(anchor)
	if err != nil {
		return fmt.Errorf("canonicalize anchor: %w", err)
	}

	// Decode signature from base64.
	sigBytes, err := base64.StdEncoding.DecodeString(anchor.Signature)
	if err != nil {
		return fmt.Errorf("%w: invalid signature encoding", ErrInvalidSignature)
	}

	// RS-3: Validate signature length before passing to the crypto library.
	// ML-DSA-65 signatures are always exactly 3309 bytes (FIPS 204).
	if len(sigBytes) != 3309 {
		return fmt.Errorf("%w: invalid signature length %d (want 3309)", ErrInvalidSignature, len(sigBytes))
	}

	// Verify ML-DSA-65 signature (no pre-hash per FIPS 204).
	scheme := mldsa65.Scheme()
	pub, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("%w: parse public key: %v", ErrInvalidSignature, err)
	}
	// nil opts = empty context string = FIPS 204 §5.3 pure ML-DSA.Verify (not HashML-DSA).
	// Cloud KMS PQ_SIGN_ML_DSA_65 uses the same pure variant with no context string.
	// Do NOT pass a non-nil context without updating all signing paths and both SDKs.
	// Note: scheme.Verify panics (sign.ErrTypeMismatch) if pub is not *mldsa65.PublicKey;
	// this is safe here because pub always comes from scheme.UnmarshalBinaryPublicKey above.
	if !scheme.Verify(pub, canonical, sigBytes, nil) {
		return ErrInvalidSignature
	}

	return nil
}

// =============================================================================
// Canonical JSON Types
// =============================================================================

// canonicalEntryRange is the canonical form of the entry range sub-object.
// Keys are in ALPHABETICAL order (end before start) per the backend schema.
type canonicalEntryRange struct {
	EndEntryID   string `json:"end_entry_id"`
	StartEntryID string `json:"start_entry_id"`
}

// canonicalAnchorV4Data is the Version=4 canonical form (ui_chainops_18).
// Adds `verified_through` to the v3 layout. Fields remain in alphabetical
// order per RFC 8785; verified_through sorts between range and signing_key_id.
//
// All SDKs (Go, Python, JS) must produce byte-identical output.
type canonicalAnchorV4Data struct {
	AnchorID         string              `json:"anchor_id"`
	ChainHash        string              `json:"chain_hash"`
	CompanyID        string              `json:"company_id"`
	CreatedAtMs      int64               `json:"created_at_ms"`
	EntryCount       int64               `json:"entry_count"`
	PreviousAnchorID string              `json:"previous_anchor_id"`
	Range            canonicalEntryRange `json:"range"`
	SigningKeyID     string              `json:"signing_key_id"`
	VerifiedThrough  int64               `json:"verified_through"`
	Version          int                 `json:"version"`
}

// canonicalAnchorData is the canonical form of an anchor for signature verification.
//
// CRITICAL: This struct MUST match the AnchorCanonicalJSON format produced by
// internal/chainlinker/anchor_canonical.go exactly. Fields are in ALPHABETICAL
// order per RFC 8785. All SDKs (Go, Python, JS) must produce identical output.
//
// Canonical key ordering (alphabetical):
//
//	anchor_id, chain_hash, company_id, created_at_ms, entry_count,
//	previous_anchor_id, range, signing_key_id, version
//
// Range sub-object key ordering (alphabetical):
//
//	end_entry_id, start_entry_id
//
// The "signature" field is EXCLUDED from canonical form.
type canonicalAnchorData struct {
	AnchorID         string              `json:"anchor_id"`
	ChainHash        string              `json:"chain_hash"`
	CompanyID        string              `json:"company_id"`
	CreatedAtMs      int64               `json:"created_at_ms"`
	EntryCount       int64               `json:"entry_count"`
	PreviousAnchorID string              `json:"previous_anchor_id"`
	Range            canonicalEntryRange `json:"range"`
	SigningKeyID     string              `json:"signing_key_id"`
	Version          int                 `json:"version"`
}

// =============================================================================
// Canonicalization Functions
// =============================================================================

// canonicalizeAnchorForVersion dispatches by anchor.Version to the right
// canonical form (ui_chainops_18 C3/M5). NEVER probe by signature prefix
// or by field presence; probing creates a downgrade oracle.
func canonicalizeAnchorForVersion(anchor Anchor) ([]byte, error) {
	switch anchor.Version {
	case 4:
		return canonicalizeAnchorV4(anchor)
	default:
		// v1/v2/v3 use the existing canonical form.
		return canonicalizeAnchor(anchor)
	}
}

// canonicalizeAnchorV4 returns Version=4 canonical bytes (ui_chainops_18).
// Adds verified_through to the v3 layout.
func canonicalizeAnchorV4(anchor Anchor) ([]byte, error) {
	data := canonicalAnchorV4Data{
		AnchorID:         anchor.AnchorID,
		ChainHash:        anchor.ChainHash,
		CompanyID:        anchor.CompanyID,
		CreatedAtMs:      anchor.CreatedAtMs,
		EntryCount:       anchor.EntryCount,
		PreviousAnchorID: anchor.PreviousAnchorID,
		Range: canonicalEntryRange{
			EndEntryID:   anchor.Range.EndEntryID,
			StartEntryID: anchor.Range.StartEntryID,
		},
		SigningKeyID:    anchor.SigningKeyID,
		VerifiedThrough: anchor.VerifiedThrough,
		Version:         anchor.Version,
	}
	return json.Marshal(data)
}

// canonicalizeAnchor returns deterministic JSON bytes for signature verification.
//
// # Description
//
// Uses an explicit struct with alphabetically sorted JSON keys (RFC 8785).
// The canonical form is a flat JSON object — no nested chain_state or metadata
// sub-objects. This matches AnchorCanonicalJSON in the Aleutian backend.
//
// All SDKs must produce identical output — see cross-SDK test vectors.
//
// CRITICAL: The Signature field is NOT included in the canonical form.
// The signature is computed over the anchor data, not over itself.
func canonicalizeAnchor(anchor Anchor) ([]byte, error) {
	data := canonicalAnchorData{
		AnchorID:         anchor.AnchorID,
		ChainHash:        anchor.ChainHash,
		CompanyID:        anchor.CompanyID,
		CreatedAtMs:      anchor.CreatedAtMs,
		EntryCount:       anchor.EntryCount,
		PreviousAnchorID: anchor.PreviousAnchorID,
		Range: canonicalEntryRange{
			EndEntryID:   anchor.Range.EndEntryID,
			StartEntryID: anchor.Range.StartEntryID,
		},
		SigningKeyID: anchor.SigningKeyID,
		Version:      anchor.Version,
	}

	return json.Marshal(data)
}

// =============================================================================
// File Loading Functions
// =============================================================================

// LoadAnchor loads an anchor from a JSON file.
//
// # Description
//
// Reads and parses an anchor from a JSON file. The file must contain the
// flat snake_case JSON format produced by the Aleutian backend. Use with
// [VerifyAnchorLocally] to verify the loaded anchor.
//
// # Inputs
//
//   - path: Path to the anchor JSON file
//
// # Outputs
//
//   - Anchor: The parsed anchor
//   - error: Non-nil if file cannot be read or parsed
//
// # Example
//
//	anchor, err := verification.LoadAnchor("anchor.json")
//	if err != nil {
//	    log.Fatalf("load anchor: %v", err)
//	}
func LoadAnchor(path string) (Anchor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Anchor{}, fmt.Errorf("read anchor file: %w", err)
	}

	var anchor Anchor
	if err := json.Unmarshal(data, &anchor); err != nil {
		return Anchor{}, fmt.Errorf("parse anchor JSON: %w", err)
	}

	return anchor, nil
}

// LoadExportedEntries loads entries from a JSON export file.
//
// # Description
//
// Reads and parses exported entries from a JSON file. The file should
// contain an array of entry objects.
//
// # Inputs
//
//   - path: Path to the entries JSON file
//
// # Outputs
//
//   - []ExportedEntry: The parsed entries
//   - error: Non-nil if file cannot be read or parsed
//
// # Example
//
//	entries, err := verification.LoadExportedEntries("export.json")
//	if err != nil {
//	    log.Fatalf("load entries: %v", err)
//	}
func LoadExportedEntries(path string) ([]ExportedEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read entries file: %w", err)
	}

	var entries []ExportedEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse entries JSON: %w", err)
	}

	return entries, nil
}

// CanonicalizeAnchor returns the canonical JSON bytes for an anchor.
//
// # Description
//
// Public interface to the canonicalization function, useful for debugging
// or cross-SDK compatibility testing. The output must match the Python and
// JS SDK canonicalize functions byte-for-byte.
//
// # Inputs
//
//   - anchor: The anchor to canonicalize
//
// # Outputs
//
//   - []byte: Canonical JSON bytes
//   - error: Non-nil if serialization fails
//
// # Example
//
//	canonical, _ := verification.CanonicalizeAnchor(anchor)
//	fmt.Printf("Canonical JSON: %s\n", canonical)
func CanonicalizeAnchor(anchor Anchor) ([]byte, error) {
	return canonicalizeAnchor(anchor)
}
