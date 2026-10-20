// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"fmt"
	"regexp"
)

// capture_entry_v3.go: public verifier-SDK mirror of the producer-side
// capture-chain leaf encoder (`internal/captureentry/canonical_v3.go`,
// chainlinker_modernization_01b). Byte-identical by construction and pinned by
// the shared golden vectors in `testdata/v3_golden_capture_request.json` — the
// SAME file the producer bakes. Any drift surfaces immediately in
// TestCaptureV3_FixtureParity.
//
// # Why a mirror, not an import
//
// This SDK is a SEPARATE Go module; customers depend on it without pulling in
// `internal/...`. The mirror is intentional and the load-bearing protection
// against drift is the shared golden fixture set (the chain_d discipline).
//
// # The two orthogonal mode fields
//
// encryption_mode {zero-knowledge|aleutian-managed|cmek} is KEY CUSTODY;
// processing_mode {zk|pii_inspection} is INSPECTION AUTHORIZATION. They are
// independent. processing_mode=="zk" requires an empty compliance surface
// (pii_detected=false, pii_action="none", pii_categories="", dlp="") — enforced
// here so a verifier rejects a self-contradictory zk leaf.

// EventTypeCaptureRequestV3 is the entry_type discriminator for a capture-chain
// AI-request leaf. It shares DomainPrefixV3 with the SAR/consent entries;
// domain separation is via this length-prefixed entry_type at the fixed header
// offset (see the producer-side EntryTypeCaptureRequest doc).
//
// # WARNING — load-bearing constant
//
// Changing this string re-domains every capture leaf and breaks signature
// verification for all history.
const EventTypeCaptureRequestV3 EventTypeV3 = "capture.request.v3"

// maxPlausibleTimestampMsSDK mirrors the producer's far-future sanity ceiling
// (~year 2200) for the server-stamped anchor clock.
const maxPlausibleTimestampMsSDK int64 = 7258118400000 // 2200-01-01T00:00:00Z UnixMilli

// Capture-entry vocabularies + charsets (mirror of the producer-side; see
// internal/captureentry/canonical_v3.go for rationale on each).
var (
	captureEncryptionModeAllowedSDK = map[string]struct{}{
		"zero-knowledge":   {},
		"aleutian-managed": {},
		"cmek":             {},
	}
	captureProcessingModeAllowedSDK = map[string]struct{}{
		"zk":             {},
		"pii_inspection": {},
	}
	capturePIIActionAllowedSDK = map[string]struct{}{
		"none":     {},
		"flagged":  {},
		"blocked":  {},
		"redacted": {},
	}
	// Hyphen REQUIRED: real TrustLevel includes "self-reported".
	captureProvenanceReSDK = regexp.MustCompile(`^[a-z0-9_-]{0,32}$`)
	captureProviderReSDK   = regexp.MustCompile(`^[a-z0-9_.-]{0,64}$`)
	captureModelReSDK      = regexp.MustCompile(`^[A-Za-z0-9_./-]{0,128}$`)
	captureRegionReSDK     = regexp.MustCompile(`^[a-z0-9-]{0,16}$`)
	// v3PIIDigestKeyVersionReSDK pins the pii_digest_key_version charset
	// (pii_hmac_key_rotation_R3). Source-namespaced lowercase IDs like "sm:v1".
	v3PIIDigestKeyVersionReSDK = regexp.MustCompile(`^[a-z0-9:_.-]{0,64}$`)
)

// CaptureRequestEntryV3 is the verifier-SDK representation of a capture-chain
// leaf. Field set + json tags match the producer and the cross-language fixture
// `input` block exactly (snake_case). entry_type is a constant, not a field.
//
// # Description
//
// All hash/digest fields (content_hash, user_id, pii_categories, dlp) are
// lowercase-128-hex (SHA-512 / HMAC-SHA512) or — for the optional digests —
// empty. The verifier validates SHAPE; the per-tenant HMAC keying property is a
// producer-side responsibility (it cannot be checked from the hex alone).
//
// # Concurrency
//
// Immutable value type; safe for concurrent use.
type CaptureRequestEntryV3 struct {
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
}

// EntryTypeV3 returns the capture entry-type tag.
func (e CaptureRequestEntryV3) EntryTypeV3() EventTypeV3 { return EventTypeCaptureRequestV3 }

// sealedChainEntryV3 makes CaptureRequestEntryV3 satisfy the sealed
// ChainEntryV3 interface (only in-package types can).
func (e CaptureRequestEntryV3) sealedChainEntryV3(chainEntryV3SealTag) {}

// encodeCanonicalV3 writes the capture-leaf canonical bytes: the 4-field header
// (company_id, entry_type, signing_key_id, timestamp_ms) then the 15-field body
// in alphabetical order. Byte-identical to the producer encoder.
func (e CaptureRequestEntryV3) encodeCanonicalV3(enc *v3EncoderSDK) {
	enc.appendV3Header(e.CompanyID, string(EventTypeCaptureRequestV3), e.SigningKeyID, e.TimestampMs)

	enc.appendStr(e.CaptureMethod)  // 1
	enc.appendStr(e.ContentHash)    // 2
	enc.appendStr(e.DLP)            // 3
	enc.appendStr(e.EncryptionMode) // 4
	enc.appendStr(e.Model)          // 5
	enc.appendStr(e.PIIAction)      // 6
	enc.appendStr(e.PIICategories)  // 7
	if e.PIIDetected {              // 8 (bool → u64 0/1)
		enc.appendU64(1)
	} else {
		enc.appendU64(0)
	}
	enc.appendStr(e.PIIDigestKeyVersion) // 9 (pii_hmac_key_rotation_R3)
	enc.appendStr(e.ProcessingMode)      // 10
	enc.appendStr(e.Provider)            // 11
	enc.appendStr(e.Region)              // 12
	enc.appendStr(e.SourceType)          // 13
	enc.appendStr(e.TrustLevel)          // 14
	enc.appendStr(e.UserID)              // 15
}

// validateV3 runs the full producer-mirror validation. Returns wrapped
// ErrInvalidEntryV3 on the first failure.
func (e CaptureRequestEntryV3) validateV3() error {
	// --- Header ---
	if e.CompanyID == "" {
		return fmt.Errorf("CanonicalBytesV3: %w: company_id empty", ErrInvalidEntryV3)
	}
	if !v3CompanyIDReSDK.MatchString(e.CompanyID) {
		return fmt.Errorf("CanonicalBytesV3: %w: company_id must match comp_<26-char Crockford-base32 ULID>", ErrInvalidEntryV3)
	}
	if err := validateV3StringFieldSDK("company_id", e.CompanyID); err != nil {
		return err
	}
	if err := validateV3SigningKeyIDSDK(e.SigningKeyID); err != nil {
		return err
	}
	if e.TimestampMs <= 0 {
		return fmt.Errorf("CanonicalBytesV3: %w: timestamp_ms must be positive (got %d)", ErrInvalidEntryV3, e.TimestampMs)
	}
	if e.TimestampMs > maxPlausibleTimestampMsSDK {
		return fmt.Errorf("CanonicalBytesV3: %w: timestamp_ms %d exceeds the year-2200 sanity ceiling", ErrInvalidEntryV3, e.TimestampMs)
	}

	// --- Body: required hex fields ---
	if !v3SHA512HexReSDK.MatchString(e.ContentHash) {
		return fmt.Errorf("CanonicalBytesV3: %w: content_hash must be exactly 128 lowercase hex chars (SHA-512)", ErrInvalidEntryV3)
	}
	if !v3SHA512HexReSDK.MatchString(e.UserID) {
		return fmt.Errorf("CanonicalBytesV3: %w: user_id must be exactly 128 lowercase hex chars (HMAC-SHA512 pseudonym)", ErrInvalidEntryV3)
	}

	// --- Body: optional hex digests (empty OR 128-hex) ---
	if err := captureValidateOptionalHexDigestSDK("dlp", e.DLP); err != nil {
		return err
	}
	if err := captureValidateOptionalHexDigestSDK("pii_categories", e.PIICategories); err != nil {
		return err
	}

	// --- Body: pii_digest_key_version (pii_hmac_key_rotation_R3) ---
	if !v3PIIDigestKeyVersionReSDK.MatchString(e.PIIDigestKeyVersion) {
		return fmt.Errorf("CanonicalBytesV3: %w: pii_digest_key_version must match ^[a-z0-9:_.-]{0,64}$ (got %q)", ErrInvalidEntryV3, e.PIIDigestKeyVersion)
	}
	// Present iff a digest is present.
	captureHasDigest := e.PIICategories != "" || e.DLP != ""
	if captureHasDigest && e.PIIDigestKeyVersion == "" {
		return fmt.Errorf("CanonicalBytesV3: %w: pii_digest_key_version required when pii_categories or dlp is present", ErrInvalidEntryV3)
	}
	if !captureHasDigest && e.PIIDigestKeyVersion != "" {
		return fmt.Errorf("CanonicalBytesV3: %w: pii_digest_key_version must be empty when no pii/dlp digest is present (got %q)", ErrInvalidEntryV3, e.PIIDigestKeyVersion)
	}

	// --- Body: closed-vocabulary enums ---
	if _, ok := captureEncryptionModeAllowedSDK[e.EncryptionMode]; !ok {
		return fmt.Errorf("CanonicalBytesV3: %w: encryption_mode must be one of {zero-knowledge, aleutian-managed, cmek} (got %q)", ErrInvalidEntryV3, e.EncryptionMode)
	}
	if _, ok := captureProcessingModeAllowedSDK[e.ProcessingMode]; !ok {
		return fmt.Errorf("CanonicalBytesV3: %w: processing_mode must be one of {zk, pii_inspection} (got %q)", ErrInvalidEntryV3, e.ProcessingMode)
	}
	if _, ok := capturePIIActionAllowedSDK[e.PIIAction]; !ok {
		return fmt.Errorf("CanonicalBytesV3: %w: pii_action must be one of {none, flagged, blocked, redacted} (got %q)", ErrInvalidEntryV3, e.PIIAction)
	}

	// zk cross-field invariant: processing_mode=="zk" (inspection NOT authorized)
	// ⇒ the compliance surface MUST be empty.
	if e.ProcessingMode == "zk" {
		if e.PIIDetected {
			return fmt.Errorf("CanonicalBytesV3: %w: processing_mode=zk forbids pii_detected=true (inspection not authorized)", ErrInvalidEntryV3)
		}
		if e.PIIAction != "none" {
			return fmt.Errorf("CanonicalBytesV3: %w: processing_mode=zk requires pii_action=none (got %q)", ErrInvalidEntryV3, e.PIIAction)
		}
		if e.PIICategories != "" {
			return fmt.Errorf("CanonicalBytesV3: %w: processing_mode=zk requires empty pii_categories", ErrInvalidEntryV3)
		}
		if e.DLP != "" {
			return fmt.Errorf("CanonicalBytesV3: %w: processing_mode=zk requires empty dlp", ErrInvalidEntryV3)
		}
	}

	// --- Body: charset-pinned open-vocabulary fields (empty permitted) ---
	if !captureProviderReSDK.MatchString(e.Provider) {
		return fmt.Errorf("CanonicalBytesV3: %w: provider must match ^[a-z0-9_.-]{0,64}$ (got %q)", ErrInvalidEntryV3, e.Provider)
	}
	if !captureModelReSDK.MatchString(e.Model) {
		return fmt.Errorf("CanonicalBytesV3: %w: model must match ^[A-Za-z0-9_./-]{0,128}$ (got %q)", ErrInvalidEntryV3, e.Model)
	}
	if !captureRegionReSDK.MatchString(e.Region) {
		return fmt.Errorf("CanonicalBytesV3: %w: region must match ^[a-z0-9-]{0,16}$ (got %q)", ErrInvalidEntryV3, e.Region)
	}
	if !captureProvenanceReSDK.MatchString(e.CaptureMethod) {
		return fmt.Errorf("CanonicalBytesV3: %w: capture_method must match ^[a-z0-9_-]{0,32}$ (got %q)", ErrInvalidEntryV3, e.CaptureMethod)
	}
	if !captureProvenanceReSDK.MatchString(e.SourceType) {
		return fmt.Errorf("CanonicalBytesV3: %w: source_type must match ^[a-z0-9_-]{0,32}$ (got %q)", ErrInvalidEntryV3, e.SourceType)
	}
	if !captureProvenanceReSDK.MatchString(e.TrustLevel) {
		return fmt.Errorf("CanonicalBytesV3: %w: trust_level must match ^[a-z0-9_-]{0,32}$ (got %q)", ErrInvalidEntryV3, e.TrustLevel)
	}

	// Defense-in-depth UTF-8 / NFC-cap / control-byte guard on every string body field.
	for _, f := range []struct{ name, val string }{
		{"capture_method", e.CaptureMethod},
		{"content_hash", e.ContentHash},
		{"dlp", e.DLP},
		{"encryption_mode", e.EncryptionMode},
		{"model", e.Model},
		{"pii_action", e.PIIAction},
		{"pii_categories", e.PIICategories},
		{"processing_mode", e.ProcessingMode},
		{"provider", e.Provider},
		{"region", e.Region},
		{"source_type", e.SourceType},
		{"trust_level", e.TrustLevel},
		{"user_id", e.UserID},
	} {
		if err := validateV3StringFieldSDK(f.name, f.val); err != nil {
			return err
		}
	}
	return nil
}

// captureValidateOptionalHexDigestSDK accepts empty OR exactly 128 lowercase hex.
func captureValidateOptionalHexDigestSDK(name, value string) error {
	if value == "" {
		return nil
	}
	if !v3SHA512HexReSDK.MatchString(value) {
		return fmt.Errorf("CanonicalBytesV3: %w: %s must be empty or exactly 128 lowercase hex chars (HMAC-SHA512 digest)", ErrInvalidEntryV3, name)
	}
	return nil
}

// Compile-time interface check.
var _ ChainEntryV3 = CaptureRequestEntryV3{}
