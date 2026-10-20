// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// dsar_chain_d: V3 canonical encoder mirror for the public verifier
// SDK. Byte-identical to the producer-side encoder
// (`internal/consent/canonical_v3.go`). Both implementations are
// tested against the same `testdata/v3_golden_sar_*.json`
// fixtures — any drift surfaces immediately.
//
// # Why a mirror instead of a shared package
//
// `sdk/verification-go` is a SEPARATE Go module
// (`github.com/aleutian-ai/verification-go`) — customers depend on
// it without pulling in `internal/consent`. The mirror is
// intentional and the load-bearing protection against drift is the
// shared golden fixture set.
//
// # Encoding (per pqc_05c v3 §3 + §4 + §7)
//
//   - 4-field common header, alphabetical: company_id, entry_type,
//     signing_key_id, timestamp_ms (NO schema_version per OQ-13)
//   - Per-event-type body, alphabetical within the body
//   - Strings: NFC-normalize, then u32 BE length prefix, then UTF-8
//     bytes (post-NFC byte length per §7)
//   - int64 / uint64: u64 BE encoding; v3 fields are non-negative
//   - String length cap: 256 bytes post-NFC per spec §7

// DomainPrefixV3 is the locked v3 domain prefix used for
// content-hash and signature derivation. See chain_b
// `ChainCanonicalDomainPrefixV3` for the producer-side
// counterpart.
//
// # WARNING — load-bearing constant
//
// Changing this byte sequence invalidates every signed v3 chain
// entry across all language ports.
const DomainPrefixV3 = "aleutian.chain.entry.v3:"

// domainPrefixV3Bytes is the pre-computed []byte form of
// DomainPrefixV3 to avoid the per-verify string-to-bytes
// allocation (chain_d Crypto L2 review fix).
var domainPrefixV3Bytes = []byte(DomainPrefixV3)

// maxV3StringFieldBytesSDK is the v3 spec §7 byte cap — same value
// as the producer-side `maxV3StringFieldBytes`. Distinct from v2's
// 1024-byte cap.
const maxV3StringFieldBytesSDK = 256

// v3SHA512HexLenSDK matches the producer-side constant.
const v3SHA512HexLenSDK = 128

// MaxCanonicalBytesV3 is the verifier's per-entry canonical-bytes cap.
// Per-field caps (`maxV3StringFieldBytesSDK = 256`) bound individual
// strings; this constant bounds the SUM across an entry's TLV stream,
// so a pathologically over-padded entry cannot force the ML-DSA-65
// verifier to do unbounded work on an attacker-shaped input. Locked
// at 4096 bytes to match the Python SDK's `MAX_CANONICAL_BYTES_V3`
// (see chain_d M4). The widest v3 SAR entry today fits comfortably
// under 1 KiB; 4× headroom absorbs future field additions without
// forcing a SemVer-breaking bound bump.
//
// Cross-language consistency is load-bearing: a divergent value in
// any one SDK becomes a per-tenant DoS vector against customers
// using the laxer SDK.
const MaxCanonicalBytesV3 = 4096

// ErrInvalidEntryV3 is the wrapped sentinel returned by encoder
// validation failures. Customer code can `errors.Is(err,
// ErrInvalidEntryV3)` to distinguish encoder rejections from
// signature/content-hash failures (which use distinct sentinels;
// see verify_v3.go).
var ErrInvalidEntryV3 = errors.New("verification: invalid v3 chain entry")

// Validation regexes (mirror of producer-side; see chain_b
// `canonical_v3.go` for rationale on each).
var (
	v3RequestIDReSDK     = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	v3IntentEntryIDReSDK = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	v3CompanyIDReSDK     = regexp.MustCompile(`^comp_[0-9A-HJKMNP-TV-Z]{26}$`)
	v3SHA512HexReSDK     = regexp.MustCompile(`^[0-9a-f]{128}$`)
	v3LegalBasisReSDK    = regexp.MustCompile(`^[a-z0-9_+]{1,64}$`)
	v3SourceChannelReSDK = regexp.MustCompile(`^[a-z0-9_+]{1,64}$`)
	v3ScopeReSDK         = regexp.MustCompile(`^(all|grant_[A-Za-z0-9_-]{1,64})$`)
	v3SigningKeyIDReSDK  = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,128}$`)

	// v3CertificateIDReSDK is the canonical shape mirror of the
	// producer-side `v3CertificateIDPattern` (see
	// `internal/consent/canonical_v3.go`). Pinned in
	// TestM7_FixtureParityWithProducer via the shared golden vector.
	v3CertificateIDReSDK = regexp.MustCompile(`^cert_[0-9a-f]{32}$`)
)

// Note: the SAR pii_digest_key_version shape check (pii_hmac_key_rotation_R4)
// reuses v3PIIDigestKeyVersionReSDK, already declared in capture_entry_v3.go
// (R3). One regex for both leaf families — same source-namespaced contract,
// same BQ column shape.

// Locked vocabulary maps (mirror of producer-side).
var (
	v3SARTypeAllowedSDK = map[SARTypeV3]struct{}{
		SARTypeAccessV3:  {},
		SARTypeErasureV3: {},
		SARTypeBothV3:    {},
	}
	v3SARFulfillmentKindAllowedSDK = map[SARFulfillmentKindV3]struct{}{
		SARFulfillmentKindAccessV3:  {},
		SARFulfillmentKindErasureV3: {},
		SARFulfillmentKindBothV3:    {},
	}
)

// =============================================================================
// Public API
// =============================================================================

// CanonicalBytesV3 is the exported entry-point encoder. Given a
// typed v3 chain entry, validates the entry and emits the
// canonical TLV byte sequence (header + alphabetical body) per
// pqc_05c v3 §3 + §4.
//
// # Inputs
//
//   - entry: a typed v3 chain entry (one of SARIntentEntryV3,
//     SARAcknowledgedEntryV3, SARFulfilledEntryV3, SARRejectedEntryV3)
//
// # Outputs
//
//   - []byte: canonical bytes; nil on validation/encoding failure
//   - error: wrapped ErrInvalidEntryV3 on validation failure
//
// # Concurrency
//
// Pure function; safe for concurrent use.
func CanonicalBytesV3(entry ChainEntryV3) ([]byte, error) {
	if entry == nil {
		return nil, fmt.Errorf("CanonicalBytesV3: %w: entry is nil", ErrInvalidEntryV3)
	}
	if err := entry.validateV3(); err != nil {
		return nil, err
	}
	enc := &v3EncoderSDK{buf: make([]byte, 0, 640)}
	entry.encodeCanonicalV3(enc)
	if enc.err != nil {
		return nil, enc.err
	}
	return enc.buf, nil
}

// ContentHashV3 returns SHA-512(prefix || canonical) hex-encoded —
// the v3 content-hash preimage per pqc_05c v3 §8.
func ContentHashV3(canonical []byte) string {
	h := sha512.New()
	h.Write(domainPrefixV3Bytes)
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}

// EncodeAndHashV3 is the one-call convenience that pairs
// CanonicalBytesV3 + ContentHashV3 for production callers
// (audit-api handlers + verifier code paths).
func EncodeAndHashV3(entry ChainEntryV3) (canonical []byte, contentHashHex string, err error) {
	canonical, err = CanonicalBytesV3(entry)
	if err != nil {
		return nil, "", err
	}
	return canonical, ContentHashV3(canonical), nil
}

// =============================================================================
// Encoder helper
// =============================================================================

// v3EncoderSDK bundles the buffer + the captured first-error slot
// so per-event-type body encoders can append fields without
// explicit error plumbing on every call. Mirror of producer-side
// `v3Encoder`.
type v3EncoderSDK struct {
	buf []byte
	err error
}

// appendStr writes a length-prefixed UTF-8 string with the spec's
// "post-NFC, post-UTF-8 byte length" semantics (pqc_05c v3 §7).
func (e *v3EncoderSDK) appendStr(s string) {
	if e.err != nil {
		return
	}
	nfc := norm.NFC.String(s)
	if len(nfc) > maxV3StringFieldBytesSDK {
		// Privacy Inv 4: opaque on actual length (NFC oracle).
		e.err = fmt.Errorf("CanonicalBytesV3: appendStr: %w: field exceeds %d bytes after NFC",
			ErrInvalidEntryV3, maxV3StringFieldBytesSDK)
		return
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(nfc)))
	e.buf = append(e.buf, lenBuf[:]...)
	e.buf = append(e.buf, nfc...)
}

// appendU64 writes a u64 BE non-negative integer. v3 has no
// signed-int fields; callers attempting to emit negative values
// indicate a validator bug — the encoder traps it as a distinct
// invariant violation.
func (e *v3EncoderSDK) appendU64(v int64) {
	if e.err != nil {
		return
	}
	if v < 0 {
		e.err = fmt.Errorf("CanonicalBytesV3: appendU64: encoder invariant violated (negative int64 reached encoder; validator must have rejected): got %d", v)
		return
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	e.buf = append(e.buf, b[:]...)
}

// appendV3Header writes the 4-field common header in alphabetical
// order: company_id, entry_type, signing_key_id, timestamp_ms.
func (e *v3EncoderSDK) appendV3Header(companyID, entryType, signingKeyID string, timestampMs int64) {
	e.appendStr(companyID)
	e.appendStr(entryType)
	e.appendStr(signingKeyID)
	e.appendU64(timestampMs)
}

// =============================================================================
// Per-entry encodeCanonicalV3 + validateV3 methods
// =============================================================================

func (e SARIntentEntryV3) encodeCanonicalV3(enc *v3EncoderSDK) {
	enc.appendV3Header(e.CompanyID, string(e.EntryType), e.SigningKeyID, e.TimestampMs)
	// pii_digest_key_version (R4): alphabetical-first body field, emitted IFF
	// non-empty so a pre-rotation legacy leaf (empty version) hashes
	// byte-identically to its original signing.
	if e.PIIDigestKeyVersion != "" {
		enc.appendStr(e.PIIDigestKeyVersion)
	}
	enc.appendStr(e.ReasonHash.Hex())      // reason_hash
	enc.appendStr(e.RequestID)             // request_id
	enc.appendStr(string(e.SARType))       // sar_type
	enc.appendStr(e.Scope)                 // scope
	enc.appendStr(string(e.SourceChannel)) // source_channel
}

func (e SARAcknowledgedEntryV3) encodeCanonicalV3(enc *v3EncoderSDK) {
	enc.appendV3Header(e.CompanyID, string(e.EntryType), e.SigningKeyID, e.TimestampMs)
	enc.appendStr(e.IntentEntryID)
	enc.appendStr(e.RequestID)
}

func (e SARFulfilledEntryV3) encodeCanonicalV3(enc *v3EncoderSDK) {
	enc.appendV3Header(e.CompanyID, string(e.EntryType), e.SigningKeyID, e.TimestampMs)
	enc.appendStr(e.CertificateID)           // 1 (NEW 2026-05-16 — alphabetical-first body field)
	enc.appendStr(string(e.FulfillmentKind)) // 2
	enc.appendStr(e.IntentEntryID)           // 3
	enc.appendStr(e.LegalBasis)              // 4
	enc.appendStr(e.ManifestRoot)            // 5
	enc.appendStr(e.RequestID)               // 6
	enc.appendU64(e.TombstoneCount)          // 7
}

func (e SARRejectedEntryV3) encodeCanonicalV3(enc *v3EncoderSDK) {
	enc.appendV3Header(e.CompanyID, string(e.EntryType), e.SigningKeyID, e.TimestampMs)
	enc.appendStr(e.IntentEntryID) // intent_entry_id
	enc.appendStr(e.LegalBasis)    // legal_basis
	// pii_digest_key_version (R4): emitted IFF non-empty (legacy-compat).
	if e.PIIDigestKeyVersion != "" {
		enc.appendStr(e.PIIDigestKeyVersion)
	}
	enc.appendStr(e.RationaleHash.Hex()) // rationale_hash
	enc.appendStr(e.RequestID)           // request_id
}

func (e SARExtendedEntryV3) encodeCanonicalV3(enc *v3EncoderSDK) {
	enc.appendV3Header(e.CompanyID, string(e.EntryType), e.SigningKeyID, e.TimestampMs)
	enc.appendU64(e.ExtendedDueAtMs) // extended_due_at_ms
	enc.appendStr(e.IntentEntryID)   // intent_entry_id
	// pii_digest_key_version (R4): emitted IFF non-empty (legacy-compat).
	if e.PIIDigestKeyVersion != "" {
		enc.appendStr(e.PIIDigestKeyVersion)
	}
	enc.appendStr(e.ReasonHash.Hex()) // reason_hash
	enc.appendStr(e.RequestID)        // request_id
}

// =============================================================================
// Validation (mirror of producer-side)
// =============================================================================

func validateV3CommonHeaderSDK(companyID, signingKeyID string, timestampMs int64, entryType, expected EventTypeV3) error {
	if companyID == "" {
		return fmt.Errorf("CanonicalBytesV3: %w: company_id empty", ErrInvalidEntryV3)
	}
	if !v3CompanyIDReSDK.MatchString(companyID) {
		return fmt.Errorf("CanonicalBytesV3: %w: company_id must match comp_<26-char Crockford-base32 ULID>",
			ErrInvalidEntryV3)
	}
	if err := validateV3StringFieldSDK("company_id", companyID); err != nil {
		return err
	}
	if entryType != expected {
		// Privacy Inv 4: do NOT echo the caller-supplied entry_type
		// value. Operators debugging a mismatched entry_type have it
		// in their producer-side logs.
		return fmt.Errorf("CanonicalBytesV3: %w: entry_type does not match expected for this struct kind",
			ErrInvalidEntryV3)
	}
	if err := validateV3SigningKeyIDSDK(signingKeyID); err != nil {
		return err
	}
	if timestampMs <= 0 {
		// Privacy Inv 4: do NOT echo the caller-supplied value.
		return fmt.Errorf("CanonicalBytesV3: %w: timestamp_ms must be positive",
			ErrInvalidEntryV3)
	}
	return nil
}

func validateV3SigningKeyIDSDK(s string) error {
	if s == "" {
		return fmt.Errorf("CanonicalBytesV3: %w: signing_key_id empty", ErrInvalidEntryV3)
	}
	if !v3SigningKeyIDReSDK.MatchString(s) {
		return fmt.Errorf("CanonicalBytesV3: %w: signing_key_id must match ^[A-Za-z0-9_./-]{1,128}$",
			ErrInvalidEntryV3)
	}
	return validateV3StringFieldSDK("signing_key_id", s)
}

func validateV3StringFieldSDK(name, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("CanonicalBytesV3: %w: %s is not valid UTF-8",
			ErrInvalidEntryV3, name)
	}
	nfc := norm.NFC.String(value)
	if len(nfc) > maxV3StringFieldBytesSDK {
		// Privacy Inv 4: do NOT echo the post-NFC byte length —
		// emitting it gives an attacker a precise oracle on NFC
		// expansion behavior of mixed-script payloads near the cap.
		return fmt.Errorf("CanonicalBytesV3: %w: %s exceeds %d bytes after NFC",
			ErrInvalidEntryV3, name, maxV3StringFieldBytesSDK)
	}
	if hasDisallowedControlBytesV3StrictSDK(nfc) {
		return fmt.Errorf("CanonicalBytesV3: %w: %s contains a disallowed control byte",
			ErrInvalidEntryV3, name)
	}
	return nil
}

func hasDisallowedControlBytesV3StrictSDK(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7F {
			return true
		}
	}
	return false
}

func validateV3RequestIDSDK(s string) error {
	if !v3RequestIDReSDK.MatchString(s) {
		return fmt.Errorf("CanonicalBytesV3: %w: request_id must match ULID regex (Crockford-base32, 26 chars)",
			ErrInvalidEntryV3)
	}
	return nil
}

func validateV3IntentEntryIDSDK(s string) error {
	if !v3IntentEntryIDReSDK.MatchString(s) {
		return fmt.Errorf("CanonicalBytesV3: %w: intent_entry_id must match UUIDv7 regex",
			ErrInvalidEntryV3)
	}
	return nil
}

func validateV3LegalBasisSDK(s string) error {
	if s == "" {
		return fmt.Errorf("CanonicalBytesV3: %w: legal_basis empty", ErrInvalidEntryV3)
	}
	if !v3LegalBasisReSDK.MatchString(s) {
		return fmt.Errorf("CanonicalBytesV3: %w: legal_basis must match ^[a-z0-9_+]{1,64}$ (spec §6.0 charset)",
			ErrInvalidEntryV3)
	}
	return nil
}

func validateV3ManifestRootSDK(s string) error {
	if !v3SHA512HexReSDK.MatchString(s) {
		return fmt.Errorf("CanonicalBytesV3: %w: manifest_root must be exactly %d lowercase hex chars (SHA-512)",
			ErrInvalidEntryV3, v3SHA512HexLenSDK)
	}
	return nil
}

func validateV3OptionalDigestSDK(name string, d TenantHMACDigestV3) error {
	if d.IsZero() {
		return nil
	}
	if !v3SHA512HexReSDK.MatchString(d.Hex()) {
		return fmt.Errorf("CanonicalBytesV3: %w: %s digest violates shape invariant (constructor regression?)",
			ErrInvalidEntryV3, name)
	}
	return nil
}

// validateV3SARFulfilledCertificateIDSDK enforces the per-kind
// requirement matrix for the certificate_id field on a sar_fulfilled
// chain entry (added 2026-05-16 by dsar_fulfill_b_pre_02e). Mirror of
// the producer-side `validateV3SARFulfilledCertificateID`.
//
//	access  → certificate_id MUST be empty
//	erasure → certificate_id MUST match cert_<32-hex>
//	both    → certificate_id MUST match cert_<32-hex>
func validateV3SARFulfilledCertificateIDSDK(kind SARFulfillmentKindV3, certID string) error {
	switch kind {
	case SARFulfillmentKindAccessV3:
		if certID != "" {
			return fmt.Errorf("CanonicalBytesV3: %w: certificate_id must be empty when fulfillment_kind=access",
				ErrInvalidEntryV3)
		}
	case SARFulfillmentKindErasureV3, SARFulfillmentKindBothV3:
		if certID == "" {
			return fmt.Errorf("CanonicalBytesV3: %w: certificate_id is required when fulfillment_kind=%s",
				ErrInvalidEntryV3, kind)
		}
		if !v3CertificateIDReSDK.MatchString(certID) {
			return fmt.Errorf("CanonicalBytesV3: %w: certificate_id must match cert_<32-hex>",
				ErrInvalidEntryV3)
		}
	default:
		// Defense-in-depth (M4 review fix mirror): the vocabulary
		// check above runs first today, but a future refactor adding
		// a new SARFulfillmentKindV3 without updating this switch
		// would silently accept any cert_id for the unknown kind.
		return fmt.Errorf("CanonicalBytesV3: %w: unknown fulfillment_kind %q in certificate_id validator",
			ErrInvalidEntryV3, kind)
	}
	return nil
}

func validateV3RequiredDigestSDK(name string, d TenantHMACDigestV3) error {
	if d.IsZero() {
		// Phase 3 review HIGH: the prior wording said "rejection
		// without rationale is invalid" — misleading on the
		// sar_extended path where the same helper is used for
		// `reason_hash` (extension without reason is the actual
		// rule). Generic wording covers both call sites.
		return fmt.Errorf("CanonicalBytesV3: %w: %s required (must be non-zero)",
			ErrInvalidEntryV3, name)
	}
	return validateV3OptionalDigestSDK(name, d)
}

// validateV3PIIDigestKeyVersionSDK enforces the pii_digest_key_version contract
// on a SAR entry (pii_hmac_key_rotation_R4). RELAXED invariant — mirror of the
// producer-side validateV3PIIDigestKeyVersion: charset (empty allowed) + the
// only hard rule `version != "" ⇒ digest present`. A non-empty digest with an
// EMPTY version is a LEGAL pre-rotation legacy leaf, NOT an error — do not
// reject it (that would break verification of every historical SAR row).
func validateV3PIIDigestKeyVersionSDK(version string, digestPresent bool) error {
	if !v3PIIDigestKeyVersionReSDK.MatchString(version) {
		// Privacy Inv 4: do not echo the offending value.
		return fmt.Errorf("CanonicalBytesV3: %w: pii_digest_key_version must match ^[a-z0-9:_.-]{0,64}$",
			ErrInvalidEntryV3)
	}
	if err := validateV3StringFieldSDK("pii_digest_key_version", version); err != nil {
		return err
	}
	if version != "" && !digestPresent {
		return fmt.Errorf("CanonicalBytesV3: %w: pii_digest_key_version present but no PII digest to apply it to",
			ErrInvalidEntryV3)
	}
	return nil
}

// =============================================================================
// Per-entry validateV3 methods
// =============================================================================

func (e SARIntentEntryV3) validateV3() error {
	if err := validateV3CommonHeaderSDK(e.CompanyID, e.SigningKeyID, e.TimestampMs, e.EntryType, EventTypeSARIntentV3); err != nil {
		return err
	}
	if err := validateV3OptionalDigestSDK("reason_hash", e.ReasonHash); err != nil {
		return err
	}
	if err := validateV3PIIDigestKeyVersionSDK(e.PIIDigestKeyVersion, !e.ReasonHash.IsZero()); err != nil {
		return err
	}
	if err := validateV3RequestIDSDK(e.RequestID); err != nil {
		return err
	}
	if _, ok := v3SARTypeAllowedSDK[e.SARType]; !ok {
		return fmt.Errorf("CanonicalBytesV3: %w: sar_type must be access|erasure|both",
			ErrInvalidEntryV3)
	}
	if !v3ScopeReSDK.MatchString(e.Scope) {
		// Privacy Inv 4 (sdk_privacy_invariants_spec): do NOT echo
		// the offending caller value in the error message. Operators
		// debugging a bad scope have it in their producer-side logs.
		return fmt.Errorf("CanonicalBytesV3: %w: scope must match ^(all|grant_[A-Za-z0-9_-]{1,64})$",
			ErrInvalidEntryV3)
	}
	if e.SourceChannel == "" {
		return fmt.Errorf("CanonicalBytesV3: %w: source_channel empty",
			ErrInvalidEntryV3)
	}
	if !v3SourceChannelReSDK.MatchString(string(e.SourceChannel)) {
		return fmt.Errorf("CanonicalBytesV3: %w: source_channel must match ^[a-z0-9_+]{1,64}$ (spec §6.0 charset)",
			ErrInvalidEntryV3)
	}
	return nil
}

func (e SARAcknowledgedEntryV3) validateV3() error {
	if err := validateV3CommonHeaderSDK(e.CompanyID, e.SigningKeyID, e.TimestampMs, e.EntryType, EventTypeSARAcknowledgedV3); err != nil {
		return err
	}
	if err := validateV3IntentEntryIDSDK(e.IntentEntryID); err != nil {
		return err
	}
	return validateV3RequestIDSDK(e.RequestID)
}

func (e SARFulfilledEntryV3) validateV3() error {
	if err := validateV3CommonHeaderSDK(e.CompanyID, e.SigningKeyID, e.TimestampMs, e.EntryType, EventTypeSARFulfilledV3); err != nil {
		return err
	}
	if _, ok := v3SARFulfillmentKindAllowedSDK[e.FulfillmentKind]; !ok {
		return fmt.Errorf("CanonicalBytesV3: %w: fulfillment_kind must be access|erasure|both",
			ErrInvalidEntryV3)
	}
	if err := validateV3SARFulfilledCertificateIDSDK(e.FulfillmentKind, e.CertificateID); err != nil {
		return err
	}
	if err := validateV3IntentEntryIDSDK(e.IntentEntryID); err != nil {
		return err
	}
	if err := validateV3LegalBasisSDK(e.LegalBasis); err != nil {
		return err
	}
	if err := validateV3ManifestRootSDK(e.ManifestRoot); err != nil {
		return err
	}
	if err := validateV3RequestIDSDK(e.RequestID); err != nil {
		return err
	}
	if e.TombstoneCount < 0 {
		return fmt.Errorf("CanonicalBytesV3: %w: tombstone_count must be >= 0",
			ErrInvalidEntryV3)
	}
	return nil
}

func (e SARRejectedEntryV3) validateV3() error {
	if err := validateV3CommonHeaderSDK(e.CompanyID, e.SigningKeyID, e.TimestampMs, e.EntryType, EventTypeSARRejectedV3); err != nil {
		return err
	}
	if err := validateV3IntentEntryIDSDK(e.IntentEntryID); err != nil {
		return err
	}
	if err := validateV3LegalBasisSDK(e.LegalBasis); err != nil {
		return err
	}
	if err := validateV3RequiredDigestSDK("rationale_hash", e.RationaleHash); err != nil {
		return err
	}
	if err := validateV3PIIDigestKeyVersionSDK(e.PIIDigestKeyVersion, !e.RationaleHash.IsZero()); err != nil {
		return err
	}
	return validateV3RequestIDSDK(e.RequestID)
}

func (e SARExtendedEntryV3) validateV3() error {
	if err := validateV3CommonHeaderSDK(e.CompanyID, e.SigningKeyID, e.TimestampMs, e.EntryType, EventTypeSARExtendedV3); err != nil {
		return err
	}
	if err := validateV3IntentEntryIDSDK(e.IntentEntryID); err != nil {
		return err
	}
	if err := validateV3RequestIDSDK(e.RequestID); err != nil {
		return err
	}
	if e.ExtendedDueAtMs <= 0 {
		return fmt.Errorf("CanonicalBytesV3: %w: extended_due_at_ms must be > 0",
			ErrInvalidEntryV3)
	}
	// Sanity-bound at 14 months past timestamp_ms (matches producer side).
	if e.ExtendedDueAtMs > e.TimestampMs+int64(420)*24*60*60*1000 {
		return fmt.Errorf("CanonicalBytesV3: %w: extended_due_at_ms exceeds 14-month sanity bound from timestamp",
			ErrInvalidEntryV3)
	}
	if err := validateV3RequiredDigestSDK("reason_hash", e.ReasonHash); err != nil {
		return err
	}
	return validateV3PIIDigestKeyVersionSDK(e.PIIDigestKeyVersion, !e.ReasonHash.IsZero())
}
