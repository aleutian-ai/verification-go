// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

// dsar_chain_d: V3 SAR chain entry structs for the public verifier
// SDK. Mirror of `internal/consent/sar_chain_entry.go` but in the
// SDK package so external customers can depend on these shapes.
//
// # Cross-language reference
//
// Python (chain_e) and JS (chain_f) verifiers ship with the same
// struct shapes (named slightly differently per language idiom).
// The cross-language golden vectors in `testdata/v3_golden_sar_*.json`
// are the byte-level reference — any deviation between language
// ports surfaces as a hash mismatch on the fixture tests.
//
// # Privacy posture (OQ-11, locked)
//
// SAR entries are systematically actor-anonymous on chain. NONE
// of these structs carry actor pseudonyms or email-derived hashes.
// Verifiers cannot identify the data subject from the chain entry
// alone — the bridge to actor identity flows through the producer's
// per-tenant `aleutian_platform.sar_requests` table via `RequestID`.

// EventTypeV3 is a chain entry's discriminating tag. Lockd byte
// sequences per pqc_05c v3 §3.2.
type EventTypeV3 string

const (
	// EventTypeSARIntentV3 — end-user (or controller-on-behalf via
	// API) filed a Data Subject Access Request.
	EventTypeSARIntentV3 EventTypeV3 = "sar_intent"

	// EventTypeSARAcknowledgedV3 — controller acknowledged the
	// request within the GDPR Art. 12 timing window.
	EventTypeSARAcknowledgedV3 EventTypeV3 = "sar_acknowledged"

	// EventTypeSARFulfilledV3 — controller produced the export
	// (Art. 15 / 20) or executed the erasure (Art. 17). The
	// `manifest_root` field binds the chain claim to the actual
	// artifacts.
	EventTypeSARFulfilledV3 EventTypeV3 = "sar_fulfilled"

	// EventTypeSARRejectedV3 — controller declined the SAR under
	// a permitted Art. 17(3) basis. `rationale_hash` binds the
	// chain entry to the rationale text without exposing it.
	EventTypeSARRejectedV3 EventTypeV3 = "sar_rejected"

	// EventTypeSARExtendedV3 — controller invoked the GDPR
	// Art. 12(3) second-sentence extension provision, pushing the
	// response deadline out by up to 2 additional months. Only one
	// extension permitted per SAR by protocol. The bound
	// `reason_hash` field anchors the controller's cleartext
	// reason without exposing it on chain.
	//
	// Added 2026-05-15 by dsar_p4_polish_v1_0_cleanup #4.
	EventTypeSARExtendedV3 EventTypeV3 = "sar_extended"
)

// SARSourceChannelV3 identifies the surface that originated a SAR
// intent (canonical on chain per OQ-12, only on intent).
type SARSourceChannelV3 string

const (
	SARSourceChannelPortalV3 SARSourceChannelV3 = "portal" // end-user via /portal/sar
	SARSourceChannelAPIV3    SARSourceChannelV3 = "api"    // controller via /v1/sar/intent
)

// SARTypeV3 identifies the GDPR right being exercised.
type SARTypeV3 string

const (
	SARTypeAccessV3  SARTypeV3 = "access"  // Art. 15 / 20
	SARTypeErasureV3 SARTypeV3 = "erasure" // Art. 17
	SARTypeBothV3    SARTypeV3 = "both"
)

// SARFulfillmentKindV3 identifies what the controller actually did
// at fulfillment time. May differ from the intent's SARTypeV3
// when, e.g., user requested both but controller fulfilled only
// access (the erasure portion lands as a separate entry).
type SARFulfillmentKindV3 string

const (
	SARFulfillmentKindAccessV3  SARFulfillmentKindV3 = "access"
	SARFulfillmentKindErasureV3 SARFulfillmentKindV3 = "erasure"
	SARFulfillmentKindBothV3    SARFulfillmentKindV3 = "both"
)

// ChainEntryV3 is the SEALED interface implemented by every typed
// v3 chain entry struct shipped by this SDK. Customers MUST NOT
// (and CANNOT) implement their own types satisfying this interface.
//
// # Sealing (chain_d H1, locked 2026-05-11)
//
// The `sealedChainEntryV3` method takes an unexported parameter
// type (`chainEntryV3SealTag`) — only types declared in THIS
// package can implement it because external packages cannot
// construct that tag. This closes the type-confusion bypass
// where a customer (or a third-party library imported by the
// customer) could declare a struct satisfying the interface with
// attacker-chosen encoding behavior, slipping a forged signing
// input past the verifier.
//
// # Concurrency
//
// Implementers MUST be value types so concurrent reads are safe by
// default.
type ChainEntryV3 interface {
	// EntryTypeV3 returns the canonical event-type tag. Exported
	// so verifier UI / downstream tooling can branch on it
	// without importing the unexported encode/validate methods.
	EntryTypeV3() EventTypeV3

	// sealedChainEntryV3 prevents external packages from
	// satisfying this interface. See the package doc.
	sealedChainEntryV3(chainEntryV3SealTag)

	// validateV3 runs all pre-encoding semantic + structural
	// checks. Returns wrapped ErrInvalidEntryV3 on failure.
	validateV3() error

	// encodeCanonicalV3 writes the entry's canonical bytes
	// (header + alphabetical body) into the supplied encoder.
	encodeCanonicalV3(enc *v3EncoderSDK)
}

// chainEntryV3SealTag is the unexported parameter type used by
// `sealedChainEntryV3` to prevent external implementations of
// ChainEntryV3. Outside packages cannot reference this type so
// they cannot declare a method with the matching signature.
type chainEntryV3SealTag struct{}

// SARIntentEntryV3 is the v3 canonical chain entry for a filed
// DSAR. Header (CompanyID / EntryType / SigningKeyID / TimestampMs)
// + 5 alphabetical body fields per pqc_05c v3 §4.5.
type SARIntentEntryV3 struct {
	CompanyID    string      `json:"company_id"`
	EntryType    EventTypeV3 `json:"entry_type"` // = EventTypeSARIntentV3
	SigningKeyID string      `json:"signing_key_id"`
	TimestampMs  int64       `json:"timestamp_ms"`

	// PIIDigestKeyVersion is the source-namespaced PII-HMAC master
	// key version ("sm:v1") that minted ReasonHash
	// (pii_hmac_key_rotation_R4). Encoded into canonical bytes IFF
	// non-empty (alphabetical-first body field, before reason_hash).
	// A pre-rotation LEGACY leaf carries a reason_hash but an EMPTY
	// version — the empty version is OMITTED, so the reconstructed
	// canonical is byte-identical to what was originally signed and
	// the signature still verifies. The verifier enforces only the
	// RELAXED invariant `version != "" ⇒ digest present`; digest-
	// without-version is a legal legacy leaf, NOT an error.
	PIIDigestKeyVersion string `json:"pii_digest_key_version"`

	// ReasonHash: HMAC-SHA-512 hex of NFC cleartext under
	// per-tenant PII subkey (per pqc_05c v3 §4.0). Verifier
	// treats this as opaque hex — verifier-side cannot re-derive
	// the key (lives with producer). Zero-value digest = caller
	// did not supply the cleartext.
	ReasonHash TenantHMACDigestV3 `json:"reason_hash"`

	// RequestID is the SAR's canonical ULID, identical to what
	// the controller surfaces to the data subject.
	//
	// # Verifier display guidance (chain_d Privacy F5)
	//
	// Safe to display TO THE DATA SUBJECT who initiated the
	// request (it's their own request id). UNSAFE to display to
	// third parties: combined with TimestampMs it pins a
	// per-tenant SAR filing within ~1 ms.
	RequestID string `json:"request_id"`

	SARType SARTypeV3 `json:"sar_type"`
	Scope   string    `json:"scope"` // "all" | grant_<id>

	// SourceChannel records the surface that originated the
	// intent. Canonical on chain per OQ-12 — this IS audit
	// evidence (the producer's claim of "the data subject filed
	// via portal vs. controller filed via API"). Customers'
	// verifier UIs SHOULD surface this only to the requesting
	// data subject or to internal audit logs, not to a public
	// transparency surface.
	SourceChannel SARSourceChannelV3 `json:"source_channel"`
}

func (e SARIntentEntryV3) EntryTypeV3() EventTypeV3               { return EventTypeSARIntentV3 }
func (e SARIntentEntryV3) sealedChainEntryV3(chainEntryV3SealTag) {}

// SARAcknowledgedEntryV3 — header + 2 body fields per pqc_05c v3 §4.6.
type SARAcknowledgedEntryV3 struct {
	CompanyID    string      `json:"company_id"`
	EntryType    EventTypeV3 `json:"entry_type"` // = EventTypeSARAcknowledgedV3
	SigningKeyID string      `json:"signing_key_id"`
	TimestampMs  int64       `json:"timestamp_ms"`

	IntentEntryID string `json:"intent_entry_id"` // UUIDv7
	RequestID     string `json:"request_id"`
}

func (e SARAcknowledgedEntryV3) EntryTypeV3() EventTypeV3               { return EventTypeSARAcknowledgedV3 }
func (e SARAcknowledgedEntryV3) sealedChainEntryV3(chainEntryV3SealTag) {}

// SARFulfilledEntryV3 — header + 7 body fields per pqc_05c v3 §4.7
// (7th body field `certificate_id` added 2026-05-16 by
// dsar_fulfill_b_pre_02e as the alphabetical-first body field).
type SARFulfilledEntryV3 struct {
	CompanyID    string      `json:"company_id"`
	EntryType    EventTypeV3 `json:"entry_type"` // = EventTypeSARFulfilledV3
	SigningKeyID string      `json:"signing_key_id"`
	TimestampMs  int64       `json:"timestamp_ms"`

	// CertificateID is the deletion certificate identifier bound
	// to this fulfillment when erasure was performed. Per-kind
	// rules (validated):
	//   access  → MUST be empty (zero-length string)
	//   erasure → MUST match ^cert_[0-9a-f]{32}$
	//   both    → MUST match ^cert_[0-9a-f]{32}$
	// Alphabetical-first body field per pqc_05c v3 §4.7.
	CertificateID string `json:"certificate_id"`

	FulfillmentKind SARFulfillmentKindV3 `json:"fulfillment_kind"`
	IntentEntryID   string               `json:"intent_entry_id"`

	// LegalBasis: spec §6 vocabulary, charset
	// `^[a-z0-9_+]{1,64}$`. Verifier MUST accept any value
	// matching the charset — semantic vocabulary is open.
	LegalBasis string `json:"legal_basis"`

	// ManifestRoot: SHA-512 hex (128 chars; OQ-8 hardened
	// 2026-05-10). Reproducible by end-user with `sha512sum`
	// per pqc_05c v3 §5. NOT a TenantHMACDigest because it must
	// be unkeyed for end-user reproducibility.
	ManifestRoot   string `json:"manifest_root"`
	RequestID      string `json:"request_id"`
	TombstoneCount int64  `json:"tombstone_count"` // ≥ 0
}

func (e SARFulfilledEntryV3) EntryTypeV3() EventTypeV3               { return EventTypeSARFulfilledV3 }
func (e SARFulfilledEntryV3) sealedChainEntryV3(chainEntryV3SealTag) {}

// SARRejectedEntryV3 — header + 4 body fields per pqc_05c v3 §4.8.
type SARRejectedEntryV3 struct {
	CompanyID    string      `json:"company_id"`
	EntryType    EventTypeV3 `json:"entry_type"` // = EventTypeSARRejectedV3
	SigningKeyID string      `json:"signing_key_id"`
	TimestampMs  int64       `json:"timestamp_ms"`

	IntentEntryID string `json:"intent_entry_id"`
	LegalBasis    string `json:"legal_basis"`

	// PIIDigestKeyVersion is the PII-HMAC key version ("sm:v1") that
	// minted RationaleHash (pii_hmac_key_rotation_R4). Encoded IFF
	// non-empty (alphabetical slot, between legal_basis and
	// rationale_hash). See SARIntentEntryV3.PIIDigestKeyVersion for
	// the RELAXED legacy-compat contract.
	PIIDigestKeyVersion string `json:"pii_digest_key_version"`

	// RationaleHash is REQUIRED non-zero for rejection (an empty
	// rationale is invalid; validator rejects).
	RationaleHash TenantHMACDigestV3 `json:"rationale_hash"`
	RequestID     string             `json:"request_id"`
}

func (e SARRejectedEntryV3) EntryTypeV3() EventTypeV3               { return EventTypeSARRejectedV3 }
func (e SARRejectedEntryV3) sealedChainEntryV3(chainEntryV3SealTag) {}

// SARExtendedEntryV3 — header + 4 body fields per pqc_05c v3 §4.9
// (new section added 2026-05-15 by dsar_p4_polish_v1_0_cleanup #4).
//
// Body (alphabetical):
//  1. extended_due_at_ms
//  2. intent_entry_id
//  3. reason_hash
//  4. request_id
//
// `original_due_at_ms` is NOT bound — derivable from the intent
// entry's `submitted_at_ms + 30 days`. Embedding it would be
// redundant and create drift risk.
type SARExtendedEntryV3 struct {
	CompanyID    string      `json:"company_id"`
	EntryType    EventTypeV3 `json:"entry_type"` // = EventTypeSARExtendedV3
	SigningKeyID string      `json:"signing_key_id"`
	TimestampMs  int64       `json:"timestamp_ms"`

	IntentEntryID string `json:"intent_entry_id"`
	RequestID     string `json:"request_id"`

	// ExtendedDueAtMs is the new response deadline in UnixMilli
	// UTC. Must be strictly > the SAR's original_due_at AND ≤
	// original_due_at + 60 days. The +60 cap is Art. 12(3)'s
	// second sentence. Verifier sanity-bounds at 14 months past
	// timestamp_ms but does NOT independently check against the
	// original_due_at (that's an intent-row-level invariant the
	// dashboard handler enforces upstream).
	ExtendedDueAtMs int64 `json:"extended_due_at_ms"`

	// PIIDigestKeyVersion is the PII-HMAC key version ("sm:v1") that
	// minted ReasonHash (pii_hmac_key_rotation_R4). Encoded IFF
	// non-empty (alphabetical slot, between intent_entry_id and
	// reason_hash). See SARIntentEntryV3.PIIDigestKeyVersion for the
	// RELAXED legacy-compat contract.
	PIIDigestKeyVersion string `json:"pii_digest_key_version"`

	// ReasonHash is REQUIRED non-zero (extension without a reason
	// is invalid under Art. 12(3) which requires the controller
	// to inform the data subject of the reasons for the delay).
	ReasonHash TenantHMACDigestV3 `json:"reason_hash"`
}

func (e SARExtendedEntryV3) EntryTypeV3() EventTypeV3               { return EventTypeSARExtendedV3 }
func (e SARExtendedEntryV3) sealedChainEntryV3(chainEntryV3SealTag) {}

// Compile-time interface satisfaction assertions.
var (
	_ ChainEntryV3 = SARIntentEntryV3{}
	_ ChainEntryV3 = SARAcknowledgedEntryV3{}
	_ ChainEntryV3 = SARFulfilledEntryV3{}
	_ ChainEntryV3 = SARRejectedEntryV3{}
	_ ChainEntryV3 = SARExtendedEntryV3{}
)
