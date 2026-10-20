// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package tier2

// Bundle is the customer-side projection of a Tier-2 Standard-mode
// audit bundle as it lives on disk after download + unzip.
//
// # Description
//
// Callers populate ID + Manifest from the bundle's manifest.json
// (Aleutian provides a free-standing JSON file in the disclosure ZIP).
// The fields chosen here are the SUBSET OpenBundle needs to unseal the
// CEK; the rest of the manifest (file list, signatures, trust-manifest
// pointers) is not part of this struct because OpenBundle doesn't read
// it. Customers may use separate verification packages
// (sdk/verification-go) to validate signatures + trust chain.
//
// # Limitations
//
//   - JSON field tags reflect the on-wire shape under
//     manifest.json::tier2 (see compliance_tier2_envelope_and_disclosure_spec §2.7).
//     The struct may grow over time but field-tag stability is part of
//     the SDK's compatibility contract.
type Bundle struct {
	// ID is the canonical bundle identifier — AAD-bound by the producer.
	// Caller MUST pass the exact value from manifest.bundle_id; any
	// deviation breaks AAD reconstruction and fails decryption.
	ID string

	// Manifest is the parsed manifest.json document.
	Manifest Manifest
}

// Manifest is the subset of manifest.json relevant to CEK unseal.
type Manifest struct {
	// Tier2 carries the Standard-mode envelope state per spec §2.7.
	Tier2 Tier2Manifest `json:"tier2"`
}

// Tier2Manifest carries the Standard-mode envelope state.
//
// # Description
//
// Per the ADR-024 Amendment (2026-05-31), CEKEnvelopes ships with N=2
// recipients (primary + backup) for new tenants; legacy tenants pre-
// amendment may ship N=1. SealedEnvelopesIndex is the Forensic-mode
// pointer list and is unused by OpenBundle (Forensic mode goes through
// the sarenvelope path, not this package).
type Tier2Manifest struct {
	// Mode is "standard" or "forensic". OpenBundle returns
	// ErrBundleMalformed if not "standard".
	Mode string `json:"mode"`

	// CEKEnvelopes is the per-recipient bundle-CEK wraps. OpenBundle
	// scans this list for a fingerprint matching the supplied seed.
	CEKEnvelopes []CEKWrapEnvelope `json:"cek_envelopes"`

	// PubkeyCount is the producer-reported recipient count. Used as a
	// defense-in-depth cross-check against len(CEKEnvelopes); a
	// mismatch returns ErrBundleMalformed.
	PubkeyCount int `json:"pubkey_count"`
}

// CEKWrapEnvelope wraps the bundle CEK for one customer pubkey.
//
// # Description
//
// Mirrors the on-wire JSON shape emitted by
// internal/crypto/tier2envelope.SealCEKWrap. The four cryptographic
// fields (Fingerprint + KEM ciphertext + AEAD nonce + wrap ciphertext)
// are sized exactly per spec; OpenBundle validates lengths after
// base64-decoding and treats any deviation as ErrOpenFailed (NOT
// ErrBundleMalformed — a deviation post-decode is more likely tamper
// than structural malformation).
type CEKWrapEnvelope struct {
	// PubkeyFingerprint is the 32-char lowercase hex fingerprint of the
	// recipient pubkey. OpenBundle compares this constant-time against
	// the caller's seed-derived fingerprint.
	PubkeyFingerprint string `json:"pubkey_fingerprint"`

	// KEMCiphertext is the 1120-byte X-Wing KEM ciphertext, base64.
	KEMCiphertext string `json:"kem_ciphertext"`

	// WrapNonce is the AES-256-GCM nonce (12 bytes, base64).
	WrapNonce string `json:"wrap_nonce"`

	// WrapCiphertext is the AEAD-sealed bundle CEK (48 bytes = 32-byte
	// key + 16-byte GCM tag), base64.
	WrapCiphertext string `json:"wrap_ciphertext"`

	// EncapsulatedAtMs is the producer-side sealing timestamp.
	// Operator-facing only; NOT AAD-bound and NOT validated by
	// OpenBundle. Bundles with absent / future / very-old timestamps
	// still unseal successfully.
	EncapsulatedAtMs int64 `json:"encapsulated_at_ms"`
}

// OpenBundleResult is the rich return shape from OpenBundle.
//
// # Description
//
// Returned by OpenBundle so callers can introspect which slot matched
// (e.g., to log a security event "unsealed via backup key, primary
// suspected compromised"). The opaque ErrNoMatchingRecipient path
// returns a zero-value result with the CEK field nil.
//
// # Limitations
//
//   - MatchedEnvelopeIndex is the position in cek_envelopes[]; it is
//     NOT a slot label ("primary" / "backup"). Slot semantics are a
//     producer-side convention — the index is the only authoritative
//     identifier the bundle carries.
type OpenBundleResult struct {
	// CEK is the recovered 32-byte content-encryption key.
	// Callers are responsible for downstream zeroization.
	CEK []byte

	// MatchedEnvelopeIndex is the 0-based index of the cek_envelopes[]
	// entry that decrypted successfully.
	MatchedEnvelopeIndex int

	// MatchedFingerprint is the fingerprint of the envelope that
	// decrypted (equals CEKEnvelopes[MatchedEnvelopeIndex].PubkeyFingerprint).
	MatchedFingerprint string
}
