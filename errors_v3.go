// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

// dsar_chain_d M9 (typed v3 error structs).
//
// VerifyChainEntryV3's default `Error()` strings are content-
// agnostic (per chain_d H2 — never echo claimed/computed hashes
// or signing_key_id). For ops dashboards and SOC alerts that DO
// need the structured values, this file provides typed error
// types that `errors.As` extracts. Both routing surfaces are
// preserved: `errors.Is(err, ErrXxxV3)` for category, and
// `errors.As(err, &XxxErrorV3{})` for structured fields.
//
// # Why types and sentinels coexist
//
// Customers stable on `errors.Is(err, ErrV3InvalidEntry)` (or any
// of the other sentinels) don't break when we surface additional
// structured fields here. Customers needing structured access
// graduate to `errors.As` at their own pace. Both routes coexist
// because typed errors are constructed by wrapping the sentinel.
//
// # NOT shipped today
//
// The verifier code currently returns sentinel-wrapped errors
// (`fmt.Errorf("%w", ErrXxxV3)`). Promoting to structured types
// requires constructing `*XxxErrorV3{Sentinel: ErrXxxV3, ...}` at
// each error site AND ensuring `errors.Is` traversal continues
// to surface the sentinel via the type's `Unwrap()` method. This
// is wired in a follow-up — the types ship here as the locked
// public contract so customer code can be written against them
// even before the verifier emits them. (Tracked in chain_d3 — to
// be carved if/when a customer needs structured ops integration.)

// ContentHashMismatchErrorV3 is the typed counterpart to
// ErrContentHashMismatchV3. Carries the claimed and computed
// values for SOC routing (operator dashboards). Customers MUST
// NOT display these values to end users.
type ContentHashMismatchErrorV3 struct {
	Claimed  string
	Computed string
}

func (e *ContentHashMismatchErrorV3) Error() string {
	// Constant string for log surfaces; structured fields are
	// the access surface for ops tooling.
	return "verification: v3 content_hash mismatch"
}

func (e *ContentHashMismatchErrorV3) Unwrap() error { return ErrContentHashMismatchV3 }

// SignatureInvalidErrorV3 is the typed counterpart to
// ErrSignatureInvalidV3. Carries the signing_key_id for ops
// routing (so a SOC dashboard can correlate forgery indicators
// against a specific HSM key) without leaking that value into
// every Error() string.
type SignatureInvalidErrorV3 struct {
	SigningKeyID string
}

func (e *SignatureInvalidErrorV3) Error() string {
	return "verification: v3 signature invalid"
}

func (e *SignatureInvalidErrorV3) Unwrap() error { return ErrSignatureInvalidV3 }

// KeyNotInTrustManifestErrorV3 is the typed counterpart to
// ErrKeyNotInTrustManifestV3.
type KeyNotInTrustManifestErrorV3 struct {
	SigningKeyID string
}

func (e *KeyNotInTrustManifestErrorV3) Error() string {
	return "verification: v3 signing_key_id not in trust manifest"
}

func (e *KeyNotInTrustManifestErrorV3) Unwrap() error { return ErrKeyNotInTrustManifestV3 }
