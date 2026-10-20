// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// dsar_chain_d: V3 chain entry verifier.
//
// # Description
//
// VerifyChainEntryV3 is the customer-facing v3 verification entry
// point. Given a typed entry + claimed content_hash + claimed
// signature + a TrustManifest mapping signing_key_id → public
// key, the verifier:
//
//  1. Validates the entry via the same producer-side validators
//     (same regexes, same charset rules) so an invalid claim is
//     rejected with a typed error rather than silently falling
//     through to a hash mismatch.
//  2. Re-encodes canonical_bytes from the typed entry using the
//     mirror encoder (CanonicalBytesV3).
//  3. Computes the expected content_hash = SHA-512(prefix ||
//     canonical_bytes) and compares to the claimed hash with a
//     constant-time check.
//  4. Looks up the public key for `entry.SigningKeyID` via the
//     TrustManifest.
//  5. Verifies the ML-DSA-65 signature against the signing input
//     `prefix || canonical_bytes` (per pqc_05c v3 §9.1 — sign
//     prefix||canonical directly, option A).
//
// # v2 entry handling
//
// Callers who attempt to pass a v2 entry through this v3 verifier
// would get an `ErrInvalidEntryV3` from validateV3 (the v2 typed
// struct shape doesn't satisfy ChainEntryV3). For a v2 chain row
// coming over the wire as JSON, the caller dispatches by
// domain_prefix BEFORE deciding which verifier path to enter —
// see `chain.go` for the v2 path.
//
// # Concurrency
//
// Pure function; safe for concurrent use. TrustManifest must be
// concurrent-safe; the SDK's default implementation
// (`TrustManifestFromMap`) is read-only after construction.

// V3 verification error sentinels. Customer code branches on
// these to distinguish "the bytes don't match" (data integrity
// failure) from "the signature is bad" (forgery indicator) from
// "the key is unknown" (operator misconfiguration).
var (
	// ErrContentHashMismatchV3 indicates the claimed content_hash
	// does not match what the verifier computed from canonical
	// bytes. Means either the entry payload was tampered with OR
	// the producer's encoder disagrees with this SDK's encoder
	// (cross-language port regression).
	ErrContentHashMismatchV3 = errors.New("verification: v3 content_hash mismatch")

	// ErrSignatureInvalidV3 indicates the ML-DSA-65 signature does
	// not verify against the canonical bytes under the signing
	// key bound by `signing_key_id`. Likely a forgery indicator.
	ErrSignatureInvalidV3 = errors.New("verification: v3 signature invalid")

	// ErrSignatureMalformedV3 indicates the supplied signature is
	// not a valid ML-DSA-65 signature shape (wrong length, bad
	// base64, etc.). Distinguishes "input is malformed" from
	// "signature is forged" so callers can route a 400 vs a 422.
	ErrSignatureMalformedV3 = errors.New("verification: v3 signature malformed")

	// ErrKeyNotInTrustManifestV3 indicates the entry's
	// `signing_key_id` does not resolve to a public key in the
	// supplied trust manifest. Likely an operator/manifest
	// freshness issue — chain entries are append-only and key
	// bindings are append-only (per pqc_05c v3 §3.1.1).
	ErrKeyNotInTrustManifestV3 = errors.New("verification: v3 signing_key_id not in trust manifest")

	// ErrPublicKeyMalformedV3 indicates the trust manifest returned
	// a public key that is not a valid ML-DSA-65 public key
	// (wrong length / wrong type). Operator misconfiguration.
	ErrPublicKeyMalformedV3 = errors.New("verification: v3 public key malformed")

	// ErrUnsupportedEntryTypeV3 indicates the entry type reached
	// the verifier dispatch but is not in the closed set this SDK
	// recognizes. With the sealed ChainEntryV3 interface
	// (chain_d H1) external types cannot reach this path; the
	// sentinel exists as defense-in-depth in case a future
	// in-package type is added without updating the dispatch.
	ErrUnsupportedEntryTypeV3 = errors.New("verification: v3 unsupported entry type")
)

// TrustManifestV3 is the lookup surface a verifier uses to resolve
// `signing_key_id` → ML-DSA-65 public key.
//
// # Required guarantees (per pqc_05c v3 §3.1.1)
//
//   - Append-only: once a `signing_key_id` is bound to a public
//     key, the binding MUST NOT change. Rotating a key requires
//     minting a NEW `signing_key_id` value.
//   - One-to-one: a `signing_key_id` MUST resolve to exactly one
//     public key over the manifest's lifetime.
//
// Implementations backing the manifest with KMS / Vault / Secrets
// Manager / HTTP / DB lookups SHOULD honor the supplied
// `context.Context` (deadline, cancellation) and SHOULD return
// distinct errors for "not found" (operator manifest issue) vs.
// transport failure (transient infra). Verifiers map the former
// to `ErrKeyNotInTrustManifestV3`; the latter propagate up to
// caller for retry policy.
//
// # Concurrency
//
// Implementations MUST be safe for concurrent reads.
type TrustManifestV3 interface {
	// PublicKeyForSigningKeyID returns the ML-DSA-65 public key
	// bytes for the given key id. Returns:
	//   - (key, nil) on success
	//   - (nil, err) where errors.Is(err, ErrKeyNotInTrustManifestV3)
	//     is true when the id is not in the manifest
	//   - (nil, err) with any other error class for transport /
	//     infra failures
	PublicKeyForSigningKeyID(ctx context.Context, signingKeyID string) (publicKey []byte, err error)
}

// TrustManifestFromMapV3 is the canonical in-process
// implementation backed by a `map[string][]byte`. Read-only after
// construction; concurrent reads are safe. Public keys are
// validated against the ML-DSA-65 wire format at construction
// time (chain_d H3 review fix) — operators detect misconfiguration
// at manifest-load instead of per-verify.
type TrustManifestFromMapV3 struct {
	keys map[string][]byte
}

// NewTrustManifestFromMapV3 returns a manifest seeded from the
// supplied key map. The map is COPIED so post-construction
// mutations to the caller's map do not affect the manifest. Each
// public key is validated against `mldsa65.Scheme().UnmarshalBinaryPublicKey`
// at construction (chain_d H3 review fix) — empty or wrong-length
// keys are rejected with `ErrPublicKeyMalformedV3` BEFORE any
// verify call rather than lazily.
//
// # Inputs
//
//   - keys: map[signing_key_id] = ML-DSA-65 public key bytes
//     (canonical encoding per cloudflare/circl)
//
// # Outputs
//
//   - *TrustManifestFromMapV3
//   - error: wrapped `ErrPublicKeyMalformedV3` if any value fails
//     ML-DSA-65 shape validation; wrapped `ErrInvalidEntryV3` if
//     any key id is empty
func NewTrustManifestFromMapV3(keys map[string][]byte) (*TrustManifestFromMapV3, error) {
	scheme := mldsa65.Scheme()
	cp := make(map[string][]byte, len(keys))
	for k, v := range keys {
		if k == "" {
			return nil, fmt.Errorf("NewTrustManifestFromMapV3: %w: empty signing_key_id",
				ErrInvalidEntryV3)
		}
		if _, err := scheme.UnmarshalBinaryPublicKey(v); err != nil {
			// Don't echo k or v — operator metadata + raw key bytes.
			return nil, fmt.Errorf("NewTrustManifestFromMapV3: %w",
				ErrPublicKeyMalformedV3)
		}
		c := make([]byte, len(v))
		copy(c, v)
		cp[k] = c
	}
	return &TrustManifestFromMapV3{keys: cp}, nil
}

// PublicKeyForSigningKeyID implements TrustManifestV3.
func (m *TrustManifestFromMapV3) PublicKeyForSigningKeyID(_ context.Context, id string) ([]byte, error) {
	k, ok := m.keys[id]
	if !ok {
		return nil, ErrKeyNotInTrustManifestV3
	}
	return k, nil
}

// VerifyChainEntryV3 is the customer-facing v3 verifier.
//
// # Inputs
//
//   - ctx: cancellation / deadline; propagated to the trust
//     manifest lookup
//   - entry: a typed v3 chain entry (SARIntentEntryV3 etc.)
//   - claimedContentHashHex: the row's `content_hash` column
//     (128 lowercase hex chars; SHA-512)
//   - claimedSignatureB64: the row's `signature` column
//     (standard base64-encoded ML-DSA-65 signature)
//   - manifest: trust manifest for signing-key lookup
//
// # Outputs
//
//   - error: nil on successful verification; wrapped sentinel on
//     failure (ErrInvalidEntryV3 / ErrContentHashMismatchV3 /
//     ErrSignatureInvalidV3 / ErrSignatureMalformedV3 /
//     ErrKeyNotInTrustManifestV3 / ErrPublicKeyMalformedV3 /
//     ErrUnsupportedEntryTypeV3)
//
// # Error contract
//
// Error strings are intentionally content-agnostic — they
// surface the sentinel and a function tag, never user input
// (claimed hashes, signing_key_id, raw lib errors). This
// prevents a public verifier endpoint from leaking a forgery
// oracle or operator metadata via error display (chain_d H2).
// Callers needing structured access for ops dashboards route
// via `errors.Is(err, ErrXxxV3)`.
//
// # Concurrency
//
// Safe for concurrent use; the manifest argument is read-only.
func VerifyChainEntryV3(ctx context.Context, entry ChainEntryV3, claimedContentHashHex, claimedSignatureB64 string, manifest TrustManifestV3) error {
	if entry == nil {
		return fmt.Errorf("VerifyChainEntryV3: %w: entry is nil", ErrInvalidEntryV3)
	}
	if manifest == nil {
		return fmt.Errorf("VerifyChainEntryV3: trust manifest is nil")
	}
	// chain_d H2: error messages MUST NOT echo claimed hashes,
	// computed hashes, signing_key_id, or wrapped stdlib/lib
	// error strings. A public verifier (verify.aleutian.ai)
	// bubbling those into UI gives:
	//   - a forgery oracle (computed hash echoed back lets
	//     attacker pass the hash gate trivially, focusing on
	//     signature alone)
	//   - operator-metadata leakage (signing_key_id reveals KMS
	//     key version / rotation date / tenant region to anyone
	//     who triggers a bad signature)
	// Callers needing the values for debugging route them via
	// errors.As against the typed error structs (chain_d M9
	// follow-up), not via Error() string scraping.
	// Validate the entry FIRST so callers learn about a malformed
	// entry struct before we touch their claims about it. A bad
	// entry returning ErrContentHashMismatchV3 instead of
	// ErrInvalidEntryV3 would be confusing.
	canonical, err := CanonicalBytesV3(entry)
	if err != nil {
		return err // wraps ErrInvalidEntryV3
	}
	// chain_d M4 mirror (Python parity): refuse pathologically large
	// entries before invoking the ML-DSA-65 verifier. Per-field caps
	// don't bound the sum; MaxCanonicalBytesV3 does. Opaque error
	// (no length echo) per Privacy Inv 4.
	if len(canonical) > MaxCanonicalBytesV3 {
		return fmt.Errorf("VerifyChainEntryV3: %w", ErrInvalidEntryV3)
	}
	scheme := mldsa65.Scheme()

	// chain_d M1+M2: bound input sizes on the CLAIM strings
	// before expensive ops (constant-time compare, base64 decode).
	// 128 hex for content_hash; the base64 encoding of an ML-DSA-65
	// signature has a fixed maximum length.
	if len(claimedContentHashHex) != contentHashV3HexLen {
		return fmt.Errorf("VerifyChainEntryV3: %w", ErrContentHashMismatchV3)
	}
	maxSigBase64 := base64.StdEncoding.EncodedLen(scheme.SignatureSize())
	if len(claimedSignatureB64) > maxSigBase64+v3SignatureBase64Slack {
		return fmt.Errorf("VerifyChainEntryV3: %w", ErrSignatureMalformedV3)
	}
	computedHash := ContentHashV3(canonical)
	if subtle.ConstantTimeCompare([]byte(computedHash), []byte(claimedContentHashHex)) != 1 {
		return fmt.Errorf("VerifyChainEntryV3: %w", ErrContentHashMismatchV3)
	}
	sig, err := base64.StdEncoding.DecodeString(claimedSignatureB64)
	if err != nil {
		return fmt.Errorf("VerifyChainEntryV3: %w", ErrSignatureMalformedV3)
	}
	if len(sig) != scheme.SignatureSize() {
		return fmt.Errorf("VerifyChainEntryV3: %w", ErrSignatureMalformedV3)
	}
	signingKeyID, err := signingKeyIDOf(entry)
	if err != nil {
		return fmt.Errorf("VerifyChainEntryV3: %w", err)
	}
	if signingKeyID == "" {
		return fmt.Errorf("VerifyChainEntryV3: %w", ErrInvalidEntryV3)
	}
	// Manifest pubkey lookup. If the manifest implements the
	// validity-window-aware interface (`TrustManifestV3WithValidityWindows`),
	// use the timed variant so an entry whose timestamp falls outside
	// the key's window is rejected per spec §8 (Crypto/Arch review H1
	// — silent bypass on the untimed path was a load-bearing defect).
	// Manifests that don't satisfy the interface (e.g. the legacy
	// `TrustManifestFromMapV3`, which has no time concept) fall back
	// to the unchecked lookup.
	var pubBytes []byte
	if tm, ok := manifest.(TrustManifestV3WithValidityWindows); ok {
		entryTs, terr := timestampMsOf(entry)
		if terr != nil {
			return fmt.Errorf("VerifyChainEntryV3: %w", terr)
		}
		pubBytes, err = tm.PublicKeyForSigningKeyIDAtTime(ctx, signingKeyID, entryTs)
	} else {
		pubBytes, err = manifest.PublicKeyForSigningKeyID(ctx, signingKeyID)
	}
	if err != nil {
		// Manifest reports its own not-found vs. transport failure
		// via the wrapped sentinel. Propagate without echoing
		// the underlying message (which could carry KMS/Vault
		// operator details).
		if errors.Is(err, ErrKeyNotInTrustManifestV3) {
			return fmt.Errorf("VerifyChainEntryV3: %w", ErrKeyNotInTrustManifestV3)
		}
		if errors.Is(err, ErrKeyOutsideValidityWindowV3) {
			return fmt.Errorf("VerifyChainEntryV3: %w", ErrKeyOutsideValidityWindowV3)
		}
		return fmt.Errorf("VerifyChainEntryV3: trust manifest lookup failed: %w", err)
	}
	pub, err := scheme.UnmarshalBinaryPublicKey(pubBytes)
	if err != nil {
		return fmt.Errorf("VerifyChainEntryV3: %w", ErrPublicKeyMalformedV3)
	}
	// Signing input is prefix || canonical_bytes (pqc_05c v3 §9.1
	// option A — sign the preimage directly, not the content_hash).
	// Verification is deterministic; no randomness consumed (Crypto L3).
	signingInput := make([]byte, 0, len(domainPrefixV3Bytes)+len(canonical))
	signingInput = append(signingInput, domainPrefixV3Bytes...)
	signingInput = append(signingInput, canonical...)
	if !scheme.Verify(pub, signingInput, sig, nil) {
		return fmt.Errorf("VerifyChainEntryV3: %w", ErrSignatureInvalidV3)
	}
	return nil
}

// contentHashV3HexLen / v3SignatureBase64Slack are input-size
// bounds for the verifier. The content_hash is exactly
// SHA-512 hex (128 chars); a slack on the signature base64
// length tolerates trailing whitespace from naive clients but
// rejects oversized blobs that would force unbounded base64
// allocation (chain_d M2).
const (
	contentHashV3HexLen    = 128
	v3SignatureBase64Slack = 16
)

// signingKeyIDOf extracts the SigningKeyID field via the concrete
// type. Because ChainEntryV3 is SEALED (chain_d H1), only the
// five switch cases here are reachable for valid inputs. The
// default branch returns ErrUnsupportedEntryTypeV3 so a future
// in-package contributor adding a new entry type without
// updating this switch gets a loud error instead of a silent
// empty signing_key_id (which previously would have routed to a
// misleading "key not in manifest" error).
func signingKeyIDOf(e ChainEntryV3) (string, error) {
	switch x := e.(type) {
	case SARIntentEntryV3:
		return x.SigningKeyID, nil
	case SARAcknowledgedEntryV3:
		return x.SigningKeyID, nil
	case SARFulfilledEntryV3:
		return x.SigningKeyID, nil
	case SARRejectedEntryV3:
		return x.SigningKeyID, nil
	case SARExtendedEntryV3:
		return x.SigningKeyID, nil
	case CaptureRequestEntryV3:
		// chainlinker_modernization_01i: capture leaves are signed at ingest
		// (ML-DSA-65 over DomainPrefixV3‖canonical); wiring the case here lets
		// VerifyChainEntryV3 verify them instead of returning ErrUnsupportedEntryTypeV3.
		return x.SigningKeyID, nil
	default:
		return "", fmt.Errorf("signingKeyIDOf: %w: %T", ErrUnsupportedEntryTypeV3, e)
	}
}

// timestampMsOf extracts the entry's TimestampMs for trust-manifest
// validity-window enforcement. Mirror of signingKeyIDOf; the entry
// type discriminator pattern preserved across the two helpers so a
// new entry type only has to be added in two places.
func timestampMsOf(e ChainEntryV3) (int64, error) {
	switch x := e.(type) {
	case SARIntentEntryV3:
		return x.TimestampMs, nil
	case SARAcknowledgedEntryV3:
		return x.TimestampMs, nil
	case SARFulfilledEntryV3:
		return x.TimestampMs, nil
	case SARRejectedEntryV3:
		return x.TimestampMs, nil
	case SARExtendedEntryV3:
		return x.TimestampMs, nil
	case CaptureRequestEntryV3:
		return x.TimestampMs, nil // chainlinker_modernization_01i
	default:
		return 0, fmt.Errorf("timestampMsOf: %w: %T", ErrUnsupportedEntryTypeV3, e)
	}
}

// TrustManifestV3WithValidityWindows is the optional interface
// extension trust-manifest implementations satisfy when they carry
// per-key validity windows (spec §8). `TrustManifestFromURLV3`
// implements it; the legacy `TrustManifestFromMapV3` does NOT (a
// map of bytes has no time concept).
//
// `VerifyChainEntryV3` interface-asserts to this when looking up
// the pubkey; manifests that satisfy it get window enforcement
// automatically. Manifests that don't fall back to the unchecked
// `PublicKeyForSigningKeyID` path.
//
// # Why an optional interface vs. extending TrustManifestV3
//
// Adding a method to TrustManifestV3 breaks every external impl.
// The optional interface lets us add window enforcement without
// breaking back-compat — the verifier checks for the capability,
// not the type.
type TrustManifestV3WithValidityWindows interface {
	TrustManifestV3
	// PublicKeyForSigningKeyIDAtTime returns the public key bound
	// to signingKeyID, but ONLY if the supplied entry timestamp
	// falls within the key's [valid_from_ms, valid_until_ms)
	// window. Implementations MUST reject entries outside the
	// window with a typed error wrapping ErrKeyOutsideValidityWindowV3.
	PublicKeyForSigningKeyIDAtTime(
		ctx context.Context,
		signingKeyID string,
		entryTimestampMs int64,
	) ([]byte, error)
}
