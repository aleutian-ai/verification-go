// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Trust-manifest canonical bytes encoder per
// docs/customer/sar/trust_manifest_format_v1.md §3.
//
// # Why TLV and not JSON
//
// JSON encoders disagree across languages on whitespace, key order,
// unicode normalization, and integer/float boundary cases. Any of
// those would produce divergent byte sequences across the 3 SDKs and
// break signature verification. The TLV encoding here is byte-
// identical across Python / Go / JS — verified by cross-language
// golden vectors at sdk/testdata/trust_manifest_golden_*.json.
//
// # Wire format (LOCKED)
//
//	TrustManifestCanonicalDomainPrefixV1 ||
//	u32_be(version)                          ||
//	u32_be(format_version)                   ||
//	u64_be(manifest_serial)                  ||
//	u32_be(len(tenant_id))   || tenant_id    ||
//	u64_be(issued_at_ms)                     ||
//	u64_be(expires_at_ms)                    ||
//	u32_be(key_count)                        ||
//	for each key, sorted by signing_key_id ascending:
//	    u32_be(len(signing_key_id)) || signing_key_id      ||
//	    u32_be(len(algorithm))      || algorithm           ||
//	    u32_be(len(public_key))     || raw_public_key_bytes ||
//	    u64_be(valid_from_ms)                              ||
//	    u64_be(valid_until_ms)
//
// All strings MUST be NFC-normalized UTF-8 with no BOM at the
// caller. The encoder REJECTS (does not silently mutate) any
// input that is not already in NFC. This is the cross-language
// safety contract — Python `unicodedata.is_normalized("NFC", s)`
// and JS `s.normalize("NFC") === s` mirror Go's
// `norm.NFC.IsNormalString(s)` so all three SDKs reject the same
// inputs identically. Silent normalization would create
// signature-verification divergence the moment any producer or
// consumer omitted the normalize step.
// The encoder also rejects non-UTF8 input + control characters
// in string-typed fields (see input_validation_rubric §A).

// TrustManifestCanonicalDomainPrefixV1 is the LOCKED domain-prefix
// string the manifest signature is computed over. Changing it
// invalidates every previously-signed manifest, so we treat it as
// part of the wire format.
const TrustManifestCanonicalDomainPrefixV1 = "aleutian.trust_manifest.v1:"

// TrustManifestCanonicalFormatVersionV1 is the current canonical-
// bytes format version. v1 is the first locked version; v2+ would
// be a separate domain prefix and a parallel encoder.
const TrustManifestCanonicalFormatVersionV1 uint32 = 1

// Sentinel errors raised by the encoder. Callers use errors.Is to
// triage.
var (
	// ErrTrustManifestInvalidV1 wraps every input-validation
	// failure the encoder produces (bad UTF-8, control chars,
	// empty required fields, length-bound violations). Wrapping
	// a single sentinel keeps the error surface tight; the
	// wrapped message names the specific field for operators.
	ErrTrustManifestInvalidV1 = errors.New("trust_manifest: invalid v1 manifest")
)

// TrustManifestSignedKeyV1 is one signing-key entry inside the
// manifest. Field order in this struct is for readability; canonical
// encoding sorts by SigningKeyID ascending regardless.
type TrustManifestSignedKeyV1 struct {
	SigningKeyID string // the per-tenant kid; e.g. "kid_b59e64d6595cc207"
	Algorithm    string // currently always "ML-DSA-65" (alg-agility design carves the supported set)
	PublicKey    []byte // raw ML-DSA-65 public key bytes (cloudflare/circl canonical encoding)
	ValidFromMs  int64  // earliest chain-entry timestamp the verifier accepts this key for
	ValidUntilMs int64  // latest such timestamp (exclusive — chain entries at exactly ValidUntilMs are REJECTED)
}

// TrustManifestPayloadV1 is the unsigned manifest body. The
// canonical bytes computed from this payload are what the bootstrap
// key signs.
type TrustManifestPayloadV1 struct {
	Version        uint32 // outer wire version (separate from canonical format_version)
	ManifestSerial uint64 // per-tenant monotonic counter (rollback defense)
	TenantID       string // canonical company id (comp_<26-char-ULID>)
	IssuedAtMs     int64  // when this manifest was minted (UTC unix millis)
	ExpiresAtMs    int64  // when verifiers MUST stop accepting it
	Keys           []TrustManifestSignedKeyV1
}

// String-field length bounds. These match the input-validation
// rubric §A defaults; bigger values would let an attacker burn
// verifier memory by submitting a multi-MB manifest.
const (
	trustManifestTenantIDMaxLen     = 64   // comp_<26-char-ULID> is 31; 64 is generous
	trustManifestSigningKeyIDMaxLen = 128  // operator-chosen kid; same bound as v3 chain entries
	trustManifestAlgorithmMaxLen    = 64   // "ML-DSA-65" fits in 9; 64 leaves room for future names
	trustManifestPublicKeyMaxLen    = 8192 // ML-DSA-65 pubkey is 1952; 8192 leaves headroom for larger PQC schemes
	trustManifestMaxKeysPerManifest = 256  // tenants don't legitimately hold 256+ active kids; cap defends against fixture-bomb
)

// CanonicalBytesTrustManifestV1 produces the byte sequence the
// bootstrap-key signature is computed over.
//
// # Description
//
// Implements the wire format documented in this file's package
// comment. Inputs are validated before any byte is written; on
// validation failure, returns (nil, ErrTrustManifestInvalidV1-
// wrapped error).
//
// # Inputs
//
//   - payload: the manifest body to encode
//
// # Outputs
//
//   - []byte: deterministic canonical bytes
//   - error: ErrTrustManifestInvalidV1-wrapped on any validation
//     failure
//
// # Pure / safe for concurrent use
//
// No state. Encoder is fresh per call.
func CanonicalBytesTrustManifestV1(payload TrustManifestPayloadV1) ([]byte, error) {
	if err := validateTrustManifestPayloadV1(payload); err != nil {
		return nil, err
	}

	// Sort keys by signing_key_id ascending so two encoders that
	// received the same payload in different orders produce
	// byte-identical output.
	keys := make([]TrustManifestSignedKeyV1, len(payload.Keys))
	copy(keys, payload.Keys)
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].SigningKeyID < keys[j].SigningKeyID
	})

	buf := make([]byte, 0, 1024)

	// Domain prefix — first bytes the signer sees. Locked string,
	// not length-prefixed (parity with V3 chain entry encoder).
	buf = append(buf, TrustManifestCanonicalDomainPrefixV1...)

	buf = appendU32BE(buf, payload.Version)
	buf = appendU32BE(buf, TrustManifestCanonicalFormatVersionV1)
	buf = appendU64BE(buf, payload.ManifestSerial)

	buf = appendLenPrefixedString(buf, payload.TenantID)
	buf = appendI64BE(buf, payload.IssuedAtMs)
	buf = appendI64BE(buf, payload.ExpiresAtMs)

	if len(keys) > trustManifestMaxKeysPerManifest {
		return nil, fmt.Errorf("CanonicalBytesTrustManifestV1: %w: key_count=%d exceeds cap %d",
			ErrTrustManifestInvalidV1, len(keys), trustManifestMaxKeysPerManifest)
	}
	// uint32 key count — caller can't supply >256 per the cap
	// above, so the conversion is safe.
	buf = appendU32BE(buf, uint32(len(keys)))

	for _, key := range keys {
		buf = appendLenPrefixedString(buf, key.SigningKeyID)
		buf = appendLenPrefixedString(buf, key.Algorithm)
		buf = appendLenPrefixedBytes(buf, key.PublicKey)
		buf = appendI64BE(buf, key.ValidFromMs)
		buf = appendI64BE(buf, key.ValidUntilMs)
	}

	return buf, nil
}

// validateTrustManifestPayloadV1 is the gatekeeper that rejects
// invalid inputs BEFORE any byte is committed to the canonical
// buffer. Centralizes the rubric §A checks so the encoder body
// stays focused on byte layout.
func validateTrustManifestPayloadV1(p TrustManifestPayloadV1) error {
	if p.Version == 0 {
		return fmt.Errorf("validateTrustManifestPayloadV1: %w: version must be >= 1",
			ErrTrustManifestInvalidV1)
	}
	if err := checkTrustManifestStringFieldV1("tenant_id", p.TenantID, trustManifestTenantIDMaxLen); err != nil {
		return err
	}
	// All four int64 timestamp fields must be strictly positive. The
	// canonical encoder reinterprets int64 as uint64 via two's
	// complement (appendI64BE); allowing negatives would silently
	// encode as huge uint64 values and "verify" cross-language
	// (Crypto review H4, 4-agent review).
	if p.IssuedAtMs <= 0 {
		return fmt.Errorf("validateTrustManifestPayloadV1: %w: issued_at_ms must be > 0",
			ErrTrustManifestInvalidV1)
	}
	if p.ExpiresAtMs <= 0 {
		return fmt.Errorf("validateTrustManifestPayloadV1: %w: expires_at_ms must be > 0",
			ErrTrustManifestInvalidV1)
	}
	if p.ExpiresAtMs <= p.IssuedAtMs {
		return fmt.Errorf("validateTrustManifestPayloadV1: %w: expires_at_ms must be > issued_at_ms",
			ErrTrustManifestInvalidV1)
	}
	if len(p.Keys) == 0 {
		return fmt.Errorf("validateTrustManifestPayloadV1: %w: at least one key required",
			ErrTrustManifestInvalidV1)
	}

	// Per-key validation. Reject empty / oversize / non-UTF8 / control-
	// char fields. Pubkey bytes are validated for byte-length only at
	// this layer; the alg-specific structural check (`mldsa65.Scheme().
	// UnmarshalBinaryPublicKey`) happens at trust-manifest load time
	// in the runtime fetcher — keeping the canonical encoder
	// crypto-agnostic so future PQC schemes plug in cleanly.
	seen := make(map[string]bool, len(p.Keys))
	for i, k := range p.Keys {
		if err := checkTrustManifestStringFieldV1(
			fmt.Sprintf("keys[%d].signing_key_id", i), k.SigningKeyID, trustManifestSigningKeyIDMaxLen); err != nil {
			return err
		}
		if seen[k.SigningKeyID] {
			return fmt.Errorf("validateTrustManifestPayloadV1: %w: duplicate signing_key_id %q",
				ErrTrustManifestInvalidV1, k.SigningKeyID)
		}
		seen[k.SigningKeyID] = true
		if err := checkTrustManifestStringFieldV1(
			fmt.Sprintf("keys[%d].algorithm", i), k.Algorithm, trustManifestAlgorithmMaxLen); err != nil {
			return err
		}
		if len(k.PublicKey) == 0 {
			return fmt.Errorf("validateTrustManifestPayloadV1: %w: keys[%d].public_key is empty",
				ErrTrustManifestInvalidV1, i)
		}
		if len(k.PublicKey) > trustManifestPublicKeyMaxLen {
			return fmt.Errorf("validateTrustManifestPayloadV1: %w: keys[%d].public_key is %d bytes (cap %d)",
				ErrTrustManifestInvalidV1, i, len(k.PublicKey), trustManifestPublicKeyMaxLen)
		}
		if k.ValidFromMs <= 0 {
			return fmt.Errorf("validateTrustManifestPayloadV1: %w: keys[%d].valid_from_ms must be > 0",
				ErrTrustManifestInvalidV1, i)
		}
		if k.ValidUntilMs <= 0 {
			return fmt.Errorf("validateTrustManifestPayloadV1: %w: keys[%d].valid_until_ms must be > 0",
				ErrTrustManifestInvalidV1, i)
		}
		if k.ValidUntilMs <= k.ValidFromMs {
			return fmt.Errorf("validateTrustManifestPayloadV1: %w: keys[%d].valid_until_ms must be > valid_from_ms",
				ErrTrustManifestInvalidV1, i)
		}
	}
	return nil
}

func checkTrustManifestStringFieldV1(name, value string, maxLen int) error {
	if value == "" {
		return fmt.Errorf("validateTrustManifestPayloadV1: %w: %s is empty",
			ErrTrustManifestInvalidV1, name)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("validateTrustManifestPayloadV1: %w: %s is not valid UTF-8",
			ErrTrustManifestInvalidV1, name)
	}
	if len(value) > maxLen {
		return fmt.Errorf("validateTrustManifestPayloadV1: %w: %s is %d bytes (cap %d)",
			ErrTrustManifestInvalidV1, name, len(value), maxLen)
	}
	// Reject non-NFC inputs (Crypto review C1, 4-agent review).
	// REJECT, do not silently normalize — the latter would create
	// cross-language signature divergence when a Python producer
	// sends already-NFC bytes that some encoder normalizes again.
	// Caller responsibility: pass NFC strings. This is the
	// load-bearing cross-language equality contract.
	if !norm.NFC.IsNormalString(value) {
		return fmt.Errorf("validateTrustManifestPayloadV1: %w: %s is not NFC-normalized; caller must run unicodedata.normalize/s.normalize/norm.NFC before passing",
			ErrTrustManifestInvalidV1, name)
	}
	// Reject ASCII control characters. Inputs containing tab /
	// newline / NUL would otherwise survive UTF-8 validation and
	// could be used for log-injection (rubric §A row 3).
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("validateTrustManifestPayloadV1: %w: %s contains control character U+%04X",
				ErrTrustManifestInvalidV1, name, r)
		}
	}
	return nil
}

// appendU32BE writes u as 4-byte big-endian.
func appendU32BE(dst []byte, u uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return append(dst, b[:]...)
}

// appendU64BE writes u as 8-byte big-endian.
func appendU64BE(dst []byte, u uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], u)
	return append(dst, b[:]...)
}

// appendI64BE re-interprets the signed int64 as a uint64 wire
// representation (two's complement). Validates ms timestamps fit
// non-negative range first; callers should reject negative values
// before this point.
func appendI64BE(dst []byte, v int64) []byte {
	return appendU64BE(dst, uint64(v))
}

// appendLenPrefixedString writes u32_be(len) || utf8_bytes(s).
// Assumes s is already validated (non-empty, UTF-8, in-bound).
func appendLenPrefixedString(dst []byte, s string) []byte {
	// Length is bounded by the per-field caps in
	// trustManifest*MaxLen constants — all well under uint32 max.
	dst = appendU32BE(dst, uint32(len(s)))
	dst = append(dst, s...)
	return dst
}

// appendLenPrefixedBytes writes u32_be(len) || bytes. Used for the
// raw public key blob.
func appendLenPrefixedBytes(dst []byte, b []byte) []byte {
	dst = appendU32BE(dst, uint32(len(b)))
	dst = append(dst, b...)
	return dst
}
