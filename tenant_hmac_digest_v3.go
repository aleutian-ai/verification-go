// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"fmt"
	"regexp"
)

// dsar_chain_d: verifier-side opaque hex digest type for v3 PII
// hash fields. Mirrors `internal/consent.TenantHMACDigest` but
// has NO mint method — verifiers do not have the per-tenant
// subkey needed to derive HMACs. They treat the digest as an
// opaque hex string and confirm chain integrity (the hash is
// inside canonical_bytes; signature binds the bytes).
//
// # Why a typed barrier on the verifier side
//
// Symmetry with the producer-side type. Customer code that
// constructs a V3 entry to verify against a fixture (rather than
// loading from a chain row) gets the same opaque type, so the
// "this is a digest, not a free-text string" intent is preserved
// across the SDK surface.

// TenantHMACDigestV3 is an opaque, hex-encoded HMAC-SHA-512 output
// (or zero value for "not set"). The unexported `hex` field
// prevents external packages from constructing arbitrary digests
// by struct literal — use the constructors below.
type TenantHMACDigestV3 struct {
	hex string
}

// v3TenantHMACDigestHexRe matches the on-the-wire shape: 128
// lowercase hex chars (SHA-512 output).
var v3TenantHMACDigestHexRe = regexp.MustCompile(`^[0-9a-f]{128}$`)

// TenantHMACDigestFromHexV3 constructs a digest from a pre-baked
// hex string. Verifiers use this when loading chain rows: the row
// already carries the digest in hex form; the verifier wraps it
// for type-safety while traversing the chain.
//
// Empty `h` returns the zero digest (representing "field was not
// supplied at producer side").
//
// # Inputs
//
//   - h: 128 lowercase hex chars OR empty string
//
// # Outputs
//
//   - TenantHMACDigestV3
//   - error: shape violation (non-empty input not matching the
//     128-hex regex)
func TenantHMACDigestFromHexV3(h string) (TenantHMACDigestV3, error) {
	if h == "" {
		return TenantHMACDigestV3{}, nil
	}
	if !v3TenantHMACDigestHexRe.MatchString(h) {
		// Constant error message — caller's input is never echoed
		// (chain_d Privacy F4 / M11). Prevents leaking cleartext if
		// a customer misuses this with the wrong input type.
		return TenantHMACDigestV3{}, fmt.Errorf("TenantHMACDigestFromHexV3: input is not 128 lowercase hex chars")
	}
	return TenantHMACDigestV3{hex: h}, nil
}

// MustTenantHMACDigestFromHexV3 is the panicking variant for
// fixture / test callers who know their input is well-formed.
//
// # Use only on compile-time constants
//
// CLAUDE.md forbids `panic()` in library code. This function is
// scoped to fixture / test use; production callers MUST use
// `TenantHMACDigestFromHexV3` (which returns an error). The panic
// message is a CONSTANT — input is never echoed, so a caller who
// mistakenly passes cleartext does not leak it via the panic /
// stderr crash log (chain_d M11).
//
// # Panics
//
// Panics with a constant message if `h` is non-empty but not 128
// lowercase hex chars.
func MustTenantHMACDigestFromHexV3(h string) TenantHMACDigestV3 {
	d, err := TenantHMACDigestFromHexV3(h)
	if err != nil {
		// Constant panic message — do NOT include `h`. Misused
		// with cleartext, this prevents the input from showing
		// up in stderr / crash logs.
		panic("MustTenantHMACDigestFromHexV3: input is not 128 lowercase hex chars")
	}
	return d
}

// Hex returns the canonical hex representation written into chain
// canonical bytes. Empty string when the digest is the zero value.
func (d TenantHMACDigestV3) Hex() string { return d.hex }

// IsZero reports whether the digest is the zero value.
func (d TenantHMACDigestV3) IsZero() bool { return d.hex == "" }

// String implements fmt.Stringer — returns the hex form.
//
// # Log safety
//
// The digest hex is safe to log in isolation (it's a hash, not
// cleartext). BUT logging the CONTAINING entry struct via a
// reflective logger (`logger.Info("entry", entry)`) is NOT
// privacy-safe — the entry's `RequestID` and `CompanyID` are
// plaintext identifiers. Customers SHOULD use field-selected
// structured logging for chain entries (chain_d Privacy F7).
func (d TenantHMACDigestV3) String() string { return d.hex }

// MarshalJSON serializes as the hex string. Symmetric with
// UnmarshalJSON — chain rows can round-trip through JSON without
// loss.
func (d TenantHMACDigestV3) MarshalJSON() ([]byte, error) {
	if d.hex == "" {
		return []byte(`""`), nil
	}
	return []byte(`"` + d.hex + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler. The implementation
// routes through TenantHMACDigestFromHexV3 so the shape invariant
// (128 lowercase hex chars or empty) is enforced — there is no
// way to deserialize an arbitrary-shaped digest from JSON.
//
// # Security note
//
// Customers MUST NOT use this path on values they themselves
// derived from cleartext via plain SHA-512 (or any unkeyed hash).
// The producer side enforces per-tenant HMAC keying via
// `MintTenantHMACDigest` in `internal/consent`; the verifier
// receives the already-keyed hex from chain rows.
func (d *TenantHMACDigestV3) UnmarshalJSON(data []byte) error {
	if string(data) == "null" || string(data) == `""` {
		*d = TenantHMACDigestV3{}
		return nil
	}
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("TenantHMACDigestV3.UnmarshalJSON: expected JSON string")
	}
	parsed, err := TenantHMACDigestFromHexV3(string(data[1 : len(data)-1]))
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}
