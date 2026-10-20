// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"errors"
	"fmt"
)

// WrappedKeyV3Size is the total serialized size of a WrappedKeyV3 wire blob.
// Mirrors internal/crypto.WrappedKeyV3Size.
const WrappedKeyV3Size = 1169

// Sentinel errors for WrappedKeyV3 parsing. Mirrors internal/crypto sentinels.
var (
	// ErrLegacyRSAVersion is returned when the wire format contains version 0x01.
	ErrLegacyRSAVersion = errors.New("wrapped key version 0x01 is not supported")

	// ErrUnsupportedVersion is returned when the wire format contains an
	// unrecognized version byte.
	ErrUnsupportedVersion = errors.New("unrecognized wrapped key version")

	// ErrInvalidMAC is returned when the HMAC-SHA-512 integrity check fails.
	ErrInvalidMAC = errors.New("wrapped key integrity check failed — blob may be corrupted")
)

// XWINGPrivateKey is the SDK's private key type for XWING decapsulation.
//
// # Description
//
// It is structurally identical to internal/crypto.XWINGPrivateKey but is a DISTINCT
// Go type. The SDK module (github.com/aleutian-ai/verification-go) cannot import
// AleutianEnterprise/internal/crypto — Go's internal package restriction prevents
// cross-module internal imports. The SDK has its own go.mod and does NOT import any
// AleutianEnterprise/internal packages.
//
// The canonical private key is a single 32-byte seed per IETF
// draft-connolly-cfrg-xwing-kem §5.2. Key material is derived via SHAKE256(seed, 96):
//
//	expanded[0:32]  = ML-KEM d parameter
//	expanded[32:64] = ML-KEM z parameter
//	expanded[64:96] = X25519 private scalar
//
// The SDK must implement its own expandDecapsulationKey (same SHAKE256 expansion
// as internal/crypto) since it cannot import across the module boundary.
//
// Do not copy this struct — use *XWINGPrivateKey everywhere to ensure Zeroize()
// clears all copies.
//
// Callers MUST call Zeroize when the key is no longer needed.
type XWINGPrivateKey struct {
	seed [32]byte // 32-byte master seed — SHAKE256-expanded to derive ML-KEM seed + X25519 scalar
}

// Zeroize overwrites the private key seed with zeros.
//
// # Description
//
// Zeroes all 32 bytes of the Seed field, narrowing the window during which
// private key material is accessible in process memory after use.
//
// # Inputs
//
//   - receiver: *XWINGPrivateKey to zeroize
//
// # Outputs
//
//   - None.
//
// # Example
//
//	defer priv.Zeroize()
//
// # Limitations
//
//   - Go does not support mlock(2) without cgo; pages may be swapped before Zeroize is called.
//   - Defense-in-depth only; not a cryptographic guarantee.
//
// # Assumptions
//
//   - Caller has exclusive access to priv (not safe for concurrent use)
func (priv *XWINGPrivateKey) Zeroize() {
	zeroize(priv.seed[:])
}

// NewXWINGPrivateKey constructs an XWINGPrivateKey from a 32-byte seed slice.
//
// # Description
//
// Copies the seed into the unexported seed field and zeroes the caller's slice,
// ensuring the caller cannot retain an unzeroizable copy. The returned key is
// heap-allocated (pointer) to enforce the pointer-only usage pattern required
// by Zeroize().
//
// # Inputs
//
//   - seed: exactly 32 bytes — the XWING decapsulation key seed
//
// # Outputs
//
//   - *XWINGPrivateKey: key with seed populated; caller MUST defer Zeroize()
//   - error: non-nil if len(seed) != 32
//
// # Example
//
//	priv, err := NewXWINGPrivateKey(seedBytes)
//	if err != nil {
//	    return err
//	}
//	defer priv.Zeroize()
//
// # Limitations
//
//   - Any 32 bytes is a valid seed; there is no structural validation beyond length.
//
// # Assumptions
//
//   - seed was loaded from a secure key store (pqc_01e key file)
func NewXWINGPrivateKey(seed []byte) (*XWINGPrivateKey, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("xwing: invalid seed length: expected 32 bytes, got %d", len(seed))
	}
	priv := &XWINGPrivateKey{}
	copy(priv.seed[:], seed)
	zeroize(seed) // clear caller's copy
	return priv, nil
}

// Seed returns a copy of the private key seed for use in SHAKE256 expansion.
//
// # Description
//
// Returns the 32-byte seed by value (copy). This is used internally by
// expandDecapsulationKey during decapsulation (pqc_01f). The copy prevents
// callers from holding a reference to the internal seed array.
//
// # Outputs
//
//   - [32]byte: copy of the seed
func (priv *XWINGPrivateKey) Seed() [32]byte {
	return priv.seed
}

// String returns a redacted placeholder to prevent accidental logging of key material.
func (priv *XWINGPrivateKey) String() string { return "[REDACTED XWINGPrivateKey]" }

// GoString returns a redacted placeholder to prevent accidental logging of key material.
func (priv *XWINGPrivateKey) GoString() string { return "[REDACTED XWINGPrivateKey]" }

// Format implements fmt.Formatter to prevent accidental logging of key material via
// all format verbs including %+v.
func (priv *XWINGPrivateKey) Format(f fmt.State, _ rune) {
	fmt.Fprint(f, "[REDACTED XWINGPrivateKey]")
}

// SharedSecret is the 32-byte output of XWING decapsulation.
//
// # Description
//
// Used directly as the AES-256-GCM key for payload decryption. Mirrored from
// internal/crypto.SharedSecret. Includes Zeroize() for defense-in-depth key
// material cleanup and String() redaction to prevent accidental logging.
type SharedSecret [32]byte

// String returns a redacted placeholder to prevent accidental logging of key material.
func (ss SharedSecret) String() string { return "[REDACTED SharedSecret]" }

// GoString returns a redacted placeholder to prevent accidental logging of key material.
func (ss SharedSecret) GoString() string { return "[REDACTED SharedSecret]" }

// Format implements fmt.Formatter to prevent accidental logging of key material via
// all format verbs including %+v.
func (ss SharedSecret) Format(f fmt.State, _ rune) {
	fmt.Fprint(f, "[REDACTED SharedSecret]")
}

// Zeroize overwrites the shared secret with zeros.
//
// # Description
//
// Zeroes all 32 bytes of the SharedSecret array, narrowing the window during which
// the AES-256-GCM key is in process memory.
//
// # Inputs
//
//   - receiver: *SharedSecret to zeroize
//
// # Outputs
//
//   - None.
//
// # Example
//
//	ss, err := unwrapper.Unwrap(ctx, blob, priv)
//	if err != nil {
//	    return err
//	}
//	defer ss.Zeroize()
//
// # Limitations
//
//   - SharedSecret is a value type ([32]byte). Call Zeroize on the original variable,
//     not on a copy.
//
// # Assumptions
//
//   - Caller has exclusive access to ss (not safe for concurrent use)
func (ss *SharedSecret) Zeroize() {
	zeroize(ss[:])
}

// KEMUnwrapper decapsulates a wrapped DEK using the customer's private key.
//
// # Description
//
// Lives in sdk/verification-go — customer-side only. Never imported by internal/.
//
// Unwrap takes raw wire bytes (not internal/crypto.WrappedKeyV3) because the SDK is
// a separate Go module and cannot import internal/crypto. The SDK parses the wire
// format internally using the same 1169-byte layout defined in pqc_01b.
//
// wrappedKeyBytes must be exactly 1169 bytes (WrappedKeyV3Size). Implementations
// MUST return an error (not panic) if len(wrappedKeyBytes) != WrappedKeyV3Size.
//
// Takes *XWINGPrivateKey (pointer) to avoid copying the seed onto the stack,
// reducing the number of memory locations where key material resides.
//
// The SDK must also implement:
//   - expandDecapsulationKey(seed [32]byte) — SHAKE256 expansion (same as server-side)
//   - XWING decapsulation (same combiner: SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label))
//   - Wire format parsing (version + key_id + mlkem_ct + x25519_epk + mac)
type KEMUnwrapper interface {
	// Unwrap parses the 1169-byte wire blob, verifies the MAC, decapsulates
	// the XWING ciphertext with priv, and returns the 32-byte shared secret.
	//
	// # Inputs
	//
	//   - ctx: context for composability (may carry deadlines)
	//   - wrappedKeyBytes: exactly 1169 bytes (WrappedKeyV3 wire format)
	//   - priv: pointer to the customer's XWING private key
	//
	// # Outputs
	//
	//   - SharedSecret: 32-byte value; caller MUST defer ss.Zeroize()
	//   - error: ErrInvalidMAC, ErrLegacyRSAVersion, ErrUnsupportedVersion, or other
	Unwrap(ctx context.Context, wrappedKeyBytes []byte, priv *XWINGPrivateKey) (SharedSecret, error)
}

// zeroize overwrites b with zeros to reduce the window during which key material
// is accessible in Go heap memory after use.
//
//go:noinline
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
