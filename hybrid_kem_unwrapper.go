// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/sha512"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

// Wire format constants for WrappedKeyV3 parsing.
// Must match internal/crypto/kem.go exactly — kept in sync manually.
const (
	sdkWrappedKeyV3Size  = 1169
	sdkWrappedKeyVersion = byte(0x03)
	sdkLegacyRSAVersion  = byte(0x01)
	sdkMACKey            = "aleutian-kem-v3-mac"

	// Wire format byte offsets.
	// Layout: version(1) | keyID(16) | mlkem_ct(1088) | x25519_epk(32) | mac(32)
	sdkOffKeyID     = 1
	sdkOffMLKEMCT   = 17   // 1 + 16
	sdkOffX25519EPK = 1105 // 1 + 16 + 1088
	sdkOffMAC       = 1137 // 1 + 16 + 1088 + 32
)

// xwingLabel is the 6-byte XWING domain separator per IETF draft-connolly-cfrg-xwing-kem §5.3.
// ASCII: \././^\ — the X-Wing emoticon.
// Must match internal/crypto/xwing.go:21 exactly.
var xwingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

// Compile-time interface assertion.
var _ KEMUnwrapper = (*HybridKEMUnwrapper)(nil)

// HybridKEMUnwrapper implements KEMUnwrapper using the X-Wing hybrid KEM algorithm.
//
// # Description
//
// Self-contained implementation that does not import internal/crypto. Parses the
// WrappedKeyV3 wire format, verifies the MAC, expands the private key seed via
// SHAKE256, and performs the X-Wing combiner (ML-KEM-768 + X25519 + SHA3-256).
//
// This is the customer-side SDK implementation. The server-side uses
// internal/crypto.XWINGDecapsulate which has an identical algorithm but separate code.
//
// # Limitations
//
//   - mlkem.NewDecapsulationKey768 allocates ~2400 bytes internally that cannot be
//     explicitly zeroized (Go stdlib limitation).
type HybridKEMUnwrapper struct{}

// Unwrap parses a 1169-byte WrappedKeyV3 wire blob, verifies the MAC,
// decapsulates the X-Wing ciphertext with priv, and returns the 32-byte shared secret.
//
// # Description
//
// Validation order (security-critical — do not reorder):
//  1. Length check: len != 1169 → descriptive size error.
//  2. MAC verification: HMAC-SHA-512 over bytes [0:1137) compared to bytes [1137:1169).
//     Verified BEFORE version dispatch to prevent reaching version-specific code
//     paths on corrupted data.
//  3. Version dispatch: 0x01 → ErrLegacyRSAVersion; non-0x03 → ErrUnsupportedVersion.
//  4. Field extraction and X-Wing decapsulation.
//
// # Inputs
//
//   - ctx: context for composability (may carry deadlines)
//   - wrappedKeyBytes: exactly 1169 bytes (WrappedKeyV3 wire format)
//   - priv: pointer to the customer's X-Wing private key (32-byte seed)
//
// # Outputs
//
//   - SharedSecret: 32-byte value; caller MUST defer ss.Zeroize()
//   - error: ErrInvalidMAC, ErrLegacyRSAVersion, ErrUnsupportedVersion, or other
//
// # Example
//
//	unwrapper := &verification.HybridKEMUnwrapper{}
//	ss, err := unwrapper.Unwrap(ctx, wrappedBlob, priv)
//	if err != nil {
//	    return err
//	}
//	defer ss.Zeroize()
//
// # Assumptions
//
//   - wrappedKeyBytes was produced by a KEMWrapper.Wrap call or loaded from storage
//   - priv corresponds to the public key used during wrapping
func (h *HybridKEMUnwrapper) Unwrap(
	_ context.Context,
	wrappedKeyBytes []byte,
	priv *XWINGPrivateKey,
) (SharedSecret, error) {
	var ss SharedSecret

	// Step 0: Validate pointer inputs at public API boundary.
	if priv == nil {
		return ss, errors.New("xwing: private key must not be nil")
	}

	// Step 1: Size check.
	if len(wrappedKeyBytes) != sdkWrappedKeyV3Size {
		return ss, fmt.Errorf("invalid wrapped key: expected %d bytes, got %d",
			sdkWrappedKeyV3Size, len(wrappedKeyBytes))
	}

	// Step 2: MAC verification BEFORE version dispatch.
	//
	// Truncate the HMAC-SHA-512 output to 32 bytes to match the server's
	// computeWrappedKeyMAC (internal/crypto/kem.go), which truncates to
	// 256 bits per NIST SP 800-107 §5.3.4 because the wire format
	// reserves 32 bytes for the MAC field. Truncated MAC retains 128-bit
	// forgery resistance which is the bottleneck regardless of inner
	// hash choice. Before this fix the SDK compared 32 wire bytes
	// against a 64-byte expected value and ALWAYS returned ErrInvalidMAC
	// on well-formed wrapped keys.
	// See tickets/code_complete/dsar_triage_integration_pqc_1.md.
	mac := wrappedKeyBytes[sdkOffMAC:sdkWrappedKeyV3Size]
	macH := hmac.New(sha512.New, []byte(sdkMACKey))
	macH.Write(wrappedKeyBytes[:sdkOffMAC])
	expectedMAC := macH.Sum(nil)[:32]
	if !hmac.Equal(mac, expectedMAC) {
		return ss, ErrInvalidMAC
	}

	// Step 3: Version dispatch (after MAC — integrity before interpretation).
	version := wrappedKeyBytes[0]
	if version == sdkLegacyRSAVersion {
		return ss, ErrLegacyRSAVersion
	}
	if version != sdkWrappedKeyVersion {
		return ss, fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, version)
	}

	// Step 4: Parse fields per wire layout.
	// Layout: version(1) | keyID(16) | mlkem_ct(1088) | x25519_epk(32) | mac(32)
	mlkemCT := wrappedKeyBytes[sdkOffMLKEMCT:sdkOffX25519EPK] // [17:1105] = 1088 bytes
	x25519EPK := wrappedKeyBytes[sdkOffX25519EPK:sdkOffMAC]   // [1105:1137] = 32 bytes

	// Step 5: Expand private key seed via SHAKE256.
	seed := priv.Seed()
	defer zeroize(seed[:])
	mlkemSeed, x25519Priv := expandDecapsulationKeySDK(seed)
	defer zeroize(mlkemSeed[:])
	defer zeroize(x25519Priv[:])

	// Step 6: X25519 DH(priv, epk) → ss_X.
	// Per IETF draft-connolly-cfrg-xwing-kem §4.2, low-order points must not
	// cause failure because ML-KEM provides independent security. On error,
	// substitute 32 zero bytes (matching server-side behavior in xwing.go).
	x25519SS, err := curve25519.X25519(x25519Priv[:], x25519EPK)
	if err != nil {
		x25519SS = make([]byte, 32)
	}
	defer zeroize(x25519SS)

	// Step 7: ML-KEM-768 decapsulate with seed.
	dk, err := mlkem.NewDecapsulationKey768(mlkemSeed[:])
	if err != nil {
		return ss, fmt.Errorf("parse ML-KEM decapsulation key: %w", err)
	}
	mlkemSS, err := dk.Decapsulate(mlkemCT)
	if err != nil {
		return ss, fmt.Errorf("ML-KEM decapsulate: %w", err)
	}
	defer zeroize(mlkemSS)

	// Step 8: Derive recipient X25519 public key from private scalar (for combiner).
	x25519PK, err := curve25519.X25519(x25519Priv[:], curve25519.Basepoint)
	if err != nil {
		return ss, fmt.Errorf("derive X25519 public key: %w", err)
	}
	defer zeroize(x25519PK)

	// Step 9: X-Wing combiner: SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)
	// Field order is fixed by IETF draft-connolly-cfrg-xwing-kem §5.4 (draft-06).
	// Label is LAST. Do not reorder.
	combiner := sha3.New256()
	combiner.Write(mlkemSS)    // ss_M
	combiner.Write(x25519SS)   // ss_X
	combiner.Write(x25519EPK)  // ct_X (ephemeral public key)
	combiner.Write(x25519PK)   // pk_X (recipient public key)
	combiner.Write(xwingLabel) // label LAST per draft-06
	combiner.Sum(ss[:0])

	return ss, nil
}

// expandDecapsulationKeySDK expands a 32-byte seed via SHAKE256 to derive
// the ML-KEM-768 seed (d‖z, 64 bytes) and X25519 private scalar (32 bytes).
//
// # Description
//
// Identical logic to internal/crypto.expandDecapsulationKey — must be kept in sync.
// Per IETF draft-connolly-cfrg-xwing-kem §5.2:
//
//	expanded = SHAKE256(seed, 96)
//	mlkem_d  = expanded[0:32]
//	mlkem_z  = expanded[32:64]
//	x25519   = expanded[64:96]
//
// # Inputs
//
//   - seed: 32-byte master seed
//
// # Outputs
//
//   - mlkemSeed: 64-byte ML-KEM seed (d‖z); caller MUST defer zeroize
//   - x25519Priv: 32-byte X25519 private scalar; caller MUST defer zeroize
//
// # Assumptions
//
//   - seed was loaded from a secure key store via NewXWINGPrivateKey
func expandDecapsulationKeySDK(seed [32]byte) (mlkemSeed [64]byte, x25519Priv [32]byte) {
	h := sha3.NewShake256()
	h.Write(seed[:])
	var expanded [96]byte
	_, _ = h.Read(expanded[:])
	copy(mlkemSeed[:], expanded[:64])
	copy(x25519Priv[:], expanded[64:96])
	zeroize(expanded[:])
	return
}
