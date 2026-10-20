// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package mldsa exposes a standalone FIPS 204 (ML-DSA-65) signature verifier.
//
// # Description
//
// This package wraps cloudflare/circl's ML-DSA-65 implementation in a minimal
// API suitable for auditors and downstream consumers who want to verify an
// Aleutian-signed artifact without pulling in the full verification SDK
// surface. The primitive is intentionally framework-free: it accepts raw
// bytes and returns a sentinel error.
//
// The compliance evidence generator and all three Aleutian verification SDKs
// (Go, Python, JS) converge on identical semantics, enforced by the shared
// KAT vectors at sdk/testdata/mldsa_vectors.json.
//
// # Wire Format
//
//   - publicKey: raw 1952-byte ML-DSA-65 public key (FIPS 204 §5.2)
//   - message: arbitrary bytes; no pre-hashing — ML-DSA-65 hashes internally
//   - signature: raw 3309-byte ML-DSA-65 signature (FIPS 204 §5.3)
//   - context: empty (FIPS 204 pure mode, matches Cloud KMS PQ_SIGN_ML_DSA_65)
//
// # Example
//
//	err := mldsa.Verify(pubKey, canonicalJSON, sigBytes)
//	switch {
//	case errors.Is(err, mldsa.ErrInvalidPublicKey):
//	    // public key is malformed or wrong size
//	case errors.Is(err, mldsa.ErrInvalidSignatureLength):
//	    // signature is not exactly 3309 bytes
//	case errors.Is(err, mldsa.ErrSignatureVerificationFailed):
//	    // cryptographic verification failed (bad sig, wrong key, mutated msg)
//	case err != nil:
//	    // unexpected error
//	default:
//	    // verified
//	}
package mldsa

import (
	"errors"
	"fmt"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Sentinel errors. Use errors.Is to branch on them.
var (
	// ErrInvalidPublicKey is returned when the public key is the wrong length
	// or fails to parse under ML-DSA-65 binary encoding.
	ErrInvalidPublicKey = errors.New("mldsa: invalid public key")

	// ErrInvalidSignatureLength is returned when the signature is not exactly
	// 3309 bytes. ML-DSA-65 signatures are fixed length per FIPS 204.
	ErrInvalidSignatureLength = errors.New("mldsa: invalid signature length")

	// ErrSignatureVerificationFailed is returned when the signature does not
	// verify against the given public key and message. Covers all
	// cryptographic-failure cases (bad signature, wrong key, mutated message).
	ErrSignatureVerificationFailed = errors.New("mldsa: signature verification failed")
)

// PublicKeySize is the byte length of an ML-DSA-65 public key (FIPS 204).
const PublicKeySize = mldsa65.PublicKeySize

// SignatureSize is the byte length of an ML-DSA-65 signature (FIPS 204).
const SignatureSize = mldsa65.SignatureSize

// Verify checks an ML-DSA-65 signature in FIPS 204 pure mode.
//
// # Description
//
// Verifies signature against the message under the given public key using
// ML-DSA-65 with an empty context string. No pre-hashing is applied — the
// scheme hashes the message internally per FIPS 204 §5.3.
//
// The empty context string matches Cloud KMS PQ_SIGN_ML_DSA_65 and all three
// Aleutian verification SDKs. Do not change without coordinated updates
// across every signing path.
//
// # Inputs
//
//   - publicKey: raw 1952-byte ML-DSA-65 public key
//   - message: the exact bytes that were signed (e.g., RFC 8785 canonical JSON)
//   - signature: raw 3309-byte ML-DSA-65 signature
//
// # Outputs
//
//   - error: nil on success; ErrInvalidPublicKey, ErrInvalidSignatureLength,
//     or ErrSignatureVerificationFailed on failure. Check with errors.Is.
//
// # Example
//
//	if err := mldsa.Verify(pk, canonicalBytes, sig); err != nil {
//	    return fmt.Errorf("anchor signature invalid: %w", err)
//	}
//
// # Limitations
//
//   - Does not resolve key IDs; callers provide the raw public key bytes.
//   - Does not check revocation status; that is the trust-store loader's job.
//   - No context string is supported; pure FIPS 204 mode only.
//
// # Assumptions
//
//   - message bytes are already canonicalized to match what was signed.
//   - publicKey bytes are the raw 1952-byte encoding, not PEM or DER-wrapped.
func Verify(publicKey, message, signature []byte) error {
	if len(publicKey) != PublicKeySize {
		return fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidPublicKey, len(publicKey), PublicKeySize)
	}
	if len(signature) != SignatureSize {
		return fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidSignatureLength, len(signature), SignatureSize)
	}

	scheme := mldsa65.Scheme()
	pub, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}

	// nil opts = empty context string = FIPS 204 §5.3 pure ML-DSA.Verify.
	// scheme.Verify on a public key obtained from UnmarshalBinaryPublicKey
	// will not panic on type mismatch — the type was just constructed by the
	// same scheme above.
	if !scheme.Verify(pub, message, signature, nil) {
		return ErrSignatureVerificationFailed
	}
	return nil
}
