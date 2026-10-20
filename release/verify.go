// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"errors"
	"fmt"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Sentinel errors. Callers can errors.Is dispatch on these.
var (
	// ErrPlaceholderPubkey is returned when the embedded release
	// pubkey is still the all-zero placeholder (pre-ceremony state).
	// VerifyChecksums never returns "valid" against an unset key —
	// fail-closed.
	ErrPlaceholderPubkey = errors.New("sdk-release: release pubkey is the pre-ceremony placeholder; cannot verify")

	// ErrInvalidSignatureSize wraps a signature whose length is not
	// exactly 3309 bytes (FIPS-204 ML-DSA-65 sig size).
	ErrInvalidSignatureSize = errors.New("sdk-release: signature is not 3309 bytes")

	// ErrInvalidSignature is the catch-all for "signature does not
	// verify" — wrong key, tampered SHA256SUMS, or sig produced
	// under a different ML-DSA variant.
	ErrInvalidSignature = errors.New("sdk-release: signature does not verify against the embedded release pubkey")
)

// VerifyChecksums verifies a detached ML-DSA-65 signature against
// the embedded release public key.
//
// # Description
//
// Pure pure-mode ML-DSA-65 verify (no context, no pre-hash). Matches
// the sign-side contract (cloud/scripts/sign-release-checksums.sh +
// cmd/aleutian-release-sign).
//
// # Inputs
//
//   - sumsBytes: the raw bytes of SHA256SUMS as published by Aleutian
//   - sigBytes:  the raw bytes of SHA256SUMS.sig (exactly 3309 bytes)
//
// # Outputs
//
//   - error: nil on successful verification; one of the sentinel
//     errors above on failure
//
// # Use
//
//	sums, _ := os.ReadFile("SHA256SUMS")
//	sig, _  := os.ReadFile("SHA256SUMS.sig")
//	if err := release.VerifyChecksums(sums, sig); err != nil {
//	    log.Fatalf("release signature failed: %v", err)
//	}
//	// then verify individual binary hashes against sums
func VerifyChecksums(sumsBytes, sigBytes []byte) error {
	if IsPlaceholder() {
		return ErrPlaceholderPubkey
	}
	if len(sigBytes) != mldsa65.SignatureSize {
		return fmt.Errorf("%w: got %d, want %d",
			ErrInvalidSignatureSize, len(sigBytes), mldsa65.SignatureSize)
	}
	scheme := mldsa65.Scheme()
	pub, err := scheme.UnmarshalBinaryPublicKey(ReleasePubkey())
	if err != nil {
		return fmt.Errorf("sdk-release: parse embedded pubkey: %w", err)
	}
	if !scheme.Verify(pub, sumsBytes, sigBytes, nil) {
		return ErrInvalidSignature
	}
	return nil
}
