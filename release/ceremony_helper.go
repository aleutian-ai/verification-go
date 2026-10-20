// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"encoding/hex"
	"errors"
	"fmt"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ValidatePubkeyHex is the operator-facing pre-ceremony validation
// hook. After running `gcloud kms keys versions get-public-key` +
// `xxd -p`, the operator pipes the result through this function (via
// the cmd/aleutian-release-ceremony-validate helper) to confirm:
//
//  1. The hex string decodes cleanly.
//  2. The decoded bytes are exactly 1952 (ML-DSA-65 pubkey size).
//  3. circl's mldsa65 scheme accepts the bytes as a well-formed
//     public key (parse-roundtrip).
//
// Returning nil means the hex is safe to paste into pubkey.go's
// releasePubkeyV1HexPlaceholder constant. Returning an error means
// DO NOT EMBED — fix the upstream export before continuing.
//
// # Why this exists separate from VerifyChecksums
//
// VerifyChecksums refuses to run while the embedded pubkey is the
// placeholder. So the operator can't use it to pre-flight a new key.
// This helper exists exclusively for the ceremony step: validate the
// hex BEFORE editing the source file, so the operator catches a
// truncated copy/paste before it lands in a SDK release.
func ValidatePubkeyHex(pubkeyHex string) error {
	if pubkeyHex == "" {
		return errors.New("pubkey hex is empty (forgot to redirect xxd output?)")
	}
	// MLDSA-65 pubkey = 1952 bytes → 3904 hex chars exactly.
	const wantChars = 3904
	if len(pubkeyHex) != wantChars {
		return fmt.Errorf("pubkey hex is %d chars, want %d (1952-byte ML-DSA-65 pubkey)",
			len(pubkeyHex), wantChars)
	}
	raw, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return fmt.Errorf("hex decode: %w", err)
	}
	scheme := mldsa65.Scheme()
	if _, err := scheme.UnmarshalBinaryPublicKey(raw); err != nil {
		return fmt.Errorf("circl rejected the bytes as ML-DSA-65 pubkey: %w", err)
	}
	return nil
}
