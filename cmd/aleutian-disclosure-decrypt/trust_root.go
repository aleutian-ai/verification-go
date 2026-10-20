// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// trustRootPubkeyV1Hex pins the ML-DSA-65 public key that signed the
// trust manifest's root_signature_b64 field. Pre-ceremony this is
// empty; SDK builds that ship with the empty placeholder accept the
// trust manifest's root signature on faith and rely on the bundle
// ML-DSA-65 signature as the load-bearing integrity check.
//
// Post-ceremony, Aleutian publishes a new SDK minor version with the
// real 3904-char hex-encoded pubkey embedded here. Customers running
// a placeholder SDK against a post-ceremony bundle still verify the
// bundle sig correctly; only the redundant trust-root verification is
// skipped.
const trustRootPubkeyV1Hex = ""

// TrustRootIsPlaceholder reports whether the SDK build still ships
// with the pre-ceremony placeholder trust-root pubkey.
func TrustRootIsPlaceholder() bool {
	return trustRootPubkeyV1Hex == ""
}

// VerifyTrustManifestRoot verifies the trust manifest's
// root_signature_b64 against the embedded trust-root pubkey. Returns
// nil when the embedded pubkey is the placeholder (the caller is
// expected to WARN the operator separately).
func VerifyTrustManifestRoot(tmBytes []byte, rootSigB64 string) error {
	if TrustRootIsPlaceholder() {
		return nil
	}
	if rootSigB64 == "" {
		return fmt.Errorf("%w: trust manifest root_signature_b64 is empty (post-ceremony bundle MUST carry a root sig)", ErrStructural)
	}
	sig, err := base64.StdEncoding.DecodeString(rootSigB64)
	if err != nil {
		return fmt.Errorf("%w: decode root_signature_b64: %v", ErrStructural, err)
	}
	if len(sig) != mlDSA65SigSize {
		return fmt.Errorf("%w: root_signature_b64 is %d bytes, expected %d (ML-DSA-65)",
			ErrStructural, len(sig), mlDSA65SigSize)
	}
	pubBytes, err := hex.DecodeString(trustRootPubkeyV1Hex)
	if err != nil {
		return fmt.Errorf("%w: decode pinned trust root pubkey hex: %v", ErrStructural, err)
	}
	scheme := mldsa65.Scheme()
	pub, err := scheme.UnmarshalBinaryPublicKey(pubBytes)
	if err != nil {
		return fmt.Errorf("%w: parse pinned trust root pubkey: %v", ErrStructural, err)
	}
	if !scheme.Verify(pub, tmBytes, sig, nil) {
		return fmt.Errorf("%w: trust manifest root signature verification failed", ErrStructural)
	}
	return nil
}
