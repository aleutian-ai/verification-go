// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

// trust_root.go — SDK-side pinned ML-DSA-65 root public key.
//
// # Description
//
// Mirror of internal/compliance/trust_root.go for the customer-facing
// SDK. The root pubkey is selected at build time via build tags:
//
//	default build       → fixtures/trust-root-dev.pub     (dev/local)
//	-tags=trust_staging → fixtures/trust-root-staging.pub (staging)
//	-tags=trust_prod    → fixtures/trust-root-prod.pub    (prod)
//
// One tag matches at a time, so a customer SDK release is
// cryptographically committed to verifying manifests signed under
// one env's root. Compile-time pin defeats runtime mis-selection.
//
// # Use
//
// Customers normally do not touch these directly — LoadTrustManifest
// in trust_manifest.go verifies the fetched manifest against
// TrustRootPublicKey automatically. Exported for unit tests, audit
// inspection ("which root am I built against?"), and the explicit
// `OfflineOnly` SDK option that uses fixture-pinned keys without
// fetching at all.

// MLDSA65PublicKeySize is the raw public-key length for ML-DSA-65
// (FIPS 204 pure mode). Mirrored from internal/compliance.
const MLDSA65PublicKeySize = 1952

// TrustRootKeyID is the canonical identifier referenced by manifest
// audit markers when naming the root. Same string across envs;
// disambiguation is by pubkey bytes + ActiveTrustEnv.
const TrustRootKeyID = "trust-root-mldsa65"

// TrustRootPublicKey is the pinned ML-DSA-65 root public key for the
// build target's env. Assigned by the env-specific init() in
// trust_root_{default,staging,prod}.go.
//
// Length is enforced to MLDSA65PublicKeySize at init; mismatch panics.
var TrustRootPublicKey []byte

// ActiveTrustEnv records which build-tag fixture was selected.
// One of "dev", "staging", "prod".
var ActiveTrustEnv string

// IsTrustRootPlaceholder reports whether TrustRootPublicKey is the
// all-zero placeholder shipped before the 15n_fix_A4 root-key
// ceremony populates the env fixture.
//
// # Outputs
//
//   - true if every byte of TrustRootPublicKey is zero.
//   - false once the ceremony has installed real bytes.
//
// # Use
//
// LoadTrustManifest checks this before attempting to verify a
// fetched manifest; placeholder root → fail-loud with a pointer to
// the ceremony documentation. Customer code rarely calls this
// directly.
func IsTrustRootPlaceholder() bool {
	for _, b := range TrustRootPublicKey {
		if b != 0 {
			return false
		}
	}
	return true
}
