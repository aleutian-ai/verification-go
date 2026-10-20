// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

// Embedded bootstrap-key set per environment, per spec §6
// (sdk_trust_manifest_format_spec).
//
// # What this is
//
// The trust manifest is signed by a "bootstrap" key whose public
// half is COMPILED INTO this SDK. A manifest whose
// `bootstrap_signing_key_id` is NOT in the embedded set for the
// caller's chosen environment is refused — even if the signature
// verifies against some other public key. This closes the supply-
// chain attack where a stolen historic bootstrap key signs a
// manifest the current SDK would otherwise accept.
//
// # Current state (2026-06-12)
//
// The pubkey bytes here are ALL-ZERO PLACEHOLDERS pending the
// bootstrap ceremony tracked in `sdk_trust_manifest_bootstrap_root
// _ceremony`. Until the ceremony runs:
//
//   - `TrustManifestFromURLV3` constructed against any env reports
//     `IsBootstrapPlaceholder() == true`
//   - Verification against this SDK build will REFUSE every
//     manifest (fail-closed)
//   - Customers who try to use the SDK get
//     `ErrManifestUnknownBootstrapKeyV3` with a hint to upgrade
//     the SDK
//
// This is identical to the release-pubkey placeholder pattern in
// `sdk/verification-go/release/pubkey.go` (Phase E H3).
//
// # Post-ceremony
//
// The ceremony script writes real ML-DSA-65 public-key bytes into
// the maps below. Customers consuming the post-ceremony SDK get
// signatures-actually-verify behavior automatically — they don't
// need to do anything beyond `go install ...@<post-ceremony-version>`.

// TrustManifestEnv names the customer's chosen environment. Embedded
// bootstrap sets are partitioned per env to prevent cross-env mixups
// (e.g. a dev-signed manifest being trusted by a prod SDK build).
type TrustManifestEnv string

const (
	TrustManifestEnvDev     TrustManifestEnv = "dev"
	TrustManifestEnvStaging TrustManifestEnv = "staging"
	TrustManifestEnvProd    TrustManifestEnv = "prod"
)

// IsValid reports whether e is one of the three supported envs.
func (e TrustManifestEnv) IsValid() bool {
	switch e {
	case TrustManifestEnvDev, TrustManifestEnvStaging, TrustManifestEnvProd:
		return true
	}
	return false
}

// embeddedBootstrapKeyBlob is the structural shape of one bootstrap-
// pubkey entry. The byte slice is the raw ML-DSA-65 public key
// (1952 bytes when populated; ZERO bytes pre-ceremony).
type embeddedBootstrapKeyBlob struct {
	SigningKeyID string
	PublicKey    []byte
}

// embeddedBootstrapKeys returns the bootstrap-key set for the env.
// Returns nil for unknown env. Callers should check IsValid() first.
//
// Returned slices are COPIES — caller may mutate without affecting
// other consumers. Allocating per-call is fine because manifest
// loading is a once-per-customer-session operation.
func embeddedBootstrapKeys(env TrustManifestEnv) []embeddedBootstrapKeyBlob {
	var out []embeddedBootstrapKeyBlob
	switch env {
	case TrustManifestEnvDev:
		for _, b := range bootstrapKeysDev {
			pk := make([]byte, len(b.PublicKey))
			copy(pk, b.PublicKey)
			out = append(out, embeddedBootstrapKeyBlob{SigningKeyID: b.SigningKeyID, PublicKey: pk})
		}
	case TrustManifestEnvStaging:
		for _, b := range bootstrapKeysStaging {
			pk := make([]byte, len(b.PublicKey))
			copy(pk, b.PublicKey)
			out = append(out, embeddedBootstrapKeyBlob{SigningKeyID: b.SigningKeyID, PublicKey: pk})
		}
	case TrustManifestEnvProd:
		for _, b := range bootstrapKeysProd {
			pk := make([]byte, len(b.PublicKey))
			copy(pk, b.PublicKey)
			out = append(out, embeddedBootstrapKeyBlob{SigningKeyID: b.SigningKeyID, PublicKey: pk})
		}
	}
	return out
}

// IsBootstrapPlaceholder reports whether the embedded bootstrap-key
// set for env still holds all-zero pubkey bytes (i.e. the ceremony
// hasn't run for this SDK build). Customers can use this to fail
// fast on the wrong SDK version BEFORE attempting any verify, with
// a clear "upgrade your SDK" message.
//
// # Caveat
//
// Returning false does NOT mean the keys are correct — just that
// they're non-zero. The signature verify step is the actual proof.
func IsBootstrapPlaceholder(env TrustManifestEnv) bool {
	for _, b := range embeddedBootstrapKeys(env) {
		for _, x := range b.PublicKey {
			if x != 0 {
				return false
			}
		}
	}
	return true
}

// mldsa65PubkeySize is the FIPS 204 ML-DSA-65 public-key byte
// length. Used both for placeholder slice allocation here and for
// validation when a customer-supplied trust manifest is loaded.
const mldsa65PubkeySize = 1952

// Placeholder bootstrap-key sets. Each environment ships ONE active
// bootstrap key today; the set can grow during a rotation window
// (old key + new key both valid for an overlap period). The kid
// names match the convention in `sdk_trust_manifest_bootstrap_root
// _ceremony` §1.

var bootstrapKeysDev = []embeddedBootstrapKeyBlob{
	{
		SigningKeyID: "bootstrap-trust-manifest-dev-2026-v1",
		PublicKey:    make([]byte, mldsa65PubkeySize), // PLACEHOLDER — all zeros
	},
}

var bootstrapKeysStaging = []embeddedBootstrapKeyBlob{
	{
		SigningKeyID: "bootstrap-trust-manifest-staging-2026-v1",
		PublicKey:    make([]byte, mldsa65PubkeySize), // PLACEHOLDER — all zeros
	},
}

var bootstrapKeysProd = []embeddedBootstrapKeyBlob{
	{
		SigningKeyID: "bootstrap-trust-manifest-prod-2026-v1",
		PublicKey:    make([]byte, mldsa65PubkeySize), // PLACEHOLDER — all zeros
	},
}
