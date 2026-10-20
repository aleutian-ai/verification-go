// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

// V2DeprecationWarning is the locked WARNING string the SDK CLI emits
// when verifying a bundle whose manifest.format_version is 2.
//
// # Description
//
// Per compliance_bundle_format_spec.md (CV-02 amendment), v2 bundles
// (no framework_version pinned) are accepted-with-warning by SDK
// verifiers. Producers emit v3 only. v2 has no real installed base
// pre-launch but may exist in internal/staging archives during
// rollout.
//
// All three SDKs (Go, Python, JS) MUST emit byte-identical warning
// text for cross-language byte-identity (CV-09 contract). The
// SUPPORTED_BUNDLE_VERSIONS check itself lives in the bundle
// verifier; this constant + helper just lock the output string.
const V2DeprecationWarning = "WARNING: format_version=2 bundle does not pin framework_version. Step-9 self-attestation cross-check unavailable. Producer should re-emit at format_version=3."

// FormatV2DeprecationWarning returns the v2 deprecation warning when
// formatVersion is 2, empty string otherwise.
//
// # Description
//
// Verifier flow (illustrative, lives in the future bundle verifier):
//
//	if warning := frameworks.FormatV2DeprecationWarning(manifest.FormatVersion); warning != "" {
//	    fmt.Fprintln(stderr, warning)
//	    // skip step 9 — no framework_version to cross-check
//	} else {
//	    fwk, err := frameworks.LoadFrameworkFromBundle(bundleFS, manifest.FrameworkVersion)
//	    ...
//	}
//
// # Inputs
//
//   - formatVersion: the manifest's format_version int.
//
// # Outputs
//
//   - string: V2DeprecationWarning when formatVersion == 2; "" otherwise.
//     Bare empty string (not "OK", not a positive message) so the caller
//     can treat it as the conventional "no warning to emit" signal.
func FormatV2DeprecationWarning(formatVersion int) string {
	if formatVersion == 2 {
		return V2DeprecationWarning
	}
	return ""
}
