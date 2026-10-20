// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"encoding/base64"
	"encoding/json"
	"fmt"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Bundle-verify constants. Mirrors the producer-side layout.
const (
	bundleSignaturePath = "signature.bin"
	trustManifestPath   = "trust_manifest/manifest.json"
	mlDSA65SigSize      = 3309
	mlDSA65PubKeySize   = 1952
	algMLDSA65          = "ML-DSA-65"
)

// trustManifestEntry mirrors the subset of
// compliance.TrustManifestEntry the CLI needs.
type trustManifestEntry struct {
	KeyID        string `json:"key_id"`
	PublicKeyB64 string `json:"public_key_b64"`
	Algorithm    string `json:"algorithm"`
	RevokedAtMs  *int64 `json:"revoked_at_ms"`
}

// trustManifest mirrors the subset of compliance.TrustManifest the
// CLI needs. The root_signature_b64 verification against a pinned
// root is deferred to a follow-up (same posture as the proprietary
// build's Phase B first cut — bundle sig verify is the load-bearing
// integrity check).
type trustManifest struct {
	Version          int64                `json:"version"`
	GeneratedAtMs    int64                `json:"generated_at_ms"`
	Env              string               `json:"env"`
	PlatformKeys     []trustManifestEntry `json:"platform_keys"`
	TenantKeys       []trustManifestEntry `json:"tenant_keys"`
	RootSignatureB64 string               `json:"root_signature_b64"`
}

// VerifyBundleSignature reads signature.bin + the trust manifest,
// resolves the signing key by manifest.signing_key_id, and verifies
// the ML-DSA-65 signature over the raw canonical manifest bytes.
// Pipeline matches the proprietary build verbatim.
func VerifyBundleSignature(zr *zip.Reader, signingKeyID string, manifestBytes []byte) error {
	if signingKeyID == "" {
		return fmt.Errorf("%w: manifest.signing_key_id is empty", ErrStructural)
	}
	if len(manifestBytes) == 0 {
		return fmt.Errorf("%w: manifestBytes is empty", ErrStructural)
	}

	sigBytes, err := readZipFile(zr, bundleSignaturePath)
	if err != nil {
		return fmt.Errorf("%w: read %s: %v", ErrStructural, bundleSignaturePath, err)
	}
	if len(sigBytes) != mlDSA65SigSize {
		return fmt.Errorf("%w: %s is %d bytes, expected %d (ML-DSA-65)",
			ErrStructural, bundleSignaturePath, len(sigBytes), mlDSA65SigSize)
	}

	tmBytes, err := readZipFile(zr, trustManifestPath)
	if err != nil {
		return fmt.Errorf("%w: read %s: %v", ErrStructural, trustManifestPath, err)
	}
	var tm trustManifest
	if err := json.Unmarshal(tmBytes, &tm); err != nil {
		return fmt.Errorf("%w: parse trust manifest: %v", ErrStructural, err)
	}

	if err := VerifyTrustManifestRoot(tmBytes, tm.RootSignatureB64); err != nil {
		return err
	}

	pubBytes, perr := resolveSigningPubkey(tm, signingKeyID)
	if perr != nil {
		return fmt.Errorf("%w: %v", ErrStructural, perr)
	}

	scheme := mldsa65.Scheme()
	pub, err := scheme.UnmarshalBinaryPublicKey(pubBytes)
	if err != nil {
		return fmt.Errorf("%w: parse signing key %q: %v", ErrStructural, signingKeyID, err)
	}
	if !scheme.Verify(pub, manifestBytes, sigBytes, nil) {
		return fmt.Errorf("%w: bundle signature verification failed for key %q",
			ErrStructural, signingKeyID)
	}
	return nil
}

// resolveSigningPubkey walks the trust manifest's platform + tenant
// keys for an entry matching keyID.
func resolveSigningPubkey(tm trustManifest, keyID string) ([]byte, error) {
	for _, group := range [][]trustManifestEntry{tm.PlatformKeys, tm.TenantKeys} {
		for _, e := range group {
			if e.KeyID != keyID {
				continue
			}
			if e.RevokedAtMs != nil && *e.RevokedAtMs > 0 {
				return nil, fmt.Errorf("signing key %q is revoked", keyID)
			}
			if e.Algorithm != algMLDSA65 {
				return nil, fmt.Errorf("signing key %q algorithm=%q, expected %q",
					keyID, e.Algorithm, algMLDSA65)
			}
			pub, err := base64.StdEncoding.DecodeString(e.PublicKeyB64)
			if err != nil {
				return nil, fmt.Errorf("decode public_key_b64 for %q: %v", keyID, err)
			}
			if len(pub) != mlDSA65PubKeySize {
				return nil, fmt.Errorf("signing key %q is %d bytes, expected %d",
					keyID, len(pub), mlDSA65PubKeySize)
			}
			return pub, nil
		}
	}
	return nil, fmt.Errorf("signing key %q not found in trust manifest", keyID)
}
