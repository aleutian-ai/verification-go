// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
)

// HashTemplate returns the lowercase hex SHA-512 digest of
// (ConsentTextHashPrefix || b).
//
// # Description
//
// Mirrors internal/consent.HashTemplate exactly. Used by external callers to
// independently verify a chain entry's consent_template_hash against a
// template they fetched from docs.aleutian.ai. The resulting 128-character
// lowercase hex string is byte-identical to the value the server stored at
// grant time.
//
// # Inputs
//
//   - b: raw template bytes — the SDK does NOT normalize; canonicalization
//     (NFC, LF line endings, etc.) is the server's responsibility at
//     template load time
//
// # Outputs
//
//   - string: 128 lowercase hex characters (SHA-512 output)
//
// # Example
//
//	tplBytes, _ := os.ReadFile("docs-aleutian-ai-consent-v1.txt")
//	h := verification.HashTemplate(tplBytes)
//	if h != entry.ConsentTemplateHash {
//	    return fmt.Errorf("template drift")
//	}
//
// # Limitations
//
//   - Does not normalize input bytes; caller must pass exactly the bytes the
//     server hashed
//
// # Assumptions
//
//   - ConsentTextHashPrefix is stable (locked by the v2 schema)
func HashTemplate(b []byte) string {
	h := sha512.New()
	h.Write([]byte(ConsentTextHashPrefix))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// HashRendered returns the lowercase hex HMAC-SHA512 digest of
// (ConsentRenderedHashPrefix || b), keyed with tenantPepper.
//
// # Description
//
// Mirrors internal/consent.NewKeyedRenderedHasher(tenantPepper).Hash(b)
// exactly. Used by external callers to independently verify a chain entry's
// consent_rendered_hash against the exact bytes they saw at grant time
// (returned by GET /v1/consent/text).
//
// BREAKING CHANGE (consent_rendered_hash epic): prior releases computed
// unkeyed SHA-512, which has never matched server output — the server has
// HMAC-keyed this hash since 2026-04-16 (18_20_review_01). There is no
// unkeyed variant to fall back to; a caller must obtain tenantPepper via the
// consent-pepper reveal endpoint
// (POST /v1/internal/consent/rendered-pepper/reveal, consent_rendered_hash_04)
// before this function can produce a value that verifies anything.
//
// Domain-separated from HashTemplate via the distinct prefix
// ConsentRenderedHashPrefix ("aleutian.consent.rendered.v2:") so that
// HashTemplate(b) != HashRendered(b, p) for any input b and any key p. This
// prevents a cross-protocol confusion attack where a rendered blob is
// replayed as a template body (18_20 review finding B4).
//
// # Inputs
//
//   - b: raw rendered bytes — the exact body returned by GET /v1/consent/text
//   - tenantPepper: the tenant's revealed consent-rendered-hash sub-key
//     (consent_rendered_hash_04). Must be the exact bytes the reveal endpoint
//     returned; any other value produces a digest that does not match the
//     server's stored consent_rendered_hash.
//
// # Outputs
//
//   - string: 128 lowercase hex characters (HMAC-SHA512 output)
//
// # Example
//
//	body := fetchRenderedConsentBody(customerID)
//	pepper, _ := hex.DecodeString(revealedPepperHex)
//	h := verification.HashRendered(body, pepper)
//	if h != entry.ConsentRenderedHash {
//	    return fmt.Errorf("rendered body drift — do not sign")
//	}
//
// # Limitations
//
//   - Does not normalize input bytes; caller must pass exactly the bytes the
//     server hashed
//   - Independently verifiable ONLY with the tenant's revealed pepper — not
//     from the public bytes alone. This is deliberate: it is the fix for the
//     rainbow-table oracle an unkeyed hash of PII-adjacent bytes created.
//
// # Assumptions
//
//   - ConsentRenderedHashPrefix is stable (locked by the v2 schema)
func HashRendered(b []byte, tenantPepper []byte) string {
	mac := hmac.New(sha512.New, tenantPepper)
	mac.Write([]byte(ConsentRenderedHashPrefix))
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil))
}
