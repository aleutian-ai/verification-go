// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// MLDSAPubKeySize is the size in bytes of a raw ML-DSA-65 public key (FIPS 204).
// Verified at startup by init() against mldsa65.Scheme().PublicKeySize().
const MLDSAPubKeySize = 1952

func init() {
	scheme := mldsa65.Scheme()
	if MLDSAPubKeySize != scheme.PublicKeySize() {
		panic(fmt.Sprintf("MLDSAPubKeySize constant mismatch: constant=%d circl=%d",
			MLDSAPubKeySize, scheme.PublicKeySize()))
	}
}

// subjectPublicKeyInfo mirrors the ASN.1 SubjectPublicKeyInfo structure used
// by Cloud KMS when returning ML-DSA-65 public keys.
type subjectPublicKeyInfo struct {
	Algorithm struct {
		OID        asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	PublicKey asn1.BitString
}

// =============================================================================
// Embedded Public Keys (SC-2: mutex-protected, unexported map)
// =============================================================================
//
// # Pinning strategy (15n_fix_A4, 2026-05-17)
//
// The embedded anchor-signing keys are loaded from build-tag-gated JSON
// fixtures under fixtures/embedded-keys-{dev,staging,prod}.json. Selection
// is at build time via the same build tags as the trust-root pubkey:
//
//   default build       → fixtures/embedded-keys-dev.json     (dev)
//   -tags=trust_staging → fixtures/embedded-keys-staging.json (staging)
//   -tags=trust_prod    → fixtures/embedded-keys-prod.json    (prod)
//
// See keys_dev.go, keys_staging.go, keys_prod.go.

// embeddedKeysMu guards all access to embeddedPublicKeys.
// SC-2: Use RWMutex so concurrent reads (GetPublicKey, ListKeyIDs) don't block.
var embeddedKeysMu sync.RWMutex

// embeddedPublicKeys stores raw 1952-byte ML-DSA-65 public keys keyed by ID.
// SC-2: Unexported to prevent unsynchronized external mutation. Use the
// accessor functions GetPublicKey, AddPublicKey, ListKeyIDs, IsKnownKey.
//
// Initialized by the env-specific init() in keys_{dev,staging,prod}.go.
var embeddedPublicKeys = map[string][]byte{}

// loadKeysFromFixture parses the per-env JSON fixture and populates
// embeddedPublicKeys. Called from the env-specific init() in
// keys_{dev,staging,prod}.go. Panics on malformed fixture (caught by
// Go's package-init machinery before main() runs).
func loadKeysFromFixture(env string, fixtureBytes []byte) {
	var byID map[string]string
	if err := json.Unmarshal(fixtureBytes, &byID); err != nil {
		panic(fmt.Sprintf("verification-go: fixtures/embedded-keys-%s.json invalid JSON: %v", env, err))
	}
	for id, b64 := range byID {
		raw := mustDecodeKey(b64)
		embeddedPublicKeys[id] = raw
	}
}

// PublicKeysEndpoint is the URL for fetching current public keys.
//
// # Description
//
// Use this endpoint to check for key revocations or fetch keys not included
// in the embedded set. The response is a JSON object mapping key IDs to
// base64-encoded SPKI public keys.
//
// # Security Considerations
//
// This endpoint should only be used when online verification is acceptable.
// For fully offline verification, use the embedded keys via [GetPublicKey].
const PublicKeysEndpoint = "https://keys.aleutian.ai/.well-known/anchor-signing-keys.json"

// =============================================================================
// Key Retrieval Functions
// =============================================================================

// GetPublicKey returns an embedded raw ML-DSA-65 public key by ID.
//
// # Description
//
// Looks up a public key from the embedded key set by its key ID. This is
// typically called during anchor verification to find the signing key.
//
// AQ-4: Returns a defensive copy of the key bytes to prevent callers from
// mutating the embedded key map.
//
// # Inputs
//
//   - keyID: The key identifier from anchor.SigningKeyID
//
// # Outputs
//
//   - []byte: A copy of the raw 1952-byte ML-DSA-65 public key
//   - error: ErrUnknownKeyID if key not found
//
// # Example
//
//	key, err := GetPublicKey("aleutian-ml-dsa-65-2026-v1")
//	if err != nil {
//	    return fmt.Errorf("get key: %w", err)
//	}
//
// # Limitations
//
//   - Only returns keys embedded at build time or added via AddPublicKey
//   - Cannot check for key revocation without network access
func GetPublicKey(keyID string) ([]byte, error) {
	embeddedKeysMu.RLock()
	key, ok := embeddedPublicKeys[keyID]
	embeddedKeysMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKeyID, keyID)
	}

	// AQ-4: Return a defensive copy to prevent mutation of the internal map.
	out := make([]byte, len(key))
	copy(out, key)
	return out, nil
}

// IsKnownKey reports whether the key ID is present in the embedded key set.
//
// # Inputs
//
//   - keyID: The key identifier to check
//
// # Outputs
//
//   - bool: True if the key ID is known
func IsKnownKey(keyID string) bool {
	embeddedKeysMu.RLock()
	_, ok := embeddedPublicKeys[keyID]
	embeddedKeysMu.RUnlock()
	return ok
}

// ListKeyIDs returns a sorted list of all known key IDs.
//
// # Outputs
//
//   - []string: Sorted slice of key IDs currently in the embedded set
func ListKeyIDs() []string {
	embeddedKeysMu.RLock()
	ids := make([]string, 0, len(embeddedPublicKeys))
	for id := range embeddedPublicKeys {
		ids = append(ids, id)
	}
	embeddedKeysMu.RUnlock()

	// Sort for deterministic output without holding the lock.
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	return ids
}

// AddPublicKey adds a raw ML-DSA-65 public key to the embedded set.
//
// # Description
//
// Allows runtime addition of public keys for testing or when keys are
// fetched from [PublicKeysEndpoint]. Added keys persist for the lifetime
// of the process.
//
// # Inputs
//
//   - keyID: The key identifier
//   - publicKey: The raw 1952-byte ML-DSA-65 public key
//
// # Outputs
//
//   - error: Non-nil if publicKey is not 1952 bytes
//
// # Security Considerations
//
// Only add keys from trusted sources. Added keys are used for signature
// verification and could allow forged anchors if compromised.
//
// # Example
//
//	// Fetch and add a key from the keys endpoint
//	key, _ := fetchKeyFromEndpoint("aleutian-ml-dsa-65-2027-v1")
//	if err := AddPublicKey("aleutian-ml-dsa-65-2027-v1", key); err != nil {
//	    log.Fatalf("add key: %v", err)
//	}
func AddPublicKey(keyID string, publicKey []byte) error {
	if len(publicKey) != MLDSAPubKeySize {
		return fmt.Errorf("invalid public key size: got %d, want %d", len(publicKey), MLDSAPubKeySize)
	}
	// Store a copy to prevent the caller mutating the stored key.
	stored := make([]byte, len(publicKey))
	copy(stored, publicKey)

	embeddedKeysMu.Lock()
	embeddedPublicKeys[keyID] = stored
	embeddedKeysMu.Unlock()
	return nil
}

// RemovePublicKey removes a key from the embedded set by ID.
//
// # Description
//
// Removes a previously added key. Primarily intended for test cleanup
// so that test-added ephemeral keys do not pollute the embedded key set
// across test runs in the same process. No-op if the key is not present.
//
// # Inputs
//
//   - keyID: The key identifier to remove
func RemovePublicKey(keyID string) {
	embeddedKeysMu.Lock()
	delete(embeddedPublicKeys, keyID)
	embeddedKeysMu.Unlock()
}

// ValidateEmbeddedKeys checks that no embedded key is an all-zero placeholder.
//
// # Description
//
// SC-1: Production deployments MUST call this function at startup and handle
// the returned error (e.g., fail fast before serving traffic). The embedded
// keys in this SDK release are development placeholders and MUST be replaced
// with real keys before production use.
//
// # Outputs
//
//   - error: Non-nil if any embedded key consists entirely of zero bytes
//
// # Example
//
//	if err := verification.ValidateEmbeddedKeys(); err != nil {
//	    log.Fatalf("embedded keys not set for production: %v", err)
//	}
func ValidateEmbeddedKeys() error {
	embeddedKeysMu.RLock()
	defer embeddedKeysMu.RUnlock()

	for id, key := range embeddedPublicKeys {
		allZero := true
		for _, b := range key {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return fmt.Errorf(
				"embedded key %q is a development placeholder (all-zero bytes); "+
					"replace with a real ML-DSA-65 public key before production use", id,
			)
		}
	}
	return nil
}

// mustDecodeKey decodes a base64-encoded SPKI DER ML-DSA-65 public key and
// extracts the raw 1952-byte key bytes.
// Panics on invalid input (only used for compile-time embedded keys).
func mustDecodeKey(base64Key string) []byte {
	der, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		panic(fmt.Sprintf("invalid embedded key base64: %v", err))
	}
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		panic(fmt.Sprintf("invalid embedded key SPKI DER: %v", err))
	}
	raw := spki.PublicKey.Bytes
	if len(raw) != MLDSAPubKeySize {
		panic(fmt.Sprintf("embedded key wrong size: got %d bytes, want %d", len(raw), MLDSAPubKeySize))
	}
	return raw
}
