// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package sarenvelope implements the customer-side Open primitive for
// Aleutian's SAR-style sealed envelopes. The wire format is what
// internal/crypto/sarenvelope.Seal produces in the proprietary tree
// and what Tier-2 Forensic-mode compliance bundles use per-row.
//
// # What's in here
//
// Open(envelopeJSON, seed) → plaintext. The full v2 wire format:
// JSON parse + version/alg checks + X-Wing decapsulation + AAD
// canonicalization + AES-256-GCM Open + constant-time fingerprint
// check. Byte-identical to the proprietary implementation, enforced
// by golden-vector cross-compat tests at the parent module.
//
// # What's not in here
//
// Seal — customers never produce sealed envelopes; the producer side
// lives in the proprietary tree. This package is intentionally
// decryption-only.
//
// # Stability
//
// The wire format (v2) is LOCKED. Any change requires bumping
// EnvelopeVersionV2 and shipping a new constant. The cross-compat
// golden vector test will fail at compile time if a hash drifts.
package sarenvelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cloudflare/circl/kem/xwing"
	"golang.org/x/crypto/hkdf"
)

// Wire-format constants. Open requires exactly these values; the
// proprietary Seal emits exactly these values.
const (
	EnvelopeVersionV2 = 2
	KEMAlgorithmXWing = "xwing"
	AEADAES256GCM     = "aes-256-gcm"

	// SARReasonSealInfoV2 is the HKDF `info` string used by both
	// sides. Bound to the envelope version.
	SARReasonSealInfoV2 = "aleutian.sar.reason.v2"

	// XWingPubkeySize is the canonical 1216-byte X-Wing public key
	// (1184 ML-KEM-768 + 32 X25519).
	XWingPubkeySize = 1216

	// XWingSeedSize is the 32-byte X-Wing seed.
	XWingSeedSize = 32

	// FingerprintHexLen is the canonical Aleutian fingerprint width
	// (32 lowercase hex chars = 16 bytes of SHA-512(canonical pubkey
	// bytes) = 128 bits of collision resistance).
	FingerprintHexLen = 32

	// aesKeySize is 32 bytes for AES-256.
	aesKeySize = 32

	// gcmNonceSize is the standard 12-byte GCM nonce.
	gcmNonceSize = 12

	// maxCiphertextBytes is the wire-side ciphertext cap. Matches the
	// proprietary side's 32 KiB ceiling — absurd envelopes fail fast
	// pre-AEAD.
	maxCiphertextBytes = 32 * 1024

	// maxReasonBytes mirrors the proprietary side's 4 KiB plaintext
	// cap. Seal rejects payloads larger than this; Open accepts the
	// full maxCiphertextBytes window (GCM tag adds 16 bytes).
	maxReasonBytes = 4 * 1024
)

// Sentinel errors. Open collapses all decryption-time failure modes
// to ErrDecryptFailed so a caller cannot distinguish "wrong key"
// from "tampered ciphertext" via the error return.
//
// These wrap the same semantics as the proprietary sarenvelope
// package's sentinels; the wire-format text differs ("sdk-sarenvelope:"
// vs "sarenvelope:") so a caller can distinguish which implementation
// produced the error, but the errors.Is dispatch behaves identically.
var (
	ErrInvalidEnvelope    = errors.New("sdk-sarenvelope: invalid envelope")
	ErrUnsupportedVersion = errors.New("sdk-sarenvelope: unsupported envelope_version (only 2 is supported)")
	ErrUnsupportedAlg     = errors.New("sdk-sarenvelope: unsupported kem_algorithm (only \"xwing\" is supported)")
	ErrUnsupportedAEAD    = errors.New("sdk-sarenvelope: unsupported aead (only \"aes-256-gcm\" is supported)")
	ErrInvalidPubkeySize  = errors.New("sdk-sarenvelope: invalid xwing public key size")
	ErrInvalidPrivkeySize = errors.New("sdk-sarenvelope: invalid xwing seed size (must be 32 bytes)")
	ErrInvalidFingerprint = errors.New("sdk-sarenvelope: fingerprint is not a valid 32-char lowercase hex string")
	ErrDecryptFailed      = errors.New("sdk-sarenvelope: decrypt failed")
	ErrReasonTooLong      = fmt.Errorf("sdk-sarenvelope: reason exceeds %d-byte cap", maxReasonBytes)
)

// AssociatedData is the metadata block authenticated (but not
// encrypted) by AES-GCM. Field order is the canonical AAD order —
// encoding/json serializes struct fields in declaration order, so
// this is the canonicalization.
type AssociatedData struct {
	CompanyID  string `json:"company_id"`
	RequestID  string `json:"request_id"`
	SealedAtMs int64  `json:"sealed_at_ms"`
}

// SealInput bundles the inputs to Seal so the call site can't
// transpose CompanyID and RequestID. Mirrors the proprietary
// internal/crypto/sarenvelope.SealInput byte-for-byte at the wire.
type SealInput struct {
	// RecipientPubkey is the raw 1216-byte X-Wing public key.
	RecipientPubkey []byte
	// Reason is the cleartext payload (bounded to maxReasonBytes
	// = 4 KiB).
	Reason []byte
	// AD is the metadata block authenticated via AEAD AAD.
	AD AssociatedData
}

// envelopeWire is the on-wire JSON shape. Field order matches the
// proprietary side's declared order.
type envelopeWire struct {
	EnvelopeVersion      int            `json:"envelope_version"`
	KEMAlgorithm         string         `json:"kem_algorithm"`
	RecipientFingerprint string         `json:"recipient_fingerprint"`
	KEMCiphertextB64     string         `json:"kem_ciphertext_b64"`
	AEAD                 string         `json:"aead"`
	NonceB64             string         `json:"nonce_b64"`
	CiphertextB64        string         `json:"ciphertext_b64"`
	AssociatedData       AssociatedData `json:"associated_data"`
}

// Seal produces a sarenvelope-v2 wire blob targeting
// input.RecipientPubkey.
//
// # Description
//
// Byte-identical output to the proprietary
// internal/crypto/sarenvelope.Seal when given the same inputs. The
// cross-compat golden vector test at
// AleutianEnterprise/test/cross_compat/ enforces the contract: any
// drift between the two implementations breaks CI.
//
// Pipeline mirrors the proprietary side:
//
//  1. Validate input.RecipientPubkey is 1216 bytes.
//  2. Validate input.Reason ≤ 4 KiB.
//  3. Reject '|' in input.AD.RequestID (HKDF salt ambiguity guard;
//     see proprietary docs).
//  4. X-Wing encapsulate to recipient pubkey → KEM ciphertext +
//     shared secret.
//  5. Compute fingerprint of recipient pubkey.
//  6. HKDF-SHA-512 derive AES-256 key with salt =
//     fpRawBytes || '|' || RequestID, info = SARReasonSealInfoV2.
//  7. AES-256-GCM seal Reason with AAD = canonical JSON of AD.
//  8. Emit JSON envelope per the v2 wire shape.
//
// # Inputs
//
//   - input: SealInput with all three fields populated. RecipientPubkey
//     MUST be exactly 1216 bytes; Reason MUST be ≤ 4 KiB.
//
// # Outputs
//
//   - []byte: JSON envelope bytes (one envelope, ready to write to disk
//     or stuff into a manifest field)
//   - error: ErrInvalidPubkeySize / ErrReasonTooLong / wrapped error
//     from crypto/rand or the underlying primitives
//
// # Limitations
//
//   - Reason cap is 4 KiB. Larger payloads must be sealed under a
//     different mode (proprietary Tier-2 Standard mode uses a bundle-
//     level CEK; not in this package).
//   - RequestID must not contain '|' — rejected explicitly so two
//     distinct submissions can't accidentally derive the same AEAD
//     key via salt ambiguity.
//
// # Thread Safety
//
// Pure function; safe for concurrent use.
func Seal(input SealInput) ([]byte, error) {
	return sealWithRand(input, rand.Reader)
}

// sealWithRand is the internal Seal entry point with an injectable
// RNG for deterministic test vectors. Production callers go through
// Seal (which passes rand.Reader).
func sealWithRand(input SealInput, randReader io.Reader) ([]byte, error) {
	if len(input.RecipientPubkey) != XWingPubkeySize {
		return nil, fmt.Errorf("%w: got %d, want %d",
			ErrInvalidPubkeySize, len(input.RecipientPubkey), XWingPubkeySize)
	}
	if len(input.Reason) > maxReasonBytes {
		return nil, ErrReasonTooLong
	}
	if strings.ContainsRune(input.AD.RequestID, '|') {
		return nil, fmt.Errorf("sdk-sarenvelope: request_id must not contain '|'")
	}

	scheme := xwing.Scheme()
	pub, err := scheme.UnmarshalBinaryPublicKey(input.RecipientPubkey)
	if err != nil {
		return nil, fmt.Errorf("sdk-sarenvelope: unmarshal pubkey: %w", err)
	}
	fp, err := Fingerprint(input.RecipientPubkey)
	if err != nil {
		return nil, fmt.Errorf("sdk-sarenvelope: fingerprint: %w", err)
	}

	// xwing.Scheme().Encapsulate draws randomness internally. For
	// deterministic vectors we use EncapsulateDeterministically keyed
	// by `randReader`.
	var kemCT, ss []byte
	if randReader == rand.Reader {
		kemCT, ss, err = scheme.Encapsulate(pub)
	} else {
		seed := make([]byte, scheme.EncapsulationSeedSize())
		if _, rerr := io.ReadFull(randReader, seed); rerr != nil {
			return nil, fmt.Errorf("sdk-sarenvelope: read encap seed: %w", rerr)
		}
		kemCT, ss, err = scheme.EncapsulateDeterministically(pub, seed)
	}
	if err != nil {
		return nil, fmt.Errorf("sdk-sarenvelope: encapsulate: %w", err)
	}
	defer zeroize(ss)

	aeadKey, err := deriveAEADKey(ss, fp, input.AD.RequestID)
	if err != nil {
		return nil, err
	}
	defer zeroize(aeadKey)

	aad, err := canonicalAAD(input.AD)
	if err != nil {
		return nil, fmt.Errorf("sdk-sarenvelope: marshal aad: %w", err)
	}

	nonce := make([]byte, gcmNonceSize)
	if _, rerr := io.ReadFull(randReader, nonce); rerr != nil {
		return nil, fmt.Errorf("sdk-sarenvelope: read nonce: %w", rerr)
	}

	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, fmt.Errorf("sdk-sarenvelope: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sdk-sarenvelope: gcm: %w", err)
	}
	ct := gcm.Seal(nil, nonce, input.Reason, aad)

	wire := envelopeWire{
		EnvelopeVersion:      EnvelopeVersionV2,
		KEMAlgorithm:         KEMAlgorithmXWing,
		RecipientFingerprint: fp,
		KEMCiphertextB64:     base64.StdEncoding.EncodeToString(kemCT),
		AEAD:                 AEADAES256GCM,
		NonceB64:             base64.StdEncoding.EncodeToString(nonce),
		CiphertextB64:        base64.StdEncoding.EncodeToString(ct),
		AssociatedData:       input.AD,
	}
	return json.Marshal(wire)
}

// Open decrypts a sarenvelope-v2 wire blob under the supplied 32-byte
// X-Wing seed.
//
// # Description
//
// Pipeline:
//
//  1. Validate seed size (32 bytes).
//  2. JSON-decode the envelope with DisallowUnknownFields.
//  3. Reject non-v2 / non-xwing / non-aes-256-gcm wire values.
//  4. Base64-decode KEM ciphertext / nonce / ciphertext; check sizes.
//  5. Derive the X-Wing pubkey from the seed and compute its
//     fingerprint.
//  6. X-Wing decapsulate to recover the shared secret.
//  7. HKDF-SHA-512 derive the AEAD key with salt =
//     fingerprintRawBytes || '|' || requestID and info =
//     SARReasonSealInfoV2.
//  8. AES-256-GCM Open with AAD = canonical JSON of AssociatedData.
//  9. Verify the envelope's stated recipient fingerprint matches the
//     seed's derived fingerprint in constant time. AEAD success +
//     fingerprint match are required jointly for a non-error return.
//
// # Inputs
//
//   - envelopeJSON: raw wire bytes (one envelope file from
//     tier2/sealed_envelopes/<row>_<fp>.bin)
//   - seed: 32-byte X-Wing seed
//
// # Outputs
//
//   - []byte: recovered plaintext payload
//   - error: ErrInvalidPrivkeySize on bad seed size; ErrInvalidEnvelope /
//     ErrUnsupportedVersion / ErrUnsupportedAlg / ErrUnsupportedAEAD
//     on structural failures; ErrDecryptFailed for any AEAD or
//     fingerprint failure (collapsed to deny oracle attacks).
func Open(envelopeJSON []byte, seed []byte) ([]byte, error) {
	if len(seed) != XWingSeedSize {
		return nil, ErrInvalidPrivkeySize
	}

	var wire envelopeWire
	dec := json.NewDecoder(bytes.NewReader(envelopeJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if wire.EnvelopeVersion != EnvelopeVersionV2 {
		return nil, ErrUnsupportedVersion
	}
	if wire.KEMAlgorithm != KEMAlgorithmXWing {
		return nil, ErrUnsupportedAlg
	}
	if wire.AEAD != AEADAES256GCM {
		return nil, ErrUnsupportedAEAD
	}

	kemCT, err := base64.StdEncoding.DecodeString(wire.KEMCiphertextB64)
	if err != nil {
		return nil, fmt.Errorf("%w: kem_ciphertext_b64: %v", ErrInvalidEnvelope, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(wire.NonceB64)
	if err != nil {
		return nil, fmt.Errorf("%w: nonce_b64: %v", ErrInvalidEnvelope, err)
	}
	if len(nonce) != gcmNonceSize {
		return nil, fmt.Errorf("%w: nonce must be %d bytes", ErrInvalidEnvelope, gcmNonceSize)
	}
	ct, err := base64.StdEncoding.DecodeString(wire.CiphertextB64)
	if err != nil {
		return nil, fmt.Errorf("%w: ciphertext_b64: %v", ErrInvalidEnvelope, err)
	}
	if len(ct) > maxCiphertextBytes {
		return nil, fmt.Errorf("%w: ciphertext exceeds %d-byte cap", ErrInvalidEnvelope, maxCiphertextBytes)
	}

	scheme := xwing.Scheme()
	pub, priv := scheme.DeriveKeyPair(seed)

	rawPub, err := pub.MarshalBinary()
	if err != nil {
		return nil, ErrDecryptFailed
	}
	gotFP, err := Fingerprint(rawPub)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	fpOK := subtle.ConstantTimeCompare([]byte(gotFP), []byte(wire.RecipientFingerprint)) == 1

	ss, err := scheme.Decapsulate(priv, kemCT)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	defer zeroize(ss)

	aeadKey, err := deriveAEADKey(ss, wire.RecipientFingerprint, wire.AssociatedData.RequestID)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	defer zeroize(aeadKey)

	aad, err := canonicalAAD(wire.AssociatedData)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	plain, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil || !fpOK {
		return nil, ErrDecryptFailed
	}
	return plain, nil
}

// Fingerprint computes the canonical Aleutian 32-char lowercase-hex
// fingerprint of a raw 1216-byte X-Wing public key:
// SHA-512(pubkey)[:16] → hex.
//
// # Inputs
//
//   - pubkey: raw 1216-byte X-Wing public key
//
// # Outputs
//
//   - string: 32-char lowercase hex
//   - error: ErrInvalidPubkeySize if pubkey is not exactly 1216 bytes
func Fingerprint(pubkey []byte) (string, error) {
	if len(pubkey) != XWingPubkeySize {
		return "", ErrInvalidPubkeySize
	}
	h := sha512.Sum512(pubkey)
	return hex.EncodeToString(h[:FingerprintHexLen/2]), nil
}

// deriveAEADKey HKDF-SHA-512 derives the AES-256-GCM key. Salt is
// raw fingerprint bytes || '|' || requestID; info is the locked
// SARReasonSealInfoV2 constant. Matches the proprietary side
// byte-for-byte.
func deriveAEADKey(ss []byte, fingerprint, requestID string) ([]byte, error) {
	fpRaw, err := hex.DecodeString(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("sdk-sarenvelope: decode fingerprint hex: %w", err)
	}
	if len(fpRaw) != FingerprintHexLen/2 {
		return nil, fmt.Errorf("sdk-sarenvelope: fingerprint decoded to %d bytes, want %d: %w",
			len(fpRaw), FingerprintHexLen/2, ErrInvalidFingerprint)
	}

	salt := make([]byte, 0, len(fpRaw)+1+len(requestID))
	salt = append(salt, fpRaw...)
	salt = append(salt, '|')
	salt = append(salt, requestID...)

	r := hkdf.New(sha512.New, ss, salt, []byte(SARReasonSealInfoV2))
	key := make([]byte, aesKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("sdk-sarenvelope: hkdf: %w", err)
	}
	return key, nil
}

// canonicalAAD returns the deterministic JSON encoding of ad.
// encoding/json serializes fields in declaration order, so the
// AssociatedData struct definition above IS the canonicalization.
func canonicalAAD(ad AssociatedData) ([]byte, error) {
	return json.Marshal(ad)
}

// zeroize wipes a byte slice in place. Best-effort; defer-invoked
// usage keeps the slice alive across the wipe so the compiler cannot
// elide it.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
