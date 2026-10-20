// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package seedwrap provides at-rest passphrase wrap/unwrap for
// long-lived PQC seed material — typically an X-Wing private-key PEM
// that a customer holds for opening Tier-2 disclosure bundles.
//
// # Threat model
//
// The seed is already at-rest-encrypted by whichever store the holder
// chose (macOS Keychain item encrypted under login password; 1Password
// vault encrypted under account password + Secret Key; or filesystem
// with 0600 perms). Passphrase wrap adds a second factor: even if the
// store is compromised (laptop seized with Keychain unlocked, 1Password
// session-token exfil, filesystem snapshot), the seed remains unusable
// without the passphrase.
//
// This is NOT a replacement for the store's at-rest encryption. It is
// an additional layer that holders with stricter custody requirements
// can opt into.
//
// # Wire format
//
//	PEM block type: "ALEUTIAN PASSPHRASE-WRAPPED PRIVATE KEY"
//	PEM body (binary, then base64 inside the PEM):
//	  magic           "ASW1"               (4 bytes)
//	  kdf_memory      uint32 (big-endian)  (4 bytes)
//	  kdf_iterations  uint32 (big-endian)  (4 bytes)
//	  kdf_parallelism uint8                (1 byte)
//	  salt            16 bytes random
//	  nonce           12 bytes random      (AES-GCM)
//	  ciphertext+tag  variable
//
// Plaintext is the raw inner PEM (xwingkeyfile private-key block), so
// Unwrap returns bytes that go directly into
// `xwingkeyfile.UnmarshalPrivateKey`.
//
// # Why custom envelope vs. `age`?
//
// The single-recipient passphrase use case is narrow enough that
// `age`'s recipient flexibility isn't load-bearing here, and
// `golang.org/x/crypto/argon2` is already a transitive SDK dep so
// the envelope adds zero new dependencies. If multi-recipient or
// interop with `age` tooling is later needed, swap with care — the
// wire format above is small, documented, and locked.
package seedwrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// PEMBlockType is the PEM block type used for wrapped seeds. Distinct
// from `xwingkeyfile.PEMTypePrivateKey` so a quick `head -1 *.priv`
// tells the operator whether the file is passphrase-protected.
const PEMBlockType = "ALEUTIAN PASSPHRASE-WRAPPED PRIVATE KEY"

// Magic identifies the wire format. Bump on incompatible changes.
var Magic = [4]byte{'A', 'S', 'W', '1'}

// KDF parameters. Above OWASP 2024 baseline (47 MiB / 1 iter); this is
// once-per-rotation at keygen + once-per-decrypt at sar-decrypt, both
// interactive — operators can afford ~500ms cost per invocation in
// exchange for stronger resistance to offline passphrase cracking.
const (
	argon2Memory      uint32 = 64 * 1024 // 64 MiB in KiB
	argon2Iterations  uint32 = 3
	argon2Parallelism uint8  = 1
	keyLen            uint32 = 32 // AES-256
	saltLen           int    = 16
	nonceLen          int    = 12
)

// MinPassphraseLen is the minimum passphrase length accepted by Wrap.
// 8 chars is a UX-vs-security compromise: NIST SP 800-63B 5.1.1.2
// requires ≥8 for memorized secrets. Operators with stricter policies
// can wrap their own validation around Wrap.
const MinPassphraseLen = 8

// Sentinel errors. Callers should use errors.Is to distinguish.
var (
	ErrShortPassphrase = errors.New("seedwrap: passphrase too short (min 8 chars)")
	ErrInvalidPEM      = errors.New("seedwrap: input is not a passphrase-wrapped PEM block")
	ErrCorruptEnvelope = errors.New("seedwrap: envelope is structurally malformed")
	ErrWrongPassphrase = errors.New("seedwrap: passphrase did not unwrap the seed")
	ErrEmptyPlaintext  = errors.New("seedwrap: nothing to wrap (empty input)")
)

// IsWrapped returns true iff `data` parses as a PEM block of our
// `PEMBlockType`. Lets callers detect a wrapped vs. unwrapped seed
// without attempting to decrypt.
func IsWrapped(data []byte) bool {
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	return block.Type == PEMBlockType
}

// Wrap encrypts plaintext under passphrase, returning the wrapped PEM.
//
// # Description
//
// Generates a fresh salt + nonce, derives an AES-256 key via Argon2id,
// AES-256-GCM-encrypts plaintext, and serializes the envelope into a
// PEM block of type PEMBlockType. KDF parameters are embedded in the
// envelope so future cost adjustments don't break old wraps.
//
// # Inputs
//
//   - plaintext: bytes to wrap (typically the raw xwingkeyfile PEM)
//   - passphrase: operator-supplied passphrase (≥ MinPassphraseLen chars)
//
// # Outputs
//
//   - []byte: armored PEM bytes ready to persist
//   - error: ErrShortPassphrase / ErrEmptyPlaintext / wrapped randomness or crypto failures
//
// # Security posture
//
//   - Passphrase bytes are not retained after KDF (caller still owns
//     the buffer; consider zeroizing after Wrap returns).
//   - Derived AEAD key is wiped on this side before returning.
//   - Nonce + salt are freshly random per call; no determinism.
func Wrap(plaintext []byte, passphrase []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrEmptyPlaintext
	}
	if len(passphrase) < MinPassphraseLen {
		return nil, ErrShortPassphrase
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("seedwrap: read salt: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("seedwrap: read nonce: %w", err)
	}

	key := argon2.IDKey(passphrase, salt, argon2Iterations, argon2Memory, argon2Parallelism, keyLen)
	defer zeroize(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("seedwrap: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seedwrap: gcm: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, Magic[:])

	body := make([]byte, 0, 4+4+4+1+saltLen+nonceLen+len(ct))
	body = append(body, Magic[:]...)
	body = appendBigU32(body, argon2Memory)
	body = appendBigU32(body, argon2Iterations)
	body = append(body, argon2Parallelism)
	body = append(body, salt...)
	body = append(body, nonce...)
	body = append(body, ct...)

	armored := pem.EncodeToMemory(&pem.Block{
		Type:  PEMBlockType,
		Bytes: body,
	})
	if armored == nil {
		return nil, errors.New("seedwrap: PEM encode produced nil")
	}
	return armored, nil
}

// Unwrap decrypts a passphrase-wrapped PEM produced by Wrap.
//
// # Description
//
// Parses the PEM, validates magic + KDF params, derives the AEAD key
// via Argon2id with the embedded parameters, and AES-256-GCM-opens the
// ciphertext. All decryption-time failures collapse to
// ErrWrongPassphrase to deny a passphrase-distinguisher oracle.
//
// # Inputs
//
//   - armored: PEM bytes (as produced by Wrap)
//   - passphrase: operator-supplied passphrase
//
// # Outputs
//
//   - []byte: original plaintext
//   - error: ErrInvalidPEM / ErrCorruptEnvelope / ErrWrongPassphrase
func Unwrap(armored []byte, passphrase []byte) ([]byte, error) {
	block, _ := pem.Decode(armored)
	if block == nil {
		return nil, fmt.Errorf("%w: pem.Decode returned nil", ErrInvalidPEM)
	}
	if block.Type != PEMBlockType {
		return nil, fmt.Errorf("%w: block type %q (want %q)", ErrInvalidPEM, block.Type, PEMBlockType)
	}
	body := block.Bytes

	const minLen = 4 + 4 + 4 + 1 + saltLen + nonceLen
	if len(body) < minLen {
		return nil, fmt.Errorf("%w: body %d bytes < minimum %d", ErrCorruptEnvelope, len(body), minLen)
	}
	if subtle.ConstantTimeCompare(body[:4], Magic[:]) != 1 {
		return nil, fmt.Errorf("%w: magic mismatch", ErrCorruptEnvelope)
	}
	off := 4
	memKiB := binary.BigEndian.Uint32(body[off : off+4])
	off += 4
	iters := binary.BigEndian.Uint32(body[off : off+4])
	off += 4
	par := body[off]
	off += 1
	salt := body[off : off+saltLen]
	off += saltLen
	nonce := body[off : off+nonceLen]
	off += nonceLen
	ct := body[off:]

	// Refuse absurd KDF params that would either burn CPU forever or be
	// trivially cheap to crack. The 1 MiB / 1-iter floor is below the
	// 2024 OWASP baseline but allows test vectors with smaller params
	// to still parse; the upper bounds prevent a hostile wrapped file
	// from triggering a 100-GiB Argon2 allocation.
	if memKiB < 1024 || memKiB > 4*1024*1024 {
		return nil, fmt.Errorf("%w: kdf memory %d KiB out of range", ErrCorruptEnvelope, memKiB)
	}
	if iters < 1 || iters > 100 {
		return nil, fmt.Errorf("%w: kdf iterations %d out of range", ErrCorruptEnvelope, iters)
	}
	if par < 1 || par > 16 {
		return nil, fmt.Errorf("%w: kdf parallelism %d out of range", ErrCorruptEnvelope, par)
	}

	key := argon2.IDKey(passphrase, salt, iters, memKiB, par, keyLen)
	defer zeroize(key)

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	plain, err := gcm.Open(nil, nonce, ct, Magic[:])
	if err != nil {
		// Collapse to ErrWrongPassphrase regardless of why GCM rejected
		// (wrong key, tampered ciphertext, truncated body). Caller
		// cannot distinguish; this denies an oracle.
		return nil, ErrWrongPassphrase
	}
	return plain, nil
}

// appendBigU32 appends u as a big-endian 4-byte sequence.
func appendBigU32(dst []byte, u uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return append(dst, b[:]...)
}

// zeroize wipes b. Best-effort: the Go compiler may elide writes to a
// dead slice; defer-invoked usage keeps the slice alive until function
// exit.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
