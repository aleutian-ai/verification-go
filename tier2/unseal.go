// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package tier2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// Wire format constants. Must match
// internal/crypto/tier2envelope/{errors,aad,kdf}.go byte-for-byte. Any
// drift here breaks cross-language interop and the SDK's compatibility
// contract.
const (
	// XWingSeedSize is the canonical X-Wing private seed size.
	XWingSeedSize = 32

	// xwingPubkeySize is the on-wire X-Wing public key size:
	// 1184-byte ML-KEM-768 EK followed by 32-byte X25519 PK.
	xwingPubkeySize = 1216

	// xwingCiphertextWireSize is the on-wire X-Wing KEM ciphertext size:
	// 1088-byte ML-KEM-768 ct followed by 32-byte X25519 ephemeral PK.
	xwingCiphertextWireSize = 1088 + 32

	// fingerprintHexLen is the canonical Aleutian fingerprint width:
	// 16 raw bytes encoded as 32 lowercase hex characters. Computed as
	// hex(SHA-512(pubkey1216)[:16]).
	fingerprintHexLen = 32

	// aesKeySize is the AEAD key size (AES-256-GCM).
	aesKeySize = 32

	// nonceSize is the AES-GCM nonce size.
	nonceSize = 12

	// aeadTagSize is the AES-256-GCM authentication tag size.
	aeadTagSize = 16

	// maxCEKWrapBytes is the exact decoded size of a wrap_ciphertext:
	// 32-byte key + 16-byte GCM tag.
	maxCEKWrapBytes = aesKeySize + aeadTagSize

	// tierModeStandard is the only legal tier_mode value in §2.2 AAD.
	tierModeStandard = "standard"

	// envelopeKindCEK marks a CEK-wrap AEAD operation (§2.2 closed enum).
	envelopeKindCEK = "cek"

	// aadPrefix is the fixed prefix prepended to every Standard-mode AAD blob.
	// IMMUTABLE FORMAT per spec §2.2.
	aadPrefix = "aleutian.tier2.row.v1:"

	// hkdfInfoCEKWrap is the fixed domain prefix for the CEK-wrap HKDF info
	// string per spec §2.3. IMMUTABLE.
	hkdfInfoCEKWrap = "aleutian.tier2.cek_wrap.v1:"
)

// xwingLabel is the 6-byte X-Wing combiner domain separator per IETF
// draft-connolly-cfrg-xwing-kem §5.3. ASCII: \././^\ (the X-Wing
// emoticon). MUST match the producer's label byte-for-byte.
var xwingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

// OpenBundle unseals a Tier-2 Standard-mode bundle using one of the
// customer's X-Wing private-key seeds.
//
// # Description
//
// Derives the seed's public-key fingerprint, scans the bundle's
// cek_envelopes for a matching entry via constant-time compare, then
// runs the per-envelope X-Wing decap + HKDF + AES-GCM open path to
// recover the bundle CEK. Either the primary or the backup seed will
// successfully unseal the same bundle; the function is slot-agnostic.
//
// # Inputs
//
//   - seed: exactly XWingSeedSize (32) bytes
//   - bundle: parsed bundle with manifest.tier2.cek_envelopes populated
//
// # Outputs
//
//   - OpenBundleResult: CEK + matched envelope index + matched fingerprint
//   - error: ErrSeedInvalid, ErrBundleMalformed, ErrNoMatchingRecipient,
//     ErrOpenFailed
//
// # Example
//
//	res, err := tier2.OpenBundle(seed, bundle)
//	if err != nil {
//	    return err
//	}
//	defer wipe(res.CEK)
//	log.Printf("unsealed via envelope %d (%s)", res.MatchedEnvelopeIndex, res.MatchedFingerprint)
//
// # Limitations
//
//   - Standard mode only. Forensic-mode bundles (Tier2.Mode != "standard")
//     return ErrBundleMalformed; use a different unseal path for those.
//   - Caller is responsible for verifying the bundle's signature + trust
//     chain BEFORE calling OpenBundle. This function does not validate
//     authenticity beyond the per-envelope AEAD step.
//   - Single-seed only. Customers holding both primary + backup seeds
//     should pick one to unseal; calling twice provides no additional
//     information beyond MatchedEnvelopeIndex.
//
// # Assumptions
//
//   - The bundle was produced by a conforming sealer (internal
//     tier2envelope.SealCEKWrap or a byte-equivalent implementation).
//   - bundle.ID matches the bundle_id the sealer bound into AAD. A
//     mismatch yields ErrOpenFailed.
func OpenBundle(seed []byte, bundle *Bundle) (OpenBundleResult, error) {
	if len(seed) != XWingSeedSize {
		return OpenBundleResult{}, fmt.Errorf("%w: got %d bytes, want %d",
			ErrSeedInvalid, len(seed), XWingSeedSize)
	}
	if bundle == nil {
		return OpenBundleResult{}, ErrBundleMalformed
	}
	if bundle.ID == "" {
		return OpenBundleResult{}, ErrBundleMalformed
	}
	if bundle.Manifest.Tier2.Mode != tierModeStandard {
		return OpenBundleResult{}, ErrBundleMalformed
	}
	envs := bundle.Manifest.Tier2.CEKEnvelopes
	if len(envs) == 0 {
		return OpenBundleResult{}, ErrBundleMalformed
	}
	// Defense in depth: producer-reported pubkey_count MUST match the
	// list length. A skew here means truncation or a misformed manifest.
	if bundle.Manifest.Tier2.PubkeyCount != 0 &&
		bundle.Manifest.Tier2.PubkeyCount != len(envs) {
		return OpenBundleResult{}, ErrBundleMalformed
	}

	myFP, err := DeriveFingerprint(seed)
	if err != nil {
		return OpenBundleResult{}, err
	}

	// Constant-time scan: iterate every envelope so the loop's wall-
	// clock cost does not depend on WHICH envelope matches. The
	// short-circuit lives at the AEAD-open layer (one decap+open per
	// match) which is unavoidable — what we control here is the SCAN
	// cost.
	matchIdx := -1
	for i, env := range envs {
		if len(env.PubkeyFingerprint) != fingerprintHexLen {
			// Skip malformed entries — but keep scanning so the timing
			// signature doesn't betray which slot is well-formed.
			continue
		}
		if subtle.ConstantTimeCompare([]byte(env.PubkeyFingerprint), []byte(myFP)) == 1 {
			matchIdx = i
			// Do NOT break — continue the loop so total time is
			// O(N) regardless of which slot matched.
			//
			// We capture the first match; collisions are
			// cryptographically implausible (fingerprint = 128-bit
			// truncated SHA-512) but if a malicious bundle includes
			// two identical fingerprints, the first wins.
		}
	}
	if matchIdx < 0 {
		return OpenBundleResult{}, ErrNoMatchingRecipient
	}

	matched := envs[matchIdx]
	cek, err := openCEKWrap(matched, bundle.ID, int64(matchIdx), seed)
	if err != nil {
		return OpenBundleResult{}, err
	}
	return OpenBundleResult{
		CEK:                  cek,
		MatchedEnvelopeIndex: matchIdx,
		MatchedFingerprint:   matched.PubkeyFingerprint,
	}, nil
}

// DeriveFingerprint computes the 32-char lowercase hex public-key
// fingerprint from a 32-byte X-Wing private-key seed.
//
// # Description
//
// Mirrors the producer-side calculation in
// internal/crypto/sarenvelope.Fingerprint: SHA-512 over the 1216-byte
// canonical pubkey, truncated to 16 raw bytes, hex-encoded. Callers
// use this for offline cross-checking ("does my seed match envelope
// index 0 or 1?") without having to load the full bundle.
//
// # Inputs
//
//   - seed: exactly XWingSeedSize (32) bytes
//
// # Outputs
//
//   - string: 32-char lowercase hex
//   - error: ErrSeedInvalid on wrong size
//
// # Example
//
//	fp, err := tier2.DeriveFingerprint(seed)
//	if err != nil { return err }
//	// Compare to envelope fingerprints from manifest.json.
func DeriveFingerprint(seed []byte) (string, error) {
	if len(seed) != XWingSeedSize {
		return "", fmt.Errorf("%w: got %d bytes, want %d",
			ErrSeedInvalid, len(seed), XWingSeedSize)
	}
	pub, err := derivePubkey(seed)
	if err != nil {
		return "", err
	}
	defer wipe(pub)
	h := sha512.Sum512(pub)
	return hex.EncodeToString(h[:fingerprintHexLen/2]), nil
}

// openCEKWrap is the per-envelope decap+open pipeline. Mirrors
// internal/crypto/tier2envelope/envelope.go::OpenCEKWrap byte-for-byte
// (validation order, AAD construction, KDF parameters, AEAD primitive).
//
// All cryptographic failure modes collapse to ErrOpenFailed. The single
// sentinel is deliberate — distinguishing "wrong key" from "tampered"
// from "AAD mismatch" would give a remote attacker an oracle.
func openCEKWrap(env CEKWrapEnvelope, bundleID string, envelopeIndex int64, seed []byte) ([]byte, error) {
	nonce, err := base64.StdEncoding.DecodeString(env.WrapNonce)
	if err != nil || len(nonce) != nonceSize {
		return nil, ErrOpenFailed
	}
	ctxt, err := base64.StdEncoding.DecodeString(env.WrapCiphertext)
	if err != nil || len(ctxt) != maxCEKWrapBytes {
		return nil, ErrOpenFailed
	}
	kemCT, err := base64.StdEncoding.DecodeString(env.KEMCiphertext)
	if err != nil || len(kemCT) != xwingCiphertextWireSize {
		return nil, ErrOpenFailed
	}

	aad, err := buildAAD(bundleID, "", envelopeKindCEK, 0, envelopeIndex)
	if err != nil {
		return nil, ErrOpenFailed
	}

	// X-Wing decapsulate seed → shared secret.
	ss, err := xwingDecapsulate(seed, kemCT)
	if err != nil {
		return nil, ErrOpenFailed
	}
	defer wipe(ss)

	wrapKey, err := deriveCEKWrapKey(ss, bundleID, env.PubkeyFingerprint)
	if err != nil {
		return nil, ErrOpenFailed
	}
	defer wipe(wrapKey)

	pt, err := aeadOpen(wrapKey, nonce, ctxt, aad)
	if err != nil {
		return nil, ErrOpenFailed
	}
	if len(pt) != aesKeySize {
		// Defense in depth: recovered CEK MUST be exactly 32 bytes.
		return nil, ErrOpenFailed
	}
	return pt, nil
}

// buildAAD constructs the canonical Standard-mode associated-data blob
// per spec §2.2. IMMUTABLE FORMAT — must mirror
// internal/crypto/tier2envelope/aad.go::AADInput.Build byte-for-byte.
//
// Layout:
//
//	aadPrefix ||
//	u32_be(len(bundle_id))    || bundle_id    ||
//	u32_be(len(tier_mode))    || tier_mode    ||
//	u32_be(len(row_id))       || row_id       ||
//	u32_be(len(envelope_kind)) || envelope_kind ||
//	u64_be(row_index)         ||
//	u64_be(envelope_index)
func buildAAD(bundleID, rowID, envelopeKind string, rowIndex, envelopeIndex int64) ([]byte, error) {
	if bundleID == "" {
		return nil, fmt.Errorf("aad: bundle_id required")
	}
	if envelopeKind != envelopeKindCEK {
		return nil, fmt.Errorf("aad: envelope_kind %q unsupported in SDK", envelopeKind)
	}
	if rowID != "" {
		return nil, fmt.Errorf("aad: row_id must be empty for envelope_kind=cek")
	}
	if rowIndex < 0 || envelopeIndex < 0 {
		return nil, fmt.Errorf("aad: indices must be >= 0")
	}
	want := len(aadPrefix) +
		4 + len(bundleID) +
		4 + len(tierModeStandard) +
		4 + len(rowID) +
		4 + len(envelopeKind) +
		8 + 8
	out := make([]byte, 0, want)
	out = append(out, aadPrefix...)
	out = appendLP(out, bundleID)
	out = appendLP(out, tierModeStandard)
	out = appendLP(out, rowID)
	out = appendLP(out, envelopeKind)
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], uint64(rowIndex))
	out = append(out, idx[:]...)
	binary.BigEndian.PutUint64(idx[:], uint64(envelopeIndex))
	out = append(out, idx[:]...)
	return out, nil
}

// appendLP appends u32_be(len(s)) || s.
func appendLP(out []byte, s string) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(s)))
	out = append(out, hdr[:]...)
	out = append(out, s...)
	return out
}

// deriveCEKWrapKey derives the AEAD wrap-key for a CEK envelope from
// the X-Wing shared secret per spec §2.3.
//
// IMMUTABLE FORMAT — must mirror
// internal/crypto/tier2envelope/kdf.go::deriveCEKWrapKey byte-for-byte:
//
//	ikm   = ss
//	salt  = hex.DecodeString(fpHex)               // 16 raw bytes
//	info  = hkdfInfoCEKWrap || LP(bundle_id) || LP(fpHex)
//	output_len = aesKeySize (32)
//	wrap_key = HKDF-SHA-512(ikm, salt, info, output_len)
func deriveCEKWrapKey(ss []byte, bundleID, fpHex string) ([]byte, error) {
	if bundleID == "" {
		return nil, fmt.Errorf("kdf: bundle_id required")
	}
	if len(fpHex) != fingerprintHexLen {
		return nil, fmt.Errorf("kdf: bad fpHex len %d", len(fpHex))
	}
	fpRaw, err := hex.DecodeString(fpHex)
	if err != nil {
		return nil, fmt.Errorf("kdf: decode fp: %w", err)
	}
	info := make([]byte, 0, len(hkdfInfoCEKWrap)+4+len(bundleID)+4+len(fpHex))
	info = append(info, hkdfInfoCEKWrap...)
	info = appendLP(info, bundleID)
	info = appendLP(info, fpHex)
	r := hkdf.New(sha512.New, ss, fpRaw, info)
	key := make([]byte, aesKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("kdf: hkdf: %w", err)
	}
	return key, nil
}

// aeadOpen performs AES-256-GCM open. The single-sentinel collapse at
// the caller layer means we only need to surface "failed" — no need to
// distinguish bad-key from bad-ciphertext at this layer.
func aeadOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aead: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aead: cipher.NewGCM: %w", err)
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// xwingDecapsulate runs the X-Wing KEM decapsulation against the
// supplied seed + wire-format ciphertext.
//
// Algorithm mirrors HybridKEMUnwrapper.Unwrap in the parent SDK
// (sdk/verification-go/hybrid_kem_unwrapper.go) but operates on the
// tier2envelope wire format (1120-byte ct = 1088 ML-KEM + 32 X25519
// EPK, no MAC, no version prefix) rather than the WrappedKeyV3 format.
//
// Steps per draft-connolly-cfrg-xwing-kem §5.4:
//  1. Expand seed via SHAKE256 to (mlkem_d || mlkem_z || x25519_priv).
//  2. ML-KEM-768 decapsulate(seed, mlkem_ct) → ss_M (32 bytes).
//  3. X25519(x25519_priv, x25519_epk)        → ss_X (32 bytes).
//  4. SHA3-256(ss_M || ss_X || ct_X || pk_X || label) → shared secret.
func xwingDecapsulate(seed, ct []byte) ([]byte, error) {
	if len(ct) != xwingCiphertextWireSize {
		return nil, fmt.Errorf("xwing: ct wrong length")
	}
	mlkemCT := ct[:1088]
	x25519EPK := ct[1088:]

	mlkemSeed, x25519Priv, err := expandSeed(seed)
	if err != nil {
		return nil, err
	}
	defer wipe(mlkemSeed)
	defer wipe(x25519Priv)

	dk, err := mlkem.NewDecapsulationKey768(mlkemSeed)
	if err != nil {
		return nil, fmt.Errorf("xwing: mlkem decap key: %w", err)
	}
	mlkemSS, err := dk.Decapsulate(mlkemCT)
	if err != nil {
		return nil, fmt.Errorf("xwing: mlkem decapsulate: %w", err)
	}
	defer wipe(mlkemSS)

	// X25519: low-order points must NOT cause failure per IETF
	// draft-connolly-cfrg-xwing-kem §4.2 — ML-KEM provides
	// independent security. Substitute zeros on error to match
	// server-side behavior.
	x25519SS, err := curve25519.X25519(x25519Priv, x25519EPK)
	if err != nil {
		x25519SS = make([]byte, 32)
	}
	defer wipe(x25519SS)

	x25519PK, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("xwing: derive x25519 pk: %w", err)
	}
	defer wipe(x25519PK)

	h := sha3.New256()
	h.Write(mlkemSS)
	h.Write(x25519SS)
	h.Write(x25519EPK)
	h.Write(x25519PK)
	h.Write(xwingLabel)
	return h.Sum(nil), nil
}

// derivePubkey computes the 1216-byte canonical X-Wing public key from
// a 32-byte seed: 1184-byte ML-KEM-768 EK followed by 32-byte X25519 PK.
//
// Mirrors the producer-side derivation so the fingerprint computed by
// the SDK matches the value the producer wrote into
// CEKWrapEnvelope.PubkeyFingerprint.
func derivePubkey(seed []byte) ([]byte, error) {
	mlkemSeed, x25519Priv, err := expandSeed(seed)
	if err != nil {
		return nil, err
	}
	defer wipe(mlkemSeed)
	defer wipe(x25519Priv)

	dk, err := mlkem.NewDecapsulationKey768(mlkemSeed)
	if err != nil {
		return nil, fmt.Errorf("derive pub: mlkem decap key: %w", err)
	}
	mlkemEK := dk.EncapsulationKey().Bytes() // 1184 bytes
	if len(mlkemEK) != 1184 {
		return nil, fmt.Errorf("derive pub: mlkem ek len %d, want 1184", len(mlkemEK))
	}
	x25519PK, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive pub: x25519: %w", err)
	}
	out := make([]byte, 0, xwingPubkeySize)
	out = append(out, mlkemEK...)
	out = append(out, x25519PK...)
	return out, nil
}

// expandSeed implements the IETF draft-connolly-cfrg-xwing-kem §5.2
// expansion: SHAKE256(seed, 96) → mlkem_d (32) || mlkem_z (32) || x25519_priv (32).
// Mirrors sdk/verification-go/hybrid_kem_unwrapper.go::expandDecapsulationKeySDK.
//
// Returns mlkem_seed = mlkem_d || mlkem_z (64 bytes) for use with
// mlkem.NewDecapsulationKey768.
func expandSeed(seed []byte) (mlkemSeed, x25519Priv []byte, err error) {
	if len(seed) != XWingSeedSize {
		return nil, nil, fmt.Errorf("expand: seed size %d, want %d", len(seed), XWingSeedSize)
	}
	h := sha3.NewShake256()
	h.Write(seed)
	expanded := make([]byte, 96)
	if _, err := io.ReadFull(h, expanded); err != nil {
		return nil, nil, fmt.Errorf("expand: shake256: %w", err)
	}
	mlkemSeed = make([]byte, 64)
	copy(mlkemSeed, expanded[:64])
	x25519Priv = make([]byte, 32)
	copy(x25519Priv, expanded[64:])
	wipe(expanded)
	return mlkemSeed, x25519Priv, nil
}

// wipe zeros a byte slice in place. Best-effort — the Go runtime may
// keep copies in registers or scheduler-stashed memory; we rely on
// the broader practice (no exfiltration of address space) for the
// security argument.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
