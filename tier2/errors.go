// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package tier2 implements the customer-side unseal path for Tier-2
// Standard-mode audit bundles produced by Aleutian's compliance
// disclosure pipeline.
//
// Per ADR-024 Amendment (2026-05-31), every tenant registers two X-Wing
// keypairs (primary + backup) and bundles ship with N=2 cek_envelopes —
// one wrapped to each recipient pubkey. OpenBundle accepts a single
// 32-byte seed, locates the envelope matching that seed's derived public
// key fingerprint via constant-time compare, and decrypts it.
//
// # Byte-parity with the internal producer
//
// This package is the Apache-2.0-licensed re-implementation of the
// proprietary internal/crypto/tier2envelope Opener. The wire format
// (CEKWrapEnvelope JSON shape, AAD construction per spec §2.2, HKDF
// info+salt per spec §2.3, X-Wing KEM combiner per IETF
// draft-connolly-cfrg-xwing-kem) is identical byte-for-byte.
//
// # SECURITY
//
// OpenBundle short-circuits at multiple internal stages (base64 decode,
// fingerprint scan, KEM decapsulate, AEAD open) whose latency differs
// by orders of magnitude. Do NOT expose this directly as a
// network-facing service without a fixed-latency wrapper — the timing
// differences are a remote oracle for distinguishing wrong-key /
// tampered-ciphertext / structural-reject failure modes. The intended
// consumer is a customer-controlled CLI or in-process unseal step on
// the customer's own infrastructure.
package tier2

import "errors"

// ErrSeedInvalid signals that the supplied seed is not exactly
// XWingSeedSize bytes. The caller passed a malformed key.
var ErrSeedInvalid = errors.New("aleutian/tier2: invalid xwing seed (must be 32 bytes)")

// ErrBundleMalformed signals that the bundle is structurally invalid:
// nil pointer, missing manifest, missing tier2 block, or empty
// cek_envelopes list. The bundle was not produced by a conforming
// sealer or has been truncated.
var ErrBundleMalformed = errors.New("aleutian/tier2: bundle malformed")

// ErrNoMatchingRecipient signals that the seed's derived fingerprint
// does not match any envelope in the bundle's cek_envelopes list. The
// caller is holding a seed for a different tenant, or the bundle was
// sealed under a key that has since been rotated out and the seed
// belongs to an older slot.
//
// SECURITY: this error is opaque. It does NOT include the seed's
// fingerprint, the bundle's recipient list, or any slot label. A
// distinguishing error would leak which envelopes a bundle carries to
// an attacker who controls the seed.
var ErrNoMatchingRecipient = errors.New("aleutian/tier2: no matching recipient envelope")

// ErrOpenFailed signals that the matched envelope's AEAD decryption
// failed. Returned for: wrong seed for the matched fingerprint (a
// fingerprint collision is implausible but the per-envelope AEAD step
// still validates), tampered ciphertext, AAD mismatch on bundle_id or
// envelope_index, or oversized ciphertext. The single-sentinel design
// mirrors the internal Opener's anti-oracle posture.
var ErrOpenFailed = errors.New("aleutian/tier2: open failed (wrong key, tampered, or AAD mismatch)")
