// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
)

// bundleManifestRootDomain is the TLV recipe domain-separation prefix for the
// export-bundle manifest_root. It MUST byte-match the producer's
// internal/export_builder/manifest/manifest_root.go constant.
//
// v2 (0b_2): the root commits to ONLY path + SHA-512 per file. Kind, Bytes, and
// RowCount are informational columns in files[] that a verifier cannot
// reproduce from the file bytes, so they are NOT bound into the signed root —
// binding them added cross-language drift surface with no integrity benefit.
// What the signature must pin is "which file, and what content" — path + hash.
const bundleManifestRootDomain = "aleutian.compliance_bundle.v2:"

// ErrBundleManifestRoot is returned when a BundleFileEntry SHA-512 is not
// exactly 128 lowercase-hex chars (64 raw bytes) or the file count overflows.
var ErrBundleManifestRoot = errors.New("bundle manifest_root: invalid inputs")

// BundleFileEntry is one entry of an export bundle manifest's files[] array.
// Kind / Bytes / RowCount are informational (present for display + tooling) and
// are NOT part of the signed manifest_root recipe (v2).
type BundleFileEntry struct {
	Path     string `json:"path"`
	SHA512   string `json:"sha512"`
	Kind     string `json:"kind"`
	Bytes    int64  `json:"bytes"`
	RowCount *int64 `json:"row_count,omitempty"`
}

// ComputeBundleManifestRoot recomputes the export-bundle manifest_root over the
// v2 TLV recipe and returns it as 128-char lowercase hex SHA-512.
//
// # Description
//
// Recipe = `aleutian.compliance_bundle.v2:` || u32_be(N) ||
// foreach file in (files sorted by path):
//
//	u32_be(len(path)) || path
//	u32_be(64)        || sha512_raw_bytes (decoded from the hex field)
//
// All multi-byte integers are big-endian. This is the offline-verifier half of
// the contract the producer signs; a mismatch against the manifest's claimed
// manifest_root means files[] was altered after signing.
//
// # Inputs
//
//   - files: the manifest's files[] entries. ComputeBundleManifestRoot sorts a
//     COPY by path (the producer computes over path-sorted files), so callers
//     may pass them in the manifest's array order.
//
// # Outputs
//
//   - string: 128-char lowercase hex SHA-512.
//   - error: ErrBundleManifestRoot if any SHA512 is not 64 raw bytes of hex or
//     the file count overflows uint32.
//
// # Example
//
//	root, err := sdk.ComputeBundleManifestRoot(manifest.Files)
//	if err != nil { return err }
//	if root != manifest.ManifestRoot { return sdk.ErrBundleTampered }
//
// # Limitations
//
//   - Does not read files off disk; it hashes the CLAIMED sha512 values. Pair
//     with a per-file re-hash (VerifyBundleDir) to bind the claim to bytes.
//
// # Assumptions
//
//   - Each SHA512 is a content hash the caller will independently re-verify.
func ComputeBundleManifestRoot(files []BundleFileEntry) (string, error) {
	if len(files) > math.MaxUint32 {
		return "", fmt.Errorf("%w: file count %d exceeds uint32", ErrBundleManifestRoot, len(files))
	}

	sorted := make([]BundleFileEntry, len(files))
	copy(sorted, files)
	// Stable sort on the sole key (path) — with unique paths (enforced below)
	// stability is moot, but it removes any producer/verifier ordering ambiguity
	// as defense-in-depth (D1).
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	h := sha512.New()
	h.Write([]byte(bundleManifestRootDomain))

	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], uint32(len(sorted)))
	h.Write(u32[:])

	for i, f := range sorted {
		// Reject duplicate paths: an ambiguous inventory must not hash to a
		// well-defined root (D1). Adjacent after the sort.
		if i > 0 && f.Path == sorted[i-1].Path {
			return "", fmt.Errorf("%w: duplicate path %q in files[]", ErrBundleManifestRoot, f.Path)
		}
		// Canonicalization strictness: sha512 MUST be exactly 128 LOWERCASE hex
		// chars (D3). hex.DecodeString alone would accept uppercase, which would
		// pass the root but fail a lowercase re-hash comparison downstream.
		if len(f.SHA512) != 128 || !isLowerHex(f.SHA512) {
			return "", fmt.Errorf("%w: file index %d path %q: sha512 must be 128 lowercase hex chars", ErrBundleManifestRoot, i, f.Path)
		}
		raw, err := hex.DecodeString(f.SHA512)
		if err != nil || len(raw) != 64 {
			return "", fmt.Errorf("%w: file index %d path %q: sha512 hex decode failed", ErrBundleManifestRoot, i, f.Path)
		}
		if len(f.Path) > math.MaxUint32 {
			return "", fmt.Errorf("%w: file index %d: path length overflows uint32", ErrBundleManifestRoot, i)
		}
		binary.BigEndian.PutUint32(u32[:], uint32(len(f.Path)))
		h.Write(u32[:])
		h.Write([]byte(f.Path))

		binary.BigEndian.PutUint32(u32[:], 64)
		h.Write(u32[:])
		h.Write(raw)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// isLowerHex reports whether s is composed solely of [0-9a-f].
func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
