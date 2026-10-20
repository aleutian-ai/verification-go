// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

// sha512HexOf is a tiny helper for the golden vectors.
func sha512HexOf(s string) string {
	sum := sha512.Sum512([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestComputeBundleManifestRoot_GoldenVector pins the v2 manifest_root recipe
// to a cross-language golden vector. The expected value was independently
// computed by a Python implementation of the same TLV recipe (see the ticket);
// any Go/Python/JS producer or verifier MUST reproduce it byte-for-byte. A
// change here is a breaking wire-format change requiring a domain bump.
func TestComputeBundleManifestRoot_GoldenVector(t *testing.T) {
	// Deliberately UNSORTED input — ComputeBundleManifestRoot must sort by path.
	files := []BundleFileEntry{
		{Path: "chain_extracts/consent.jsonl", SHA512: sha512HexOf("consent"), Kind: "chain_extract", Bytes: 7},
		{Path: "anchors/anchors.jsonl", SHA512: sha512HexOf("anchor"), Kind: "anchor", Bytes: 6},
		{Path: "README.txt", SHA512: sha512HexOf("readme"), Kind: "readme", Bytes: 6},
		{Path: "trust_manifest/manifest.json", SHA512: sha512HexOf("trust"), Kind: "trust_manifest", Bytes: 5},
	}
	const wantRoot = "238e7ae596d9ef2a45d05ddc687032f8d96e74a91c32dc925c9251c3ffa0ba00c3a494f0397d41666dfc1ffe2cf451fa33cdb7a852f17638cd3a20f5f7515932"

	got, err := ComputeBundleManifestRoot(files)
	if err != nil {
		t.Fatalf("ComputeBundleManifestRoot: %v", err)
	}
	if got != wantRoot {
		t.Errorf("manifest_root golden mismatch (recipe drift!)\n got:  %s\n want: %s", got, wantRoot)
	}

	// Kind / Bytes / RowCount are NOT bound into the root (v2): mutating them
	// must NOT change manifest_root.
	mutated := make([]BundleFileEntry, len(files))
	copy(mutated, files)
	rc := int64(99)
	mutated[0].Kind = "DIFFERENT"
	mutated[0].Bytes = 123456
	mutated[0].RowCount = &rc
	got2, err := ComputeBundleManifestRoot(mutated)
	if err != nil {
		t.Fatalf("ComputeBundleManifestRoot(mutated): %v", err)
	}
	if got2 != wantRoot {
		t.Errorf("Kind/Bytes/RowCount must NOT affect manifest_root (v2); got %s", got2)
	}

	// Sort-independence: pre-sorting the input yields the same root.
	sorted := []BundleFileEntry{
		{Path: "README.txt", SHA512: sha512HexOf("readme")},
		{Path: "anchors/anchors.jsonl", SHA512: sha512HexOf("anchor")},
		{Path: "chain_extracts/consent.jsonl", SHA512: sha512HexOf("consent")},
		{Path: "trust_manifest/manifest.json", SHA512: sha512HexOf("trust")},
	}
	got3, err := ComputeBundleManifestRoot(sorted)
	if err != nil {
		t.Fatalf("ComputeBundleManifestRoot(sorted): %v", err)
	}
	if got3 != wantRoot {
		t.Errorf("root must be order-independent after internal sort; got %s", got3)
	}

	// A changed content hash MUST change the root.
	tampered := make([]BundleFileEntry, len(files))
	copy(tampered, files)
	tampered[0].SHA512 = sha512HexOf("TAMPERED")
	got4, err := ComputeBundleManifestRoot(tampered)
	if err != nil {
		t.Fatalf("ComputeBundleManifestRoot(tampered): %v", err)
	}
	if got4 == wantRoot {
		t.Error("a changed file SHA-512 must change manifest_root")
	}
}

// TestComputeBundleManifestRoot_InvalidSHA rejects malformed hashes.
func TestComputeBundleManifestRoot_InvalidSHA(t *testing.T) {
	upper := "ABCDEF" + sha512HexOf("x")[6:] // valid length, but uppercase (D3)
	for _, bad := range []string{"", "abcd", "zz" + sha512HexOf("x")[2:], upper} {
		if _, err := ComputeBundleManifestRoot([]BundleFileEntry{{Path: "p", SHA512: bad}}); err == nil {
			t.Errorf("expected error for malformed/non-lowercase sha512 %q", bad)
		}
	}
}

// TestComputeBundleManifestRoot_RejectsDuplicatePaths — D1: an ambiguous
// inventory must not hash to a well-defined root.
func TestComputeBundleManifestRoot_RejectsDuplicatePaths(t *testing.T) {
	files := []BundleFileEntry{
		{Path: "chain_extracts/a.jsonl", SHA512: sha512HexOf("1")},
		{Path: "chain_extracts/a.jsonl", SHA512: sha512HexOf("2")},
	}
	if _, err := ComputeBundleManifestRoot(files); err == nil {
		t.Error("duplicate path must error")
	}
}
