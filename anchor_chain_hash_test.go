// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

// TestSeedAnchorHash_IsExactlySHA512OfDomainSeed pins the constant to its
// canonical computation. If this drifts, the SDK and producer would silently
// disagree on genesis anchors — and no real-data test would catch it because
// genesis anchors are rare.
func TestSeedAnchorHash_IsExactlySHA512OfDomainSeed(t *testing.T) {
	h := sha512.Sum512([]byte("aleutian.anchor.seed.v2"))
	want := hex.EncodeToString(h[:])
	if SeedAnchorHash != want {
		t.Fatalf("SeedAnchorHash drift:\n  got:  %s\n  want: %s", SeedAnchorHash, want)
	}
}

// TestComputeAnchorChainHash_GoldenVector pins one hand-computed (input ->
// output) pair so the SHA-512 formula cannot silently change. Same vector
// MUST be added byte-identically to the Python and JS SDKs (cross-language
// parity is the whole point of the domain separator).
func TestComputeAnchorChainHash_GoldenVector(t *testing.T) {
	// Inputs chosen to be short, ASCII-only, and representative of a real
	// genesis anchor's call shape. NOT taken from real production data —
	// constructing a deterministic vector matters more than realism here.
	prevAnchorHash := SeedAnchorHash
	companyID := "comp_01TESTCOMPANYULID0000000000"
	startEntryID := "019eXXXX-0000-7000-8000-000000000001"
	endEntryID := "019eXXXX-0000-7000-8000-000000000003"
	tipChainHash := "00112233445566778899aabbccddeeff" +
		"00112233445566778899aabbccddeeff" +
		"00112233445566778899aabbccddeeff" +
		"00112233445566778899aabbccddeeff"

	// Independent recomputation (do NOT call ComputeAnchorChainHash here —
	// the point of a golden vector is that the test math is independent of
	// the production formula).
	h := sha512.New()
	h.Write([]byte("aleutian.anchor.v2:"))
	h.Write([]byte(prevAnchorHash))
	h.Write([]byte("|"))
	h.Write([]byte(companyID))
	h.Write([]byte("|"))
	h.Write([]byte(startEntryID))
	h.Write([]byte("|"))
	h.Write([]byte(endEntryID))
	h.Write([]byte("|"))
	h.Write([]byte(tipChainHash))
	want := hex.EncodeToString(h.Sum(nil))

	got := ComputeAnchorChainHash(prevAnchorHash, companyID, startEntryID, endEntryID, tipChainHash)
	if got != want {
		t.Fatalf("ComputeAnchorChainHash drift:\n  got:  %s\n  want: %s", got, want)
	}
}

// TestComputeAnchorChainHash_DomainSeparation guards against the worst case:
// if the domain prefix were removed or changed, two structurally-different
// computations could collide. Verify the prefix is load-bearing by checking
// that omitting it yields a different result.
func TestComputeAnchorChainHash_DomainSeparation(t *testing.T) {
	prev := SeedAnchorHash
	cid := "comp_X"
	s := "entry_start"
	e := "entry_end"
	tip := "tip_hash"

	with := ComputeAnchorChainHash(prev, cid, s, e, tip)

	// Compute without the domain prefix.
	h := sha512.New()
	h.Write([]byte(prev))
	h.Write([]byte("|"))
	h.Write([]byte(cid))
	h.Write([]byte("|"))
	h.Write([]byte(s))
	h.Write([]byte("|"))
	h.Write([]byte(e))
	h.Write([]byte("|"))
	h.Write([]byte(tip))
	without := hex.EncodeToString(h.Sum(nil))

	if with == without {
		t.Fatalf("domain prefix is not load-bearing — with == without == %s", with)
	}
}
