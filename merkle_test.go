// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"bytes"
	"testing"
)

func mLeaf(i byte) []byte { return MerkleLeafHash([]byte{i}) }

func TestVerifyMerkleInclusion_FourLeafTree(t *testing.T) {
	L0, L1, L2, L3 := mLeaf(0), mLeaf(1), mLeaf(2), mLeaf(3)
	h01 := merkleNodeHash(L0, L1)
	h23 := merkleNodeHash(L2, L3)
	root := merkleNodeHash(h01, h23)

	cases := []struct {
		m     int
		proof [][]byte
	}{
		{0, [][]byte{L1, h23}},
		{1, [][]byte{L0, h23}},
		{2, [][]byte{L3, h01}},
		{3, [][]byte{L2, h01}},
	}
	for _, c := range cases {
		if !VerifyMerkleInclusion(mLeaf(byte(c.m)), c.m, 4, c.proof, root) {
			t.Errorf("inclusion for leaf %d did not verify", c.m)
		}
	}
	// Negatives.
	if VerifyMerkleInclusion(mLeaf(9), 0, 4, [][]byte{L1, h23}, root) {
		t.Error("tampered leaf must not verify")
	}
	if VerifyMerkleInclusion(mLeaf(0), 0, 4, [][]byte{L1}, root) {
		t.Error("short proof must not verify")
	}
	if VerifyMerkleInclusion(mLeaf(0), 0, 4, [][]byte{L1, h23}, MerkleEmptyRoot()) {
		t.Error("wrong root must not verify")
	}
}

func TestVerifyMerkleInclusion_SingleLeaf(t *testing.T) {
	L0 := mLeaf(0)
	if !VerifyMerkleInclusion(L0, 0, 1, nil, L0) {
		t.Error("single-leaf inclusion must verify with empty proof")
	}
	if VerifyMerkleInclusion(L0, 0, 1, [][]byte{L0}, L0) {
		t.Error("single-leaf with a non-empty proof must not verify")
	}
}

func TestVerifyMerkleConsistency_Cases(t *testing.T) {
	L0, L1, L2, L3 := mLeaf(0), mLeaf(1), mLeaf(2), mLeaf(3)
	h01 := merkleNodeHash(L0, L1)
	h23 := merkleNodeHash(L2, L3)
	root4 := merkleNodeHash(h01, h23)

	// m=1, n=2: rootA=L0, rootB=node(L0,L1), proof=[L1].
	if !VerifyMerkleConsistency(1, 2, L0, merkleNodeHash(L0, L1), [][]byte{L1}) {
		t.Error("consistency 1->2 did not verify")
	}
	// m=2, n=4: rootA=h01, rootB=root4, proof=[h23].
	if !VerifyMerkleConsistency(2, 4, h01, root4, [][]byte{h23}) {
		t.Error("consistency 2->4 did not verify")
	}
	// m==n identical: empty proof, equal roots.
	if !VerifyMerkleConsistency(4, 4, root4, root4, nil) {
		t.Error("m==n identical must verify")
	}
	// m==0: empty prefix, rootA must be EmptyRoot.
	if !VerifyMerkleConsistency(0, 4, MerkleEmptyRoot(), root4, nil) {
		t.Error("m==0 with EmptyRoot must verify")
	}
	// Negatives.
	if VerifyMerkleConsistency(2, 4, h01, root4, [][]byte{L0}) {
		t.Error("tampered consistency proof must not verify")
	}
	if VerifyMerkleConsistency(2, 4, h23, root4, [][]byte{h23}) {
		t.Error("wrong earlier root must not verify")
	}
}

func TestMerkleEmptyRoot_And_LeafDomainSeparation(t *testing.T) {
	if len(MerkleEmptyRoot()) != merkleHashSize {
		t.Fatal("empty root wrong size")
	}
	if bytes.Equal(MerkleLeafHash([]byte{0}), merkleNodeHash(MerkleLeafHash([]byte{0}), MerkleLeafHash([]byte{1}))) {
		t.Fatal("leaf/node domain separation broken")
	}
}
