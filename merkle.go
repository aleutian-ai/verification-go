// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"crypto/sha512"
	"crypto/subtle"
)

// RFC 9162 (Certificate Transparency 2.0) Merkle tree verification, SHA-512 variant
// (Aleutian ADR 003 — chainlinker_modernization_02h). Byte-identical to the server's
// internal/merkle: leaf domain byte 0x00, node domain byte 0x01, SHA-512 throughout.
//
// This is the offline VERIFY half only — customers fold a proof served by audit-api up to
// the Merkle root that a signature-verified v5 anchor committed to. Proof GENERATION is
// server-side and not mirrored here.

const merkleHashSize = sha512.Size

// MerkleLeafHash computes the RFC 9162 leaf hash SHA-512(0x00 || data). For the audit
// chain, data is the 64 RAW bytes of an entry's content_hash (hex-decode first — hashing
// the ASCII hex would diverge from the server).
func MerkleLeafHash(data []byte) []byte {
	h := sha512.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// merkleNodeHash computes SHA-512(0x01 || left || right).
func merkleNodeHash(left, right []byte) []byte {
	h := sha512.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// MerkleEmptyRoot is the RFC 9162 empty-tree hash SHA-512("").
func MerkleEmptyRoot() []byte {
	s := sha512.Sum512(nil)
	return s[:]
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less than n (n > 1).
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// VerifyMerkleInclusion verifies an RFC 9162 inclusion proof: that leafHash is the leaf at
// index m of a tree of the given size whose root is root. root MUST come from a
// signature-verified v5 anchor.
func VerifyMerkleInclusion(leafHash []byte, m, treeSize int, proof [][]byte, root []byte) bool {
	if m < 0 || treeSize <= 0 || m >= treeSize {
		return false
	}
	computed, ok := rootFromMerkleInclusion(leafHash, m, treeSize, proof)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(computed, root) == 1
}

func rootFromMerkleInclusion(leafHash []byte, m, n int, proof [][]byte) ([]byte, bool) {
	if n == 1 {
		if len(proof) != 0 {
			return nil, false
		}
		return leafHash, true
	}
	if len(proof) == 0 {
		return nil, false
	}
	sibling := proof[len(proof)-1]
	rest := proof[:len(proof)-1]
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		left, ok := rootFromMerkleInclusion(leafHash, m, k, rest)
		if !ok {
			return nil, false
		}
		return merkleNodeHash(left, sibling), true
	}
	right, ok := rootFromMerkleInclusion(leafHash, m-k, n-k, rest)
	if !ok {
		return nil, false
	}
	return merkleNodeHash(sibling, right), true
}

// VerifyMerkleConsistency verifies an RFC 9162 consistency proof: that the tree of size n
// (root rootB) is an append-only extension of the tree of size m (root rootA). Both roots
// MUST come from signature-verified anchors.
func VerifyMerkleConsistency(m, n int, rootA, rootB []byte, proof [][]byte) bool {
	if m < 0 || n < 0 || m > n {
		return false
	}
	if m == n {
		return len(proof) == 0 && subtle.ConstantTimeCompare(rootA, rootB) == 1
	}
	if m == 0 {
		return len(proof) == 0 && subtle.ConstantTimeCompare(rootA, MerkleEmptyRoot()) == 1
	}
	if len(proof) == 0 {
		return false
	}

	node := m - 1
	lastNode := n - 1
	for node%2 == 1 {
		node /= 2
		lastNode /= 2
	}

	var hash1, hash2 []byte
	idx := 0
	if node > 0 {
		hash1 = proof[0]
		hash2 = proof[0]
		idx = 1
	} else {
		hash1 = rootA
		hash2 = rootA
	}

	for ; idx < len(proof); idx++ {
		if lastNode == 0 {
			return false
		}
		p := proof[idx]
		if node%2 == 1 || node == lastNode {
			hash1 = merkleNodeHash(p, hash1)
			hash2 = merkleNodeHash(p, hash2)
			for node%2 == 0 && node != 0 {
				node /= 2
				lastNode /= 2
			}
		} else {
			hash2 = merkleNodeHash(hash2, p)
		}
		node /= 2
		lastNode /= 2
	}

	return subtle.ConstantTimeCompare(hash1, rootA) == 1 &&
		subtle.ConstantTimeCompare(hash2, rootB) == 1
}
