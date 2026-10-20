// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// content_hash.go provides golden vector generation for cross-language
// content hash compatibility testing between Go and Python SDKs.
//
// # Two-Step Hash Pipeline
//
// The keyed content hash is computed in two steps:
//
//  1. SHA-512 with domain prefix (plaintext hash):
//     plaintext_hash = SHA-512("aleutian.content.v1:" + request + "\x00" + response)
//
//  2. HMAC-SHA512 wrap (keyed hash for BQ storage):
//     final_hash = HMAC-SHA512(key=company_key, msg=plaintext_hash_bytes)
//
// The HMAC input is the 64-byte raw SHA-512 digest, NOT the hex string.
// This is the critical cross-language contract: Python must decode the
// hex to bytes before computing HMAC, matching Go exactly.
//
// # References
//
//   - FIPS 198-1: HMAC construction
//   - FIPS 180-4: SHA-512
//   - Ticket 25_35b: Go batch handler implementation
//   - Ticket 25_35c: Cross-language golden test (this file)

package verification

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

// ContentHashGoldenVector holds one cross-language test vector for
// the keyed content hash pipeline.
//
// # Description
//
// Each vector captures the full two-step computation:
//  1. SHA-512 of the domain-prefixed payload (SHA512Hex — intermediate)
//  2. HMAC-SHA512 of the 64-byte digest using the company key (ExpectedContentHash — final)
//
// The Python SDK must produce ExpectedContentHash given the same inputs.
// Any divergence indicates the HMAC input differs (bytes vs hex string).
//
// # Fields
//
//   - ID: unique vector identifier for test reporting
//   - CompanyKeyHex: 64-char hex encoding of the 32-byte company key
//   - Request: plaintext request string
//   - Response: plaintext response string (empty for blocks vectors)
//   - Blocks: canonical JSON string for multi-block vectors (empty for single-block)
//   - DomainPrefix: hash domain prefix (aleutian.content.v1: or aleutian.content.blocks.v1:)
//   - SHA512Hex: intermediate 128-char hex SHA-512 of the domain-prefixed payload
//   - ExpectedContentHash: final 128-char hex HMAC-SHA512 output
type ContentHashGoldenVector struct {
	ID                  string `json:"id"`
	CompanyKeyHex       string `json:"company_key_hex"`
	Request             string `json:"request"`
	Response            string `json:"response,omitempty"`
	Blocks              string `json:"blocks,omitempty"`
	DomainPrefix        string `json:"domain_prefix"`
	SHA512Hex           string `json:"sha512_hex"`
	ExpectedContentHash string `json:"expected_content_hash"`
}

// singleBlockDomainPrefix is the domain prefix for single-block content hashes.
// Must match CONTENT_HASH_PREFIX in the Python SDK and the Go normalizer.
const singleBlockDomainPrefix = "aleutian.content.v1:"

// multiBlockDomainPrefix is the domain prefix for multi-block content hashes.
// Must match CONTENT_HASH_BLOCKS_PREFIX in the Python SDK and the Go normalizer.
const multiBlockDomainPrefix = "aleutian.content.blocks.v1:"

// computeSingleBlockSHA512 returns the 64-byte SHA-512 digest of the
// domain-prefixed single-block payload: domain_prefix + request + "\x00" + response.
func computeSingleBlockSHA512(request, response string) []byte {
	h := sha512.New()
	h.Write([]byte(singleBlockDomainPrefix))
	h.Write([]byte(request))
	h.Write([]byte{0x00})
	h.Write([]byte(response))
	return h.Sum(nil)
}

// computeMultiBlockSHA512 returns the 64-byte SHA-512 digest of the
// domain-prefixed multi-block payload: domain_prefix + request + "\x00" + blocksJSON.
func computeMultiBlockSHA512(request, blocksJSON string) []byte {
	h := sha512.New()
	h.Write([]byte(multiBlockDomainPrefix))
	h.Write([]byte(request))
	h.Write([]byte{0x00})
	h.Write([]byte(blocksJSON))
	return h.Sum(nil)
}

// hmacSHA512Hex computes HMAC-SHA512(key, msg) and returns the 128-char hex output.
// msg must be the raw 64-byte digest, not hex-encoded.
// Returns an error if key is shorter than 32 bytes.
func hmacSHA512Hex(key, msg []byte) (string, error) {
	if len(key) < 32 {
		return "", fmt.Errorf("hmacSHA512Hex: key must be at least 32 bytes, got %d", len(key))
	}
	mac := hmac.New(sha512.New, key)
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// makeSingleBlockVector builds a ContentHashGoldenVector for a single-block interaction.
// id is the vector identifier. companyKey must be exactly 32 bytes.
func makeSingleBlockVector(id string, companyKey []byte, request, response string) ContentHashGoldenVector {
	sha512Bytes := computeSingleBlockSHA512(request, response)
	sha512HexStr := hex.EncodeToString(sha512Bytes)
	finalHash, err := hmacSHA512Hex(companyKey, sha512Bytes)
	if err != nil {
		panic(fmt.Sprintf("makeSingleBlockVector %q: %v", id, err))
	}
	return ContentHashGoldenVector{
		ID:                  id,
		CompanyKeyHex:       hex.EncodeToString(companyKey),
		Request:             request,
		Response:            response,
		DomainPrefix:        singleBlockDomainPrefix,
		SHA512Hex:           sha512HexStr,
		ExpectedContentHash: finalHash,
	}
}

// makeMultiBlockVector builds a ContentHashGoldenVector for a multi-block interaction.
// blocksJSON is the canonical JSON string (already serialized). companyKey must be 32 bytes.
func makeMultiBlockVector(id string, companyKey []byte, request, blocksJSON string) ContentHashGoldenVector {
	sha512Bytes := computeMultiBlockSHA512(request, blocksJSON)
	sha512HexStr := hex.EncodeToString(sha512Bytes)
	finalHash, err := hmacSHA512Hex(companyKey, sha512Bytes)
	if err != nil {
		panic(fmt.Sprintf("makeMultiBlockVector %q: %v", id, err))
	}
	return ContentHashGoldenVector{
		ID:                  id,
		CompanyKeyHex:       hex.EncodeToString(companyKey),
		Request:             request,
		Blocks:              blocksJSON,
		DomainPrefix:        multiBlockDomainPrefix,
		SHA512Hex:           sha512HexStr,
		ExpectedContentHash: finalHash,
	}
}

// GenerateContentHashGoldenVectors returns the set of cross-language test vectors
// for the keyed content hash pipeline.
//
// # Description
//
// Generates vectors covering: single-block basic, unicode content, empty response,
// non-zero key, and multi-block path. All vectors use synthetic test data only —
// no real customer prompts or real company keys.
//
// # Outputs
//
//   - []ContentHashGoldenVector: at least 5 vectors covering all code paths
//
// # Assumptions
//
//   - Callers write this to sdk/testdata/content_hash_golden.json
//   - Python test reads the file and verifies exact match
//   - SOC2 CC6: no real customer data in golden vectors
func GenerateContentHashGoldenVectors() []ContentHashGoldenVector {
	// All-zero key: simplest case, easy to reproduce manually.
	zeroKey := make([]byte, 32)

	// Incrementing key: 0x00, 0x01, ..., 0x1F.
	incrKey := make([]byte, 32)
	for i := range incrKey {
		incrKey[i] = byte(i)
	}

	// Alternating key: 0xAA, 0x55, 0xAA, ...
	altKey := make([]byte, 32)
	for i := range altKey {
		if i%2 == 0 {
			altKey[i] = 0xAA
		} else {
			altKey[i] = 0x55
		}
	}

	return []ContentHashGoldenVector{
		// Vector 1: basic single-block with all-zero key
		makeSingleBlockVector(
			"single-block-basic",
			zeroKey,
			"hello",
			"world",
		),
		// Vector 2: unicode content (emoji + multibyte chars)
		makeSingleBlockVector(
			"single-block-unicode",
			incrKey,
			"什么是递归？",
			"递归是指函数调用自身。例如：f(n) = n * f(n-1) 🔁",
		),
		// Vector 3: empty response
		makeSingleBlockVector(
			"single-block-empty-response",
			zeroKey,
			"ping",
			"",
		),
		// Vector 4: non-trivial key and longer content
		makeSingleBlockVector(
			"single-block-long-content",
			altKey,
			"explain the concept of gradient descent in machine learning",
			"Gradient descent is an optimization algorithm used to minimize a loss function by iteratively moving in the direction of steepest descent.",
		),
		// Vector 5: multi-block path (single text block)
		// blocksJSON matches Python's _canonicalize_blocks_json output exactly.
		makeMultiBlockVector(
			"blocks-single-text",
			incrKey,
			"run the deploy script",
			`[{"type":"text","name":"","input":"","text":"Running deploy..."}]`,
		),
		// Vector 6: multi-block with tool_use (JSON input canonicalized)
		makeMultiBlockVector(
			"blocks-tool-use",
			zeroKey,
			"write a go main file",
			`[{"type":"text","name":"","input":"","text":"here is the code:"},{"type":"tool_use","name":"write_file","input":"{\"content\":\"package main\",\"path\":\"main.go\"}","text":""}]`,
		),
	}
}
