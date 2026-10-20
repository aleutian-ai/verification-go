// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// goldenFile is the path to this module's copy of
// sdk/testdata/content_hash_golden.json, relative to this file and resolved at
// test time via runtime.Caller. The copy lets the tests pass outside the
// monorepo; scripts/publish-sdks.sh refuses one that differs from
// sdk/testdata.
const contentHashGoldenFile = "testdata/shared/content_hash_golden.json"

// contentHashGoldenRoot is the JSON envelope written to the golden file.
type contentHashGoldenRoot struct {
	Version     string                    `json:"version"`
	Description string                    `json:"description"`
	Algorithm   string                    `json:"algorithm"`
	Note        string                    `json:"note"`
	Vectors     []ContentHashGoldenVector `json:"vectors"`
}

// resolveGoldenPath returns an absolute path to the golden JSON file,
// resolved relative to this source file's directory.
func resolveGoldenPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), contentHashGoldenFile)
}

// TestContentHash_GenerateGoldenFile writes the golden JSON fixture to
// sdk/testdata/content_hash_golden.json.
//
// Run this test once (or after any algorithm change) to regenerate the file:
//
//	go test -run TestContentHash_GenerateGoldenFile ./sdk/verification-go/
//
// The generated file must be committed. CI verifies it by reading it back
// (TestContentHash_GoldenVectorsCorrect) and the Python test reads it too.
func TestContentHash_GenerateGoldenFile(t *testing.T) {
	vectors := GenerateContentHashGoldenVectors()
	root := contentHashGoldenRoot{
		Version:     "1",
		Description: "Cross-language content hash golden vectors for HMAC-SHA512 keyed path",
		Algorithm:   "HMAC-SHA512(company_content_key, SHA-512(domain_prefix + request + 0x00 + response_or_blocks))",
		Note:        "HMAC input is the 64-byte raw SHA-512 digest, NOT the hex string. Python must decode hex before HMACing.",
		Vectors:     vectors,
	}

	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		t.Fatalf("marshal golden root: %v", err)
	}
	data = append(data, '\n') // trailing newline

	goldenPath := resolveGoldenPath(t)
	if err := os.WriteFile(goldenPath, data, 0o644); err != nil {
		t.Fatalf("write golden file %s: %v", goldenPath, err)
	}
	t.Logf("wrote %d vectors to %s", len(vectors), goldenPath)
}

// TestContentHash_GoldenVectorsCorrect reads sdk/testdata/content_hash_golden.json
// and verifies that each vector's ExpectedContentHash is correct.
//
// This test runs in CI and catches any accidental drift between the generator
// and the committed file.
func TestContentHash_GoldenVectorsCorrect(t *testing.T) {
	goldenPath := resolveGoldenPath(t)
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file %s: %v (run TestContentHash_GenerateGoldenFile first)", goldenPath, err)
	}

	var root contentHashGoldenRoot
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("unmarshal golden file: %v", err)
	}

	if len(root.Vectors) < 5 {
		t.Fatalf("golden file has %d vectors, want at least 5", len(root.Vectors))
	}

	for _, v := range root.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			keyBytes, err := hex.DecodeString(v.CompanyKeyHex)
			if err != nil {
				t.Fatalf("decode company_key_hex: %v", err)
			}

			// Recompute SHA-512 from the domain prefix and payload.
			var sha512Bytes []byte
			if v.Blocks != "" {
				sha512Bytes = computeMultiBlockSHA512(v.Request, v.Blocks)
			} else {
				sha512Bytes = computeSingleBlockSHA512(v.Request, v.Response)
			}

			// Verify SHA512Hex matches.
			wantSHA512Hex := hex.EncodeToString(sha512Bytes)
			if v.SHA512Hex != wantSHA512Hex {
				t.Errorf("SHA512Hex mismatch:\n  got:  %s\n  want: %s", v.SHA512Hex, wantSHA512Hex)
			}

			// Recompute HMAC-SHA512 using decoded bytes (not hex string).
			mac := hmac.New(sha512.New, keyBytes)
			mac.Write(sha512Bytes)
			gotFinalHash := hex.EncodeToString(mac.Sum(nil))

			if gotFinalHash != v.ExpectedContentHash {
				t.Errorf("ExpectedContentHash mismatch:\n  got:  %s\n  want: %s", gotFinalHash, v.ExpectedContentHash)
			}

			// Verify output is 128-char lowercase hex (64-byte HMAC-SHA512 output).
			if len(v.ExpectedContentHash) != 128 {
				t.Errorf("ExpectedContentHash length = %d, want 128", len(v.ExpectedContentHash))
			}
		})
	}
}

// TestContentHash_HMACInputIsDecodedBytes verifies that the golden vectors
// use decoded bytes as HMAC input — NOT the hex string.
//
// If a golden vector used hex-string input, HMAC(key, hex_string) would equal
// HMAC(key, hex_string_bytes), which is a 128-byte message instead of 64 bytes.
// This test catches that class of bug by verifying the two paths differ.
func TestContentHash_HMACInputIsDecodedBytes(t *testing.T) {
	goldenPath := resolveGoldenPath(t)
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Skipf("golden file not found (%v) — run TestContentHash_GenerateGoldenFile first", err)
	}

	var root contentHashGoldenRoot
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, v := range root.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			keyBytes, err := hex.DecodeString(v.CompanyKeyHex)
			if err != nil {
				t.Fatalf("decode key: %v", err)
			}

			sha512HexBytes := []byte(v.SHA512Hex) // the 128-char hex string as bytes

			// HMAC of the hex string (incorrect behavior).
			macHex := hmac.New(sha512.New, keyBytes)
			macHex.Write(sha512HexBytes)
			wrongHash := hex.EncodeToString(macHex.Sum(nil))

			// ExpectedContentHash must NOT equal HMAC(key, hex_string).
			if v.ExpectedContentHash == wrongHash {
				t.Errorf("vector %q: ExpectedContentHash equals HMAC(key, hex_string) — HMAC input must be decoded bytes, not hex string", v.ID)
			}
		})
	}
}
