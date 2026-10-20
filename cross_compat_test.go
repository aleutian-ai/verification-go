// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"crypto/sha512"
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

// TestCrossCompatibility_ChainHash verifies that the SDK chain hash computation
// produces identical results to the internal implementation.
//
// These test vectors are computed using the exact same algorithm as internal/chain/hash.go:
//
//	SHA512("aleutian.chain.v2:" + previous_hash + "|" + run_id + "|" + sequence_num + "|" + timestamp + "|" + content_hash)
//
// Timestamp format: "2006-01-02T15:04:05.000000Z" (microsecond precision, UTC)
func TestCrossCompatibility_ChainHash(t *testing.T) {
	// Compute expected hashes using the exact formula (reference implementation)
	computeExpected := func(prev, runID string, seq int64, ts time.Time, content string) string {
		tsFormatted := ts.UTC().Format("2006-01-02T15:04:05.000000Z")
		preimage := "aleutian.chain.v2:" + prev + "|" + runID + "|" + strconv.FormatInt(seq, 10) + "|" + tsFormatted + "|" + content
		hash := sha512.Sum512([]byte(preimage))
		return hex.EncodeToString(hash[:])
	}

	tests := []struct {
		name         string
		previousHash string
		runID        string
		sequenceNum  int64
		timestamp    time.Time
		contentHash  string
	}{
		{
			name:         "first_entry",
			previousHash: "",
			runID:        "run_550e8400-e29b-41d4-a716-446655440000",
			sequenceNum:  0,
			timestamp:    time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC),
			contentHash:  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		},
		{
			name:         "with_microseconds",
			previousHash: "e1c7f8ab8b9f8c3a2d1e4f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5de1c7f8ab8b9f8c3a2d1e4f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d",
			runID:        "run_550e8400-e29b-41d4-a716-446655440000",
			sequenceNum:  1,
			timestamp:    time.Date(2026, 1, 20, 12, 0, 1, 123456000, time.UTC), // 123456 microseconds
			contentHash:  "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
		},
		{
			name:         "large_sequence",
			previousHash: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			runID:        "run-large-seq",
			sequenceNum:  999999999,
			timestamp:    time.Date(2026, 12, 31, 23, 59, 59, 999999000, time.UTC),
			contentHash:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
		{
			name:         "tombstone_content",
			previousHash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			runID:        "run-tomb",
			sequenceNum:  5,
			timestamp:    time.Date(2026, 6, 15, 8, 30, 0, 0, time.UTC),
			contentHash:  "TOMBSTONE:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compute using SDK function
			sdkHash := ComputeChainHash(tt.previousHash, tt.runID, tt.sequenceNum, tt.timestamp, tt.contentHash)

			// Compute using direct formula (simulating internal implementation)
			expectedHash := computeExpected(tt.previousHash, tt.runID, tt.sequenceNum, tt.timestamp, tt.contentHash)

			if sdkHash != expectedHash {
				t.Errorf("chain hash mismatch:\n  SDK:      %s\n  Expected: %s", sdkHash, expectedHash)
			}
		})
	}
}

// TestCrossCompatibility_TimestampFormat verifies the timestamp formatting matches
// BigQuery's FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%E6SZ', ts) output.
func TestCrossCompatibility_TimestampFormat(t *testing.T) {
	tests := []struct {
		name     string
		time     time.Time
		expected string
	}{
		{
			name:     "zero_microseconds",
			time:     time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC),
			expected: "2026-01-20T12:00:00.000000Z",
		},
		{
			name:     "with_microseconds",
			time:     time.Date(2026, 1, 20, 12, 0, 1, 123456000, time.UTC),
			expected: "2026-01-20T12:00:01.123456Z",
		},
		{
			name:     "max_microseconds",
			time:     time.Date(2026, 1, 20, 12, 0, 0, 999999000, time.UTC),
			expected: "2026-01-20T12:00:00.999999Z",
		},
		{
			name:     "end_of_year",
			time:     time.Date(2026, 12, 31, 23, 59, 59, 999999000, time.UTC),
			expected: "2026-12-31T23:59:59.999999Z",
		},
		{
			name:     "single_digit_month_day",
			time:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			expected: "2026-01-01T00:00:00.000000Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatTimestampMicro(tt.time)
			if result != tt.expected {
				t.Errorf("timestamp format mismatch:\n  got:  %s\n  want: %s", result, tt.expected)
			}
		})
	}
}

// TestCrossCompatibility_ChainHashPrefix verifies the domain prefix matches.
func TestCrossCompatibility_ChainHashPrefix(t *testing.T) {
	expectedPrefix := "aleutian.chain.v2:"
	if ChainHashPrefix != expectedPrefix {
		t.Errorf("ChainHashPrefix = %q, want %q", ChainHashPrefix, expectedPrefix)
	}
}

// TestCrossCompatibility_TombstoneFormat verifies tombstone constants match internal.
func TestCrossCompatibility_TombstoneFormat(t *testing.T) {
	// These values must match internal/chain/tombstone.go
	if TombstoneContentHashPrefix != "TOMBSTONE:" {
		t.Errorf("TombstoneContentHashPrefix = %q, want %q", TombstoneContentHashPrefix, "TOMBSTONE:")
	}
	if TombstoneEntryIDPrefix != "tomb_" {
		t.Errorf("TombstoneEntryIDPrefix = %q, want %q", TombstoneEntryIDPrefix, "tomb_")
	}
	if TombstoneEntryType != "tombstone" {
		t.Errorf("TombstoneEntryType = %q, want %q", TombstoneEntryType, "tombstone")
	}
}

// TestCrossCompatibility_WebhookSignature verifies webhook signatures match internal.
func TestCrossCompatibility_WebhookSignature(t *testing.T) {
	// These values must match internal/webhook/constants.go
	if WebhookSignatureHeader != "X-Aleutian-Signature" {
		t.Errorf("WebhookSignatureHeader = %q, want %q", WebhookSignatureHeader, "X-Aleutian-Signature")
	}
	if WebhookSignatureVersion != "v1" {
		t.Errorf("WebhookSignatureVersion = %q, want %q", WebhookSignatureVersion, "v1")
	}
}
