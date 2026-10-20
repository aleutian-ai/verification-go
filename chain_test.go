// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"testing"
	"time"
)

func TestComputeChainHash(t *testing.T) {
	tests := []struct {
		name         string
		previousHash string
		runID        string
		sequenceNum  int64
		timestamp    time.Time
		contentHash  string
	}{
		{
			name:         "first entry empty previous",
			previousHash: "",
			runID:        "run_550e8400-e29b-41d4-a716-446655440000",
			sequenceNum:  0,
			timestamp:    time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC),
			contentHash:  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		},
		{
			name:         "subsequent entry with previous hash",
			previousHash: "e1c7f8ab8b9f8c3a2d1e4f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5de1c7f8ab8b9f8c3a2d1e4f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d",
			runID:        "run_550e8400-e29b-41d4-a716-446655440000",
			sequenceNum:  1,
			timestamp:    time.Date(2026, 1, 20, 12, 0, 1, 123456000, time.UTC),
			contentHash:  "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
		},
		{
			name:         "tombstone content hash",
			previousHash: "f2d8e9bc9c0a9d4b3e2f5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6ef2d8e9bc9c0a9d4b3e2f5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
			runID:        "run_550e8400-e29b-41d4-a716-446655440000",
			sequenceNum:  2,
			timestamp:    time.Date(2026, 1, 20, 12, 0, 2, 0, time.UTC),
			contentHash:  "TOMBSTONE:c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
		},
		{
			name:         "large sequence number",
			previousHash: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			runID:        "run-xyz",
			sequenceNum:  999999999,
			timestamp:    time.Date(2026, 12, 31, 23, 59, 59, 999999000, time.UTC),
			contentHash:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := ComputeChainHash(tt.previousHash, tt.runID, tt.sequenceNum, tt.timestamp, tt.contentHash)

			// Verify hash is 128 lowercase hex characters (SHA-512)
			if len(hash) != 128 {
				t.Errorf("hash length = %d, want 128", len(hash))
			}
			for _, c := range hash {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("hash contains non-lowercase-hex character: %c", c)
					break
				}
			}

			// Verify determinism
			hash2 := ComputeChainHash(tt.previousHash, tt.runID, tt.sequenceNum, tt.timestamp, tt.contentHash)
			if hash != hash2 {
				t.Errorf("hash not deterministic: got %s and %s", hash, hash2)
			}
		})
	}
}

func TestComputeChainHashMs(t *testing.T) {
	// Test that ComputeChainHashMs produces same result as ComputeChainHash
	// when timestamp has no sub-millisecond precision
	ts := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	tsMs := ts.UnixMilli()

	hash1 := ComputeChainHash("", "run-xyz", 0, ts, "abc123")
	hash2 := ComputeChainHashMs("", "run-xyz", 0, tsMs, "abc123")

	if hash1 != hash2 {
		t.Errorf("ComputeChainHashMs produced different hash:\n  ComputeChainHash:   %s\n  ComputeChainHashMs: %s", hash1, hash2)
	}
}

func TestFormatTimestampMicro(t *testing.T) {
	tests := []struct {
		name     string
		time     time.Time
		expected string
	}{
		{
			name:     "zero microseconds",
			time:     time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC),
			expected: "2026-01-20T12:00:00.000000Z",
		},
		{
			name:     "with microseconds",
			time:     time.Date(2026, 1, 20, 12, 0, 1, 123456000, time.UTC),
			expected: "2026-01-20T12:00:01.123456Z",
		},
		{
			name:     "max values",
			time:     time.Date(2099, 12, 31, 23, 59, 59, 999999000, time.UTC),
			expected: "2099-12-31T23:59:59.999999Z",
		},
		{
			name:     "non-UTC timezone converted",
			time:     time.Date(2026, 1, 20, 14, 0, 0, 0, time.FixedZone("EST", -5*3600)),
			expected: "2026-01-20T19:00:00.000000Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatTimestampMicro(tt.time)
			if result != tt.expected {
				t.Errorf("FormatTimestampMicro() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestVerifyChainOffline(t *testing.T) {
	ctx := context.Background()

	// Build a valid chain
	ts1 := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	ts2 := time.Date(2026, 1, 20, 12, 0, 1, 0, time.UTC)
	ts3 := time.Date(2026, 1, 20, 12, 0, 2, 0, time.UTC)

	hash1 := ComputeChainHash("", "run-123", 0, ts1, "content1")
	hash2 := ComputeChainHash(hash1, "run-123", 1, ts2, "content2")
	hash3 := ComputeChainHash(hash2, "run-123", 2, ts3, "content3")

	validEntries := []ExportedEntry{
		{
			EntryID:     "entry_1",
			EntryType:   "request",
			Timestamp:   FormatTimestampMicro(ts1),
			RunID:       "run-123",
			SequenceNum: 0,
			GlobalSeq:   1,
			ContentHash: "content1",
			ChainHash:   hash1,
		},
		{
			EntryID:     "entry_2",
			EntryType:   "request",
			Timestamp:   FormatTimestampMicro(ts2),
			RunID:       "run-123",
			SequenceNum: 1,
			GlobalSeq:   2,
			ContentHash: "content2",
			ChainHash:   hash2,
		},
		{
			EntryID:     "entry_3",
			EntryType:   "request",
			Timestamp:   FormatTimestampMicro(ts3),
			RunID:       "run-123",
			SequenceNum: 2,
			GlobalSeq:   3,
			ContentHash: "content3",
			ChainHash:   hash3,
		},
	}

	t.Run("valid chain", func(t *testing.T) {
		result, err := VerifyChainOffline(ctx, validEntries, ChainVerifyOptions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Valid {
			t.Errorf("expected valid chain, got %d breaks", len(result.Breaks))
			for _, b := range result.Breaks {
				t.Logf("break: %+v", b)
			}
		}
		if result.EntriesVerified != 3 {
			t.Errorf("EntriesVerified = %d, want 3", result.EntriesVerified)
		}
	})

	t.Run("valid chain with deprecated ExpectedLastHash", func(t *testing.T) {
		// Legacy raw-equality path. Kept until next minor for callers who
		// hand-fed the entry's chain_hash. Cannot bind to a real producer
		// anchor — see anchor-binding test below for the supported flow.
		result, err := VerifyChainOffline(ctx, validEntries, ChainVerifyOptions{
			ExpectedLastHash: hash3,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Valid {
			t.Errorf("expected valid chain, got %d breaks", len(result.Breaks))
		}
	})

	t.Run("valid chain with Anchor binding (genesis)", func(t *testing.T) {
		// Build a producer-style anchor: chain_hash is the result of
		// ComputeAnchorChainHash, NOT byte-equal to the entry's hash.
		anchor := Anchor{
			Version:          3,
			AnchorID:         "anchor_test",
			CompanyID:        "comp_test",
			Range:            EntryRange{StartEntryID: "entry-1", EndEntryID: "entry-3"},
			EntryCount:       3,
			PreviousAnchorID: SeedAnchorID,
			ChainHash: ComputeAnchorChainHash(
				SeedAnchorHash, "comp_test", "entry-1", "entry-3", hash3,
			),
		}
		result, err := VerifyChainOffline(ctx, validEntries, ChainVerifyOptions{
			Anchor: &anchor,
			// PreviousAnchorHash left empty; SDK fills from SeedAnchorHash
			// because PreviousAnchorID == SeedAnchorID.
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Valid {
			t.Errorf("expected valid anchor-bound chain, got %d breaks:", len(result.Breaks))
			for _, b := range result.Breaks {
				t.Logf("  %+v", b)
			}
		}
	})

	t.Run("Anchor binding mismatch", func(t *testing.T) {
		// Tampered anchor.chain_hash — binding must fail.
		anchor := Anchor{
			Version:          3,
			AnchorID:         "anchor_bad",
			CompanyID:        "comp_test",
			Range:            EntryRange{StartEntryID: "entry-1", EndEntryID: "entry-3"},
			EntryCount:       3,
			PreviousAnchorID: SeedAnchorID,
			ChainHash:        "deadbeef" + hash3[8:], // wrong
		}
		result, err := VerifyChainOffline(ctx, validEntries, ChainVerifyOptions{
			Anchor: &anchor,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Valid {
			t.Errorf("expected invalid due to anchor binding mismatch")
		}
		if len(result.Breaks) == 0 || result.Breaks[len(result.Breaks)-1].BreakType != "anchor_mismatch" {
			t.Errorf("expected anchor_mismatch break, got %+v", result.Breaks)
		}
	})

	t.Run("deprecated ExpectedLastHash mismatch", func(t *testing.T) {
		result, err := VerifyChainOffline(ctx, validEntries, ChainVerifyOptions{
			ExpectedLastHash: "wrong_hash",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Valid {
			t.Errorf("expected invalid chain due to anchor mismatch")
		}
		if len(result.Breaks) != 1 {
			t.Errorf("expected 1 break, got %d", len(result.Breaks))
		}
		if result.Breaks[0].BreakType != "anchor_mismatch" {
			t.Errorf("expected anchor_mismatch, got %s", result.Breaks[0].BreakType)
		}
	})

	t.Run("hash mismatch", func(t *testing.T) {
		tamperedEntries := make([]ExportedEntry, len(validEntries))
		copy(tamperedEntries, validEntries)
		tamperedEntries[1].ChainHash = "tampered_hash"

		result, err := VerifyChainOffline(ctx, tamperedEntries, ChainVerifyOptions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Valid {
			t.Errorf("expected invalid chain due to hash mismatch")
		}
		found := false
		for _, b := range result.Breaks {
			if b.BreakType == "hash_mismatch" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected hash_mismatch break type")
		}
	})

	t.Run("sequence gap", func(t *testing.T) {
		gapEntries := make([]ExportedEntry, len(validEntries))
		copy(gapEntries, validEntries)
		gapEntries[2].GlobalSeq = 5 // Gap from 2 to 5

		result, err := VerifyChainOffline(ctx, gapEntries, ChainVerifyOptions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		found := false
		for _, b := range result.Breaks {
			if b.BreakType == "sequence_gap" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected sequence_gap break type")
		}
	})

	t.Run("empty entries", func(t *testing.T) {
		_, err := VerifyChainOffline(ctx, []ExportedEntry{}, ChainVerifyOptions{})
		if err != ErrEmptyEntries {
			t.Errorf("expected ErrEmptyEntries, got %v", err)
		}
	})

	t.Run("max entries limit", func(t *testing.T) {
		result, err := VerifyChainOffline(ctx, validEntries, ChainVerifyOptions{
			MaxEntries: 2,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.EntriesVerified != 2 {
			t.Errorf("EntriesVerified = %d, want 2", result.EntriesVerified)
		}
	})

	t.Run("max breaks limit", func(t *testing.T) {
		// Create entries with multiple breaks
		brokenEntries := []ExportedEntry{
			{
				EntryID:     "entry_1",
				EntryType:   "request",
				Timestamp:   FormatTimestampMicro(ts1),
				RunID:       "run-123",
				SequenceNum: 0,
				GlobalSeq:   1,
				ContentHash: "content1",
				ChainHash:   "wrong1",
			},
			{
				EntryID:     "entry_2",
				EntryType:   "request",
				Timestamp:   FormatTimestampMicro(ts2),
				RunID:       "run-123",
				SequenceNum: 1,
				GlobalSeq:   2,
				ContentHash: "content2",
				ChainHash:   "wrong2",
			},
			{
				EntryID:     "entry_3",
				EntryType:   "request",
				Timestamp:   FormatTimestampMicro(ts3),
				RunID:       "run-123",
				SequenceNum: 2,
				GlobalSeq:   3,
				ContentHash: "content3",
				ChainHash:   "wrong3",
			},
		}

		result, err := VerifyChainOffline(ctx, brokenEntries, ChainVerifyOptions{
			MaxBreaks: 1,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Breaks) > 1 {
			t.Errorf("expected at most 1 break with MaxBreaks=1, got %d", len(result.Breaks))
		}
	})
}

// TestVerifyChainOfflineWithTombstones verifies a chain containing an entry that
// was lawfully erased.
//
// # How the fixture is built, and why it matters (sdk_verify_01)
//
// This test previously computed the tombstone's chain hash FROM the tombstone
// content hash:
//
//	hash2 := ComputeChainHash(hash1, "run-123", 1, ts2, tombstoneHash)  // WRONG
//
// A producer never emits that value. internal/storage/tombstone.go CreateTombstone
// PRESERVES the original entry's chain hash — computed from its real content hash
// before erasure — so that entries chained after it stay correctly linked, and so
// that anchors signed over that range remain valid.
//
// The old fixture therefore described an entry that cannot occur in production,
// and it passed against a verifier that recomputed tombstone hashes. Real chains
// were reported as broken while this test stayed green.
//
// Build the tombstone the way the producer does: hash from the ORIGINAL content,
// then preserve it.
func TestVerifyChainOfflineWithTombstones(t *testing.T) {
	ctx := context.Background()

	ts1 := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	ts2 := time.Date(2026, 1, 20, 12, 0, 1, 0, time.UTC)

	// Valid tombstone content hash — random by construction, so it cannot be
	// recomputed from anything.
	tombstoneHash := "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	// The entry's REAL content hash, before erasure.
	originalContentHash := "content2"

	hash1 := ComputeChainHash("", "run-123", 0, ts1, "content1")
	// Computed from the ORIGINAL content, then preserved through the erasure.
	hash2 := ComputeChainHash(hash1, "run-123", 1, ts2, originalContentHash)

	entries := []ExportedEntry{
		{
			EntryID:     "entry_1",
			EntryType:   "request",
			Timestamp:   FormatTimestampMicro(ts1),
			RunID:       "run-123",
			SequenceNum: 0,
			GlobalSeq:   1,
			ContentHash: "content1",
			ChainHash:   hash1,
		},
		{
			EntryID:     "tomb_550e8400-e29b-41d4-a716-446655440000",
			EntryType:   "tombstone",
			Timestamp:   FormatTimestampMicro(ts2),
			RunID:       "run-123",
			SequenceNum: 1,
			GlobalSeq:   2,
			ContentHash: tombstoneHash,
			ChainHash:   hash2,
		},
	}

	result, err := VerifyChainOffline(ctx, entries, ChainVerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid chain with tombstone")
		for _, b := range result.Breaks {
			t.Logf("break: %+v", b)
		}
	}
	if result.TombstonesFound != 1 {
		t.Errorf("TombstonesFound = %d, want 1", result.TombstonesFound)
	}
}

func TestVerifyChainOfflineInvalidTombstone(t *testing.T) {
	ctx := context.Background()

	ts1 := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)

	// Invalid tombstone content hash (too short)
	invalidTombstoneHash := "TOMBSTONE:short"

	hash1 := ComputeChainHash("", "run-123", 0, ts1, invalidTombstoneHash)

	entries := []ExportedEntry{
		{
			EntryID:     "tomb_550e8400-e29b-41d4-a716-446655440000",
			EntryType:   "tombstone",
			Timestamp:   FormatTimestampMicro(ts1),
			RunID:       "run-123",
			SequenceNum: 0,
			GlobalSeq:   1,
			ContentHash: invalidTombstoneHash,
			ChainHash:   hash1,
		},
	}

	result, err := VerifyChainOffline(ctx, entries, ChainVerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Errorf("expected invalid chain due to invalid tombstone")
	}
	found := false
	for _, b := range result.Breaks {
		if b.BreakType == "invalid_tombstone" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected invalid_tombstone break type")
	}
}
