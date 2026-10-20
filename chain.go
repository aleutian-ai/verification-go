// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"strconv"
	"time"
)

// ChainHashPrefix is the domain separation prefix for chain hash computation.
//
// # Description
//
// This prefix provides:
//   - Namespace isolation: prevents cross-context hash confusion
//   - Version identifier: "v2" identifies the SHA-512 chain hash algorithm
//   - Distinct terminator: ':' separates prefix from field data
//
// v2 replaced v1 (SHA-256) to achieve ~2^170 quantum collision resistance (BHT)
// vs ~2^85 for SHA-256, matching NIST guidance for long-term tamper-evident logs.
const ChainHashPrefix = "aleutian.chain.v2:"

// ComputeChainHash computes the SHA-512 chain hash for an audit entry.
//
// # Description
//
// Uses Aleutian's chain hash formula:
//
//	SHA512("aleutian.chain.v2:" + previousHash + "|" + runID + "|" + sequenceNum + "|" + timestamp + "|" + contentHash)
//
// The timestamp is formatted as RFC3339 with microsecond precision:
// "2006-01-02T15:04:05.000000Z"
//
// # Inputs
//
//   - previousHash: Previous entry's chain_hash (empty string for first entry in chain)
//   - runID: Batch run identifier (UUID)
//   - sequenceNum: 0-indexed position within the batch run
//   - timestamp: Entry timestamp. Must be the exact value from storage.
//   - contentHash: SHA-512 hex digest of entry content, or tombstone content hash
//
// # Outputs
//
//   - string: 128-character lowercase hex SHA-512 hash
//
// # Examples
//
// First entry in a chain:
//
//	hash := ComputeChainHash("", "run-550e8400", 0, entryTime, "a1b2c3...")
//
// Subsequent entry:
//
//	hash := ComputeChainHash(prevHash, "run-550e8400", 1, entryTime, "d4e5f6...")
//
// # Limitations
//
//   - Caller must ensure timestamp matches the exact value from storage.
//     Any precision differences will produce different hashes.
//
// # Assumptions
//
//   - previousHash is "" (first entry) or a 128-character lowercase hex string (SHA-512)
//   - runID does NOT contain the pipe character '|'
//   - sequenceNum is non-negative
//   - contentHash does NOT contain the pipe character '|'
//   - timestamp will be converted to UTC if not already
func ComputeChainHash(previousHash, runID string, sequenceNum int64, timestamp time.Time, contentHash string) string {
	// Build the preimage in a stack-allocated buffer.
	// Typical size: ~361 bytes (prefix + 128-char hash + uuid + seq + timestamp + 128-char hash + separators)
	// 512-byte buffer handles all cases without heap allocation.
	var buf [512]byte
	input := buf[:0]

	// Build: "aleutian.chain.v2:" + previousHash|runID|sequenceNum|timestamp|contentHash
	input = append(input, ChainHashPrefix...)
	input = append(input, previousHash...)
	input = append(input, '|')
	input = append(input, runID...)
	input = append(input, '|')
	input = strconv.AppendInt(input, sequenceNum, 10)
	input = append(input, '|')
	input = appendTimestampMicro(input, timestamp)
	input = append(input, '|')
	input = append(input, contentHash...)

	// Compute SHA-512. Sum512 returns a [64]byte → 128 hex chars.
	sum := sha512.Sum512(input)
	return hex.EncodeToString(sum[:])
}

// ComputeChainHashMs computes the chain hash using a millisecond timestamp.
//
// # Description
//
// Equivalent to [ComputeChainHash] but accepts the timestamp as int64
// milliseconds since Unix epoch (UTC). The timestamp is formatted with
// microsecond precision where the last 3 digits are always "000".
//
// This function is intended for SDK callers that work with int64 timestamps.
//
// # Inputs
//
//   - previousHash: Previous entry's chain_hash (empty for first entry)
//   - runID: Batch run identifier
//   - sequenceNum: 0-indexed position within the batch run
//   - timestampMs: Unix timestamp in milliseconds (UTC)
//   - contentHash: SHA-512 hex digest of entry content
//
// # Outputs
//
//   - string: 128-character lowercase hex SHA-512 hash
//
// # Limitations
//
//   - Loses sub-millisecond precision. If the original timestamp has
//     non-zero microseconds beyond milliseconds, this function will
//     produce a different hash than [ComputeChainHash].
func ComputeChainHashMs(previousHash, runID string, sequenceNum int64, timestampMs int64, contentHash string) string {
	return ComputeChainHash(previousHash, runID, sequenceNum, time.UnixMilli(timestampMs).UTC(), contentHash)
}

// VerifyChainOffline verifies a complete chain from exported data.
//
// # Description
//
// Performs full chain verification using exported entries without requiring
// network access to Aleutian APIs. Checks:
//   - Chain hash continuity (each entry links to previous)
//   - Sequence number continuity (no gaps)
//   - Tombstone format validity
//   - Anchor binding (if opts.Anchor is non-nil): recomputes the expected
//     anchor-of-anchors hash via ComputeAnchorChainHash and compares it to
//     opts.Anchor.ChainHash. See ChainVerifyOptions.Anchor for the inputs
//     callers must supply.
//
// WARNING (M-4): OfflineBreak contains EntryID and hashes that may correlate
// to PII. Consider truncating hashes before logging: hash[:8] is sufficient.
//
// # Inputs
//
//   - ctx: Context for cancellation (reserved for future use)
//   - entries: Slice of exported entries to verify (must be ordered by GlobalSeq)
//   - opts: Verification options
//
// # Outputs
//
//   - OfflineVerificationResult: Summary of verification with any breaks found
//   - error: Non-nil if entries slice is empty
//
// # Examples
//
//	entries, _ := LoadExportedEntries("export.json")
//	anchor, _ := LoadAnchor("anchor.json")
//	result, err := VerifyChainOffline(ctx, entries, ChainVerifyOptions{
//	    Anchor:             &anchor,
//	    PreviousAnchorHash: verification.SeedAnchorHash, // for genesis anchor
//	    MaxBreaks:          100,
//	})
//	if err != nil {
//	    log.Fatalf("verification error: %v", err)
//	}
//	if !result.Valid {
//	    for _, b := range result.Breaks {
//	        log.Printf("break at %d: %s", b.Position, b.BreakType)
//	    }
//	}
//
// # Limitations
//
//   - Entries must be pre-sorted by GlobalSeq (ascending)
//   - Does not validate entry content (only chain hash)
//   - Does not verify timestamps are monotonically increasing
func VerifyChainOffline(ctx context.Context, entries []ExportedEntry, opts ChainVerifyOptions) (OfflineVerificationResult, error) {
	if len(entries) == 0 {
		return OfflineVerificationResult{}, ErrEmptyEntries
	}

	// M-10: Resource bounds - limit entries processed
	entriesToProcess := entries
	if opts.MaxEntries > 0 && len(entries) > opts.MaxEntries {
		entriesToProcess = entries[:opts.MaxEntries]
	}

	start := time.Now()
	var breaks []OfflineBreak
	previousHash := ""
	previousSeq := int64(0)
	tombstonesFound := 0

	for i, entry := range entriesToProcess {
		// M-10: Stop early if too many breaks found
		if opts.MaxBreaks > 0 && len(breaks) >= opts.MaxBreaks {
			break
		}

		// Check sequence continuity (except for first entry)
		if i > 0 && entry.GlobalSeq != previousSeq+1 {
			breaks = append(breaks, OfflineBreak{
				Position:  i,
				EntryID:   entry.EntryID,
				BreakType: "sequence_gap",
				Context: map[string]string{
					"expected_seq": strconv.FormatInt(previousSeq+1, 10),
					"actual_seq":   strconv.FormatInt(entry.GlobalSeq, 10),
				},
			})
		}

		// Tombstones: validate FORMAT ONLY, then advance on the stored hash.
		//
		// A tombstone retains the ORIGINAL entry's chain_hash, which was computed
		// from that entry's real content_hash before erasure (see CreateTombstone).
		// Its chain hash is therefore NOT reproducible from its own fields, and
		// recomputing it here reports hash_mismatch on every lawfully erased entry
		// — telling a customer their chain is broken precisely when they are
		// demonstrating that they honoured a deletion request (sdk_verify_01).
		//
		// The preservation is deliberate, not an oddity: anchors sign the chain
		// hash. Recomputing on erasure would invalidate every anchor covering that
		// range, so exercising a right to erasure would destroy the proof the data
		// ever existed. Preserving it keeps erasure and provability compatible.
		//
		// Subsequent entries were chained against the stored value, so that is what
		// the next iteration must link from. Mirrors the producer-side verifier.
		if IsTombstone(entry.EntryType, entry.EntryID) {
			tombstonesFound++
			if !ValidateTombstoneContentHash(entry.ContentHash) {
				breaks = append(breaks, OfflineBreak{
					Position:  i,
					EntryID:   entry.EntryID,
					BreakType: "invalid_tombstone",
					Context: map[string]string{
						"content_hash_len": strconv.Itoa(len(entry.ContentHash)),
					},
				})
			}
			previousHash = entry.ChainHash
			previousSeq = entry.GlobalSeq
			continue
		}

		// Parse timestamp and compute expected chain hash
		ts, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
		if err != nil {
			breaks = append(breaks, OfflineBreak{
				Position:  i,
				EntryID:   entry.EntryID,
				BreakType: "invalid_timestamp",
				Context:   map[string]string{},
			})
			previousHash = entry.ChainHash
			previousSeq = entry.GlobalSeq
			continue
		}

		expectedHash := ComputeChainHash(
			previousHash,
			entry.RunID,
			entry.SequenceNum,
			ts,
			entry.ContentHash,
		)

		if subtle.ConstantTimeCompare([]byte(entry.ChainHash), []byte(expectedHash)) != 1 {
			breaks = append(breaks, OfflineBreak{
				Position:     i,
				EntryID:      entry.EntryID,
				ExpectedHash: expectedHash,
				ActualHash:   entry.ChainHash,
				BreakType:    "hash_mismatch",
				Context:      map[string]string{},
			})
		}

		// Advance using the computed hash, not the stored one. If entry.ChainHash
		// was tampered, using it would cascade false positives to all subsequent entries.
		previousHash = expectedHash
		previousSeq = entry.GlobalSeq
	}

	// Anchor binding: when caller supplied an Anchor, recompute the expected
	// anchor-of-anchors hash from the walked tip + caller-supplied previous
	// anchor hash + anchor metadata, and compare against anchor.ChainHash.
	//
	// This is the right way to bind a walked chain to a signed anchor: the
	// producer's anchor.chain_hash lives in the "aleutian.anchor.v2:" domain
	// and incorporates the previous anchor + company id + entry range + tip
	// chain_hash. Byte-comparing the tip alone (the legacy ExpectedLastHash
	// path below) cannot work because the domains differ.
	if opts.Anchor != nil {
		anchor := opts.Anchor
		prevAnchorHash := opts.PreviousAnchorHash
		// Genesis convenience: if the caller signalled a genesis anchor via
		// PreviousAnchorID == SeedAnchorID and left PreviousAnchorHash
		// empty, fall back to SeedAnchorHash. Mid-chain anchors with an
		// empty PreviousAnchorHash will fail to bind — by design, because
		// no trust can be established without the prior anchor's hash.
		if prevAnchorHash == "" && anchor.PreviousAnchorID == SeedAnchorID {
			prevAnchorHash = SeedAnchorHash
		}
		expected := ComputeAnchorChainHash(
			prevAnchorHash,
			anchor.CompanyID,
			anchor.Range.StartEntryID,
			anchor.Range.EndEntryID,
			previousHash, // walked tip chain_hash from the loop above
		)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(anchor.ChainHash)) != 1 {
			lastIdx := len(entriesToProcess) - 1
			breaks = append(breaks, OfflineBreak{
				Position:     lastIdx,
				EntryID:      entriesToProcess[lastIdx].EntryID,
				ExpectedHash: expected,
				ActualHash:   anchor.ChainHash,
				BreakType:    "anchor_mismatch",
				Context:      map[string]string{},
			})
		}
	} else if opts.ExpectedLastHash != "" {
		// Deprecated legacy path: raw byte-equality between walked tip and a
		// caller-supplied hash. This was always broken for real Aleutian
		// anchors because anchor.chain_hash != tip.chain_hash. Preserved for
		// any caller still passing the field; will be removed next minor.
		if subtle.ConstantTimeCompare([]byte(previousHash), []byte(opts.ExpectedLastHash)) != 1 {
			lastIdx := len(entriesToProcess) - 1
			breaks = append(breaks, OfflineBreak{
				Position:     lastIdx,
				EntryID:      entriesToProcess[lastIdx].EntryID,
				ExpectedHash: opts.ExpectedLastHash,
				ActualHash:   previousHash,
				BreakType:    "anchor_mismatch",
				Context:      map[string]string{},
			})
		}
	}

	return OfflineVerificationResult{
		Valid:           len(breaks) == 0,
		EntriesVerified: len(entriesToProcess),
		TombstonesFound: tombstonesFound,
		Breaks:          breaks,
		Duration:        time.Since(start),
	}, nil
}

// appendTimestampMicro appends a timestamp formatted as "2006-01-02T15:04:05.000000Z"
// to the buffer without allocating. This matches BigQuery's
// FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%E6SZ', ts) output.
func appendTimestampMicro(buf []byte, t time.Time) []byte {
	t = t.UTC()
	year, month, day := t.Date()
	hour, min, sec := t.Clock()
	micro := t.Nanosecond() / 1000 // truncate to microseconds

	buf = appendIntPadded(buf, year, 4)
	buf = append(buf, '-')
	buf = appendIntPadded(buf, int(month), 2)
	buf = append(buf, '-')
	buf = appendIntPadded(buf, day, 2)
	buf = append(buf, 'T')
	buf = appendIntPadded(buf, hour, 2)
	buf = append(buf, ':')
	buf = appendIntPadded(buf, min, 2)
	buf = append(buf, ':')
	buf = appendIntPadded(buf, sec, 2)
	buf = append(buf, '.')
	buf = appendIntPadded(buf, micro, 6)
	buf = append(buf, 'Z')

	return buf
}

// appendIntPadded appends a non-negative integer to buf, zero-padded to width.
func appendIntPadded(buf []byte, val int, width int) []byte {
	var tmp [10]byte
	pos := len(tmp)
	if val == 0 {
		pos--
		tmp[pos] = '0'
	} else {
		for val > 0 {
			pos--
			tmp[pos] = byte('0' + val%10)
			val /= 10
		}
	}
	for len(tmp)-pos < width {
		pos--
		tmp[pos] = '0'
	}
	return append(buf, tmp[pos:]...)
}

// FormatTimestampMicro formats a time.Time as "2006-01-02T15:04:05.000000Z".
//
// # Description
//
// Formats a timestamp with microsecond precision in UTC. This is the exact
// format used in chain hash computation and matches BigQuery's output format.
//
// # Inputs
//
//   - t: Time to format
//
// # Outputs
//
//   - string: Formatted timestamp
//
// # Example
//
//	ts := FormatTimestampMicro(time.Now())
//	// Returns: "2026-01-25T12:00:00.123456Z"
func FormatTimestampMicro(t time.Time) string {
	var buf [27]byte
	result := appendTimestampMicro(buf[:0], t)
	return string(result)
}
