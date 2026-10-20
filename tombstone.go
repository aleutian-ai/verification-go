// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import "strings"

// =============================================================================
// Tombstone Constants
// =============================================================================

const (
	// TombstoneContentHashPrefix is the prefix used for tombstone content hashes.
	// Format: "TOMBSTONE:" + 64 lowercase hex chars = 74 chars total.
	TombstoneContentHashPrefix = "TOMBSTONE:"

	// TombstoneEntryIDPrefix is the prefix used for tombstone entry IDs.
	// Format: "tomb_" + UUID (36 chars) = 41 chars total.
	TombstoneEntryIDPrefix = "tomb_"

	// TombstoneEntryType is the entry_type value for tombstone entries.
	TombstoneEntryType = "tombstone"

	// tombstoneContentHashLen is the total length of a valid tombstone content hash.
	tombstoneContentHashLen = 74 // len("TOMBSTONE:") + 64
)

// =============================================================================
// Detection Functions
// =============================================================================

// IsTombstone checks whether an entry is a tombstone.
//
// # Description
//
// Performs a fast check using the entry_type and entry_id fields.
// Both conditions must be true for the entry to be identified as a tombstone:
//   - entryType must equal "tombstone" (exact match, case-sensitive)
//   - entryID must start with "tomb_" prefix
//
// This function does NOT validate the full tombstone format. Use
// [ValidateTombstoneContentHash] for content hash validation.
//
// # Inputs
//
//   - entryType: The entry_type column value from audit_entries
//   - entryID: The entry_id column value from audit_entries
//
// # Outputs
//
//   - bool: true if the entry is a tombstone
//
// # Examples
//
//	// Tombstone entry
//	IsTombstone("tombstone", "tomb_550e8400-e29b-41d4-a716-446655440000") // true
//
//	// Regular entry
//	IsTombstone("request", "req_550e8400-e29b-41d4-a716-446655440000") // false
//
//	// Partial match (both conditions required)
//	IsTombstone("tombstone", "req_12345") // false (wrong ID prefix)
//	IsTombstone("request", "tomb_12345")  // false (wrong type)
//
// # Limitations
//
//   - Case-sensitive: "Tombstone" or "TOMBSTONE" entry types return false
//   - Does not validate UUID format after the "tomb_" prefix
func IsTombstone(entryType, entryID string) bool {
	return entryType == TombstoneEntryType && strings.HasPrefix(entryID, TombstoneEntryIDPrefix)
}

// IsTombstoneContentHash checks whether a content hash uses tombstone format.
//
// # Description
//
// A lighter check than [ValidateTombstoneContentHash] — only verifies the
// prefix is present, not the full format. Useful for quick classification.
//
// # Inputs
//
//   - contentHash: The content_hash column value from audit_entries
//
// # Outputs
//
//   - bool: true if contentHash starts with "TOMBSTONE:"
//
// # Examples
//
//	IsTombstoneContentHash("TOMBSTONE:abcdef...") // true
//	IsTombstoneContentHash("a1b2c3d4e5f6...")     // false
//
// # Limitations
//
//   - Does not validate hex format or length after prefix
func IsTombstoneContentHash(contentHash string) bool {
	return strings.HasPrefix(contentHash, TombstoneContentHashPrefix)
}

// =============================================================================
// Validation Functions
// =============================================================================

// ValidateTombstoneContentHash validates that a content hash has the correct
// tombstone format.
//
// # Description
//
// A valid tombstone content hash is:
//
//	"TOMBSTONE:" + 64 lowercase hexadecimal characters
//
// Total length: 74 characters.
//
// # Inputs
//
//   - contentHash: The content_hash value to validate
//
// # Outputs
//
//   - bool: true if the content hash has valid tombstone format
//
// # Examples
//
//	ValidateTombstoneContentHash("TOMBSTONE:a1b2...64 hex chars...") // true
//	ValidateTombstoneContentHash("TOMBSTONE:ABC1...")                // false (uppercase)
//	ValidateTombstoneContentHash("TOMBSTONE:short")                 // false (too short)
//	ValidateTombstoneContentHash("a1b2c3...")                       // false (no prefix)
//
// # Limitations
//
//   - Only validates format, not cryptographic properties
//   - Valid hex characters are [0-9a-f] (lowercase only)
func ValidateTombstoneContentHash(contentHash string) bool {
	if len(contentHash) != tombstoneContentHashLen {
		return false
	}
	if !strings.HasPrefix(contentHash, TombstoneContentHashPrefix) {
		return false
	}
	// Validate hex portion (after "TOMBSTONE:" prefix)
	hexPart := contentHash[len(TombstoneContentHashPrefix):]
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
