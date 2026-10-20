// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import "testing"

func TestIsTombstone(t *testing.T) {
	tests := []struct {
		name      string
		entryType string
		entryID   string
		want      bool
	}{
		{
			name:      "valid tombstone",
			entryType: "tombstone",
			entryID:   "tomb_550e8400-e29b-41d4-a716-446655440000",
			want:      true,
		},
		{
			name:      "regular request entry",
			entryType: "request",
			entryID:   "req_550e8400-e29b-41d4-a716-446655440000",
			want:      false,
		},
		{
			name:      "wrong type with tomb prefix",
			entryType: "request",
			entryID:   "tomb_550e8400-e29b-41d4-a716-446655440000",
			want:      false,
		},
		{
			name:      "tombstone type with wrong prefix",
			entryType: "tombstone",
			entryID:   "req_550e8400-e29b-41d4-a716-446655440000",
			want:      false,
		},
		{
			name:      "uppercase TOMBSTONE type (case-sensitive)",
			entryType: "TOMBSTONE",
			entryID:   "tomb_12345",
			want:      false,
		},
		{
			name:      "mixed case Tombstone type",
			entryType: "Tombstone",
			entryID:   "tomb_12345",
			want:      false,
		},
		{
			name:      "empty strings",
			entryType: "",
			entryID:   "",
			want:      false,
		},
		{
			name:      "tomb_ prefix only",
			entryType: "tombstone",
			entryID:   "tomb_",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTombstone(tt.entryType, tt.entryID)
			if got != tt.want {
				t.Errorf("IsTombstone(%q, %q) = %v, want %v", tt.entryType, tt.entryID, got, tt.want)
			}
		})
	}
}

func TestIsTombstoneContentHash(t *testing.T) {
	tests := []struct {
		name        string
		contentHash string
		want        bool
	}{
		{
			name:        "valid tombstone content hash",
			contentHash: "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			want:        true,
		},
		{
			name:        "regular content hash",
			contentHash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			want:        false,
		},
		{
			name:        "lowercase tombstone prefix",
			contentHash: "tombstone:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			want:        false,
		},
		{
			name:        "prefix only",
			contentHash: "TOMBSTONE:",
			want:        true,
		},
		{
			name:        "empty string",
			contentHash: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTombstoneContentHash(tt.contentHash)
			if got != tt.want {
				t.Errorf("IsTombstoneContentHash(%q) = %v, want %v", tt.contentHash, got, tt.want)
			}
		})
	}
}

func TestValidateTombstoneContentHash(t *testing.T) {
	tests := []struct {
		name        string
		contentHash string
		want        bool
	}{
		{
			name:        "valid tombstone content hash",
			contentHash: "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			want:        true,
		},
		{
			name:        "all zeros hex",
			contentHash: "TOMBSTONE:0000000000000000000000000000000000000000000000000000000000000000",
			want:        true,
		},
		{
			name:        "all f hex",
			contentHash: "TOMBSTONE:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			want:        true,
		},
		{
			name:        "too short",
			contentHash: "TOMBSTONE:a1b2c3d4",
			want:        false,
		},
		{
			name:        "too long",
			contentHash: "TOMBSTONE:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2ff",
			want:        false,
		},
		{
			name:        "uppercase hex (invalid)",
			contentHash: "TOMBSTONE:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
			want:        false,
		},
		{
			name:        "mixed case hex (invalid)",
			contentHash: "TOMBSTONE:A1b2C3d4E5f6A1b2C3d4E5f6A1b2C3d4E5f6A1b2C3d4E5f6A1b2C3d4E5f6A1b2",
			want:        false,
		},
		{
			name:        "non-hex characters",
			contentHash: "TOMBSTONE:g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			want:        false,
		},
		{
			name:        "regular content hash",
			contentHash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			want:        false,
		},
		{
			name:        "prefix only",
			contentHash: "TOMBSTONE:",
			want:        false,
		},
		{
			name:        "empty string",
			contentHash: "",
			want:        false,
		},
		{
			name:        "lowercase prefix (invalid)",
			contentHash: "tombstone:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateTombstoneContentHash(tt.contentHash)
			if got != tt.want {
				t.Errorf("ValidateTombstoneContentHash(%q) = %v, want %v", tt.contentHash, got, tt.want)
			}
		})
	}
}

func TestTombstoneConstants(t *testing.T) {
	// Verify constants match expected values
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
