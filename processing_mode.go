// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package verification provides the Aleutian AI verification SDK for
// offline chain and anchor verification.
package verification

import (
	"encoding/binary"
	"errors"
)

// =============================================================================
// Processing Mode — v=2 canonical encoder
//
// Cross-language byte-equality contract
// ======================================
// EncodeProcessingModeCanonicalFields produces output that is byte-identical
// to the internal Go encoder (internal/storage.EncodeProcessingModeCanonicalFields)
// for the same inputs. This invariant is enforced by the shared golden vectors
// in sdk/testdata/processing_mode_golden.json, verified by the test suite.
//
// TLV encoding format (v=2)
// ==========================
// Each field is: u32 BE byte-length || raw UTF-8 bytes. The two fields are
// concatenated in alphabetical key order:
//   1. processing_mode_at_write         : u32 BE len + mode bytes
//   2. processing_mode_set_by_event_id  : u32 BE len + event id bytes
//
// Ticket reference: 18_05h
// =============================================================================

const (
	// ZK is the canonical wire string for the zero-knowledge processing mode.
	// Mirrors internal/storage.ProcessingModeZK.
	ZK = "zk"

	// PIIInspection is the canonical wire string for the PII inspection mode.
	// Mirrors internal/storage.ProcessingModePIIInspection.
	PIIInspection = "pii_inspection"
)

// ErrUnknownProcessingMode is returned by ParseProcessingMode when the input
// is not one of the two known canonical mode strings.
var ErrUnknownProcessingMode = errors.New("verification: unknown processing mode")

// ParseProcessingMode validates that s is a known canonical processing mode.
//
// # Description
//
// Byte-strict parser: accepts only "zk" or "pii_inspection" exactly. No
// trimming, no case folding, no Unicode normalization is applied. Mirrors
// ParseProcessingMode in internal/storage/processing_mode_types.go (ticket
// 18_01, Clarification 5): a corrupted or normalised input that the internal
// encoder rejects must also be rejected here.
//
// # Inputs
//
//   - s: the raw string to validate
//
// # Outputs
//
//   - string: the input string unchanged if it is a known mode
//   - error: ErrUnknownProcessingMode if s is not "zk" or "pii_inspection"
//
// # Example
//
//	mode, err := verification.ParseProcessingMode("zk")
//	if err != nil {
//	    return fmt.Errorf("invalid mode: %w", err)
//	}
//
// # Limitations
//
//   - Does not validate the event id or the (mode, event_id) binding rules.
//     Those invariants are enforced at write time by the internal encoder.
//
// # Assumptions
//
//   - The input comes from a stored chain entry where the internal encoder
//     has already enforced the binding rules at write time.
func ParseProcessingMode(s string) (string, error) {
	if s == ZK || s == PIIInspection {
		return s, nil
	}
	return "", ErrUnknownProcessingMode
}

// EncodeProcessingModeCanonicalFields produces the deterministic TLV byte
// sequence for the two v=2 canonical-form processing mode fields.
//
// # Description
//
// Output is byte-identical to EncodeProcessingModeCanonicalFields in
// internal/storage/processing_mode_canonical.go for the same inputs. The
// cross-language byte-equality contract is enforced by the shared golden
// vectors in sdk/testdata/processing_mode_golden.json.
//
// Output format (alphabetical TLV):
//
//	[u32 BE] len(mode bytes)
//	[bytes]  mode bytes (UTF-8)
//	[u32 BE] len(setByEventID bytes)
//	[bytes]  setByEventID bytes (UTF-8)
//
// All length prefixes are big-endian unsigned 32-bit integers. Length
// measures bytes, not Unicode code points. Mode strings and event IDs
// are pure ASCII so byte length and character length are equal — but the
// implementation uses len([]byte(s)) to make the contract explicit.
//
// # Inputs
//
//   - mode: the processing mode wire string; must be ZK or PIIInspection
//   - setByEventID: the event id that set the processing mode; any non-empty
//     string accepted by the internal ValidateProcessingModeEventID (UUIDv4
//     or a recognised system sentinel)
//
// # Outputs
//
//   - []byte: the TLV-encoded bytes for the two canonical fields
//   - error: ErrUnknownProcessingMode if mode is not a known mode
//
// # Example
//
//	b, err := verification.EncodeProcessingModeCanonicalFields("zk", "system:bootstrap")
//	if err != nil {
//	    return fmt.Errorf("encode: %w", err)
//	}
//	// len(b) == 26 (4+2+4+16)
//
// # Limitations
//
//   - Encodes only the two new v=2 fields; the surrounding pqc_05c
//     canonical-form fields are not included.
//   - Does not validate setByEventID against UUIDv4 format or
//     pii_inspection+sentinel binding rules; those are enforced at write
//     time by the internal encoder.
//
// # Assumptions
//
//   - The caller is composing canonical bytes for a v=2 chain entry.
func EncodeProcessingModeCanonicalFields(mode, setByEventID string) ([]byte, error) {
	if _, err := ParseProcessingMode(mode); err != nil {
		return nil, err
	}
	modeBytes := []byte(mode)
	eventBytes := []byte(setByEventID)

	out := make([]byte, 0, 8+len(modeBytes)+len(eventBytes))

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(modeBytes)))
	out = append(out, lenBuf[:]...)
	out = append(out, modeBytes...)

	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(eventBytes)))
	out = append(out, lenBuf[:]...)
	out = append(out, eventBytes...)

	return out, nil
}
