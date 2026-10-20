// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"bytes"
	"fmt"
)

// canonicalJSON is the byte-identical canonical encoding contract for
// Framework JSON across the Go, Python, and JS SDKs.
//
// # Description
//
// The output of canonicalJSON(f) MUST byte-match
//
//	json.dumps(framework_dict, sort_keys=True, ensure_ascii=False,
//	           separators=(",", ":"))
//
// in Python and the equivalent JS handwritten emitter. CV-09 enforces
// this via golden vectors.
//
// Rules:
//
//   - Object keys are emitted in strict alphabetical (ASCII-byte) order.
//   - No whitespace between tokens (no space after `:` or `,`).
//   - Strings are UTF-8 with `ensure_ascii=False` semantics: characters
//     U+0020 and above (except `"` and `\`) are emitted as raw UTF-8
//     bytes; characters below U+0020 are emitted as `\uXXXX` with
//     LOWERCASE hex digits to match Python's json module.
//   - Standard short escapes used for `"`, `\`, `\b`, `\f`, `\n`,
//     `\r`, `\t`. HTML-unsafe characters (`<`, `>`, `&`) are NOT
//     escaped — this is the deliberate departure from Go's
//     encoding/json default and is required for byte-identity with
//     Python's json.dumps.
//   - The Framework schema contains only strings and arrays of structs
//     containing only strings. No numbers, no booleans, no nested
//     objects beyond Control / OutOfScopeControl. Number / boolean /
//     null canonicalization is deliberately out of scope.
//
// Forward-compat note (sealed against the "decode-then-rehash bypass"):
// The loader passes the *decoded struct* (not the original raw bytes)
// to canonicalJSON when verifying the self-attestation hash. If a
// future field were added to the on-wire JSON without updating this
// struct + encoder, json.Decoder.DisallowUnknownFields would reject it
// at decode time before we ever reach canonicalJSON — that is the
// forward-compat fail-closed mechanism. DO NOT "optimize" the loader
// to hash the original raw bytes instead; doing so removes the
// fail-closed property and lets a producer smuggle silent fields past
// older SDKs.
func canonicalJSON(f Framework) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeFramework(&buf, f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeFramework(buf *bytes.Buffer, f Framework) error {
	// Keys are listed in strict alphabetical order. This list is the
	// authoritative schema for the canonical encoding — any new field
	// added to Framework MUST also be added here, in alphabetical
	// position, or canonicalJSON will silently omit it.
	buf.WriteByte('{')
	writeStringField(buf, "aleutian_snapshot_at", f.AleutianSnapshotAt, false)
	writeRawField(buf, "controls", true)
	if err := encodeControlArray(buf, f.Controls); err != nil {
		return err
	}
	writeRawField(buf, "controls_out_of_scope", true)
	if err := encodeOutOfScopeArray(buf, f.ControlsOutOfScope); err != nil {
		return err
	}
	writeStringField(buf, "controls_sha512_hex", f.ControlsSHA512Hex, true)
	writeStringField(buf, "framework_id", string(f.FrameworkID), true)
	writeStringField(buf, "framework_published_at", f.FrameworkPublishedAt, true)
	writeStringField(buf, "version_id", string(f.VersionID), true)
	buf.WriteByte('}')
	return nil
}

func encodeControlArray(buf *bytes.Buffer, controls []Control) error {
	buf.WriteByte('[')
	for i, c := range controls {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteByte('{')
		writeStringField(buf, "category", c.Category, false)
		writeStringField(buf, "id", c.ID, true)
		writeStringField(buf, "status", string(c.Status), true)
		writeStringField(buf, "title", c.Title, true)
		writeStringField(buf, "what_we_dont_prove", c.WhatWeDontProve, true)
		writeStringField(buf, "what_we_prove", c.WhatWeProve, true)
		buf.WriteByte('}')
	}
	buf.WriteByte(']')
	return nil
}

func encodeOutOfScopeArray(buf *bytes.Buffer, items []OutOfScopeControl) error {
	buf.WriteByte('[')
	for i, c := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteByte('{')
		writeStringField(buf, "id", c.ID, false)
		writeStringField(buf, "reason", c.Reason, true)
		buf.WriteByte('}')
	}
	buf.WriteByte(']')
	return nil
}

// writeStringField emits `,"key":"value"` (or `"key":"value"` for the
// first field in an object — leadingComma=false).
func writeStringField(buf *bytes.Buffer, key, value string, leadingComma bool) {
	if leadingComma {
		buf.WriteByte(',')
	}
	encodeJSONString(buf, key)
	buf.WriteByte(':')
	encodeJSONString(buf, value)
}

// writeRawField emits `,"key":` (or `"key":` when leadingComma=false),
// leaving the caller to write the raw value that follows.
func writeRawField(buf *bytes.Buffer, key string, leadingComma bool) {
	if leadingComma {
		buf.WriteByte(',')
	}
	encodeJSONString(buf, key)
	buf.WriteByte(':')
}

// encodeJSONString writes s as a JSON string literal with Python's
// json.dumps(ensure_ascii=False) semantics. See canonicalJSON's
// package doc for the byte-identity contract.
func encodeJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
