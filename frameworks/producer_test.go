// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestPinForBundle_HappyPath(t *testing.T) {
	entry, err := PinForBundle(SOC2_2017)
	if err != nil {
		t.Fatalf("PinForBundle(SOC2_2017): %v", err)
	}
	if entry.VersionID != "soc2-2017@20260531" {
		t.Errorf("VersionID: got %q want %q", entry.VersionID, "soc2-2017@20260531")
	}
	if entry.Path != "frameworks/soc2-2017@20260531/controls.json" {
		t.Errorf("Path: got %q want %q", entry.Path, "frameworks/soc2-2017@20260531/controls.json")
	}
	if entry.SizeBytes != int64(len(entry.Contents)) {
		t.Errorf("SizeBytes: got %d want %d", entry.SizeBytes, len(entry.Contents))
	}

	// File-level hash matches independently computed SHA-512.
	sum := sha512.Sum512(entry.Contents)
	want := hex.EncodeToString(sum[:])
	if entry.SHA512Hex != want {
		t.Errorf("SHA512Hex: got %q want %q", entry.SHA512Hex, want)
	}

	// Contents must round-trip through LoadFromReader.
	loaded, err := LoadFromReader(strings.NewReader(string(entry.Contents)))
	if err != nil {
		t.Fatalf("LoadFromReader(entry.Contents): %v", err)
	}
	if loaded.FrameworkID != SOC2_2017 {
		t.Errorf("round-trip framework_id: got %q want %q", loaded.FrameworkID, SOC2_2017)
	}
	if loaded.VersionID != entry.VersionID {
		t.Errorf("round-trip version_id: got %q want %q", loaded.VersionID, entry.VersionID)
	}
}

func TestPinForBundle_UnknownFrameworkID(t *testing.T) {
	_, err := PinForBundle(FrameworkID("nonexistent-framework"))
	if !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("got err=%v, want ErrUnknownVersion", err)
	}
}

func TestPinForBundle_Deterministic(t *testing.T) {
	// Same input -> byte-identical output every call. Critical for
	// CV-09 byte-identity across Go/Python/JS and for the producer's
	// determinism guard.
	first, err := PinForBundle(SOC2_2017)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := PinForBundle(SOC2_2017)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(first.Contents) != string(second.Contents) {
		t.Error("PinForBundle is non-deterministic across calls; Contents differ")
	}
	if first.SHA512Hex != second.SHA512Hex {
		t.Errorf("PinForBundle is non-deterministic; SHA512Hex differs: %q vs %q", first.SHA512Hex, second.SHA512Hex)
	}
}

func TestPinForBundle_AllLatest(t *testing.T) {
	// Every entry in Latest must produce a valid bundle entry.
	for id, vid := range Latest {
		id, vid := id, vid
		t.Run(string(id), func(t *testing.T) {
			entry, err := PinForBundle(id)
			if err != nil {
				t.Fatalf("PinForBundle(%q): %v", id, err)
			}
			if entry.VersionID != vid {
				t.Errorf("VersionID: got %q want %q", entry.VersionID, vid)
			}
			if !strings.HasPrefix(entry.Path, "frameworks/") {
				t.Errorf("Path: got %q; want prefix frameworks/", entry.Path)
			}
			if !strings.HasSuffix(entry.Path, "/controls.json") {
				t.Errorf("Path: got %q; want suffix /controls.json", entry.Path)
			}
			if len(entry.Contents) == 0 {
				t.Error("Contents empty")
			}
			if entry.SHA512Hex == "" || len(entry.SHA512Hex) != 128 {
				t.Errorf("SHA512Hex: got %q (len=%d); want 128-char hex", entry.SHA512Hex, len(entry.SHA512Hex))
			}
		})
	}
}
