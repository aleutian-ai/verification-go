// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/verification-go/frameworks"
)

func TestListFrameworks_AllNineEntriesPresent(t *testing.T) {
	tmp, err := os.CreateTemp("", "list_*.out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	listFrameworks(tmp)
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 9 {
		t.Errorf("got %d lines; want 9", len(lines))
	}
	// Sorted by framework_id; SOC 2 should be last alphabetically.
	if !strings.HasPrefix(lines[len(lines)-1], "soc2-2017\t") {
		t.Errorf("last line should be SOC 2 (alphabetical sort); got %q", lines[len(lines)-1])
	}
}

func TestShowFramework_HappyPath(t *testing.T) {
	tmp, err := os.CreateTemp("", "show_*.out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if err := showFramework(tmp, "soc2-2017@20260531"); err != nil {
		t.Fatalf("showFramework: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Framework:              soc2-2017",
		"Version:                soc2-2017@20260531",
		"In-scope controls:      6",
	} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, body)
		}
	}
}

func TestShowFramework_UnknownVersion(t *testing.T) {
	tmp, err := os.CreateTemp("", "show_unk_*.out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	err = showFramework(tmp, "nonexistent@99999999")
	if err == nil {
		t.Fatal("expected error for unknown version; got nil")
	}
	if !strings.Contains(err.Error(), "unknown framework version") {
		t.Errorf("error should mention 'unknown framework version'; got %q", err.Error())
	}
}

func TestVerifyControlsFile_HappyPath(t *testing.T) {
	// Write a known-valid controls.json to a temp file via the
	// canonical helper, then verify it round-trips.
	soc2, err := frameworks.LoadFromEmbedded("soc2-2017@20260531")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := frameworks.CanonicalJSONOnWire(soc2)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "controls.json")
	if err := os.WriteFile(path, canonical, 0o644); err != nil {
		t.Fatal(err)
	}

	tmp, err := os.CreateTemp("", "verify_*.out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if err := verifyControlsFile(tmp, path); err != nil {
		t.Fatalf("verifyControlsFile: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(body, []byte("OK\n")) {
		t.Errorf("expected output to start with 'OK\\n'; got %q", body)
	}
}

func TestVerifyControlsFile_TamperedFile(t *testing.T) {
	soc2, err := frameworks.LoadFromEmbedded("soc2-2017@20260531")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := frameworks.CanonicalJSONOnWire(soc2)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte("Logical access"), []byte("AudiX access"), 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "controls.json")
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	tmp, err := os.CreateTemp("", "verify_tampered_*.out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	err = verifyControlsFile(tmp, path)
	if err == nil {
		t.Fatal("expected verification failure on tampered file; got nil")
	}
	// Should wrap ErrAttestationMismatch transitively.
	if !strings.Contains(err.Error(), "controls_sha512_hex") {
		t.Errorf("error should reference the hash field; got %q", err.Error())
	}
}
