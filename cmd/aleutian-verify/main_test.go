// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Mirrors the Python tests/test_main_cli.py + JS test/cli.test.ts
// surface byte-for-byte. The cross-language smoke (TODO) diffs all
// three outputs over the same fixture — these tests catch the
// per-language regressions before that smoke runs.

package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdk "github.com/aleutian-ai/verification-go"
)

const ifaceWant = "go-sdk"

// fixtureEntry is the on-disk JSON shape (snake_case). Distinct from
// sdk.ExportedEntry which uses Go field names; we serialize as JSON
// here to match what load_exported_entries / loadExportedEntries
// consume in the other SDKs.
type fixtureEntry struct {
	EntryID     string `json:"entry_id"`
	EntryType   string `json:"entry_type"`
	Timestamp   string `json:"timestamp"`
	RunID       string `json:"run_id"`
	SequenceNum int64  `json:"sequence_num"`
	GlobalSeq   int64  `json:"global_seq"`
	ContentHash string `json:"content_hash"`
	ChainHash   string `json:"chain_hash"`
}

func writeFixture(t *testing.T, dir string, n int) (anchorPath, entriesPath, lastHash string) {
	t.Helper()
	entries := make([]fixtureEntry, 0, n)
	prevHash := ""
	for i := 0; i < n; i++ {
		ts := time.Date(2026, 1, 20, 12, 0, i, 0, time.UTC)
		tsStr := ts.UTC().Format("2006-01-02T15:04:05.000000Z")
		hContent := sha512.Sum512([]byte(fmt.Sprintf("content_%d", i)))
		contentHash := hex.EncodeToString(hContent[:])
		chainHash := sdk.ComputeChainHash(prevHash, "run_test", int64(i), ts, contentHash)
		entries = append(entries, fixtureEntry{
			EntryID:     fmt.Sprintf("entry_%d", i),
			EntryType:   "request",
			Timestamp:   tsStr,
			RunID:       "run_test",
			SequenceNum: int64(i),
			GlobalSeq:   int64(i),
			ContentHash: contentHash,
			ChainHash:   chainHash,
		})
		prevHash = chainHash
	}
	// Producer-style anchor: chain_hash is the result of
	// ComputeAnchorChainHash, NOT byte-equal to the tip entry's chain_hash.
	// PreviousAnchorID = SeedAnchorID makes this a genesis anchor — the
	// CLI auto-fills SeedAnchorHash as the previous-anchor input.
	startID := entries[0].EntryID
	endID := entries[len(entries)-1].EntryID
	anchorChainHash := sdk.ComputeAnchorChainHash(
		sdk.SeedAnchorHash, "comp_test", startID, endID, prevHash,
	)
	anchor := map[string]any{
		"version":     2,
		"anchor_id":   "anc_test",
		"company_id":  "comp_test",
		"chain_hash":  anchorChainHash,
		"entry_count": n,
		"range": map[string]string{
			"start_entry_id": startID,
			"end_entry_id":   endID,
		},
		"signature":          "",
		"signing_key_id":     "key_test",
		"created_at_ms":      int64(1737374400000),
		"previous_anchor_id": sdk.SeedAnchorID,
		"verified_through":   n,
	}
	anchorPath = filepath.Join(dir, "anchor.json")
	entriesPath = filepath.Join(dir, "entries.json")
	ab, _ := json.Marshal(anchor)
	eb, _ := json.Marshal(entries)
	if err := os.WriteFile(anchorPath, ab, 0o600); err != nil {
		t.Fatalf("write anchor: %v", err)
	}
	if err := os.WriteFile(entriesPath, eb, 0o600); err != nil {
		t.Fatalf("write entries: %v", err)
	}
	return anchorPath, entriesPath, prevHash
}

func runCLI(argv ...string) (int, map[string]any) {
	var stdout, stderr bytes.Buffer
	code := run(argv, &stdout, &stderr)
	out := map[string]any{}
	if stdout.Len() > 0 {
		_ = json.Unmarshal(stdout.Bytes(), &out)
	}
	return code, out
}

func TestCLI_ValidChain_ExitsZero(t *testing.T) {
	dir := t.TempDir()
	anchor, entries, _ := writeFixture(t, dir, 3)
	code, out := runCLI("verify", "--anchor", anchor, "--entries", entries)
	if code != exitValid {
		t.Fatalf("code = %d, want %d (out=%v)", code, exitValid, out)
	}
	if out["status"] != "valid" {
		t.Errorf("status = %v, want valid", out["status"])
	}
	if int(out["chain_length"].(float64)) != 3 {
		t.Errorf("chain_length = %v, want 3", out["chain_length"])
	}
	if out["interface"] != ifaceWant {
		t.Errorf("interface = %v, want %q", out["interface"], ifaceWant)
	}
	if len(out["bundle_sha256"].(string)) != 64 {
		t.Errorf("bundle_sha256 length = %d, want 64", len(out["bundle_sha256"].(string)))
	}
}

func TestCLI_ValidChain_LockedFieldSet(t *testing.T) {
	dir := t.TempDir()
	anchor, entries, _ := writeFixture(t, dir, 1)
	_, out := runCLI("verify", "--anchor", anchor, "--entries", entries)
	want := map[string]bool{
		"bundle_sha256": true,
		"chain_length":  true,
		"interface":     true,
		"status":        true,
	}
	for k := range out {
		if !want[k] {
			t.Errorf("unexpected key %q on success", k)
		}
	}
	for k := range want {
		if _, ok := out[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
}

func TestCLI_TamperedEntry_ReturnsInvalid(t *testing.T) {
	dir := t.TempDir()
	anchor, entries, _ := writeFixture(t, dir, 3)
	raw, _ := os.ReadFile(entries)
	var parsed []fixtureEntry
	_ = json.Unmarshal(raw, &parsed)
	for i := range parsed[1].ChainHash {
		_ = i
	}
	parsed[1].ChainHash = "0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	out, _ := json.Marshal(parsed)
	_ = os.WriteFile(entries, out, 0o600)

	code, parsedOut := runCLI("verify", "--anchor", anchor, "--entries", entries)
	if code != exitInvalid {
		t.Fatalf("code = %d, want %d", code, exitInvalid)
	}
	if parsedOut["status"] != "invalid" {
		t.Errorf("status = %v, want invalid", parsedOut["status"])
	}
	if _, ok := parsedOut["reason"]; !ok {
		t.Errorf("missing reason on invalid")
	}
	if _, ok := parsedOut["breaks"]; !ok {
		t.Errorf("missing breaks on invalid")
	}
}

func TestCLI_AnchorMismatch_ReturnsInvalid(t *testing.T) {
	dir := t.TempDir()
	anchorPath, entriesPath, _ := writeFixture(t, dir, 2)
	raw, _ := os.ReadFile(anchorPath)
	var anchor map[string]any
	_ = json.Unmarshal(raw, &anchor)
	anchor["chain_hash"] = "1111111111111111111111111111111111111111111111111111111111111111" +
		"1111111111111111111111111111111111111111111111111111111111111111"
	out, _ := json.Marshal(anchor)
	_ = os.WriteFile(anchorPath, out, 0o600)

	code, parsedOut := runCLI("verify", "--anchor", anchorPath, "--entries", entriesPath)
	if code != exitInvalid {
		t.Fatalf("code = %d, want %d", code, exitInvalid)
	}
	if parsedOut["status"] != "invalid" {
		t.Errorf("status = %v, want invalid", parsedOut["status"])
	}
}

func TestCLI_MissingAnchorFile_IOError(t *testing.T) {
	dir := t.TempDir()
	_, entries, _ := writeFixture(t, dir, 1)
	code, out := runCLI("verify", "--anchor", filepath.Join(dir, "nope.json"), "--entries", entries)
	if code != exitIOOrParse {
		t.Fatalf("code = %d, want %d (out=%v)", code, exitIOOrParse, out)
	}
	if out["status"] != "invalid" {
		t.Errorf("status = %v, want invalid", out["status"])
	}
}

func TestCLI_MissingFlag_UsageError(t *testing.T) {
	code, _ := runCLI("verify", "--anchor", "/tmp/a.json")
	if code != exitUsage {
		t.Errorf("code = %d, want %d", code, exitUsage)
	}
}

func TestCLI_NoSubcommand_UsageError(t *testing.T) {
	code, _ := runCLI()
	if code != exitUsage {
		t.Errorf("code = %d, want %d", code, exitUsage)
	}
}

func TestCLI_BundleSHA256_SameFile_SameSha(t *testing.T) {
	dir := t.TempDir()
	anchor, entries, _ := writeFixture(t, dir, 2)
	_, outA := runCLI("verify", "--anchor", anchor, "--entries", entries)
	_, outB := runCLI("verify", "--anchor", anchor, "--entries", entries)
	if outA["bundle_sha256"] != outB["bundle_sha256"] {
		t.Errorf("same-file sha differs: %v vs %v", outA["bundle_sha256"], outB["bundle_sha256"])
	}
}

func TestCLI_BundleSHA256_DifferentFile_DifferentSha(t *testing.T) {
	dirA := filepath.Join(t.TempDir(), "a")
	dirB := filepath.Join(t.TempDir(), "b")
	_ = os.MkdirAll(dirA, 0o700)
	_ = os.MkdirAll(dirB, 0o700)
	anchorA, entriesA, _ := writeFixture(t, dirA, 2)
	anchorB, entriesB, _ := writeFixture(t, dirB, 3)
	_, outA := runCLI("verify", "--anchor", anchorA, "--entries", entriesA)
	_, outB := runCLI("verify", "--anchor", anchorB, "--entries", entriesB)
	if outA["bundle_sha256"] == outB["bundle_sha256"] {
		t.Errorf("different-file sha matched unexpectedly: %v", outA["bundle_sha256"])
	}
}

// --- 12f_e: optional offline --manifest freshness advisory ---

// Without --manifest, the output MUST NOT carry a manifest block — the
// locked cross-SDK contract is unchanged for the no-flag path.
func TestCLI_NoManifestFlag_NoManifestBlock(t *testing.T) {
	dir := t.TempDir()
	anchor, entries, _ := writeFixture(t, dir, 2)
	_, out := runCLI("verify", "--anchor", anchor, "--entries", entries)
	if _, ok := out["manifest"]; ok {
		t.Errorf("manifest block present without --manifest flag: %v", out["manifest"])
	}
}

// A malformed manifest file surfaces manifest.error but MUST NOT change
// the chain verdict or exit code — freshness is advisory (ADR-029 §D5).
func TestCLI_ManifestGarbage_AdvisoryErrorDoesNotFailChain(t *testing.T) {
	dir := t.TempDir()
	anchor, entries, _ := writeFixture(t, dir, 3)
	badManifest := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(badManifest, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write bad manifest: %v", err)
	}
	code, out := runCLI("verify", "--anchor", anchor, "--entries", entries, "--manifest", badManifest)
	if code != exitValid {
		t.Fatalf("advisory manifest error changed exit code: got %d want %d", code, exitValid)
	}
	if out["status"] != "valid" {
		t.Errorf("status = %v, want valid (chain is intact; manifest is advisory)", out["status"])
	}
	mb, ok := out["manifest"].(map[string]any)
	if !ok {
		t.Fatalf("manifest block missing/wrong type: %v", out["manifest"])
	}
	if _, ok := mb["error"]; !ok {
		t.Errorf("expected manifest.error for garbage manifest, got %v", mb)
	}
}

// A manifest whose root signature doesn't verify is likewise advisory:
// error surfaced, chain verdict + exit code untouched.
func TestCLI_ManifestBadRootSignature_Advisory(t *testing.T) {
	dir := t.TempDir()
	anchor, entries, _ := writeFixture(t, dir, 2)
	// Structurally valid manifest JSON but signed by nobody the pinned
	// root trusts — ParseAndVerifyTrustManifest rejects it.
	forged := `{"version":9,"generated_at_ms":1782864000000,"env":"dev","approved_by":"x","root_key_id":"r","schema_note":"","platform_keys":[],"tenant_keys":[],"root_signature_b64":"AAAA"}`
	mp := filepath.Join(dir, "forged.json")
	if err := os.WriteFile(mp, []byte(forged), 0o600); err != nil {
		t.Fatalf("write forged manifest: %v", err)
	}
	code, out := runCLI("verify", "--anchor", anchor, "--entries", entries, "--manifest", mp)
	if code != exitValid {
		t.Fatalf("bad-sig manifest changed exit code: got %d want %d", code, exitValid)
	}
	mb, ok := out["manifest"].(map[string]any)
	if !ok {
		t.Fatalf("manifest block missing: %v", out["manifest"])
	}
	if _, ok := mb["error"]; !ok {
		t.Errorf("expected manifest.error for bad root signature, got %v", mb)
	}
}
