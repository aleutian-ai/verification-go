// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const realBundleFixture = "testdata/bundle_v1_real"

// TestVerifyBundleDir_RealSignatureVerifies_V2RootGuard exercises the crypto
// path against a REAL signed bundle (manifest.json + signature.bin +
// trust_manifest snapshot produced live on dev). It proves two things at once:
//
//   - The signature + trust-manifest path works on real data: the ML-DSA-65
//     signature over the raw manifest bytes verifies with the key resolved
//     from the bundle's own trust_manifest snapshot (zero network).
//   - The v2 manifest_root guard correctly REJECTS a bundle signed with the
//     old v1 recipe (this fixture is v1) — proving the recipe-version binding.
//
// A full PASS (Valid=true) requires a v2-recipe bundle and is covered by the
// live end-to-end proof after the v2 producer deploys.
func TestVerifyBundleDir_RealSignatureVerifies_V2RootGuard(t *testing.T) {
	if _, err := os.Stat(realBundleFixture); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	res, err := VerifyBundleDir(realBundleFixture)
	if err == nil || !errors.Is(err, ErrBundleInvalid) {
		t.Fatalf("expected ErrBundleInvalid (v1 root vs v2 verifier); got err=%v valid=%v", err, res.Valid)
	}
	if res.Valid {
		t.Error("v1 bundle must not verify under the v2 recipe")
	}
	if res.BundleID != "exp_01KXC0MAJ7MZJ1A4JHMKKSVKPY" {
		t.Errorf("BundleID = %q; want the fixture's id", res.BundleID)
	}
	// Must have gotten PAST the signature step (real signature verified) and
	// failed specifically on the root recompute.
	if res.Reason == "" || !strings.Contains(res.Reason, "manifest_root") {
		t.Errorf("expected a manifest_root failure (signature must have passed); reason=%q", res.Reason)
	}
}

// TestVerifyBundleDir_TamperedManifestFailsSignature flips a byte in the signed
// manifest.json; the signature (over the raw bytes) must no longer verify.
func TestVerifyBundleDir_TamperedManifestFailsSignature(t *testing.T) {
	if _, err := os.Stat(realBundleFixture); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	dir := copyFixture(t, realBundleFixture)
	// Flip a byte inside manifest.json (keep it valid JSON: mutate a hex digit
	// in a sha512 value so the bytes differ but json.Unmarshal still succeeds).
	mp := filepath.Join(dir, "manifest.json")
	b, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	// swap the first two lowercase hex chars we find inside a quoted value
	for i := 1; i < len(b)-1; i++ {
		if b[i] == 'a' && b[i-1] == '"' {
			b[i] = 'b'
			break
		}
		if b[i] == 'a' {
			b[i] = 'b'
			break
		}
	}
	if err := os.WriteFile(mp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyBundleDir(dir)
	if err == nil || !errors.Is(err, ErrBundleInvalid) || res.Valid {
		t.Fatalf("tampered manifest must fail signature; got err=%v valid=%v", err, res.Valid)
	}
	if !strings.Contains(res.Reason, "signature") {
		t.Errorf("expected a signature failure; reason=%q", res.Reason)
	}
}

// TestVerifyBundleDir_BadSignatureLength truncates signature.bin.
func TestVerifyBundleDir_BadSignatureLength(t *testing.T) {
	if _, err := os.Stat(realBundleFixture); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	dir := copyFixture(t, realBundleFixture)
	if err := os.WriteFile(filepath.Join(dir, "signature.bin"), []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundleDir(dir); err == nil || !errors.Is(err, ErrBundleInvalid) {
		t.Fatalf("short signature must fail; got %v", err)
	}
}

// TestVerifyBundleDir_MissingManifest returns a structural (non-ErrBundleInvalid) error.
func TestVerifyBundleDir_MissingManifest(t *testing.T) {
	dir := t.TempDir()
	res, err := VerifyBundleDir(dir)
	if err == nil || res.Valid {
		t.Fatalf("missing manifest must error; got %v valid=%v", err, res.Valid)
	}
	if errors.Is(err, ErrBundleInvalid) {
		t.Error("a missing manifest is a structural error, not a verification failure")
	}
}

// TestVerifyBundleDir_EmptySigningKeyID rejects a manifest with no signing key.
func TestVerifyBundleDir_EmptySigningKeyID(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"),
		[]byte(`{"bundle_id":"x","signing_key_id":"","manifest_root":"","files":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyBundleDir(dir)
	if err == nil || !errors.Is(err, ErrBundleInvalid) || res.Valid {
		t.Fatalf("empty signing_key_id must fail as invalid; got %v valid=%v", err, res.Valid)
	}
}

// TestUnlistedBundleFile covers the extras-rejection helper directly (the
// content-hash + full-PASS paths are live-proven with a v2 bundle).
func TestUnlistedBundleFile(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "manifest.json", "m")
	mustWrite(t, dir, "signature.bin", "s")
	mustWrite(t, dir, "chain_extracts/consent.jsonl", "c")
	mustWrite(t, dir, "anchors/anchors.jsonl", "a")

	listed := map[string]struct{}{
		"chain_extracts/consent.jsonl": {},
		"anchors/anchors.jsonl":        {},
	}
	// No extras (manifest.json + signature.bin are exempt).
	if extra, err := unlistedBundleFile(dir, listed); err != nil || extra != "" {
		t.Fatalf("clean bundle should report no extras; extra=%q err=%v", extra, err)
	}
	// Add a sneaky file.
	mustWrite(t, dir, "sneaky.jsonl", "x")
	extra, err := unlistedBundleFile(dir, listed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(extra, "sneaky.jsonl") {
		t.Errorf("expected sneaky.jsonl reported as extra; got %q", extra)
	}
}

// TestSafeBundlePath rejects traversal / absolute / NUL / empty paths (A1).
func TestSafeBundlePath(t *testing.T) {
	dir := t.TempDir()
	bad := []string{
		"",
		"../escape",
		"../../etc/passwd",
		"a/../../escape",
		"/etc/passwd",
		"with\x00nul",
	}
	for _, p := range bad {
		if _, err := safeBundlePath(dir, p); err == nil {
			t.Errorf("safeBundlePath must reject %q", p)
		}
	}
	// A benign nested path is accepted and stays inside dir.
	good, err := safeBundlePath(dir, "chain_extracts/consent.jsonl")
	if err != nil {
		t.Fatalf("benign path rejected: %v", err)
	}
	if !strings.HasPrefix(good, dir) {
		t.Errorf("resolved path %q escaped dir %q", good, dir)
	}
}

// TestHashRegularFileCapped rejects symlinks (A2) + oversized files (A3).
func TestHashRegularFileCapped(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(real, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Regular file within cap → hashes.
	if _, err := hashRegularFileCapped(real, 1<<20); err != nil {
		t.Fatalf("regular file should hash: %v", err)
	}
	// Oversized → rejected.
	if _, err := hashRegularFileCapped(real, 2); err == nil {
		t.Error("oversized file must be rejected")
	}
	// Symlink → rejected (even pointing at a valid file).
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := hashRegularFileCapped(link, 1<<20); err == nil {
		t.Error("symlink must be rejected (A2)")
	}
}

// --- helpers ---

func copyFixture(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.Walk(src, func(p string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func mustWrite(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
