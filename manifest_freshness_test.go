// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// The freshness helper is a customer-facing verdict primitive shared
// across the Go/Python/JS SDKs. The golden vectors in
// sdk/testdata/manifest_freshness_golden.json are the single source of
// truth: all three SDKs load the SAME file and MUST agree on every
// field, byte-for-byte, on the verdict_line (ADR-029 §D5 / 12f_e).

type freshnessGoldenExpect struct {
	AgeDays          int64  `json:"age_days"`
	Stale            bool   `json:"stale"`
	RollbackDetected bool   `json:"rollback_detected"`
	VerdictLine      string `json:"verdict_line"`
	RevocationNote   string `json:"revocation_note"`
}

type freshnessGoldenCase struct {
	Name            string                `json:"name"`
	Version         int64                 `json:"version"`
	GeneratedAtMs   int64                 `json:"generated_at_ms"`
	NowMs           int64                 `json:"now_ms"`
	LastSeenVersion int64                 `json:"last_seen_version"`
	Expect          freshnessGoldenExpect `json:"expect"`
}

type freshnessGoldenFile struct {
	MaxAgeDays int64                 `json:"max_age_days"`
	Cases      []freshnessGoldenCase `json:"cases"`
}

func loadFreshnessGolden(t *testing.T) freshnessGoldenFile {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "testdata", "shared", "manifest_freshness_golden.json") // a copy of sdk/testdata/manifest_freshness_golden.json; publish-sdks.sh refuses one that differs
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g freshnessGoldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	if len(g.Cases) == 0 {
		t.Fatal("golden file has no cases")
	}
	return g
}

func TestEvaluateManifestFreshness_GoldenVectors(t *testing.T) {
	g := loadFreshnessGolden(t)
	if g.MaxAgeDays != ManifestFreshnessMaxAgeDays {
		t.Fatalf("golden max_age_days=%d but SDK constant=%d — cross-SDK threshold drift",
			g.MaxAgeDays, ManifestFreshnessMaxAgeDays)
	}
	for _, tc := range g.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			f := EvaluateManifestFreshness(tc.Version, tc.GeneratedAtMs, tc.NowMs, tc.LastSeenVersion)
			if f.AgeDays != tc.Expect.AgeDays {
				t.Errorf("AgeDays = %d, want %d", f.AgeDays, tc.Expect.AgeDays)
			}
			if f.Stale != tc.Expect.Stale {
				t.Errorf("Stale = %v, want %v", f.Stale, tc.Expect.Stale)
			}
			if f.RollbackDetected != tc.Expect.RollbackDetected {
				t.Errorf("RollbackDetected = %v, want %v", f.RollbackDetected, tc.Expect.RollbackDetected)
			}
			if got := f.VerdictLine(); got != tc.Expect.VerdictLine {
				t.Errorf("VerdictLine mismatch:\n got: %q\nwant: %q", got, tc.Expect.VerdictLine)
			}
			if got := f.RevocationNote(); got != tc.Expect.RevocationNote {
				t.Errorf("RevocationNote mismatch:\n got: %q\nwant: %q", got, tc.Expect.RevocationNote)
			}
		})
	}
}

// TestEvaluateManifestFreshness_NeverBareValid pins the honest-verdict
// contract: the verdict line always names the manifest version + date and
// the revocation-freshness caveat — never a bare "valid" (ADR-029 §D5,
// ticket 15 honest-verdict).
func TestEvaluateManifestFreshness_NeverBareValid(t *testing.T) {
	f := EvaluateManifestFreshness(3, 1782864000000, 1783036800000, -1)
	line := f.VerdictLine()
	for _, want := range []string{"trust manifest v3", "dated 2026-07-01", "not reflected"} {
		if !strings.Contains(line, want) {
			t.Errorf("verdict line %q missing required substring %q", line, want)
		}
	}
	if line == "valid" || line == "Signature valid." {
		t.Errorf("verdict line is bare-valid: %q", line)
	}
}

// TestEvaluateManifestFreshness_RollbackIsStatefulOnly documents the
// stateless-limit AC: a negative lastSeenVersion disables rollback
// detection even for a version-1 manifest.
func TestEvaluateManifestFreshness_RollbackIsStatefulOnly(t *testing.T) {
	stateless := EvaluateManifestFreshness(1, 1782864000000, 1783036800000, -1)
	if stateless.RollbackDetected {
		t.Error("stateless (lastSeen<0) must never report rollback")
	}
	stateful := EvaluateManifestFreshness(1, 1782864000000, 1783036800000, 5)
	if !stateful.RollbackDetected {
		t.Error("stateful lastSeen=5 vs version=1 must report rollback")
	}
	equal := EvaluateManifestFreshness(5, 1782864000000, 1783036800000, 5)
	if equal.RollbackDetected {
		t.Error("equal version (5 vs 5) is not a rollback")
	}
}

// TestParseAndVerifyTrustManifest_OfflineHappyPath proves the offline
// (bytes, no network) manifest load + freshness pipeline end-to-end: a
// root-signed manifest parses, its Version/GeneratedAt survive, and the
// freshness verdict is computed from them. This is the CISO "verify
// against published keys with no egress" motion (12f_e).
func TestParseAndVerifyTrustManifest_OfflineHappyPath(t *testing.T) {
	priv := withTestRoot(t)
	body := minimalManifestBody(t) // version=7, generated_at_ms=1700000000000
	signed := buildSignedManifestBytes(t, priv, body)

	m, err := ParseAndVerifyTrustManifest(signed)
	if err != nil {
		t.Fatalf("ParseAndVerifyTrustManifest: %v", err)
	}
	if m.Version != 7 {
		t.Fatalf("version = %d, want 7", m.Version)
	}

	// 1700000000000 ms = 2023-11-14; evaluated at a fixed later "now"
	// (2023-12-20) => stale (>30d).
	nowMs := int64(1703030400000) // 2023-12-20T00:00:00Z
	f := EvaluateManifestFreshness(m.Version, m.GeneratedAt.UnixMilli(), nowMs, -1)
	if !f.Stale {
		t.Errorf("expected stale verdict for a >30d-old manifest, got age=%d", f.AgeDays)
	}
	if !strings.Contains(f.VerdictLine(), "trust manifest v7") {
		t.Errorf("verdict line missing version: %q", f.VerdictLine())
	}
	if !strings.Contains(f.VerdictLine(), "[WARNING:") {
		t.Errorf("stale verdict line missing WARNING: %q", f.VerdictLine())
	}
}

// A manifest signed by a key the pinned root doesn't trust MUST be
// rejected by the offline parse (authenticity is orthogonal to freshness,
// but the offline load still fails closed on a bad root signature).
func TestParseAndVerifyTrustManifest_BadRootSignature_FailsClosed(t *testing.T) {
	// Pin a fresh root, but sign with a DIFFERENT key.
	_ = withTestRoot(t)
	scheme := mldsa65.Scheme()
	_, attackerSK, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("gen attacker key: %v", err)
	}
	body := minimalManifestBody(t)
	signed := buildSignedManifestBytes(t, *(attackerSK.(*mldsa65.PrivateKey)), body)

	if _, err := ParseAndVerifyTrustManifest(signed); err == nil {
		t.Fatal("expected bad-root-signature manifest to fail offline parse")
	}
}
