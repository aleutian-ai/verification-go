// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package tier2

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// dualFixture mirrors the JSON committed by cmd/tier2-fixture-gen.
// The shape is the cross-language byte-parity contract — Python + JS
// SDK tests load THE SAME FILE and must produce THE SAME CEK.
type dualFixture struct {
	Schema         string `json:"schema"`
	BundleID       string `json:"bundle_id"`
	PrimarySeedHex string `json:"primary_seed_hex"`
	PrimaryFP      string `json:"primary_fp"`
	BackupSeedHex  string `json:"backup_seed_hex"`
	BackupFP       string `json:"backup_fp"`
	ExpectedCEKHex string `json:"expected_cek_hex"`
	WrongSeedHex   string `json:"wrong_seed_hex"`
	Manifest       struct {
		Tier2 Tier2Manifest `json:"tier2"`
	} `json:"manifest"`
}

func loadDualFixture(t *testing.T) dualFixture {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "testdata", "tier2_dual_v1.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f dualFixture
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if f.Schema != "tier2_dual_v1" {
		t.Fatalf("fixture schema = %q; want tier2_dual_v1", f.Schema)
	}
	return f
}

// TestFixture_PrimarySeedUnseals verifies the Go SDK can open the
// committed cross-language fixture and recover the expected CEK.
func TestFixture_PrimarySeedUnseals(t *testing.T) {
	f := loadDualFixture(t)
	seed, _ := hex.DecodeString(f.PrimarySeedHex)
	expectedCEK, _ := hex.DecodeString(f.ExpectedCEKHex)

	bundle := &Bundle{ID: f.BundleID, Manifest: Manifest{Tier2: f.Manifest.Tier2}}
	res, err := OpenBundle(seed, bundle)
	if err != nil {
		t.Fatalf("OpenBundle(primary): %v", err)
	}
	if !bytes.Equal(res.CEK, expectedCEK) {
		t.Errorf("CEK mismatch — fixture format drift detected")
	}
	if res.MatchedFingerprint != f.PrimaryFP {
		t.Errorf("matched fp = %q; want %q", res.MatchedFingerprint, f.PrimaryFP)
	}
	if res.MatchedEnvelopeIndex != 0 {
		t.Errorf("matched idx = %d; want 0", res.MatchedEnvelopeIndex)
	}
}

// TestFixture_BackupSeedUnseals verifies the second recipient slot
// also opens to the same CEK.
func TestFixture_BackupSeedUnseals(t *testing.T) {
	f := loadDualFixture(t)
	seed, _ := hex.DecodeString(f.BackupSeedHex)
	expectedCEK, _ := hex.DecodeString(f.ExpectedCEKHex)

	bundle := &Bundle{ID: f.BundleID, Manifest: Manifest{Tier2: f.Manifest.Tier2}}
	res, err := OpenBundle(seed, bundle)
	if err != nil {
		t.Fatalf("OpenBundle(backup): %v", err)
	}
	if !bytes.Equal(res.CEK, expectedCEK) {
		t.Errorf("CEK mismatch")
	}
	if res.MatchedEnvelopeIndex != 1 {
		t.Errorf("matched idx = %d; want 1", res.MatchedEnvelopeIndex)
	}
}

// TestFixture_WrongSeedRejected verifies a seed for a different keypair
// returns ErrNoMatchingRecipient against the same bundle.
func TestFixture_WrongSeedRejected(t *testing.T) {
	f := loadDualFixture(t)
	seed, _ := hex.DecodeString(f.WrongSeedHex)

	bundle := &Bundle{ID: f.BundleID, Manifest: Manifest{Tier2: f.Manifest.Tier2}}
	_, err := OpenBundle(seed, bundle)
	if !errors.Is(err, ErrNoMatchingRecipient) {
		t.Errorf("err = %v; want ErrNoMatchingRecipient", err)
	}
}

// TestFixture_DeriveFingerprint_RoundtripsToFixtureFPs verifies the
// SDK's DeriveFingerprint output matches the fingerprints the
// proprietary sealer wrote into the fixture. This is the cross-
// language fingerprint contract.
func TestFixture_DeriveFingerprint_RoundtripsToFixtureFPs(t *testing.T) {
	f := loadDualFixture(t)
	primarySeed, _ := hex.DecodeString(f.PrimarySeedHex)
	backupSeed, _ := hex.DecodeString(f.BackupSeedHex)

	pFP, err := DeriveFingerprint(primarySeed)
	if err != nil {
		t.Fatalf("derive primary: %v", err)
	}
	if pFP != f.PrimaryFP {
		t.Errorf("primary fp = %q; fixture = %q", pFP, f.PrimaryFP)
	}

	bFP, err := DeriveFingerprint(backupSeed)
	if err != nil {
		t.Fatalf("derive backup: %v", err)
	}
	if bFP != f.BackupFP {
		t.Errorf("backup fp = %q; fixture = %q", bFP, f.BackupFP)
	}
}
