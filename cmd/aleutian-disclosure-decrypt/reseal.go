// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aleutian-ai/verification-go/sarenvelope"
)

// resealedSubdir is the bundle-relative directory under --out where
// resealed envelopes land in reseal-ephemeral mode.
const resealedSubdir = "resealed"

// resealContext holds the per-bundle state for the reseal pipeline:
// the auditor's pubkey (loaded once), its fingerprint, the output
// directory, and the bundle id used as AAD-bound CompanyID.
type resealContext struct {
	auditorPubkey      []byte
	auditorFingerprint string
	outDir             string
	bundleID           string
	companyID          string
}

// newResealContext prepares the reseal pipeline. Reads + validates
// the auditor pubkey PEM, computes its fingerprint, creates the
// <outRoot>/resealed/ output subdirectory with 0o700.
func newResealContext(outRoot, bundleID, companyID, auditorPubkeyPath string) (*resealContext, error) {
	pubBytes, err := readPubkeyPEM(auditorPubkeyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read auditor pubkey: %v", ErrSeedFile, err)
	}
	fp, err := sarenvelope.Fingerprint(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: fingerprint auditor pubkey: %v", ErrSeedFile, err)
	}
	resealDir := filepath.Join(outRoot, resealedSubdir)
	if err := os.MkdirAll(resealDir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create resealed dir: %v", ErrOutputPermission, err)
	}
	return &resealContext{
		auditorPubkey:      pubBytes,
		auditorFingerprint: fp,
		outDir:             resealDir,
		bundleID:           bundleID,
		companyID:          companyID,
	}, nil
}

// reseal re-encrypts a recovered plaintext payload under the
// auditor's pubkey via sarenvelope.Seal and writes the resealed
// envelope to <outDir>/resealed/<row_id>_<auditor_fp_short>.bin.
//
// # Security invariants (mirror the proprietary implementation)
//
//   - NEVER writes plaintext to disk
//   - NEVER returns or logs the plaintext
//   - Re-encrypted bytes are byte-identical to the proprietary
//     reseal output for the same (plaintext, auditor pubkey, bundle
//     id, row id) — enforced via the cross-compat test in
//     AleutianEnterprise/test/cross_compat/
func (rc *resealContext) reseal(rowID string, plaintext []byte) (string, error) {
	envBytes, err := sarenvelope.Seal(sarenvelope.SealInput{
		RecipientPubkey: rc.auditorPubkey,
		Reason:          plaintext,
		AD: sarenvelope.AssociatedData{
			// CompanyID carries the ORIGINAL customer's canonical
			// company id so the auditor can recover the tenant
			// identity from the resealed envelope's AAD alone.
			// Bundle id is bound via RequestID below for audit
			// continuity. Byte-identical to the proprietary build.
			CompanyID:  rc.companyID,
			RequestID:  fmt.Sprintf("%s:%s", rc.bundleID, rowID),
			SealedAtMs: time.Now().UTC().UnixMilli(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("%w: reseal row %q: %v",
			ErrAEADFailure, rowID, err)
	}
	fpShort := rc.auditorFingerprint[:16]
	path := filepath.Join(rc.outDir, fmt.Sprintf("%s_%s.bin", rowID, fpShort))
	if err := os.WriteFile(path, envBytes, 0o600); err != nil {
		return "", fmt.Errorf("%w: write resealed envelope %q: %v",
			ErrOutputPermission, path, err)
	}
	h := sha512.Sum512(envBytes)
	return hex.EncodeToString(h[:]), nil
}
