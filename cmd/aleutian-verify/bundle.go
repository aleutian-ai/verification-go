// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	sdk "github.com/aleutian-ai/verification-go"
)

// bundleOut is the single-line JSON verdict for `aleutian-verify bundle`.
// Top-level keys are serialized in a stable alphabetical order so a
// cross-language byte-diff stays meaningful (same posture as the chain
// verify output). `reason` is present only when status="invalid".
type bundleOut struct {
	BundleID     string `json:"bundle_id"`
	FilesChecked int    `json:"files_checked"`
	Interface    string `json:"interface"`
	Reason       string `json:"reason,omitempty"`
	Status       string `json:"status"`
}

// runBundle offline-verifies an unpacked export bundle DIRECTORY:
//
//	aleutian-verify bundle <dir>
//
// It proves the delivered files are byte-for-byte the ones Aleutian signed —
// signature over manifest.json, manifest_root recompute, per-file re-hash, and
// no-unlisted-file — using only the bundle's own trust_manifest snapshot (zero
// network). Exit codes match the chain verifier: 0 valid, 1 invalid, 2 usage,
// 3 IO/parse.
func runBundle(argv []string, stdout, stderr io.Writer) int {
	if len(argv) != 1 || argv[0] == "-h" || argv[0] == "--help" {
		fmt.Fprintln(stderr, "usage: aleutian-verify bundle <bundle-dir>")
		fmt.Fprintln(stderr, "  Offline-verifies an unpacked export bundle (run from / point at the bundle root).")
		return exitUsage
	}
	dir := argv[0]

	res, err := sdk.VerifyBundleDir(dir)
	// Discriminate on the error TYPE, not on res.Reason (C1): an
	// ErrBundleInvalid-wrapped error is a verification VERDICT (exit 1); any
	// other non-nil error is structural/IO (exit 3) and must NOT be reported to
	// the customer as "tampered".
	if err != nil && !errors.Is(err, sdk.ErrBundleInvalid) {
		fmt.Fprintf(stderr, "bundle: %v\n", err)
		return exitIOOrParse
	}

	out := bundleOut{
		BundleID:     res.BundleID,
		FilesChecked: res.FilesChecked,
		Interface:    interfaceName,
		Status:       "valid",
	}
	if !res.Valid {
		out.Status = "invalid"
		out.Reason = res.Reason
	}

	enc := json.NewEncoder(stdout)
	if encErr := enc.Encode(out); encErr != nil {
		fmt.Fprintf(stderr, "bundle: encode output: %v\n", encErr)
		return exitIOOrParse
	}
	if res.Valid {
		return exitValid
	}
	return exitInvalid
}
