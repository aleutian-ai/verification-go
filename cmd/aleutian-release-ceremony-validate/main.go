// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command aleutian-release-ceremony-validate is the operator-facing
// pre-flight check for the release-key signing ceremony (see
// docs/runbooks/release_disclosure_decrypt.md §1.2.5).
//
// After running `gcloud kms keys versions get-public-key` + `xxd -p`
// to produce a hex-encoded ML-DSA-65 pubkey, the operator pipes that
// file through this tool to confirm it's safe to paste into
// sdk/verification-go/release/pubkey.go.
//
// Exit 0 = hex is valid, paste it into pubkey.go.
// Exit non-zero = something is wrong; the ceremony fix-it message
// describes what.
//
// Usage:
//
//	aleutian-release-ceremony-validate /tmp/release-pubkey.hex
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aleutian-ai/verification-go/release"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: aleutian-release-ceremony-validate <path/to/pubkey.hex>")
		os.Exit(2)
	}
	path := os.Args[1]
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(1)
	}
	// Trim trailing newlines + whitespace defensively. The runbook
	// uses `tr -d '\n'` so this is belt-and-braces, not load-bearing.
	hexStr := strings.TrimSpace(string(raw))
	if err := release.ValidatePubkeyHex(hexStr); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Common causes:")
		fmt.Fprintln(os.Stderr, "  - xxd output not piped through `tr -d '\\n'`")
		fmt.Fprintln(os.Stderr, "  - gcloud key uses the wrong algorithm (must be PQ_SIGN_ML_DSA_65)")
		fmt.Fprintln(os.Stderr, "  - hex file truncated by a half-failed copy")
		os.Exit(1)
	}
	fmt.Printf("OK: hex is %d chars; decodes to 1952-byte ML-DSA-65 pubkey; parses cleanly via circl\n", len(hexStr))
	fmt.Println("Safe to paste into sdk/verification-go/release/pubkey.go:44")
}
