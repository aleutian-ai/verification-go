// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command aleutian-release-verify verifies a downloaded SHA256SUMS
// file against its detached ML-DSA-65 signature, using the embedded
// Aleutian release-signing public key.
//
// # Customer workflow
//
//	# 1. Download the release artifacts.
//	curl -fLO https://releases.aleutian.ai/tier2/aleutian-disclosure-decrypt_darwin_arm64
//	curl -fLO https://releases.aleutian.ai/tier2/SHA256SUMS
//	curl -fLO https://releases.aleutian.ai/tier2/SHA256SUMS.sig
//
//	# 2. Verify the checksums file is from Aleutian.
//	aleutian-release-verify SHA256SUMS SHA256SUMS.sig
//	# → OK: SHA256SUMS verifies against the embedded Aleutian release pubkey
//
//	# 3. Verify YOUR download against SHA256SUMS.
//	shasum -a 256 -c SHA256SUMS --ignore-missing
//	# → aleutian-disclosure-decrypt_darwin_arm64: OK
//
// # Exit codes
//
//	0   signature verified
//	1   signature failed verification
//	2   usage error (missing args, file not readable)
//	3   release pubkey is the pre-ceremony placeholder (binary is too
//	    old to verify any signature; install a newer SDK release)
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/aleutian-ai/verification-go/release"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: aleutian-release-verify SHA256SUMS SHA256SUMS.sig")
		os.Exit(2)
	}
	sumsPath, sigPath := os.Args[1], os.Args[2]

	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", sumsPath, err)
		os.Exit(2)
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", sigPath, err)
		os.Exit(2)
	}

	err = release.VerifyChecksums(sums, sig)
	switch {
	case err == nil:
		fmt.Println("OK: SHA256SUMS verifies against the embedded Aleutian release pubkey")
		os.Exit(0)
	case errors.Is(err, release.ErrPlaceholderPubkey):
		fmt.Fprintln(os.Stderr, "FAIL: this aleutian-release-verify build was published before the release-key ceremony")
		fmt.Fprintln(os.Stderr, "      ran. Install a newer SDK version:")
		fmt.Fprintln(os.Stderr, "        go install github.com/aleutian-ai/verification-go/cmd/aleutian-release-verify@latest")
		os.Exit(3)
	default:
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}
