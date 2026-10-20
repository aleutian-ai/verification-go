// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

// Stable exit codes for `aleutian-disclosure-decrypt`. MUST match the
// proprietary build's codes byte-for-byte — CI / operator tooling
// depends on these values being identical across SDK and proprietary
// releases.
//
// See `cmd/aleutian-disclosure-decrypt/exit_codes.go` in the
// Aleutian monorepo for the canonical declarations.
const (
	ExitOK               = 0
	ExitStructural       = 1
	ExitNoMatchingKey    = 2
	ExitAEADFailure      = 3
	ExitNetwork          = 4
	ExitSeedFileError    = 5
	ExitOutputPermission = 6
	ExitAPIAuth          = 7
	ExitInternal         = 99
)
