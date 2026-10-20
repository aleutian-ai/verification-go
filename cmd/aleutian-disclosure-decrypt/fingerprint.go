// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/aleutian-ai/verification-go/sarenvelope"
)

// X-Wing public-key PEM block types accepted by --print-fingerprint.
// Mirrors the proprietary keygen ceremony output.
const (
	xwingPublicKeyPEMType        = "ALEUTIAN XWING PUBLIC KEY"
	xwingPublicKeyPEMTypePrimary = "ALEUTIAN XWING PRIMARY PUBLIC KEY"
	xwingPublicKeyPEMTypeBackup  = "ALEUTIAN XWING BACKUP PUBLIC KEY"
)

// PrintFingerprintRequest is the input contract for the
// --print-fingerprint subcommand. Exactly one of SeedPath or
// PubkeyPath is required.
type PrintFingerprintRequest struct {
	SeedPath   string
	PubkeyPath string
}

// PrintFingerprint resolves the input PEM (seed or pubkey) to the
// canonical 32-char hex Aleutian fingerprint. Same semantics +
// byte-identical output as the proprietary build.
func PrintFingerprint(req PrintFingerprintRequest) (string, error) {
	if (req.SeedPath == "") == (req.PubkeyPath == "") {
		return "", fmt.Errorf("%w: exactly one of --seed or --pubkey is required",
			ErrSeedFile)
	}
	if req.SeedPath != "" {
		seed, err := readSeedPEM(req.SeedPath)
		if err != nil {
			return "", err
		}
		defer zeroize(seed)
		return fingerprintFromSeed(seed)
	}
	pubBytes, err := readPubkeyPEM(req.PubkeyPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSeedFile, err)
	}
	return sarenvelope.Fingerprint(pubBytes)
}

// readPubkeyPEM reads + PEM-decodes an X-Wing public-key PEM. Stdin
// supported via "-".
func readPubkeyPEM(path string) ([]byte, error) {
	var (
		raw []byte
		err error
	)
	if path == "-" {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, 64*1024))
		if err != nil {
			return nil, fmt.Errorf("read pubkey from stdin: %v", err)
		}
	} else {
		raw, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %q: %v", path, err)
		}
	}
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("not a valid PEM file")
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after PEM block")
	}
	switch block.Type {
	case xwingPublicKeyPEMType, xwingPublicKeyPEMTypePrimary, xwingPublicKeyPEMTypeBackup:
		// OK
	default:
		return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
	}
	if len(block.Bytes) != sarenvelope.XWingPubkeySize {
		return nil, fmt.Errorf("pubkey is %d bytes, expected %d",
			len(block.Bytes), sarenvelope.XWingPubkeySize)
	}
	return block.Bytes, nil
}
