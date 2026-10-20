// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aleutian-ai/verification-go/sarenvelope"
	"github.com/aleutian-ai/verification-go/seedwrap"
	"golang.org/x/term"
)

// readSeedSource resolves the seed bytes from one of the supported
// sources (file path, stdin) and unwraps the PEM. Returns the raw
// 32-byte X-Wing seed.
//
// Pipeline (mirrors the proprietary build byte-for-byte at the wire
// layer; the unwrap math lives in github.com/aleutian-ai/verification-go/seedwrap
// which both builds now share):
//
//  1. Slurp the source bytes (file or stdin).
//  2. If the bytes parse as a passphrase-wrapped PEM
//     (seedwrap.IsWrapped), resolve the passphrase from the env var
//     or controlling-terminal prompt, then call seedwrap.Unwrap.
//  3. Otherwise treat the bytes as a raw (unwrapped) seed PEM and
//     decode via the existing readSeedPEM path.
//
// All failure modes collapse to ErrSeedFile to deny a passphrase-vs-
// envelope-vs-payload distinguisher oracle.
func readSeedSource(seedPath, passphraseEnvVar string) ([]byte, error) {
	rawBytes, err := readSeedFileOrStdin(seedPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSeedFile, err)
	}

	if seedwrap.IsWrapped(rawBytes) {
		passphrase, perr := resolvePassphrase(passphraseEnvVar)
		if perr != nil {
			return nil, fmt.Errorf("%w: %v", ErrSeedFile, perr)
		}
		defer zeroize(passphrase)

		unwrapped, uerr := seedwrap.Unwrap(rawBytes, passphrase)
		if uerr != nil {
			return nil, fmt.Errorf("%w: unwrap: %v", ErrSeedFile, uerr)
		}
		if len(unwrapped) != sarenvelope.XWingSeedSize {
			zeroize(unwrapped)
			return nil, fmt.Errorf("%w: unwrapped seed is %d bytes, expected %d",
				ErrSeedFile, len(unwrapped), sarenvelope.XWingSeedSize)
		}
		return unwrapped, nil
	}

	// Raw unwrapped PEM path — reuse the existing decoder via a
	// memory-based variant so we don't re-read the file.
	seed, err := decodeUnwrappedSeedPEM(rawBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSeedFile, err)
	}
	return seed, nil
}

// resolvePassphrase reads the seed passphrase from the named env var
// when supplied, otherwise prompts on the controlling terminal.
//
// Mirrors the proprietary build's resolvePassphrase byte-for-byte at
// the user-visible behavior layer. Env-var path is the CI-recommended
// shape (set ALEUTIAN_SEED_PASSPHRASE in your secret store); the
// interactive prompt is for operator one-off use.
func resolvePassphrase(envVar string) ([]byte, error) {
	if envVar != "" {
		v := os.Getenv(envVar)
		if v == "" {
			return nil, fmt.Errorf("env var %q is empty", envVar)
		}
		// Copy so the caller can zeroize without mutating the process
		// environment.
		out := []byte(v)
		return out, nil
	}

	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return nil, errors.New("no controlling terminal for passphrase prompt; pass --seed-passphrase-env <VAR>")
	}
	fmt.Fprint(os.Stderr, "Seed passphrase: ")
	bytePass, err := term.ReadPassword(int(os.Stderr.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %v", err)
	}
	if len(bytePass) == 0 {
		return nil, errors.New("empty passphrase")
	}
	return bytePass, nil
}

// readSeedFileOrStdin reads source bytes from a file path or stdin.
func readSeedFileOrStdin(seedPath string) ([]byte, error) {
	if seedPath == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, 64*1024))
	}
	return os.ReadFile(seedPath)
}

// decodeUnwrappedSeedPEM decodes a raw X-Wing private-key PEM from
// bytes already in memory. Extracted so readSeedSource can call it
// without re-reading the file.
//
// Accepts any of the three legitimate block types:
//   - the legacy single-key type (xwingPrivateKeyPEMType)
//   - the dual-key primary slot (xwingPrivateKeyPEMTypePrimary)
//   - the dual-key backup slot (xwingPrivateKeyPEMTypeBackup)
//
// Refuses passphrase-wrapped blocks at this layer — readSeedSource
// detects those upstream via seedwrap.IsWrapped.
func decodeUnwrappedSeedPEM(pemBytes []byte) ([]byte, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("not a valid PEM file")
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after PEM block")
	}
	switch block.Type {
	case xwingPrivateKeyPEMType,
		xwingPrivateKeyPEMTypePrimary,
		xwingPrivateKeyPEMTypeBackup:
		// OK
	case passphraseWrappedPEMType:
		// Defensive — readSeedSource should have caught this above.
		return nil, errors.New("passphrase-wrapped PEM should not reach decodeUnwrappedSeedPEM")
	default:
		return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
	}
	if len(block.Bytes) != sarenvelope.XWingSeedSize {
		return nil, fmt.Errorf("seed is %d bytes, expected %d",
			len(block.Bytes), sarenvelope.XWingSeedSize)
	}
	out := make([]byte, len(block.Bytes))
	copy(out, block.Bytes)
	return out, nil
}

// passphraseSourceHint produces a human-readable description of where
// the passphrase will come from, used by verbose-style help output.
func passphraseSourceHint(envVar string) string {
	if envVar != "" {
		return fmt.Sprintf("env:%s", strings.TrimSpace(envVar))
	}
	return "interactive prompt"
}
