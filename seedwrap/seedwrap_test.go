// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package seedwrap

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// samplePEM is a representative xwingkeyfile-shaped PEM payload (147
// bytes is the actual length we'd see in production; we use a stand-in
// of the same approximate size).
var samplePEM = []byte(`-----BEGIN ALEUTIAN HYBRID KEM PRIVATE KEY-----
QUxUMYEggEGd0pLGk1g9xF4IWsKi5kRCap5R6HouajBtIpOG5w==
-----END ALEUTIAN HYBRID KEM PRIVATE KEY-----
`)

func TestWrapUnwrap_RoundTrip(t *testing.T) {
	t.Parallel()
	pass := []byte("correct-horse-battery-staple")

	armored, err := Wrap(samplePEM, pass)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if !bytes.Contains(armored, []byte("ALEUTIAN PASSPHRASE-WRAPPED PRIVATE KEY")) {
		t.Errorf("armored PEM missing expected block type:\n%s", armored)
	}
	if !IsWrapped(armored) {
		t.Errorf("IsWrapped should return true for armored output")
	}

	plain, err := Unwrap(armored, pass)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(plain, samplePEM) {
		t.Errorf("round-trip mismatch\n got:  %q\n want: %q", plain, samplePEM)
	}
}

func TestWrapUnwrap_FreshSaltNoncePerCall(t *testing.T) {
	// Two wraps of the same plaintext with the same passphrase must
	// produce different armored output (proves we're not deterministic).
	t.Parallel()
	pass := []byte("correct-horse-battery-staple")
	a1, err := Wrap(samplePEM, pass)
	if err != nil {
		t.Fatalf("Wrap 1: %v", err)
	}
	a2, err := Wrap(samplePEM, pass)
	if err != nil {
		t.Fatalf("Wrap 2: %v", err)
	}
	if bytes.Equal(a1, a2) {
		t.Errorf("two wraps produced identical output — salt/nonce not fresh per call")
	}
	// Both must still unwrap to the same plaintext.
	for i, a := range [][]byte{a1, a2} {
		got, err := Unwrap(a, pass)
		if err != nil {
			t.Fatalf("Unwrap %d: %v", i, err)
		}
		if !bytes.Equal(got, samplePEM) {
			t.Errorf("Unwrap %d round-trip mismatch", i)
		}
	}
}

func TestUnwrap_WrongPassphraseRejects(t *testing.T) {
	t.Parallel()
	armored, err := Wrap(samplePEM, []byte("right-passphrase"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	_, err = Unwrap(armored, []byte("wrong-passphrase"))
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("err = %v; want ErrWrongPassphrase", err)
	}
}

func TestUnwrap_TamperedCiphertextFails(t *testing.T) {
	// Flipping a single byte in the ciphertext must fail AEAD open.
	t.Parallel()
	pass := []byte("correct-horse-battery-staple")
	armored, err := Wrap(samplePEM, pass)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	block, _ := pem.Decode(armored)
	if block == nil {
		t.Fatalf("Decode produced nil")
	}
	// Last byte of body is part of the GCM tag — flipping it triggers
	// AEAD rejection. (Flipping earlier bytes would also work; tag is
	// just the most predictable choice.)
	block.Bytes[len(block.Bytes)-1] ^= 0xFF
	tampered := pem.EncodeToMemory(block)

	_, err = Unwrap(tampered, pass)
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("err = %v; want ErrWrongPassphrase (tampered ct must collapse to same sentinel)", err)
	}
}

func TestUnwrap_TamperedAADFails(t *testing.T) {
	// The magic bytes are AEAD AAD. Flipping a magic byte must fail.
	t.Parallel()
	pass := []byte("correct-horse-battery-staple")
	armored, err := Wrap(samplePEM, pass)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	block, _ := pem.Decode(armored)
	// The structural magic check happens BEFORE AEAD open. So flipping
	// magic bytes triggers ErrCorruptEnvelope, not ErrWrongPassphrase.
	// That's intentional: structural validation can be distinguished by
	// the caller; only AEAD-level failures collapse.
	block.Bytes[0] ^= 0xFF
	tampered := pem.EncodeToMemory(block)
	_, err = Unwrap(tampered, pass)
	if !errors.Is(err, ErrCorruptEnvelope) {
		t.Errorf("err = %v; want ErrCorruptEnvelope on magic tamper", err)
	}
}

func TestWrap_ShortPassphraseRejected(t *testing.T) {
	t.Parallel()
	_, err := Wrap(samplePEM, []byte("short"))
	if !errors.Is(err, ErrShortPassphrase) {
		t.Errorf("err = %v; want ErrShortPassphrase", err)
	}
	// Boundary: exactly 8 chars accepted.
	_, err = Wrap(samplePEM, []byte("exact8ch"))
	if err != nil {
		t.Errorf("8-char passphrase should be accepted; got %v", err)
	}
}

func TestWrap_EmptyPlaintextRejected(t *testing.T) {
	t.Parallel()
	_, err := Wrap(nil, []byte("correct-horse-battery-staple"))
	if !errors.Is(err, ErrEmptyPlaintext) {
		t.Errorf("err = %v; want ErrEmptyPlaintext", err)
	}
	_, err = Wrap([]byte{}, []byte("correct-horse-battery-staple"))
	if !errors.Is(err, ErrEmptyPlaintext) {
		t.Errorf("empty slice: err = %v; want ErrEmptyPlaintext", err)
	}
}

func TestIsWrapped_DetectsBothShapes(t *testing.T) {
	t.Parallel()
	// Wrapped PEM → true
	armored, _ := Wrap(samplePEM, []byte("correct-horse-battery-staple"))
	if !IsWrapped(armored) {
		t.Errorf("IsWrapped(armored) should be true")
	}
	// Raw xwingkeyfile PEM → false (different block type)
	if IsWrapped(samplePEM) {
		t.Errorf("IsWrapped(raw xwing PEM) should be false")
	}
	// Random garbage → false
	garbage := make([]byte, 64)
	_, _ = rand.Read(garbage)
	if IsWrapped(garbage) {
		t.Errorf("IsWrapped(garbage) should be false")
	}
	// Empty → false
	if IsWrapped(nil) || IsWrapped([]byte{}) {
		t.Errorf("IsWrapped on empty input should be false")
	}
}

func TestUnwrap_InvalidPEMBlockType(t *testing.T) {
	t.Parallel()
	// A valid PEM but the wrong block type — caller passed an unwrapped
	// xwing PEM by accident.
	_, err := Unwrap(samplePEM, []byte("correct-horse-battery-staple"))
	if !errors.Is(err, ErrInvalidPEM) {
		t.Errorf("err = %v; want ErrInvalidPEM", err)
	}
}

func TestUnwrap_TruncatedBody(t *testing.T) {
	t.Parallel()
	armored, err := Wrap(samplePEM, []byte("correct-horse-battery-staple"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	block, _ := pem.Decode(armored)
	// Truncate body to below the minimum header size.
	block.Bytes = block.Bytes[:5]
	tiny := pem.EncodeToMemory(block)
	_, err = Unwrap(tiny, []byte("correct-horse-battery-staple"))
	if !errors.Is(err, ErrCorruptEnvelope) {
		t.Errorf("err = %v; want ErrCorruptEnvelope on truncated body", err)
	}
}

func TestUnwrap_AbsurdKDFParamsRejected(t *testing.T) {
	t.Parallel()
	// Hand-craft an envelope claiming 100 GiB Argon2 memory — should
	// be refused before Argon2 even starts.
	armored, err := Wrap(samplePEM, []byte("correct-horse-battery-staple"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	block, _ := pem.Decode(armored)
	// Bytes 4..8 hold the memory KiB field. Write 100 GiB (in KiB).
	body := block.Bytes
	body[4] = 0x06 // 100 * 1024 * 1024 KiB = 0x06400000
	body[5] = 0x40
	body[6] = 0x00
	body[7] = 0x00
	block.Bytes = body
	tampered := pem.EncodeToMemory(block)
	_, err = Unwrap(tampered, []byte("correct-horse-battery-staple"))
	if !errors.Is(err, ErrCorruptEnvelope) {
		t.Errorf("err = %v; want ErrCorruptEnvelope on absurd KDF params", err)
	}
}

func TestPEMBlockType_Stable(t *testing.T) {
	// Pin the block type string. Operators eyeball this; renaming it
	// would silently strand existing wrapped files (Unwrap rejects on
	// block-type mismatch).
	t.Parallel()
	if PEMBlockType != "ALEUTIAN PASSPHRASE-WRAPPED PRIVATE KEY" {
		t.Errorf("PEMBlockType changed: %q", PEMBlockType)
	}
}

func TestMagic_Stable(t *testing.T) {
	t.Parallel()
	if !bytes.Equal(Magic[:], []byte("ASW1")) {
		t.Errorf("Magic changed: %q", Magic[:])
	}
}

// TestArmored_LooksLikePEMBeforeUnwrap is a smoke check that the
// output is in fact PEM-armored (not raw binary) so `cat privacy.priv`
// gives an operator something readable.
func TestArmored_LooksLikePEM(t *testing.T) {
	t.Parallel()
	armored, _ := Wrap(samplePEM, []byte("correct-horse-battery-staple"))
	if !strings.HasPrefix(string(armored), "-----BEGIN ALEUTIAN PASSPHRASE-WRAPPED PRIVATE KEY-----") {
		t.Errorf("armored does not start with expected PEM header:\n%s", armored)
	}
	if !strings.Contains(string(armored), "-----END ALEUTIAN PASSPHRASE-WRAPPED PRIVATE KEY-----") {
		t.Errorf("armored missing END marker")
	}
}
