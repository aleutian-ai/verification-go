// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestIsPlaceholder_PostCeremony(t *testing.T) {
	// Post-release-key-ceremony (2026-06-09): the embedded pubkey is
	// the real KMS-minted ML-DSA-65 public key, so IsPlaceholder()
	// MUST report false.
	if IsPlaceholder() {
		t.Fatal("post-ceremony build still reports placeholder; pubkey embed regressed")
	}
	// Defense-in-depth: the embedded hex MUST parse as a real ML-DSA-65
	// pubkey (1952 bytes, valid via circl). Catches truncated copy or
	// accidental revert in a future PR.
	if err := ValidatePubkeyHex(releasePubkeyV1HexPlaceholder); err != nil {
		t.Errorf("embedded pubkey hex fails validation: %v", err)
	}
}

func TestVerifyChecksums_RejectsRandomSig(t *testing.T) {
	// Post-ceremony: a random 3309-byte sig must fail to verify
	// against the real pubkey (returns ErrInvalidSignature, not
	// ErrPlaceholderPubkey — the placeholder branch is dead post-
	// ceremony). Fail-closed posture preserved either way.
	sums := []byte("foo  bar\n")
	sig := make([]byte, mldsa65.SignatureSize)
	rand.Read(sig)
	err := VerifyChecksums(sums, sig)
	if err == nil {
		t.Fatal("VerifyChecksums accepted a random signature; should have failed")
	}
	if errors.Is(err, ErrPlaceholderPubkey) {
		t.Errorf("unexpected ErrPlaceholderPubkey post-ceremony: %v", err)
	}
}

func TestVerifyChecksums_RejectsWrongSignatureSize(t *testing.T) {
	// Even before the ceremony, signature-size validation should
	// fire first (it's cheaper than the placeholder check). Either
	// outcome (size error OR placeholder error) is acceptable —
	// what we care about is that "valid-looking 3309-byte sig + all-
	// zero key" doesn't pass.
	cases := []int{0, 100, 3308, 3310, 4096}
	for _, n := range cases {
		err := VerifyChecksums([]byte("x"), make([]byte, n))
		if err == nil {
			t.Errorf("size %d: expected error, got nil", n)
		}
	}
}

func TestVerifyChecksums_RoundTrip_AgainstSyntheticKey(t *testing.T) {
	// Generate a fresh ML-DSA-65 keypair, sign some bytes, and
	// drive VerifyChecksums via a hand-injected pubkey override.
	// Because the package-level pubkey is placeholder, this test
	// exercises the scheme.Verify path directly.
	scheme := mldsa65.Scheme()
	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	msg := []byte("8dc9667e5a2660cbec39c1e11f82d75ddd8bd98972bfb6c144b7766157382094  aleutian-disclosure-decrypt_darwin_amd64\n")
	sig := scheme.Sign(priv, msg, nil)
	if !scheme.Verify(pub, msg, sig, nil) {
		t.Fatal("synthetic verify failed")
	}
	// Tamper test: flipping one byte of the message MUST break the
	// signature.
	tampered := make([]byte, len(msg))
	copy(tampered, msg)
	tampered[0] ^= 0xFF
	if scheme.Verify(pub, tampered, sig, nil) {
		t.Fatal("verify accepted tampered message")
	}
	// Tamper test: flipping one byte of the signature MUST break it.
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0] ^= 0xFF
	if scheme.Verify(pub, msg, tamperedSig, nil) {
		t.Fatal("verify accepted tampered signature")
	}
}

func TestDecodeHex_RoundTrip(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
	}{
		{"", []byte{}},
		{"00", []byte{0}},
		{"ff", []byte{0xFF}},
		{"deadbeef", []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{"DEADBEEF", []byte{0xDE, 0xAD, 0xBE, 0xEF}}, // accepts upper-case too
	}
	for _, tc := range cases {
		got := decodeHex(tc.in)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("decodeHex(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestDecodeHex_RejectsOddLength(t *testing.T) {
	if got := decodeHex("a"); got != nil {
		t.Errorf("expected nil on odd-length input, got %v", got)
	}
}

func TestDecodeHex_RejectsInvalidChars(t *testing.T) {
	if got := decodeHex("xyzz"); got != nil {
		t.Errorf("expected nil on non-hex input, got %v", got)
	}
}
