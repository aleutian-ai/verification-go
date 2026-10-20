// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Build a fixed-shape valid payload the byte-shape tests can mutate
// from. All timestamps + serial are chosen so the resulting canonical
// bytes are stable and the golden vector below stays valid until the
// wire format is intentionally bumped.
func validV1Payload() TrustManifestPayloadV1 {
	return TrustManifestPayloadV1{
		Version:        1,
		ManifestSerial: 17,
		TenantID:       "comp_01HX9K2P3VQNRT8WZE7CMD8YH4",
		IssuedAtMs:     1_717_286_400_000,
		ExpiresAtMs:    1_719_878_400_000, // ~30 days later
		Keys: []TrustManifestSignedKeyV1{
			{
				SigningKeyID: "kid_b59e64d6595cc207",
				Algorithm:    "ML-DSA-65",
				PublicKey:    bytes.Repeat([]byte{0x11}, 1952), // pretend ML-DSA-65 pubkey
				ValidFromMs:  1_717_286_400_000,
				ValidUntilMs: 1_719_878_400_000,
			},
		},
	}
}

// TestCanonicalBytesV1_LocksHeaderPrefix is the single most important
// test in this file. The first 27 bytes of every valid v1 manifest
// MUST be the domain-prefix string literally. If a future change
// breaks this, every previously-signed manifest stops verifying.
func TestCanonicalBytesV1_LocksHeaderPrefix(t *testing.T) {
	got, err := CanonicalBytesTrustManifestV1(validV1Payload())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.HasPrefix(got, []byte(TrustManifestCanonicalDomainPrefixV1)) {
		t.Fatalf("canonical bytes do not start with the locked domain prefix\nfirst-30: %x", got[:30])
	}
}

// TestCanonicalBytesV1_GoldenVector_MinimalOneKey locks the EXACT
// byte sequence the encoder produces for a 1-key payload. This is
// the cross-language golden vector — Python and JS implementations
// MUST produce these same bytes for the same input.
//
// If you change this test, you ARE breaking the wire format. Bump
// TrustManifestCanonicalFormatVersionV1 + the domain prefix in the
// same diff.
func TestCanonicalBytesV1_GoldenVector_MinimalOneKey(t *testing.T) {
	// Use a small synthetic pubkey for readability; the
	// MaxLen check accepts up to 8192 bytes but the encoder
	// doesn't care about the bytes' meaning.
	p := TrustManifestPayloadV1{
		Version:        1,
		ManifestSerial: 1,
		TenantID:       "comp_01TEST",
		IssuedAtMs:     1_000,
		ExpiresAtMs:    2_000,
		Keys: []TrustManifestSignedKeyV1{
			{
				SigningKeyID: "kid_a",
				Algorithm:    "ML-DSA-65",
				PublicKey:    []byte{0xde, 0xad, 0xbe, 0xef},
				ValidFromMs:  1_000,
				ValidUntilMs: 2_000,
			},
		},
	}
	got, err := CanonicalBytesTrustManifestV1(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Build the expected byte sequence by hand below.
	var want bytes.Buffer
	want.WriteString(TrustManifestCanonicalDomainPrefixV1) // "aleutian.trust_manifest.v1:" (27 bytes)
	// u32_be(version=1)
	want.Write([]byte{0x00, 0x00, 0x00, 0x01})
	// u32_be(format_version=1)
	want.Write([]byte{0x00, 0x00, 0x00, 0x01})
	// u64_be(manifest_serial=1)
	want.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	// u32_be(len("comp_01TEST")=11) + bytes
	want.Write([]byte{0x00, 0x00, 0x00, 0x0b})
	want.WriteString("comp_01TEST")
	// u64_be(issued_at_ms=1000)
	want.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8})
	// u64_be(expires_at_ms=2000)
	want.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd0})
	// u32_be(key_count=1)
	want.Write([]byte{0x00, 0x00, 0x00, 0x01})
	// u32_be(len("kid_a")=5) + bytes
	want.Write([]byte{0x00, 0x00, 0x00, 0x05})
	want.WriteString("kid_a")
	// u32_be(len("ML-DSA-65")=9) + bytes
	want.Write([]byte{0x00, 0x00, 0x00, 0x09})
	want.WriteString("ML-DSA-65")
	// u32_be(len(pubkey)=4) + bytes
	want.Write([]byte{0x00, 0x00, 0x00, 0x04})
	want.Write([]byte{0xde, 0xad, 0xbe, 0xef})
	// u64_be(valid_from_ms=1000)
	want.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8})
	// u64_be(valid_until_ms=2000)
	want.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd0})

	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("golden vector mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got), hex.EncodeToString(want.Bytes()))
	}
}

// TestCanonicalBytesV1_KeyOrderingDeterministic confirms that two
// callers passing the same keys in different orders produce
// byte-identical canonical bytes — the encoder sorts internally
// before writing.
func TestCanonicalBytesV1_KeyOrderingDeterministic(t *testing.T) {
	base := validV1Payload()
	// Add a second key with id "kid_a" (sorts before "kid_b...").
	keyA := TrustManifestSignedKeyV1{
		SigningKeyID: "kid_a59e64d6595cc207",
		Algorithm:    "ML-DSA-65",
		PublicKey:    bytes.Repeat([]byte{0x22}, 1952),
		ValidFromMs:  1_717_286_400_000,
		ValidUntilMs: 1_719_878_400_000,
	}

	in1 := base
	in1.Keys = append([]TrustManifestSignedKeyV1{}, base.Keys...)
	in1.Keys = append(in1.Keys, keyA)

	in2 := base
	in2.Keys = []TrustManifestSignedKeyV1{keyA, base.Keys[0]}

	b1, err := CanonicalBytesTrustManifestV1(in1)
	if err != nil {
		t.Fatalf("encode in1: %v", err)
	}
	b2, err := CanonicalBytesTrustManifestV1(in2)
	if err != nil {
		t.Fatalf("encode in2: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("input-order sensitivity: encoder didn't sort keys before writing")
	}
}

// TestCanonicalBytesV1_FieldSensitivity confirms that every field
// (with sensible mutations) produces distinct canonical bytes.
// Catches "I accidentally didn't include that in the encoder" bugs.
func TestCanonicalBytesV1_FieldSensitivity(t *testing.T) {
	base, err := CanonicalBytesTrustManifestV1(validV1Payload())
	if err != nil {
		t.Fatalf("base: %v", err)
	}

	mutations := []struct {
		name string
		mut  func(*TrustManifestPayloadV1)
	}{
		{"version", func(p *TrustManifestPayloadV1) { p.Version++ }},
		{"manifest_serial", func(p *TrustManifestPayloadV1) { p.ManifestSerial++ }},
		{"tenant_id", func(p *TrustManifestPayloadV1) { p.TenantID = "comp_01HX9K2P3VQNRT8WZE7CMD8YH5" }},
		{"issued_at_ms", func(p *TrustManifestPayloadV1) { p.IssuedAtMs++ }},
		{"expires_at_ms", func(p *TrustManifestPayloadV1) { p.ExpiresAtMs++ }},
		{"keys[0].signing_key_id", func(p *TrustManifestPayloadV1) { p.Keys[0].SigningKeyID = "kid_c59e64d6595cc207" }},
		{"keys[0].algorithm", func(p *TrustManifestPayloadV1) { p.Keys[0].Algorithm = "ML-DSA-65-ALT" }},
		{"keys[0].public_key", func(p *TrustManifestPayloadV1) { p.Keys[0].PublicKey = bytes.Repeat([]byte{0x33}, 1952) }},
		{"keys[0].valid_from_ms", func(p *TrustManifestPayloadV1) { p.Keys[0].ValidFromMs++ }},
		{"keys[0].valid_until_ms", func(p *TrustManifestPayloadV1) { p.Keys[0].ValidUntilMs++ }},
	}
	for _, tc := range mutations {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := validV1Payload()
			tc.mut(&p)
			got, err := CanonicalBytesTrustManifestV1(p)
			if err != nil {
				t.Fatalf("mutated encode: %v", err)
			}
			if bytes.Equal(base, got) {
				t.Errorf("mutation on %s did NOT change canonical bytes — field not in encoder", tc.name)
			}
		})
	}
}

// TestCanonicalBytesV1_RejectsInvalid covers the rubric §A defenses
// — empty fields, non-UTF8, control chars, oversize, duplicate
// signing_key_ids, expired-before-issued. All errors must wrap
// ErrTrustManifestInvalidV1 so callers can dispatch via errors.Is.
func TestCanonicalBytesV1_RejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*TrustManifestPayloadV1)
	}{
		{"version=0", func(p *TrustManifestPayloadV1) { p.Version = 0 }},
		{"empty_tenant_id", func(p *TrustManifestPayloadV1) { p.TenantID = "" }},
		{"tenant_id_oversize", func(p *TrustManifestPayloadV1) {
			p.TenantID = strings.Repeat("a", trustManifestTenantIDMaxLen+1)
		}},
		{"tenant_id_control_char", func(p *TrustManifestPayloadV1) { p.TenantID = "comp_a\x00b" }},
		{"tenant_id_invalid_utf8", func(p *TrustManifestPayloadV1) {
			// Lone continuation byte — not valid UTF-8.
			p.TenantID = string([]byte{0x80, 0x80})
		}},
		{"issued_zero", func(p *TrustManifestPayloadV1) { p.IssuedAtMs = 0 }},
		{"expires_before_issued", func(p *TrustManifestPayloadV1) { p.ExpiresAtMs = p.IssuedAtMs }},
		{"no_keys", func(p *TrustManifestPayloadV1) { p.Keys = nil }},
		{"empty_signing_key_id", func(p *TrustManifestPayloadV1) { p.Keys[0].SigningKeyID = "" }},
		{"duplicate_signing_key_id", func(p *TrustManifestPayloadV1) {
			p.Keys = append(p.Keys, p.Keys[0])
		}},
		{"empty_algorithm", func(p *TrustManifestPayloadV1) { p.Keys[0].Algorithm = "" }},
		{"empty_pubkey", func(p *TrustManifestPayloadV1) { p.Keys[0].PublicKey = nil }},
		{"oversize_pubkey", func(p *TrustManifestPayloadV1) {
			p.Keys[0].PublicKey = bytes.Repeat([]byte{0x11}, trustManifestPublicKeyMaxLen+1)
		}},
		{"valid_from_zero", func(p *TrustManifestPayloadV1) { p.Keys[0].ValidFromMs = 0 }},
		{"valid_until_before_from", func(p *TrustManifestPayloadV1) {
			p.Keys[0].ValidUntilMs = p.Keys[0].ValidFromMs
		}},
		{"too_many_keys", func(p *TrustManifestPayloadV1) {
			out := make([]TrustManifestSignedKeyV1, 0, trustManifestMaxKeysPerManifest+1)
			for i := 0; i < trustManifestMaxKeysPerManifest+1; i++ {
				k := p.Keys[0]
				k.SigningKeyID = "kid_" + hex.EncodeToString([]byte{byte(i >> 8), byte(i & 0xff)})
				out = append(out, k)
			}
			p.Keys = out
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := validV1Payload()
			tc.mut(&p)
			_, err := CanonicalBytesTrustManifestV1(p)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, ErrTrustManifestInvalidV1) {
				t.Errorf("error doesn't wrap ErrTrustManifestInvalidV1: %v", err)
			}
		})
	}
}

// TestCanonicalBytesV1_RejectsNonNFC confirms the C1 fix — the
// encoder REJECTS un-normalized UTF-8 (it does not silently
// normalize). Cross-language signature equality contract per
// `sdk_trust_manifest_format_spec` §3 + §8.
func TestCanonicalBytesV1_RejectsNonNFC(t *testing.T) {
	// "café" with combining acute (U+0065 U+0301) is NFD, not NFC.
	// In NFC the same word uses the precomposed U+00E9.
	nfdCafe := "café" // 5 code points: c, a, f, e, COMBINING ACUTE ACCENT
	p := validV1Payload()
	p.TenantID = nfdCafe
	_, err := CanonicalBytesTrustManifestV1(p)
	if err == nil {
		t.Fatal("expected NFC rejection, got nil")
	}
	if !errors.Is(err, ErrTrustManifestInvalidV1) {
		t.Errorf("expected ErrTrustManifestInvalidV1, got %v", err)
	}
	if !strings.Contains(err.Error(), "NFC") {
		t.Errorf("error should mention NFC for caller guidance, got %v", err)
	}
}

// TestCanonicalBytesV1_RejectsNegativeTimestamps confirms the H4
// fix. Negative int64 timestamps would silently encode as huge
// uint64 via two's complement; the validator now rejects them.
func TestCanonicalBytesV1_RejectsNegativeTimestamps(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*TrustManifestPayloadV1)
	}{
		{"negative_issued_at", func(p *TrustManifestPayloadV1) { p.IssuedAtMs = -1 }},
		{"negative_expires_at", func(p *TrustManifestPayloadV1) {
			p.IssuedAtMs = 100
			p.ExpiresAtMs = -1
		}},
		{"negative_valid_from", func(p *TrustManifestPayloadV1) {
			p.Keys[0].ValidFromMs = -1
		}},
		{"negative_valid_until", func(p *TrustManifestPayloadV1) {
			p.Keys[0].ValidFromMs = 1
			p.Keys[0].ValidUntilMs = -1
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := validV1Payload()
			tc.mut(&p)
			_, err := CanonicalBytesTrustManifestV1(p)
			if err == nil {
				t.Errorf("expected error on %s, got nil", tc.name)
			}
			if !errors.Is(err, ErrTrustManifestInvalidV1) {
				t.Errorf("%s: error doesn't wrap ErrTrustManifestInvalidV1: %v", tc.name, err)
			}
		})
	}
}

// TestCanonicalBytesV1_DoesNotMutateInput is a safety net: the
// encoder MUST NOT mutate the caller's slice (e.g., by sorting it
// in place). Callers expect their input to survive the call
// unchanged so they can re-use it for the signature step.
func TestCanonicalBytesV1_DoesNotMutateInput(t *testing.T) {
	p := validV1Payload()
	// Add a key that sorts before the base one so the sort
	// step has work to do.
	p.Keys = append(p.Keys, TrustManifestSignedKeyV1{
		SigningKeyID: "kid_a00",
		Algorithm:    "ML-DSA-65",
		PublicKey:    bytes.Repeat([]byte{0x77}, 1952),
		ValidFromMs:  p.Keys[0].ValidFromMs,
		ValidUntilMs: p.Keys[0].ValidUntilMs,
	})
	originalFirstID := p.Keys[0].SigningKeyID

	if _, err := CanonicalBytesTrustManifestV1(p); err != nil {
		t.Fatalf("encode: %v", err)
	}

	if p.Keys[0].SigningKeyID != originalFirstID {
		t.Errorf("encoder mutated caller's slice: first key id changed from %q to %q",
			originalFirstID, p.Keys[0].SigningKeyID)
	}
}
