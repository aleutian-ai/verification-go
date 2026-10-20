// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"errors"
	"testing"
)

// windowAwareManifestSpy is a minimal TrustManifestV3WithValidityWindows
// implementation that records whether the verifier called the timed
// variant. Used to assert the H1 fix actually wires up the
// validity-window check in `VerifyChainEntryV3`.
type windowAwareManifestSpy struct {
	inner          TrustManifestV3
	timedCallCount int
	windowFrom     int64
	windowUntil    int64
	rejectWindow   bool // when true, the timed lookup returns ErrKeyOutsideValidityWindowV3
}

func (m *windowAwareManifestSpy) PublicKeyForSigningKeyID(ctx context.Context, id string) ([]byte, error) {
	// VerifyChainEntryV3 should NOT call this when our timed
	// method is available — if it does, the test fails because
	// timedCallCount stays at 0.
	return m.inner.PublicKeyForSigningKeyID(ctx, id)
}

func (m *windowAwareManifestSpy) PublicKeyForSigningKeyIDAtTime(ctx context.Context, id string, entryTs int64) ([]byte, error) {
	m.timedCallCount++
	if m.rejectWindow {
		return nil, ErrKeyOutsideValidityWindowV3
	}
	return m.inner.PublicKeyForSigningKeyID(ctx, id)
}

func TestVerifyChainEntryV3_CallsTimedVariantWhenAvailable(t *testing.T) {
	t.Parallel()
	f := mintSignedV3(t, testIntentForSigning())
	spy := &windowAwareManifestSpy{inner: f.manifest}
	if err := VerifyChainEntryV3(context.Background(), f.entry, f.contentHashHex, f.signatureB64, spy); err != nil {
		t.Fatalf("VerifyChainEntryV3: %v", err)
	}
	if spy.timedCallCount != 1 {
		t.Errorf("expected 1 call to PublicKeyForSigningKeyIDAtTime, got %d (verifier didn't dispatch to the timed variant — H1 regression)",
			spy.timedCallCount)
	}
}

func TestVerifyChainEntryV3_RejectsEntryOutsideValidityWindow(t *testing.T) {
	t.Parallel()
	f := mintSignedV3(t, testIntentForSigning())
	spy := &windowAwareManifestSpy{inner: f.manifest, rejectWindow: true}
	err := VerifyChainEntryV3(context.Background(), f.entry, f.contentHashHex, f.signatureB64, spy)
	if !errors.Is(err, ErrKeyOutsideValidityWindowV3) {
		t.Fatalf("expected ErrKeyOutsideValidityWindowV3, got %v", err)
	}
}

func TestVerifyChainEntryV3_FallsBackToUntimedForLegacyManifest(t *testing.T) {
	t.Parallel()
	// `TrustManifestFromMapV3` does NOT implement
	// TrustManifestV3WithValidityWindows. Verifier should fall
	// back to PublicKeyForSigningKeyID.
	f := mintSignedV3(t, testIntentForSigning())
	if err := VerifyChainEntryV3(context.Background(), f.entry, f.contentHashHex, f.signatureB64, f.manifest); err != nil {
		t.Fatalf("legacy manifest: %v", err)
	}
}
