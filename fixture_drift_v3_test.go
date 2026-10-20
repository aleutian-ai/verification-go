// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// dsar_chain_d M7: drift guard between SDK and producer fixture copies.
//
// # The drift risk
//
// The v3 golden fixtures are the cross-language byte contract. The SDK is a
// separate Go module (`github.com/aleutian-ai/verification-go`) so it cannot
// import from `internal/...` directly — the fixtures are copied. If the
// producer adds a vector or tightens an existing one and the SDK copy isn't
// refreshed, producer CI passes while the SDK silently keeps validating against
// a stale contract. The SDK and producer encoders would then diverge in
// production without any test failing.
//
// # aleutianchain_21: why this is now discovery-based, not a hardcoded list
//
// This guard originally carried a hand-maintained list of five SAR fixtures. By
// 2026-08-27 the producer had nine, and the list had silently omitted four of
// them — including `v3_golden_capture_request.json`, the contract for the
// highest-volume entry type on the platform, and three consent fixtures sitting
// in a directory this test was already reading.
//
// The failure was not that the list was wrong. It was that a hand-maintained
// list of contract files cannot notice a new contract file. So the fixture set
// is now DISCOVERED from the producer directories: a new golden is guarded the
// moment it is created, with no one having to remember this file exists.
//
// # If the test is skipped
//
// External CI (the public SDK's own pipeline) has no producer tree, so the test
// skips rather than fails when the producer path is unreachable — it is a
// within-monorepo guard. That does mean the guard is absent in exactly the
// standalone-consumer environment, which is accepted: drift can only be
// INTRODUCED in the monorepo, which is where the guard runs.

// producerFixtureDirs are the producer-side directories whose v3 golden
// fixtures are mirrored into the SDK. Paths are relative to this package.
//
// Adding a producer package that bakes v3 goldens? Add its testdata directory
// here — that is the only manual step, and omitting it makes the orphan check
// in TestM7_NoOrphanedSDKFixtures fail loudly rather than silently skipping.
var producerFixtureDirs = []string{
	"../../internal/consent/testdata",
	"../../internal/captureentry/testdata",
}

// v3GoldenGlob matches the cross-language golden fixtures on both sides.
const v3GoldenGlob = "v3_golden_*.json"

// sdkOnlyV3Fixtures are SDK-side goldens that legitimately have no producer
// counterpart, with the reason. Anything else without a producer source is an
// orphan and fails — a copy nobody generates is a contract nobody maintains.
var sdkOnlyV3Fixtures = map[string]string{
	"v3_golden_capture_signed.json": "baked by the SDK itself (capture_signed_golden_test.go); " +
		"exercises signature verification over an already-canonical entry, so there is no producer-side source",
}

// discoverProducerFixtures returns basename → producer path for every v3 golden
// across producerFixtureDirs, or ok=false if the producer tree is unreachable.
func discoverProducerFixtures(t *testing.T) (map[string]string, bool) {
	t.Helper()
	found := map[string]string{}
	reachable := false
	for _, dir := range producerFixtureDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		reachable = true
		matches, err := filepath.Glob(filepath.Join(dir, v3GoldenGlob))
		if err != nil {
			t.Fatalf("glob %s: %v", dir, err)
		}
		for _, m := range matches {
			name := filepath.Base(m)
			if prior, dup := found[name]; dup {
				t.Errorf("fixture %q exists in two producer directories (%s and %s); "+
					"the cross-language contract must have exactly one source", name, prior, m)
			}
			found[name] = m
		}
	}
	return found, reachable
}

// TestM7_FixtureParityWithProducer asserts every producer v3 golden has a
// byte-identical SDK copy.
func TestM7_FixtureParityWithProducer(t *testing.T) {
	t.Parallel()
	producers, reachable := discoverProducerFixtures(t)
	if !reachable {
		t.Skip("producer fixture path unavailable (external CI, single-module checkout?)")
	}
	if len(producers) == 0 {
		t.Fatal("producer directories reachable but contain no v3 goldens — " +
			"the glob or producerFixtureDirs is wrong, and a silently-empty guard is worse than none")
	}

	for name, producerPath := range producers {
		name, producerPath := name, producerPath
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			producerBytes, err := os.ReadFile(producerPath)
			if err != nil {
				t.Fatalf("read producer %s: %v", producerPath, err)
			}
			sdkPath := filepath.Join("testdata", name)
			sdkBytes, err := os.ReadFile(sdkPath)
			if err != nil {
				t.Fatalf("producer fixture %s has no SDK copy at %s: %v.\n"+
					"A producer golden with no SDK copy means the SDK is not testing that contract at all.\n"+
					"Fix: cp %s sdk/verification-go/testdata/", name, sdkPath, err, producerPath)
			}
			if !bytes.Equal(producerBytes, sdkBytes) {
				t.Errorf("%s differs between producer and SDK copies (chain_d M7 drift).\n"+
					"The SDK is validating against a stale byte contract.\n"+
					"Refresh via: cp %s sdk/verification-go/testdata/", name, producerPath)
			}
		})
	}
}

// TestM7_NoOrphanedSDKFixtures asserts every SDK v3 golden traces back to a
// producer source or is a documented SDK-only fixture.
//
// This is the direction the original guard could not check. A stale SDK copy
// whose producer source was renamed or deleted would keep passing a parity test
// that only walks the producer set.
func TestM7_NoOrphanedSDKFixtures(t *testing.T) {
	t.Parallel()
	producers, reachable := discoverProducerFixtures(t)
	if !reachable {
		t.Skip("producer fixture path unavailable (external CI, single-module checkout?)")
	}

	sdkFixtures, err := filepath.Glob(filepath.Join("testdata", v3GoldenGlob))
	if err != nil {
		t.Fatalf("glob SDK testdata: %v", err)
	}
	for _, p := range sdkFixtures {
		name := filepath.Base(p)
		if _, ok := producers[name]; ok {
			continue
		}
		if reason, ok := sdkOnlyV3Fixtures[name]; ok {
			t.Logf("%s: SDK-only by design — %s", name, reason)
			continue
		}
		t.Errorf("SDK fixture %q has no producer source and is not listed in sdkOnlyV3Fixtures.\n"+
			"Either its producer source was renamed/deleted (leaving the SDK testing a contract "+
			"nobody generates), or it is intentionally SDK-only and must be documented there.", name)
	}
}
