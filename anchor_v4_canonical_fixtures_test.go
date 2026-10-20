// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// dsar_chain_d_go_anchor_v4_audit (2026-05-27): drift guard that
// loads the cross-SDK canonical fixture file at
// `sdk/testdata/anchor_v4_canonical_vectors.json` and asserts the
// Go SDK's `canonicalizeAnchorForVersion` produces byte-identical
// output for each named vector.
//
// # Why this exists in addition to TestCanonicalize_V4StableByteForm
//
// The pre-existing inline-vector test (`anchor_v4_test.go`) only
// covers ONE vector (`minimal_v4`) and hardcodes the expected
// canonical bytes in the test source. If the canonical fixture file
// is updated (e.g., a new vector added, or an existing vector
// re-baked), the inline test will not catch the drift; this loader
// test does.
//
// Today the canonical file ships 3 vectors:
//   - minimal_v4 (also exercised inline by TestCanonicalize_V4StableByteForm)
//   - max_verified_through (boundary case: 2^63-1)
//   - v3_no_verified_through (dispatch coverage for the v3 path)

type anchorV4FixtureFile struct {
	Comment string                `json:"_comment"`
	Version int                   `json:"version"`
	Vectors []anchorV4FixtureCase `json:"vectors"`
}

// anchorV4FixtureCase decodes directly into the canonical Anchor
// type (not a shadow struct) so any future Anchor field addition
// is automatically exercised by this drift guard — a future field
// missing from the fixture decodes to zero-value, and a future
// field NOT covered by canonicalize-dispatch would cause real-vs-
// fixture bytes to diverge. Direct decoding closes the false-pass
// risk a transitional schema mirror would create.
type anchorV4FixtureCase struct {
	Name           string `json:"name"`
	Anchor         Anchor `json:"anchor"`
	CanonicalBytes string `json:"canonical_bytes"`
}

// TestCanonicalize_V4ExercisesCanonicalFixtureFile asserts the Go
// SDK matches the cross-SDK canonical fixture for every vector.
// Adding a new vector to the file requires the Go SDK to produce
// the documented bytes — drift fails this test in CI.
func TestCanonicalize_V4ExercisesCanonicalFixtureFile(t *testing.T) {
	t.Parallel()

	// Path is derived from THIS test file's location via runtime.Caller
	// rather than a CWD-relative join — robust under any test runner
	// (default `go test`, IDE configurations, `go test -exec`).
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0): could not resolve test file location")
	}
	path := filepath.Join(filepath.Dir(thisFile), "testdata", "shared", "anchor_v4_canonical_vectors.json") // a copy of sdk/testdata/anchor_v4_canonical_vectors.json; publish-sdks.sh refuses one that differs
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read canonical fixture %s: %v", path, err)
	}
	var file anchorV4FixtureFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode canonical fixture: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatalf("canonical fixture has zero vectors — fixture file may be malformed")
	}

	for _, v := range file.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			got, err := canonicalizeAnchorForVersion(v.Anchor)
			if err != nil {
				t.Fatalf("canonicalizeAnchorForVersion(%s): %v", v.Name, err)
			}
			if string(got) != v.CanonicalBytes {
				t.Errorf("v4 canonical drift on %s:\n  want: %s\n  got:  %s",
					v.Name, v.CanonicalBytes, string(got))
			}
		})
	}
}
