// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"errors"
	"sort"
	"testing"
	"testing/fstest"
)

func TestDefaultEvidencePath(t *testing.T) {
	tests := []struct {
		framework FrameworkID
		control   string
		want      string
	}{
		{SOC2_2017, "CC6.1", "chain_extracts/soc2-2017_cc6.1.jsonl"},
		{HIPAA, "§164.312(b)", "chain_extracts/hipaa_sec_164.312b.jsonl"},
		{GDPR, "Art.5(1)(f)", "chain_extracts/gdpr_art.51f.jsonl"},
		{NIST_800_53, "AU-10", "chain_extracts/nist-800-53_au-10.jsonl"},
		{CCPA_CPRA, "§1798.110", "chain_extracts/ccpa-cpra_sec_1798.110.jsonl"},
	}
	for _, tc := range tests {
		got := DefaultEvidencePath(tc.framework, tc.control)
		if got != tc.want {
			t.Errorf("DefaultEvidencePath(%q, %q) = %q; want %q",
				tc.framework, tc.control, got, tc.want)
		}
	}
}

// makeSyntheticFramework returns a small framework with mixed statuses
// so the test asserts both the "missing" and "skipped" branches.
func makeSyntheticFramework() Framework {
	return Framework{
		AleutianSnapshotAt:   "2026-05-31",
		FrameworkID:          FrameworkID("test-fw"),
		FrameworkPublishedAt: "2017-04-30",
		VersionID:            VersionID("test-fw@20260531"),
		Controls: []Control{
			{ID: "OP-1", Title: "T1", Category: "cat", Status: StatusOperating, WhatWeProve: "p1", WhatWeDontProve: "q1"},
			{ID: "OP-2", Title: "T2", Category: "cat", Status: StatusOperating, WhatWeProve: "p2", WhatWeDontProve: "q2"},
			{ID: "DES-1", Title: "T3", Category: "cat", Status: StatusDesigned, WhatWeProve: "p3", WhatWeDontProve: "q3"},
			{ID: "RM-1", Title: "T4", Category: "cat", Status: StatusRoadmap, WhatWeProve: "p4", WhatWeDontProve: "q4"},
		},
		ControlsOutOfScope: []OutOfScopeControl{{ID: "X", Reason: "r"}},
	}
}

func TestCoverageCheck_AllCovered(t *testing.T) {
	f := makeSyntheticFramework()
	bundle := fstest.MapFS{
		DefaultEvidencePath(f.FrameworkID, "OP-1"): &fstest.MapFile{Data: []byte("{}")},
		DefaultEvidencePath(f.FrameworkID, "OP-2"): &fstest.MapFile{Data: []byte("{}")},
	}
	result, err := CoverageCheck(f, bundle, nil)
	if err != nil {
		t.Fatalf("CoverageCheck: %v", err)
	}
	if len(result.Missing) != 0 {
		t.Errorf("Missing: got %v; want empty", result.Missing)
	}
	// Designed + Roadmap controls reported in skipped lists.
	if len(result.SkippedDesigned) != 1 || result.SkippedDesigned[0] != "DES-1" {
		t.Errorf("SkippedDesigned: got %v; want [DES-1]", result.SkippedDesigned)
	}
	if len(result.SkippedRoadmap) != 1 || result.SkippedRoadmap[0] != "RM-1" {
		t.Errorf("SkippedRoadmap: got %v; want [RM-1]", result.SkippedRoadmap)
	}
}

func TestCoverageCheck_OneMissing(t *testing.T) {
	f := makeSyntheticFramework()
	bundle := fstest.MapFS{
		DefaultEvidencePath(f.FrameworkID, "OP-1"): &fstest.MapFile{Data: []byte("{}")},
		// OP-2 deliberately absent.
	}
	result, err := CoverageCheck(f, bundle, nil)
	if !errors.Is(err, ErrControlCoverageMissing) {
		t.Fatalf("want ErrControlCoverageMissing; got %v", err)
	}
	if len(result.Missing) != 1 || result.Missing[0] != "OP-2" {
		t.Errorf("Missing: got %v; want [OP-2]", result.Missing)
	}
}

func TestCoverageCheck_AllOperatingMissing(t *testing.T) {
	f := makeSyntheticFramework()
	bundle := fstest.MapFS{} // empty
	result, err := CoverageCheck(f, bundle, nil)
	if !errors.Is(err, ErrControlCoverageMissing) {
		t.Fatalf("want ErrControlCoverageMissing; got %v", err)
	}
	sort.Strings(result.Missing)
	want := []string{"OP-1", "OP-2"}
	if !equalSlice(result.Missing, want) {
		t.Errorf("Missing: got %v; want %v", result.Missing, want)
	}
}

func TestCoverageCheck_DesignedAndRoadmapNotRequired(t *testing.T) {
	// Override the framework to have ONLY designed + roadmap status
	// controls. Coverage check must pass even with empty bundle.
	f := makeSyntheticFramework()
	f.Controls = []Control{
		{ID: "DES-1", Title: "T", Category: "cat", Status: StatusDesigned, WhatWeProve: "p", WhatWeDontProve: "q"},
		{ID: "RM-1", Title: "T", Category: "cat", Status: StatusRoadmap, WhatWeProve: "p", WhatWeDontProve: "q"},
	}
	result, err := CoverageCheck(f, fstest.MapFS{}, nil)
	if err != nil {
		t.Errorf("designed/roadmap-only framework must pass coverage; got %v", err)
	}
	if len(result.Missing) != 0 {
		t.Errorf("Missing should be empty; got %v", result.Missing)
	}
}

func TestCoverageCheck_CustomResolver(t *testing.T) {
	f := makeSyntheticFramework()
	// Custom resolver maps every control to a fixed path; if both
	// operating controls map to "X", a single file satisfies both.
	resolver := func(_ FrameworkID, _ string) string { return "X" }
	bundle := fstest.MapFS{"X": &fstest.MapFile{Data: []byte("{}")}}
	if _, err := CoverageCheck(f, bundle, resolver); err != nil {
		t.Errorf("custom resolver should satisfy coverage; got %v", err)
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
