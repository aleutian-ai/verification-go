// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"strings"
	"testing"
)

func TestFormatVerifiedLine_HappyPath(t *testing.T) {
	got := FormatVerifiedLine("SOC 2", "soc2-2017@20260531")
	want := "VERIFIED · SOC 2 / soc2-2017@20260531"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestFormatVerifiedLine_LegacyV2(t *testing.T) {
	// Both empty → bare VERIFIED (backward-compat for v2 bundles).
	got := FormatVerifiedLine("", "")
	want := "VERIFIED"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestFormatVerifiedLine_MixedEmptyVisible(t *testing.T) {
	// One empty, one populated: deliberately NOT normalized to bare
	// VERIFIED. Mixed state is a producer bug worth showing.
	got := FormatVerifiedLine("SOC 2", "")
	if got == "VERIFIED" {
		t.Errorf("mixed-empty inputs should NOT collapse to bare VERIFIED; got %q", got)
	}
	if !strings.Contains(got, "SOC 2") {
		t.Errorf("got %q; expected 'SOC 2' to remain visible", got)
	}
}

func TestFormatExplainBlock_HappyPath(t *testing.T) {
	f, err := LoadFromEmbedded("soc2-2017@20260531")
	if err != nil {
		t.Fatalf("LoadFromEmbedded: %v", err)
	}
	got := FormatExplainBlock(f)

	// Spot-check each field appears on its own line with the locked
	// label width.
	checks := []string{
		"Framework:              soc2-2017",
		"Version:                soc2-2017@20260531",
		"Framework published at: 2017-04-30",
		"Aleutian snapshot at:   2026-05-31",
		"In-scope controls:      6",
		"Out-of-scope controls:  15",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("explain block missing line %q\nfull output:\n%s", want, got)
		}
	}
}

func TestFormatVerifiedLine_CrossLanguageContract(t *testing.T) {
	// Pin the exact byte sequence other-language SDKs must match.
	// This is the CV-09 anchor for cross-language byte-identity on
	// the VERIFIED line.
	type tc struct {
		framework string
		version   VersionID
		want      string
	}
	for _, c := range []tc{
		{"SOC 2", "soc2-2017@20260531", "VERIFIED · SOC 2 / soc2-2017@20260531"},
		{"GDPR", "gdpr@20260531", "VERIFIED · GDPR / gdpr@20260531"},
		{"EU-AI-Act", "eu-ai-act@20260531", "VERIFIED · EU-AI-Act / eu-ai-act@20260531"},
		{"HIPAA", "hipaa@20260531", "VERIFIED · HIPAA / hipaa@20260531"},
		{"", "", "VERIFIED"},
	} {
		got := FormatVerifiedLine(c.framework, c.version)
		if got != c.want {
			t.Errorf("FormatVerifiedLine(%q, %q) = %q; want %q", c.framework, c.version, got, c.want)
		}
	}
}
