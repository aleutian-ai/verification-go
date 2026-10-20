// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"strings"
	"testing"
)

func TestFormatV2DeprecationWarning(t *testing.T) {
	tests := []struct {
		formatVersion int
		want          string
	}{
		{2, V2DeprecationWarning},
		{3, ""},
		{0, ""},
		{1, ""},
		{99, ""},
	}
	for _, tc := range tests {
		got := FormatV2DeprecationWarning(tc.formatVersion)
		if got != tc.want {
			t.Errorf("FormatV2DeprecationWarning(%d) = %q; want %q",
				tc.formatVersion, got, tc.want)
		}
	}
}

func TestV2DeprecationWarning_ContentLocked(t *testing.T) {
	// The exact byte sequence is part of the cross-language CV-09
	// contract. If this string changes, Python and JS sibling SDK
	// tests MUST be updated in the same commit.
	want := "WARNING: format_version=2 bundle does not pin framework_version. Step-9 self-attestation cross-check unavailable. Producer should re-emit at format_version=3."
	if V2DeprecationWarning != want {
		t.Errorf("V2DeprecationWarning text changed; CV-09 cross-language fixture must be regenerated")
	}
	// Sanity checks on the locked text:
	for _, must := range []string{"WARNING", "format_version=2", "framework_version", "step-9", "format_version=3"} {
		if !strings.Contains(strings.ToLower(V2DeprecationWarning), strings.ToLower(must)) {
			t.Errorf("V2DeprecationWarning missing expected substring %q", must)
		}
	}
}
