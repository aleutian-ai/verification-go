// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build trust_staging

package verification

import "testing"

func TestTrustRoot_StagingTag(t *testing.T) {
	if ActiveTrustEnv != "staging" {
		t.Fatalf("-tags=trust_staging: ActiveTrustEnv = %q, want %q",
			ActiveTrustEnv, "staging")
	}
}
