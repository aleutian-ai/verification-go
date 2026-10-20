// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build !trust_staging && !trust_prod

package verification

import "testing"

func TestTrustRoot_DefaultBuildIsDev(t *testing.T) {
	if ActiveTrustEnv != "dev" {
		t.Fatalf("default build: ActiveTrustEnv = %q, want %q",
			ActiveTrustEnv, "dev")
	}
}
