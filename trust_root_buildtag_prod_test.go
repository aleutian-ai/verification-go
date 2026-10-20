// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build trust_prod

package verification

import "testing"

func TestTrustRoot_ProdTag(t *testing.T) {
	if ActiveTrustEnv != "prod" {
		t.Fatalf("-tags=trust_prod: ActiveTrustEnv = %q, want %q",
			ActiveTrustEnv, "prod")
	}
}
