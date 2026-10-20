// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build !trust_staging && !trust_prod

package verification

import (
	_ "embed"
	"fmt"
)

// trust_root_dev.go — Default build (no trust_* tag) pins the dev
// root pubkey from fixtures/trust-root-dev.pub.

//go:embed fixtures/trust-root-dev.pub
var trustRootDevBytes []byte

func init() {
	if len(trustRootDevBytes) != MLDSA65PublicKeySize {
		panic(fmt.Sprintf(
			"verification: fixtures/trust-root-dev.pub is %d bytes; want %d. "+
				"Did the file get corrupted? Re-run 15n_fix_A4 Step 2 for dev.",
			len(trustRootDevBytes), MLDSA65PublicKeySize))
	}
	TrustRootPublicKey = trustRootDevBytes
	ActiveTrustEnv = "dev"
}
