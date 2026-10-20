// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build trust_staging

package verification

import (
	_ "embed"
	"fmt"
)

// trust_root_staging.go — Selected with `-tags=trust_staging`.

//go:embed fixtures/trust-root-staging.pub
var trustRootStagingBytes []byte

func init() {
	if len(trustRootStagingBytes) != MLDSA65PublicKeySize {
		panic(fmt.Sprintf(
			"verification: fixtures/trust-root-staging.pub is %d bytes; want %d. "+
				"Re-run 15n_fix_A4 Step 2 for staging.",
			len(trustRootStagingBytes), MLDSA65PublicKeySize))
	}
	TrustRootPublicKey = trustRootStagingBytes
	ActiveTrustEnv = "staging"
}
