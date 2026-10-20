// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build trust_prod

package verification

import (
	_ "embed"
	"fmt"
)

// trust_root_prod.go — Selected with `-tags=trust_prod`.
// Customer-facing prod SDK releases MUST build with this tag.

//go:embed fixtures/trust-root-prod.pub
var trustRootProdBytes []byte

func init() {
	if len(trustRootProdBytes) != MLDSA65PublicKeySize {
		panic(fmt.Sprintf(
			"verification: fixtures/trust-root-prod.pub is %d bytes; want %d. "+
				"Re-run 15n_fix_A4 Step 2 for prod.",
			len(trustRootProdBytes), MLDSA65PublicKeySize))
	}
	TrustRootPublicKey = trustRootProdBytes
	ActiveTrustEnv = "prod"
}
