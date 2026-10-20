// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build trust_prod

package verification

import _ "embed"

// keys_prod.go — selected with `-tags=trust_prod`.
// Customer-facing SDK releases MUST build with this tag.

//go:embed fixtures/embedded-keys-prod.json
var embeddedKeysFixtureProd []byte

func init() {
	loadKeysFromFixture("prod", embeddedKeysFixtureProd)
}
