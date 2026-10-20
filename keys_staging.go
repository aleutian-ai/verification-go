// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build trust_staging

package verification

import _ "embed"

// keys_staging.go — selected with `-tags=trust_staging`.

//go:embed fixtures/embedded-keys-staging.json
var embeddedKeysFixtureStaging []byte

func init() {
	loadKeysFromFixture("staging", embeddedKeysFixtureStaging)
}
