// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

//go:build !trust_staging && !trust_prod

package verification

import _ "embed"

// keys_dev.go — default-build embedded anchor-signing keys.
// Selected on plain `go build` / `go test` for local dev.

//go:embed fixtures/embedded-keys-dev.json
var embeddedKeysFixtureDev []byte

func init() {
	loadKeysFromFixture("dev", embeddedKeysFixtureDev)
}
