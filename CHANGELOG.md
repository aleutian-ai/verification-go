# Changelog

All notable changes to `github.com/aleutian-ai/verification-go` are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
While on the 0.x track, minor bumps may introduce breaking changes;
patch bumps remain backwards-compatible. Cross-language version
alignment activates only after a 1.0 cut.

## [Unreleased]

## [0.5.0] — 2026-10-20

The first version anyone outside the monorepo can install:
`go install github.com/aleutian-ai/verification-go/cmd/aleutian-verify@v0.5.0`.
0.4.0 was tagged in the monorepo only, so the module path never resolved.

### Fixed — before the first public release

- **The package documentation was wrong about the cryptography.** It said
  anchors are Ed25519 over SHA-256 and the SDK is stdlib-only. Anchors are
  ML-DSA-65, hashes are SHA-512, and the SDK depends on circl, x/crypto and
  x/text. It also said parts of the package were Proprietary or AGPL; every
  file is Apache-2.0. `doc.go` and the `ErrInvalidSignature` comment are
  corrected.
- **The tests pass outside the monorepo.** Eight tests read shared goldens
  from `../testdata` or `../../sdk/testdata`, which do not exist in a
  standalone checkout. They now read copies in `testdata/shared/`, and
  `scripts/publish-sdks.sh` refuses a copy that differs from `sdk/testdata`.
  The two producer-parity tests still skip outside the monorepo, as designed.

### Added

- `README.md`.


### Changed

- **BREAKING: `HashRendered(b []byte)` is now `HashRendered(b, tenantPepper []byte)`.**
  Prior releases computed unkeyed SHA-512, which has never matched
  server output — the server has HMAC-keyed this hash since
  2026-04-16 (`18_20_review_01`), closing a rainbow-table oracle on
  PII-adjacent rendered consent bytes. There is no unkeyed variant to
  fall back to. Callers obtain `tenantPepper` via the new consent-pepper
  reveal endpoint (`POST /v1/internal/consent/rendered-pepper/reveal`,
  `consent_rendered_hash_04`) before calling `HashRendered`.
  `consent_rendered_hash` epic.

### Security

Following the 4-agent code review of the trust-manifest delivery, the
following defenses were added BEFORE first customer ship:

- **NFC normalization is now enforced at the encoder boundary** —
  inputs are REJECTED if not already NFC-normalized. Prevents
  cross-language signature divergence when any string field
  (`tenant_id`, `signing_key_id`, `algorithm`) contains combining
  marks. Caller responsibility per spec §3.
- **Validity-window enforcement extends through `VerifyChainEntryV3`**
  via the new optional interface `TrustManifestV3WithValidityWindows`.
  Verifiers automatically pick up the §8 backdating defense when the
  manifest implementation supports it; legacy `TrustManifestFromMapV3`
  falls back to unchecked lookup. No breaking change to the
  `TrustManifestV3` interface.
- **Fail-closed pre-ceremony.** `NewTrustManifestFromURLV3` refuses
  the call (returns `ErrManifestUnknownBootstrapKeyV3`) when the
  embedded bootstrap-key set is still the all-zero placeholder —
  before any network call. Saves bandwidth, surfaces an actionable
  "upgrade your SDK" message.
- **Hardened SSRF defense.** Replaced hand-rolled IP-literal check
  with `net.ParseIP` + `isDangerousIP` covering loopback, RFC1918,
  link-local, ULA, CGNAT (RFC6598), and cloud metadata. Added
  DNS-rebinding defense via `DialContext` that re-validates the
  resolved IP at connect time. Redirect target re-validated against
  the same policy.
- **HTTPS transport pinning.** Default client uses `Proxy: nil`
  (env `HTTP_PROXY` / `HTTPS_PROXY` ignored) and
  `MinVersion: tls.VersionTLS13`. Customers needing a proxy or
  older TLS must supply their own `*http.Client`.
- **No-net invariant scope tightened.** Banned-imports allowlist now
  scans 16+ packages including `crypto/tls`, `golang.org/x/net/*`,
  `nhooyr.io/websocket`, `valyala/fasthttp`, `gorilla/websocket`,
  `go-resty/resty` — not just `net` and `net/http`.
- **Negative timestamps rejected.** All four `int64` ms timestamps
  validated as strictly positive before encoding; previously a
  negative would silently encode as huge `uint64` via two's
  complement.
- **Error messages do not echo wire-controlled bytes.** Attacker-
  controlled `signing_key_id`, JSON parse details, and base64
  decode details no longer reach error strings — log injection /
  terminal-escape surface eliminated.
- **Userinfo URLs rejected at parse time.** `https://user:pass@host/...`
  refused because Go's transport stack echoes the full URL into
  errors which then leak credentials to logs.
- **Algorithm-keyed signature size table.** Replaced hardcoded
  `mldsa65.SignatureSize` with `signatureSizeForAlgV3` — when
  `SupportedSignatureAlgorithmsV3` grows, the size table grows
  alongside; eliminates a future landmine.
- **`WithTrustManifestEnv` is now required.** Silent prod default
  removed; misconfigured callers get an actionable error instead
  of a confusing `ErrManifestUnknownBootstrapKeyV3`.

### Added

- **`TrustManifestFromURLV3` (`sdk_trust_manifest_from_url_go`).** New
  constructor `NewTrustManifestFromURLV3` that fetches, verifies, and
  loads a per-tenant trust manifest from a customer-supplied URL.
  Implements the v1 trust-manifest format spec
  (`docs/customer/sar/trust_manifest_format_v1.md`):

    - HTTPS-only fetch with response-size cap, IP-literal rejection,
      no `Referer` header, 3-hop redirect cap, scheme-downgrade refusal.
    - Bootstrap-signature verification against env-specific embedded
      pubkey set — manifest's `bootstrap_signing_key_id` MUST be in
      `EMBEDDED_BOOTSTRAP_KEYS_<env>` or the load is refused
      (`ErrManifestUnknownBootstrapKeyV3`) — closes the historic-key-
      steal supply-chain attack.
    - Length-prefixed TLV canonical-bytes encoder
      (`CanonicalBytesTrustManifestV1`) — byte-identical across the
      three SDKs once Python + JS port. Signed-bytes prefix locked at
      `aleutian.trust_manifest.v1:`.
    - Monotonic `manifest_serial` enforcement
      (`ErrManifestStaleV3`) — closes the rollback attack.
    - Per-key validity windows (`PublicKeyForSigningKeyIDAtTime`) —
      verifier rejects chain entries whose timestamp is outside
      `[valid_from_ms, valid_until_ms)`
      (`ErrKeyOutsideValidityWindowV3`); closes the key-backdating
      gap.
    - Algorithm-agility filter — only keys with
      `algorithm ∈ SupportedSignatureAlgorithmsV3` land in the loaded
      manifest. Unsupported algs are skipped silently per spec.
    - Validity-range cap (1 year) —
      `ErrManifestRangeUnreasonableV3` rejects "year 9999" manifests.
    - Expiry check at load time — `ErrManifestExpiredV3`.

- **Embedded bootstrap-key set (pre-ceremony placeholder).** New file
  `trust_manifest_embedded_bootstrap.go` exposes
  `IsBootstrapPlaceholder(env)` so customers can fail fast on a
  pre-ceremony SDK build. The actual bootstrap pubkey ceremony is
  tracked in `sdk_trust_manifest_bootstrap_root_ceremony`; until it
  runs, every `NewTrustManifestFromURLV3` call against any env
  returns `ErrManifestSignatureInvalidV3` because the all-zero
  placeholder can't verify a real signature. The pattern mirrors the
  release-pubkey placeholder in `sdk/verification-go/release/pubkey.go`.

- **No-net invariant test (`TestNoNetworkImportsOutsideAllowlist`).**
  Enforces that no SDK source file (other than the trust-manifest
  loader, the legacy SAR loader, the webhook-signature surface, and
  the disclosure-decrypt emit) imports any of the banned network
  transport packages. Catches a class of footguns where a future
  contributor accidentally adds a silent network call to the
  verifier surface.

- **`VerifyTrustManifestBytesV3(body, opts...)`.** Exported sibling
  constructor for customers who fetch the manifest body with their
  own mTLS client, or who load it from disk in an air-gapped lab.
  Same verification pipeline as `NewTrustManifestFromURLV3` minus
  the URL fetch.

- **`TrustManifestV3WithValidityWindows`.** Optional interface
  extension manifests can implement to support per-key validity
  windows (spec §8). `VerifyChainEntryV3` prefers it via type
  assertion; `TrustManifestFromURLV3` implements it; legacy
  `TrustManifestFromMapV3` does not (it has no time concept and
  falls back to unchecked lookup automatically).

### Notes

- Real bootstrap-pubkey embedding (the ceremony) is a separate ticket
  — `sdk_trust_manifest_bootstrap_root_ceremony`. SDK code in this
  release is correctly fail-closed in the placeholder state; running
  the ceremony does not require an SDK code change beyond pasting hex
  into a constant.

- Python and JS ports are tracked separately —
  `sdk_trust_manifest_from_url_python` and
  `sdk_trust_manifest_from_url_js`. The canonical-bytes encoder
  golden vector in `trust_manifest_canonical_v1_test.go::TestCanonicalBytesV1_GoldenVector_MinimalOneKey`
  is the cross-language contract those ports will mirror.

## [0.4.0] — 2026-06-09

Release-key ceremony: real ML-DSA-65 release pubkey embedded in
`release/pubkey.go` from the production KMS key minted at
`projects/aleutianprivacypro/locations/us-central1/keyRings/release/cryptoKeys/disclosure-decrypt-release`.
`aleutian-release-verify` now accepts signatures from the production
sign script.
