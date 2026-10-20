// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// `TrustManifestFromURLV3` per `sdk_trust_manifest_format_spec` +
// `sdk_trust_manifest_from_url_go`.
//
// # What this lets a customer do
//
//	mf, err := NewTrustManifestFromURLV3(ctx,
//	    "https://trust.acme.example.com/aleutian/trust-manifest.json",
//	    WithTrustManifestEnv(TrustManifestEnvProd),
//	    WithTrustManifestLastSeenSerial(42),
//	)
//	if err != nil { ... }
//	// mf implements TrustManifestV3 — drop into VerifyChainEntryV3
//
// # Why URL not bytes
//
// Customers don't compile our keys into their app; we don't compile
// their keys into our SDK. The trust manifest at the URL is the
// per-tenant authority: it lists every signing_key_id the tenant
// currently trusts, signed by Aleutian's bootstrap key (which IS
// embedded). The fetch happens once per session; the verifier
// reuses the loaded manifest for every chain entry verify.

// Error sentinels per `sdk_error_hierarchy_spec`. Customers branch
// via `errors.Is(err, ...)`.
var (
	// ErrManifestUnreachableV3 wraps every transport-level failure
	// (DNS, TCP, TLS, HTTP 5xx, response timeout). Operators
	// usually retry these.
	ErrManifestUnreachableV3 = errors.New("trust_manifest: unreachable")

	// ErrManifestExpiredV3 fires when the fetched manifest's
	// `expires_at_ms` has already passed at fetch time. Operators
	// MUST re-mint a fresh manifest server-side.
	ErrManifestExpiredV3 = errors.New("trust_manifest: expired")

	// ErrManifestStaleV3 fires when the fetched manifest's
	// `manifest_serial` is less than or equal to the
	// `LastSeenSerial` option supplied by the caller. Closes the
	// C2 rollback attack — an attacker who serves an old manifest
	// to downgrade key rotation is detected.
	ErrManifestStaleV3 = errors.New("trust_manifest: serial older than last-seen")

	// ErrManifestRangeUnreasonableV3 fires when the manifest's
	// validity window exceeds the SDK's max (1 year, per spec
	// §10.1). Catches misconfigured manifests with
	// "expires_at_ms=year 9999" that would survive any reasonable
	// rotation cadence.
	ErrManifestRangeUnreasonableV3 = errors.New("trust_manifest: validity range unreasonable")

	// ErrManifestNoSupportedKeysV3 fires when every key in the
	// manifest uses an algorithm this SDK doesn't support — i.e.
	// the customer has to upgrade the SDK before they can verify.
	ErrManifestNoSupportedKeysV3 = errors.New("trust_manifest: no supported keys")

	// ErrManifestSignatureInvalidV3 fires when the bootstrap-key
	// signature over the manifest's canonical bytes doesn't
	// verify. Indicates tamper or wrong-bootstrap-key.
	ErrManifestSignatureInvalidV3 = errors.New("trust_manifest: signature invalid")

	// ErrManifestUnknownBootstrapKeyV3 fires when the manifest's
	// `bootstrap_signing_key_id` is not in
	// `EMBEDDED_BOOTSTRAP_KEYS_<env>`. Closes the historic-key-
	// steal supply-chain attack. Also fires PRE-CEREMONY (when
	// every embedded key is all-zero placeholder) with hint text
	// pointing at the SDK upgrade.
	ErrManifestUnknownBootstrapKeyV3 = errors.New("trust_manifest: bootstrap_signing_key_id not in embedded set")
)

// SupportedSignatureAlgorithmsV3 is the alg-agility allowlist —
// per-key algorithm strings the SDK accepts. Used to filter keys
// in a fetched manifest; rejecting at the SDK boundary closes the
// C2 algorithm-downgrade attack (an attacker can't trick a v0.4
// SDK into accepting a key labeled "ML-DSA-44" by listing it in
// the manifest).
//
// Adding an algorithm here is a coordinated upgrade across all 3
// SDKs + the producer side; do not append casually. New entries
// MUST also be added to `signatureSizeForAlgV3` below.
var SupportedSignatureAlgorithmsV3 = []string{
	"ML-DSA-65",
}

// signatureSizeForAlgV3 maps an allowlisted algorithm string to the
// expected signature byte length. Arch review M12: previously the
// SDK assumed mldsa65.SignatureSize unconditionally — fine when the
// allowlist had one entry, but a landmine once it grows. When you
// add an algorithm to the allowlist, add its size here.
func signatureSizeForAlgV3(alg string) (int, bool) {
	switch alg {
	case "ML-DSA-65":
		return mldsa65.SignatureSize, true
	}
	return 0, false
}

// isSupportedSignatureAlgorithmV3 reports whether alg is in the
// allowlist. Linear search; the list has 1 entry and isn't expected
// to ever exceed 3.
func isSupportedSignatureAlgorithmV3(alg string) bool {
	for _, s := range SupportedSignatureAlgorithmsV3 {
		if alg == s {
			return true
		}
	}
	return false
}

// MaxManifestValidityRangeMs caps how long a manifest can claim to
// be valid for. 1 year — generous enough for slow-rotation
// customers, tight enough that a "year 9999" manifest is rejected.
// Spec §10.1.
const MaxManifestValidityRangeMs int64 = 365 * 24 * 60 * 60 * 1000

// TrustManifestFromURLV3 is a TrustManifestV3 implementation backed
// by a manifest fetched once from a customer-supplied URL.
// Read-only after construction; safe for concurrent reads.
//
// Construct via `NewTrustManifestFromURLV3`. Direct struct literal
// construction bypasses signature verify and is unsupported.
type TrustManifestFromURLV3 struct {
	// keys is the validated key set, indexed by signing_key_id.
	// Each entry carries the validity window so the verifier can
	// reject chain entries whose timestamp falls outside.
	keys map[string]trustManifestEntryV3

	// serial is exported via LoadedSerial() so callers can store
	// it as the next-fetch's LastSeenSerial.
	serial uint64

	// env is captured at construction so the manifest knows
	// which embedded bootstrap set to validate against. Not
	// exported — internal bookkeeping only.
	env TrustManifestEnv
}

// trustManifestEntryV3 is the validated, in-memory representation
// of one key in a loaded manifest.
type trustManifestEntryV3 struct {
	PublicKey    []byte // raw ML-DSA-65 pubkey bytes (1952 bytes)
	Algorithm    string // e.g. "ML-DSA-65"
	ValidFromMs  int64  // earliest chain-entry ts the key is accepted for
	ValidUntilMs int64  // latest such ts (exclusive)
}

// TrustManifestFromURLOption configures NewTrustManifestFromURLV3.
// Go functional-options idiom.
type TrustManifestFromURLOption func(*trustManifestFromURLConfig)

type trustManifestFromURLConfig struct {
	env              TrustManifestEnv
	envExplicit      bool // set true by WithTrustManifestEnv to detect missing-required-option
	lastSeenSerial   *uint64
	fetchTimeout     time.Duration
	maxResponseBytes int64
	allowIPLiteral   bool
	httpClient       *http.Client
	nowMs            func() int64 // injected clock — tests override
	// embeddedBootstrapKeysOverride lets tests substitute a real
	// keypair for the all-zero placeholder set WITHOUT mutating the
	// package-global var (Arch review H5: package-global mutation
	// in synthBootstrapKey races with t.Parallel). nil → use the
	// real embedded set per env.
	//
	// Internal-only. Set via withTrustManifestEmbeddedKeys.
	embeddedBootstrapKeysOverride []embeddedBootstrapKeyBlob
}

// WithTrustManifestEnv pins which embedded bootstrap-key set the
// fetched manifest is validated against. REQUIRED — omitting it
// returns an error at construction (Arch review M8: silent default
// to "prod" caused confusing ErrManifestUnknownBootstrapKeyV3 for
// dev customers who forgot the option).
func WithTrustManifestEnv(env TrustManifestEnv) TrustManifestFromURLOption {
	return func(c *trustManifestFromURLConfig) {
		c.env = env
		c.envExplicit = true
	}
}

// WithTrustManifestLastSeenSerial enables anti-rollback. The
// fetched manifest's `manifest_serial` must be STRICTLY GREATER
// than the supplied value or fetch fails with ErrManifestStaleV3.
// First-fetch callers omit this option.
func WithTrustManifestLastSeenSerial(s uint64) TrustManifestFromURLOption {
	return func(c *trustManifestFromURLConfig) { c.lastSeenSerial = &s }
}

// WithTrustManifestFetchTimeout overrides the default 10s fetch
// budget. Useful for slow networks; capped server-side anyway by
// the response-size cap.
func WithTrustManifestFetchTimeout(d time.Duration) TrustManifestFromURLOption {
	return func(c *trustManifestFromURLConfig) { c.fetchTimeout = d }
}

// WithTrustManifestMaxResponseBytes overrides the 1 MiB cap. A
// legitimate manifest with 256 keys × ~2 KiB each is ~512 KiB, so
// 1 MiB has headroom but rejects a "serve infinite bytes" attack.
//
// Arch review M7: the supplied value is clamped to a hard ceiling
// (`MaxTrustManifestResponseBytesCeiling` = 16 MiB) and a floor of
// 1 KiB. Values outside that range are silently clamped — this
// option exists for tuning, not for "I want 100 GiB please".
func WithTrustManifestMaxResponseBytes(n int64) TrustManifestFromURLOption {
	return func(c *trustManifestFromURLConfig) {
		if n < 1024 {
			n = 1024
		}
		if n > MaxTrustManifestResponseBytesCeiling {
			n = MaxTrustManifestResponseBytesCeiling
		}
		c.maxResponseBytes = n
	}
}

// MaxTrustManifestResponseBytesCeiling is the absolute hard cap on
// the manifest body size, regardless of caller-supplied options.
// 16 MiB is generous enough for any plausible manifest (256 keys at
// ~2 KiB each is ~512 KiB) but bounds the worst-case memory burst
// per fetch.
const MaxTrustManifestResponseBytesCeiling int64 = 16 * 1024 * 1024

// WithTrustManifestAllowIPLiteral relaxes the default refusal of
// IP-literal hostnames (e.g. `https://192.0.2.1/...`). Off by
// default because IP-literal URLs bypass DNSSEC + cert hostname
// validation expectations. Customers occasionally need this for
// air-gapped lab setups.
func WithTrustManifestAllowIPLiteral(allow bool) TrustManifestFromURLOption {
	return func(c *trustManifestFromURLConfig) { c.allowIPLiteral = allow }
}

// WithTrustManifestHTTPClient lets tests inject a fake HTTP client.
// Production code should NOT use this — the default client is
// hardened (HTTPS-only, no Referer, redirect limit, IP-literal
// rejection, fixed timeout).
func WithTrustManifestHTTPClient(c *http.Client) TrustManifestFromURLOption {
	return func(cfg *trustManifestFromURLConfig) { cfg.httpClient = c }
}

// withTrustManifestNowMs is a test-only hook to fix the clock.
// Internal — not exported. Tests reach in via package-private
// access from the same dir.
func withTrustManifestNowMs(f func() int64) TrustManifestFromURLOption {
	return func(c *trustManifestFromURLConfig) { c.nowMs = f }
}

// withTrustManifestEmbeddedKeys is a test-only hook to substitute
// a synthetic bootstrap-key set for the placeholder embedded set
// without mutating package globals (Arch review H5). Internal —
// not exported.
func withTrustManifestEmbeddedKeys(keys []embeddedBootstrapKeyBlob) TrustManifestFromURLOption {
	return func(c *trustManifestFromURLConfig) { c.embeddedBootstrapKeysOverride = keys }
}

// trustManifestJSONWire is the JSON wire shape produced by the
// Aleutian server-side trust-manifest minter. Field order in JSON
// is irrelevant; the canonical-bytes recipe rebuilds in
// deterministic order before signature verify.
type trustManifestJSONWire struct {
	Version             uint32                     `json:"version"`
	ManifestSerial      uint64                     `json:"manifest_serial"`
	TenantID            string                     `json:"tenant_id"`
	IssuedAtMs          int64                      `json:"issued_at_ms"`
	ExpiresAtMs         int64                      `json:"expires_at_ms"`
	BootstrapSigningKey string                     `json:"bootstrap_signing_key_id"`
	Keys                []trustManifestJSONWireKey `json:"keys"`
	Signature           trustManifestJSONSignature `json:"signature"`
}

type trustManifestJSONWireKey struct {
	SigningKeyID string `json:"signing_key_id"`
	Algorithm    string `json:"algorithm"`
	PublicKeyB64 string `json:"public_key_b64"`
	ValidFromMs  int64  `json:"valid_from_ms"`
	ValidUntilMs int64  `json:"valid_until_ms"`
}

type trustManifestJSONSignature struct {
	Algorithm string `json:"algorithm"`
	SigB64    string `json:"sig_b64"`
}

// NewTrustManifestFromURLV3 fetches, verifies, and returns a
// trust manifest from the customer-supplied URL.
//
// # Pipeline (enforced in order)
//
//  1. URL validation (https only, no IP literal unless allowed)
//  2. HTTPS GET with body-size cap + timeout
//  3. JSON parse with field-bound limits
//  4. Resolve bootstrap pubkey from env-specific embedded set
//     (refuses if `bootstrap_signing_key_id` not in set)
//  5. Re-encode manifest body as canonical TLV bytes
//  6. Verify ML-DSA-65 signature against bootstrap pubkey using
//     constant-time tag compare
//  7. Reject if `expires_at_ms < now`
//  8. Reject if `manifest_serial <= LastSeenSerial`
//  9. Reject if `expires_at_ms - issued_at_ms > MaxManifestValidityRangeMs`
//  10. Filter keys to algorithms in SupportedSignatureAlgorithmsV3
//  11. Validate each key's pubkey via cloudflare/circl unmarshal
//
// Any failure returns the matching sentinel; callers branch via
// errors.Is.
func NewTrustManifestFromURLV3(
	ctx context.Context,
	manifestURL string,
	opts ...TrustManifestFromURLOption,
) (*TrustManifestFromURLV3, error) {
	cfg := defaultTrustManifestFromURLConfig()
	for _, o := range opts {
		o(&cfg)
	}
	// Arch review M8: env is required, not a silent default to prod.
	// Tests that inject their own bootstrap via
	// withTrustManifestEmbeddedKeys skip this check — they're
	// exercising verify logic, not the env-resolution path.
	if !cfg.envExplicit && cfg.embeddedBootstrapKeysOverride == nil {
		return nil, fmt.Errorf("NewTrustManifestFromURLV3: WithTrustManifestEnv is required (one of dev/staging/prod) — see https://pkg.go.dev/github.com/aleutian-ai/verification-go#TrustManifestEnv")
	}
	if !cfg.env.IsValid() {
		return nil, fmt.Errorf("NewTrustManifestFromURLV3: invalid env %q", cfg.env)
	}

	// 1. URL parse + scheme + userinfo check (cheap, local;
	//    surface URL errors as URL errors before SDK-state errors).
	if err := validateTrustManifestURL(manifestURL); err != nil {
		return nil, err
	}

	// 2. Fail-closed pre-ceremony (Security review H2). If the SDK
	// was built before the bootstrap ceremony ran, every embedded
	// pubkey is all-zero; attempting an HTTP fetch wastes the
	// customer's bandwidth and produces a confusing
	// ErrManifestSignatureInvalidV3 instead of the actionable
	// "your SDK version pre-dates the bootstrap ceremony — upgrade"
	// signal. Refuse here, BEFORE the network call.
	//
	// Tests inject a synthetic bootstrap set via
	// withTrustManifestEmbeddedKeys; check that first.
	if cfg.embeddedBootstrapKeysOverride == nil && IsBootstrapPlaceholder(cfg.env) {
		return nil, fmt.Errorf("%w: env=%q SDK build pre-dates the bootstrap ceremony; upgrade to a SDK release with real embedded bootstrap keys",
			ErrManifestUnknownBootstrapKeyV3, cfg.env)
	}

	body, err := fetchTrustManifestBody(ctx, manifestURL, cfg)
	if err != nil {
		return nil, err
	}
	return verifyTrustManifestBodyAgainstConfig(body, cfg)
}

// VerifyTrustManifestBytesV3 is the bytes-in form of the
// constructor: skip the URL fetch and supply the already-downloaded
// manifest body. Used by customers who bring their own mTLS client
// or fetch transport, or by air-gapped lab setups where the
// manifest is read from disk.
//
// Same verification pipeline as NewTrustManifestFromURLV3 (per
// spec §4 through §11). Caller still supplies env (required),
// last-seen-serial, and clock-injection via the same option set.
//
// Arch review M11: previously customers had no public seam to fetch
// + verify separately — they had to either accept our hardened
// transport or roll the verify themselves.
func VerifyTrustManifestBytesV3(
	body []byte,
	opts ...TrustManifestFromURLOption,
) (*TrustManifestFromURLV3, error) {
	cfg := defaultTrustManifestFromURLConfig()
	for _, o := range opts {
		o(&cfg)
	}
	if !cfg.envExplicit && cfg.embeddedBootstrapKeysOverride == nil {
		return nil, fmt.Errorf("VerifyTrustManifestBytesV3: WithTrustManifestEnv is required")
	}
	if !cfg.env.IsValid() {
		return nil, fmt.Errorf("VerifyTrustManifestBytesV3: invalid env %q", cfg.env)
	}
	if cfg.embeddedBootstrapKeysOverride == nil && IsBootstrapPlaceholder(cfg.env) {
		return nil, fmt.Errorf("%w: env=%q SDK pre-dates the bootstrap ceremony",
			ErrManifestUnknownBootstrapKeyV3, cfg.env)
	}
	return verifyTrustManifestBodyAgainstConfig(body, cfg)
}

// verifyTrustManifestBodyAgainstConfig is the shared body-handling
// path used by both NewTrustManifestFromURLV3 (after fetch) and
// VerifyTrustManifestBytesV3 (caller-supplied body).
func verifyTrustManifestBodyAgainstConfig(body []byte, cfg trustManifestFromURLConfig) (*TrustManifestFromURLV3, error) {
	// JSON parse with DisallowUnknownFields (Security/Crypto review
	// M4). Catches a future signature_v2 / format_v2 a producer
	// adds before this SDK supports it — fail loud rather than
	// silently dropping the new field.
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var wire trustManifestJSONWire
	if err := dec.Decode(&wire); err != nil {
		// Don't %v the inner error — it may echo attacker-controlled
		// bytes from the manifest body (Privacy review M3).
		return nil, fmt.Errorf("%w: malformed JSON", ErrManifestUnreachableV3)
	}
	// Pre-encode bound check (Security review M4): refuse manifest
	// claiming >256 keys BEFORE wireToPayload allocates per-key
	// memory.
	if len(wire.Keys) > trustManifestMaxKeysPerManifest {
		return nil, fmt.Errorf("%w: key_count=%d exceeds cap %d",
			ErrManifestUnreachableV3, len(wire.Keys), trustManifestMaxKeysPerManifest)
	}

	return verifyAndBuildTrustManifestV3(wire, cfg)
}

// verifyAndBuildTrustManifestV3 is the part of the pipeline AFTER
// the JSON has been parsed off the wire. Split out so unit tests
// can drive it directly without standing up an HTTP server.
func verifyAndBuildTrustManifestV3(wire trustManifestJSONWire, cfg trustManifestFromURLConfig) (*TrustManifestFromURLV3, error) {
	// (Step 4) Bootstrap-key resolution. Refused if the manifest
	// names a key not embedded for the chosen env — this is the
	// historic-key-steal supply-chain defense.
	bootPub, err := resolveBootstrapPubkey(cfg, wire.BootstrapSigningKey)
	if err != nil {
		return nil, err
	}

	// (Step 5) Re-encode as canonical TLV bytes. The encoder
	// validates every field; if the wire contains, say, an empty
	// tenant_id or a duplicate signing_key_id, we reject here
	// BEFORE the signature compare.
	//
	// Arch review M5: b64-decode pubkeys ONCE here and reuse
	// downstream — eliminates the second decode loop that used
	// to exist below.
	payload, decodedPubkeys, err := wireToPayload(wire)
	if err != nil {
		// Decode failures are wire-format problems, not crypto
		// problems — distinguished here so the error is
		// classifiable.
		return nil, fmt.Errorf("%w: malformed wire", ErrManifestUnreachableV3)
	}
	canonical, err := CanonicalBytesTrustManifestV1(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: canonical: %v", ErrManifestSignatureInvalidV3, err)
	}

	// (Step 6) Signature verify. ML-DSA-65 pure mode (nil ctx) per
	// FIPS 204 §5.3 — matches the producer-side signer used in
	// `cmd/anchor-generator/main.go`.
	if !isSupportedSignatureAlgorithmV3(wire.Signature.Algorithm) {
		// Don't echo wire.Signature.Algorithm — attacker-controlled.
		return nil, fmt.Errorf("%w: outer-signature algorithm not in SupportedSignatureAlgorithmsV3",
			ErrManifestSignatureInvalidV3)
	}
	expectedSigSize, ok := signatureSizeForAlgV3(wire.Signature.Algorithm)
	if !ok {
		// Defense-in-depth: every value in SupportedSignatureAlgorithmsV3
		// must also be in signatureSizeForAlgV3. If they desync, fail.
		return nil, fmt.Errorf("%w: alg %q has no size entry — SDK bug, please file an issue",
			ErrManifestSignatureInvalidV3, wire.Signature.Algorithm)
	}
	sig, err := base64.StdEncoding.DecodeString(wire.Signature.SigB64)
	if err != nil {
		return nil, fmt.Errorf("%w: decode sig_b64 failed", ErrManifestSignatureInvalidV3)
	}
	if len(sig) != expectedSigSize {
		return nil, fmt.Errorf("%w: sig is %d bytes, want %d",
			ErrManifestSignatureInvalidV3, len(sig), expectedSigSize)
	}
	scheme := mldsa65.Scheme()
	pubObj, err := scheme.UnmarshalBinaryPublicKey(bootPub)
	if err != nil {
		return nil, fmt.Errorf("%w: bootstrap pubkey unmarshal: %v",
			ErrManifestSignatureInvalidV3, err)
	}
	// circl's mldsa65 Verify is internally constant-time per FIPS
	// 204 §5.3 pure mode. The `opts` arg is *sign.SignatureOpts
	// (typed, not raw context bytes); nil is the documented
	// "use scheme defaults" value, NOT a context-bytes nil.
	// See Crypto review L3: the L3 concern was about empty-context
	// vs nil-context semantics which only applies if circl
	// changes to accept []byte directly — that would be an API
	// break we'd catch at build time.
	if !scheme.Verify(pubObj, canonical, sig, nil) {
		return nil, ErrManifestSignatureInvalidV3
	}

	now := cfg.nowMs()

	// (Step 7) Expiry check.
	if now >= wire.ExpiresAtMs {
		return nil, fmt.Errorf("%w: expires_at_ms=%d now=%d",
			ErrManifestExpiredV3, wire.ExpiresAtMs, now)
	}

	// (Step 8) Monotonic serial check (anti-rollback).
	if cfg.lastSeenSerial != nil && wire.ManifestSerial <= *cfg.lastSeenSerial {
		return nil, fmt.Errorf("%w: got=%d last_seen=%d",
			ErrManifestStaleV3, wire.ManifestSerial, *cfg.lastSeenSerial)
	}

	// (Step 9) Validity range bound.
	if wire.ExpiresAtMs-wire.IssuedAtMs > MaxManifestValidityRangeMs {
		return nil, fmt.Errorf("%w: range=%d cap=%d",
			ErrManifestRangeUnreasonableV3,
			wire.ExpiresAtMs-wire.IssuedAtMs, MaxManifestValidityRangeMs)
	}

	// (Step 10 + 11) Filter to supported algs; validate each
	// pubkey via the scheme.
	out := &TrustManifestFromURLV3{
		keys:   make(map[string]trustManifestEntryV3, len(wire.Keys)),
		serial: wire.ManifestSerial,
		env:    cfg.env,
	}
	for i, k := range wire.Keys {
		if !isSupportedSignatureAlgorithmV3(k.Algorithm) {
			// Skip unsupported algs silently — that key isn't usable
			// by THIS SDK but the manifest itself is fine.
			continue
		}
		// Crypto review L5: ML-DSA-65 pubkeys are exactly 1952 bytes.
		// Catch the wrong-size case here BEFORE asking circl to
		// unmarshal — avoids a less-clear error from the scheme.
		pkBytes := decodedPubkeys[i]
		if k.Algorithm == "ML-DSA-65" && len(pkBytes) != mldsa65PubkeySize {
			// Don't echo k.SigningKeyID — Privacy M3.
			return nil, fmt.Errorf("%w: keys[%d].public_key is %d bytes (ML-DSA-65 requires %d)",
				ErrManifestSignatureInvalidV3, i, len(pkBytes), mldsa65PubkeySize)
		}
		if _, err := scheme.UnmarshalBinaryPublicKey(pkBytes); err != nil {
			return nil, fmt.Errorf("%w: keys[%d] malformed pubkey",
				ErrManifestSignatureInvalidV3, i)
		}
		out.keys[k.SigningKeyID] = trustManifestEntryV3{
			PublicKey:    pkBytes,
			Algorithm:    k.Algorithm,
			ValidFromMs:  k.ValidFromMs,
			ValidUntilMs: k.ValidUntilMs,
		}
	}
	if len(out.keys) == 0 {
		return nil, ErrManifestNoSupportedKeysV3
	}
	return out, nil
}

// PublicKeyForSigningKeyID implements TrustManifestV3.
//
// # Validity window enforcement
//
// The TrustManifestV3 interface predates the v1-format validity
// window concept. We implement the unconditional lookup here for
// backwards compatibility, and surface the validity window via the
// separate `PublicKeyForSigningKeyIDAtTime` method below — verifier
// implementations that want window enforcement call the timed
// variant instead.
func (m *TrustManifestFromURLV3) PublicKeyForSigningKeyID(_ context.Context, signingKeyID string) ([]byte, error) {
	entry, ok := m.keys[signingKeyID]
	if !ok {
		return nil, ErrKeyNotInTrustManifestV3
	}
	return entry.PublicKey, nil
}

// PublicKeyForSigningKeyIDAtTime is the validity-window-aware
// variant. Verifiers that want spec §8 enforcement call this with
// the chain entry's timestamp; the manifest refuses to return a
// pubkey if the entry timestamp falls outside the key's window.
//
// Returns ErrKeyOutsideValidityWindowV3 on a window miss.
func (m *TrustManifestFromURLV3) PublicKeyForSigningKeyIDAtTime(_ context.Context, signingKeyID string, entryTimestampMs int64) ([]byte, error) {
	entry, ok := m.keys[signingKeyID]
	if !ok {
		return nil, ErrKeyNotInTrustManifestV3
	}
	if entryTimestampMs < entry.ValidFromMs || entryTimestampMs >= entry.ValidUntilMs {
		return nil, fmt.Errorf("%w: entry_ts=%d window=[%d, %d)",
			ErrKeyOutsideValidityWindowV3, entryTimestampMs,
			entry.ValidFromMs, entry.ValidUntilMs)
	}
	return entry.PublicKey, nil
}

// ErrKeyOutsideValidityWindowV3 fires when the chain entry's
// timestamp falls outside a resolved key's
// [valid_from_ms, valid_until_ms) window. Per spec §8 — the
// load-bearing defense against backdating attacks.
var ErrKeyOutsideValidityWindowV3 = errors.New("trust_manifest: chain entry timestamp outside key validity window")

// LoadedSerial returns the manifest_serial of the fetched manifest.
// Callers persist this and pass it as `WithTrustManifestLastSeenSerial`
// on the next fetch to enable anti-rollback.
func (m *TrustManifestFromURLV3) LoadedSerial() uint64 { return m.serial }

// Env returns the environment this manifest was validated against.
func (m *TrustManifestFromURLV3) Env() TrustManifestEnv { return m.env }

// resolveBootstrapPubkey looks up the bootstrap pubkey by id in
// the embedded set for env (or the test-injected override), returning
// the matching raw pubkey bytes or ErrManifestUnknownBootstrapKeyV3.
//
// Note: kid is a PUBLIC identifier — the previous use of
// subtle.ConstantTimeCompare here was cargo-culted and removed
// per Crypto/Security review M13. Plain `==` is appropriate.
//
// Privacy review M2: the error message does NOT echo the
// attacker-controlled kid. Echoing it would leak that the
// customer's logging stack carries unvalidated wire bytes and
// could be used for log injection or terminal escape if the kid
// contains attacker-controlled bytes.
func resolveBootstrapPubkey(cfg trustManifestFromURLConfig, kid string) ([]byte, error) {
	set := cfg.embeddedBootstrapKeysOverride
	if set == nil {
		set = embeddedBootstrapKeys(cfg.env)
	}
	for _, b := range set {
		if b.SigningKeyID == kid {
			return b.PublicKey, nil
		}
	}
	return nil, fmt.Errorf("%w: env=%s (kid not echoed; check operator logs for the producer-side kid)",
		ErrManifestUnknownBootstrapKeyV3, cfg.env)
}

// wireToPayload converts the parsed JSON wire form into the
// canonical-bytes payload struct and ALSO returns the parallel
// slice of decoded pubkey bytes — Arch review M5: previously the
// same b64-decode happened twice (once for canonical, once for
// scheme validation). Now we decode once and reuse.
//
// The returned `decodedPubkeys` slice is index-aligned with
// `wire.Keys`; index i of decodedPubkeys is the pubkey for
// wire.Keys[i].
func wireToPayload(w trustManifestJSONWire) (TrustManifestPayloadV1, [][]byte, error) {
	out := TrustManifestPayloadV1{
		Version:        w.Version,
		ManifestSerial: w.ManifestSerial,
		TenantID:       w.TenantID,
		IssuedAtMs:     w.IssuedAtMs,
		ExpiresAtMs:    w.ExpiresAtMs,
		Keys:           make([]TrustManifestSignedKeyV1, 0, len(w.Keys)),
	}
	decodedPubkeys := make([][]byte, len(w.Keys))
	for i, k := range w.Keys {
		pk, err := base64.StdEncoding.DecodeString(k.PublicKeyB64)
		if err != nil {
			// Don't echo k.SigningKeyID — Privacy M3.
			return TrustManifestPayloadV1{}, nil, fmt.Errorf("keys[%d] b64 decode failed", i)
		}
		decodedPubkeys[i] = pk
		out.Keys = append(out.Keys, TrustManifestSignedKeyV1{
			SigningKeyID: k.SigningKeyID,
			Algorithm:    k.Algorithm,
			PublicKey:    pk,
			ValidFromMs:  k.ValidFromMs,
			ValidUntilMs: k.ValidUntilMs,
		})
	}
	return out, decodedPubkeys, nil
}

// defaultTrustManifestFromURLConfig returns the locked-down
// defaults for production use. Customers can override via
// WithTrustManifest* options.
func defaultTrustManifestFromURLConfig() trustManifestFromURLConfig {
	return trustManifestFromURLConfig{
		env:              TrustManifestEnvProd,
		lastSeenSerial:   nil,
		fetchTimeout:     10 * time.Second,
		maxResponseBytes: 1024 * 1024, // 1 MiB
		allowIPLiteral:   false,
		nowMs:            func() int64 { return time.Now().UTC().UnixMilli() },
	}
}

// fetchTrustManifestBody runs the URL-validation + HTTP fetch.
// Hardened per the 4-agent security review:
//
//   - HTTPS-only at parse + redirect
//   - IP-literal rejected via net.ParseIP (catches hex/octal/IPv6
//     forms that the previous string-pattern check missed)
//   - Private-range / loopback / link-local / cloud-metadata IPs
//     rejected even when AllowIPLiteral is true unless the caller
//     ALSO injects their own HTTPClient (the assumption being:
//     they know what they're doing)
//   - DNS-rebinding defense via DialContext that re-validates the
//     resolved IP at connect time
//   - Explicit TLS 1.3 minimum
//   - Proxy: nil — env-var proxies are refused; a malicious sidecar
//     setting HTTP_PROXY can't MITM
//   - User-Agent omitted by default; stripped on every redirect
//   - Referer stripped on every redirect
//   - Userinfo URLs (`https://user:pass@host/...`) rejected
//   - 3-hop redirect cap; redirect target re-validated for scheme +
//     IP-literal + private range
func fetchTrustManifestBody(ctx context.Context, manifestURL string, cfg trustManifestFromURLConfig) ([]byte, error) {
	// URL validation moved to validateTrustManifestURL() so the
	// constructor can surface URL errors before placeholder + bootstrap
	// state checks. By the time we reach fetchTrustManifestBody we
	// know the URL is structurally OK.
	u, _ := url.Parse(manifestURL)

	client := cfg.httpClient
	if client == nil {
		// Default-hardened client. Apply full SSRF host policy:
		// neither the IP-literal-default rejection nor the
		// always-on dangerous-range rejection has been opted out
		// of, since the caller is using OUR transport.
		if err := checkHostPolicy(u.Host, cfg.allowIPLiteral); err != nil {
			return nil, err
		}
		client = hardenedTrustManifestHTTPClient(cfg)
	}
	// Customer-supplied http.Client: caller owns SSRF policy.
	// This is intentional — they may be testing against
	// httptest.NewTLSServer (always 127.0.0.1), running an
	// air-gapped lab, or using a custom mTLS transport. We don't
	// second-guess.

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build req", ErrManifestUnreachableV3)
	}
	req.Header.Set("Accept", "application/json")
	// Privacy review M9: previously set a static User-Agent that
	// leaked "Aleutian customer" across redirect chains. Omit by
	// default. Production transports may want to surface it for
	// log-correlation reasons; we don't.

	resp, err := client.Do(req)
	if err != nil {
		// Don't echo the inner err — Go's net stack populates it
		// with full URLs that may include attacker-supplied bytes
		// after a redirect chain.
		return nil, ErrManifestUnreachableV3
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrManifestUnreachableV3, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cfg.maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body", ErrManifestUnreachableV3)
	}
	if int64(len(body)) > cfg.maxResponseBytes {
		return nil, fmt.Errorf("%w: body > %d bytes",
			ErrManifestUnreachableV3, cfg.maxResponseBytes)
	}
	return body, nil
}

// hardenedTrustManifestHTTPClient builds the default HTTPS-only
// client used when the caller hasn't supplied a custom one.
// Multiple Security review findings (M1/M2/M9) addressed here.
func hardenedTrustManifestHTTPClient(cfg trustManifestFromURLConfig) *http.Client {
	transport := &http.Transport{
		// Security review M1: refuse env-proxy. A malicious sidecar
		// or dep setting HTTP_PROXY/HTTPS_PROXY otherwise gets to
		// MITM the manifest fetch. If a customer legitimately
		// needs an HTTP proxy, they supply their own *http.Client
		// via WithTrustManifestHTTPClient.
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			// Security review M1: pin TLS 1.3 minimum. Older versions
			// have known weaknesses (and we should never need them
			// to talk to a properly-operated trust-store host).
			MinVersion: tls.VersionTLS13,
		},
		ForceAttemptHTTP2: true,
		// Security review H3 + DNS-rebinding defense: validate the
		// resolved IP at connect time. host-string validation
		// upstream rejects literal IPs in the URL; this catches
		// the case where a hostname resolves to a metadata-server
		// or RFC1918 IP at connect time (DNS rebinding).
		DialContext: func(ctx context.Context, network, address string) (gn net.Conn, err error) {
			// address is "host:port"; net.Dial resolves DNS lazily,
			// so we resolve here and check the IP.
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, fmt.Errorf("split: %w", splitErr)
			}
			ips, lookupErr := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if lookupErr != nil {
				return nil, lookupErr
			}
			var resolvedToAllowed net.IP
			for _, ip := range ips {
				if !cfg.allowIPLiteral && isDangerousIP(ip) {
					return nil, fmt.Errorf("%w: resolved IP %s falls into a refused range (loopback/private/link-local/cloud-metadata)",
						ErrManifestUnreachableV3, ip)
				}
				resolvedToAllowed = ip
				break
			}
			if resolvedToAllowed == nil {
				return nil, fmt.Errorf("%w: no IPs returned for host", ErrManifestUnreachableV3)
			}
			d := net.Dialer{Timeout: cfg.fetchTimeout}
			return d.DialContext(ctx, network, net.JoinHostPort(resolvedToAllowed.String(), port))
		},
	}
	return &http.Client{
		Timeout:   cfg.fetchTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Cap redirects at 3 hops. http.Client's default is 10
			// which is too lax for a single-shot manifest fetch.
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			// Strip Referer + User-Agent on every hop — manifest
			// fetches should not leak the originating page or
			// fingerprint "Aleutian customer" to redirect targets.
			req.Header.Del("Referer")
			req.Header.Del("User-Agent")
			// Refuse a redirect to a non-https target — protects
			// against scheme-downgrade ambushes via 302 to http://.
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to non-https url refused")
			}
			// Security review M2: re-validate the redirect target
			// against the IP-literal + private-range policy.
			if err := checkHostPolicy(req.URL.Host, cfg.allowIPLiteral); err != nil {
				return fmt.Errorf("redirect rejected: %w", err)
			}
			return nil
		},
	}
}

// validateTrustManifestURL performs cheap local checks: parseable,
// HTTPS-scheme, no userinfo. Run before any network or bootstrap
// state check so URL errors surface as URL errors.
func validateTrustManifestURL(manifestURL string) error {
	u, err := url.Parse(manifestURL)
	if err != nil {
		// Don't echo the underlying error — url.Parse can include
		// the raw URL in its error which may carry attacker-
		// controlled bytes when called via redirect handling.
		return fmt.Errorf("%w: malformed URL", ErrManifestUnreachableV3)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: only https URLs are accepted (got %q)",
			ErrManifestUnreachableV3, u.Scheme)
	}
	if u.User != nil {
		// Privacy review M14: a userinfo URL embeds credentials in
		// the URL string itself; the Go net stack echoes the full
		// URL into transport errors. Refuse at parse time.
		return fmt.Errorf("%w: URLs with userinfo (user@) are refused — credentials in URLs are a logging hazard",
			ErrManifestUnreachableV3)
	}
	return nil
}

// checkHostPolicy refuses URL hosts that violate the SSRF defense.
// The "host" arg is a URL Host field (which may include :port).
// Pass cfg.allowIPLiteral to relax the literal-IP refusal.
func checkHostPolicy(host string, allowIPLiteral bool) error {
	bareHost := host
	if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		bareHost = h
	}
	// IPv6 literals come bracketed in URLs — strip for ParseIP.
	if len(bareHost) >= 2 && bareHost[0] == '[' && bareHost[len(bareHost)-1] == ']' {
		bareHost = bareHost[1 : len(bareHost)-1]
	}
	if ip := net.ParseIP(bareHost); ip != nil {
		if !allowIPLiteral {
			return fmt.Errorf("%w: IP-literal hosts are refused (pass WithTrustManifestAllowIPLiteral(true) to override for air-gapped labs)",
				ErrManifestUnreachableV3)
		}
		if isDangerousIP(ip) {
			return fmt.Errorf("%w: literal IP %s falls into a refused range (loopback/private/link-local/cloud-metadata)",
				ErrManifestUnreachableV3, ip)
		}
	}
	return nil
}

// isDangerousIP reports whether ip belongs to a CIDR range we
// always refuse for SSRF defense: loopback, link-local (incl. AWS
// metadata 169.254.169.254 + GCP metadata 169.254.169.254 — same
// IP, different hostnames), unspecified, private (RFC1918 +
// fc00::/7), CGNAT (100.64.0.0/10), and IPv4-mapped IPv6
// equivalents of any of the above.
//
// Security review H3: previous string-pattern detection missed
// most of these.
func isDangerousIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// net.IP.IsPrivate covers RFC1918 + ULA fc00::/7.
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsPrivate() || ip.IsMulticast() {
		return true
	}
	// CGNAT range — not covered by IsPrivate per RFC6598.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && (ip4[1]&0xC0) == 0x40 {
			return true // 100.64.0.0/10
		}
	}
	return false
}
