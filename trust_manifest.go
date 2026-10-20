// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aleutian-ai/verification-go/mldsa"
)

// trust_manifest.go — Customer SDK live-manifest fetcher (15n_H1.1).
//
// # Description
//
// LoadTrustManifest fetches the current trust-store manifest from the
// audit-api endpoint, verifies its ML-DSA-65 signature against the
// compile-time-pinned TrustRootPublicKey, and returns a snapshot
// indexed by key_id. A per-process in-memory cache absorbs repeated
// calls until the TTL expires.
//
// # Trust model
//
//   - The audit-api endpoint is treated as an UNTRUSTED transport.
//     Whatever bytes it returns are verified against the SDK-pinned
//     root pubkey before any leaf key is exposed.
//   - The SDK never trusts a server-provided root claim. The pinned
//     fixture is the trust anchor.
//   - On signature mismatch the SDK refuses the manifest and returns
//     a typed error; callers can then decide whether to fall back to
//     fixture-pinned leaves (via the OfflineOnly option) or surface a
//     hard verification failure to the end user.
//
// # Ticket
//
//   - tickets/planned/15n_H1_1_sdk_manifest_go.md
//   - docs/technical_specifications/audit_details/21_trust_store_sdk_consumer_design.md

// Sentinel errors. Callers can switch on these via errors.Is.
var (
	// ErrManifestUnavailable means the audit-api endpoint returned a
	// non-200 or the fetch itself failed (network, DNS, etc.). Recoverable
	// in principle by retry; callers using AllowStale will receive a
	// stale-but-verified cached manifest instead.
	ErrManifestUnavailable = errors.New("verification: trust manifest unavailable")

	// ErrManifestMalformed means the response body did not parse as a
	// trust manifest or canonical JSON re-emission failed. Not recoverable;
	// the audit-api is returning bad bytes.
	ErrManifestMalformed = errors.New("verification: trust manifest is malformed")

	// ErrManifestRootSignature means the manifest's root_signature_b64
	// did not verify against the SDK-pinned TrustRootPublicKey. Hard
	// fail; either the SDK is built against the wrong env or the
	// audit-api is serving a manifest that was not signed by the
	// pinned root. Either way, refuse to expose leaves.
	ErrManifestRootSignature = errors.New("verification: trust manifest root signature did not verify against pinned root")

	// ErrTrustRootPlaceholder means TrustRootPublicKey is still the
	// all-zero placeholder shipped before the 15n_fix_A4 ceremony.
	// The SDK refuses to verify against a placeholder root.
	ErrTrustRootPlaceholder = errors.New("verification: trust root public key is the all-zero placeholder; SDK build is missing a real fixture")

	// ErrOfflineOnly means OfflineOnly was set and no cached manifest
	// exists. The caller must either populate the cache via a prior
	// online LoadTrustManifest call or accept that the SDK has no
	// leaf-key knowledge beyond what was embedded at SDK build time.
	ErrOfflineOnly = errors.New("verification: offline-only mode and no cached manifest available")
)

// TrustManifestEntry is one leaf (platform or tenant) in the manifest.
// Mirrors the schema in internal/compliance/trust_store_loader.go.
type TrustManifestEntry struct {
	KeyID         string `json:"key_id"`
	KMSKeyVersion string `json:"kms_key_version"`
	PublicKeyB64  string `json:"public_key_b64"`
	Algorithm     string `json:"algorithm"`
	AddedAtMs     int64  `json:"added_at_ms"`
	RevokedAtMs   *int64 `json:"revoked_at_ms"`
	NotAfterMs    *int64 `json:"not_after_ms"`
	TenantID      string `json:"tenant_id,omitempty"`
}

// TrustManifest is the parsed manifest snapshot returned to callers.
// All fields are read-only after construction; the snapshot is safe to
// share across goroutines.
type TrustManifest struct {
	Version      int64
	GeneratedAt  time.Time
	Env          string
	ApprovedBy   string
	RootKeyID    string
	SchemaNote   string
	PlatformKeys []TrustManifestEntry
	TenantKeys   []TrustManifestEntry

	// keys is the indexed, decoded, non-revoked subset for
	// PublicKey lookups. Constructed once at parse time.
	keys map[string][]byte
}

// PublicKey returns the raw 1952-byte ML-DSA-65 public key for the
// given key_id if it is present in the manifest AND not revoked.
//
// # Outputs
//
//   - pub: raw pubkey bytes; do not mutate.
//   - ok: true if found and non-revoked.
func (m *TrustManifest) PublicKey(keyID string) (pub []byte, ok bool) {
	if m == nil {
		return nil, false
	}
	pub, ok = m.keys[keyID]
	return pub, ok
}

// KeyIDs returns the sorted list of currently-active (non-revoked)
// key IDs in the manifest.
func (m *TrustManifest) KeyIDs() []string {
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(m.keys))
	for k := range m.keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Option configures LoadTrustManifest. Use the With* helpers below.
type Option func(*loadConfig)

type loadConfig struct {
	baseURL     string
	cacheTTL    time.Duration
	httpClient  *http.Client
	allowStale  bool
	offlineOnly bool
	// userAgent header — set so audit-api operators can see SDK fingerprints
	// in access logs.
	userAgent string
}

// WithBaseURL overrides the default audit-api endpoint
// (https://audit-api.<env>.aleutian.ai). Customers running their own
// audit-api proxy or pointing at a local instance for testing should
// pass an explicit URL here. Must NOT end with a trailing slash.
func WithBaseURL(u string) Option {
	return func(c *loadConfig) { c.baseURL = u }
}

// WithCacheTTL overrides the default in-memory cache TTL (1 hour per
// the H1.0 design). A TTL of 0 disables caching entirely (re-fetch on
// every call). Negative values are clamped to 0.
func WithCacheTTL(d time.Duration) Option {
	return func(c *loadConfig) {
		if d < 0 {
			d = 0
		}
		c.cacheTTL = d
	}
}

// WithHTTPClient overrides the default http.Client. Use this to inject
// custom timeouts, proxy settings, TLS configs, or for tests against
// httptest.Server.
func WithHTTPClient(client *http.Client) Option {
	return func(c *loadConfig) { c.httpClient = client }
}

// WithAllowStale lets LoadTrustManifest return a previously-cached
// manifest on a fetch failure (network error, non-200 response). Off
// by default — defaults are strict-fail per the H1.0 design. Customers
// using this should be aware that they may verify against a manifest
// that's older than the audit-api's current state.
func WithAllowStale(allow bool) Option {
	return func(c *loadConfig) { c.allowStale = allow }
}

// WithOfflineOnly disables manifest fetching entirely. The SDK returns
// the last successful in-memory cached manifest if any; otherwise
// ErrOfflineOnly. Intended for airgapped deployments and CTF-style
// demos where the SDK has no network egress.
func WithOfflineOnly(offline bool) Option {
	return func(c *loadConfig) { c.offlineOnly = offline }
}

// withUserAgent is unexported because customers shouldn't override it;
// audit-api operators rely on the standard SDK fingerprint.
func withUserAgent(ua string) Option {
	return func(c *loadConfig) { c.userAgent = ua }
}

// LoadTrustManifest fetches, verifies, and returns the current trust
// manifest.
//
// # Description
//
// On first call: fetch from the audit-api endpoint, verify root
// signature against the SDK-pinned TrustRootPublicKey, parse, index
// leaves by key_id, store in the per-process cache, return.
//
// On subsequent calls within cacheTTL: return the cached snapshot
// without fetching.
//
// On subsequent calls past TTL: re-fetch + re-verify. On fetch failure,
// return ErrManifestUnavailable unless AllowStale is set (in which
// case return the cached snapshot).
//
// # Inputs
//
//   - ctx: cancellation; propagated to the HTTP fetch.
//   - opts: zero or more Option values (WithBaseURL, WithCacheTTL,
//     WithHTTPClient, WithAllowStale, WithOfflineOnly).
//
// # Outputs
//
//   - *TrustManifest: read-only snapshot.
//   - error: ErrManifestUnavailable / ErrManifestMalformed /
//     ErrManifestRootSignature / ErrTrustRootPlaceholder / ErrOfflineOnly.
//
// # Example
//
//	m, err := verification.LoadTrustManifest(ctx)
//	if err != nil {
//	    return fmt.Errorf("trust manifest: %w", err)
//	}
//	pubkey, ok := m.PublicKey("chain-anchor-key-mldsa65-us")
//	if !ok {
//	    return errors.New("anchor key not in trust manifest")
//	}
//	if err := mldsa.Verify(pubkey, message, signature); err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - The cache is per-process. Multiple processes within the same
//     customer deployment fetch independently. Persisting across
//     restarts would require on-disk state, which the SDK avoids.
//   - The fetch is one shot per call; no retry-with-backoff inside
//     the SDK. Customers needing retries should wrap LoadTrustManifest
//     in their own retry loop.
//
// # Assumptions
//
//   - The SDK build is tagged for the correct env (default for dev,
//     -tags=trust_staging for staging, -tags=trust_prod for prod).
//     Cross-env fetches are detectable by inspecting m.Env after the
//     verification succeeds, but the SDK does not enforce it; it
//     trusts whatever the pinned root verifies. The build tag IS the
//     enforcement.
//   - TrustRootPublicKey has been populated by the env's
//     `15n_fix_A4` ceremony Step 2 (i.e. is not the all-zero
//     placeholder).
func LoadTrustManifest(ctx context.Context, opts ...Option) (*TrustManifest, error) {
	cfg := defaultLoadConfig()
	for _, o := range opts {
		o(&cfg)
	}

	// Refuse before even trying if the SDK was built without a real
	// trust root. This catches "SDK ships with placeholder, customer
	// integrates, nothing ever verifies" — fails loud at first call.
	if IsTrustRootPlaceholder() && !cfg.offlineOnly {
		return nil, fmt.Errorf("%w: env=%s; SDK build is missing the post-ceremony root fixture",
			ErrTrustRootPlaceholder, ActiveTrustEnv)
	}

	// OfflineOnly: never fetch. Return cached if any.
	if cfg.offlineOnly {
		if cached := globalManifestCache.snapshot(); cached != nil {
			return cached, nil
		}
		return nil, ErrOfflineOnly
	}

	// Fast path: serve cached if fresh.
	if cfg.cacheTTL > 0 {
		if cached, age, ok := globalManifestCache.snapshotWithAge(); ok && age < cfg.cacheTTL {
			return cached, nil
		}
	}

	manifest, fetchErr := fetchAndVerifyManifest(ctx, cfg)
	if fetchErr != nil {
		if cfg.allowStale {
			if cached := globalManifestCache.snapshot(); cached != nil {
				return cached, nil
			}
		}
		return nil, fetchErr
	}

	globalManifestCache.store(manifest)
	return manifest, nil
}

// defaultLoadConfig returns the H1.0-locked defaults.
func defaultLoadConfig() loadConfig {
	return loadConfig{
		baseURL:    defaultBaseURL(),
		cacheTTL:   1 * time.Hour, // H1.0 §3.2
		httpClient: &http.Client{Timeout: 30 * time.Second},
		userAgent:  "aleutian-verification-go/1.0",
	}
}

// defaultBaseURL returns the audit-api endpoint for the SDK's
// build-tagged env. Customers wanting a different host pass
// WithBaseURL.
func defaultBaseURL() string {
	// ActiveTrustEnv is set by the build-tag init. Map to public
	// audit-api hosts. These hostnames are also the ones documented
	// in client_facing/05_api_reference.md.
	switch ActiveTrustEnv {
	case "prod":
		return "https://audit-api.aleutian.ai"
	case "staging":
		return "https://audit-api.staging.aleutian.ai"
	default:
		return "https://audit-api.dev.aleutian.ai"
	}
}

// fetchAndVerifyManifest performs one HTTP fetch + signature verify +
// index. Pure function of cfg + globalManifestCache (used only for
// stale-fallback in the caller, not here).
func fetchAndVerifyManifest(ctx context.Context, cfg loadConfig) (*TrustManifest, error) {
	url := strings.TrimRight(cfg.baseURL, "/") + "/v1/trust/manifest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrManifestUnavailable, err)
	}
	req.Header.Set("User-Agent", cfg.userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: GET %s: %v", ErrManifestUnavailable, url, err)
	}
	defer resp.Body.Close()

	const maxBodyBytes = 8 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrManifestUnavailable, err)
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("%w: body exceeded %d bytes", ErrManifestMalformed, maxBodyBytes)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s returned %d: %s",
			ErrManifestUnavailable, url, resp.StatusCode, truncate(body, 256))
	}

	return parseVerifyAndIndex(body)
}

// ParseAndVerifyTrustManifest parses a raw trust-manifest JSON document,
// verifies its root signature against the SDK-pinned trust root, and
// returns the indexed snapshot — WITHOUT any network access.
//
// # Description
//
// This is the offline entry point for the CISO "verify against published
// keys" motion: a customer downloads the published manifest file once and
// verifies exported chains against it with zero network egress. It shares
// the exact parse → verify-root-signature → index invariant as
// [LoadTrustManifest]; only the transport differs (bytes vs HTTP).
//
// The returned snapshot carries Version + GeneratedAt, which callers feed
// to [EvaluateManifestFreshness] to obtain a freshness verdict.
//
// # Inputs
//
//   - raw: the manifest JSON document bytes.
//
// # Outputs
//
//   - *TrustManifest: read-only, root-signature-verified snapshot.
//   - error: ErrManifestMalformed / ErrManifestRootSignature /
//     ErrTrustRootPlaceholder on any failure.
//
// # Assumptions
//
//   - The SDK binary embeds the trust root for the environment whose
//     manifest is being verified (dev/staging/prod, selected at build).
func ParseAndVerifyTrustManifest(raw []byte) (*TrustManifest, error) {
	return parseVerifyAndIndex(raw)
}

// parseVerifyAndIndex is the core invariant: parse → extract sig →
// canonicalize sans signature → verify against pinned root → index
// non-revoked leaves. Returns ErrManifest* on any failure.
func parseVerifyAndIndex(raw []byte) (*TrustManifest, error) {
	// First decode: typed, for the schema-level fields we need.
	var typed struct {
		Version          int64                `json:"version"`
		GeneratedAtMs    int64                `json:"generated_at_ms"`
		Env              string               `json:"env"`
		ApprovedBy       string               `json:"approved_by"`
		RootKeyID        string               `json:"root_key_id"`
		SchemaNote       string               `json:"schema_note"`
		PlatformKeys     []TrustManifestEntry `json:"platform_keys"`
		TenantKeys       []TrustManifestEntry `json:"tenant_keys"`
		RootSignatureB64 string               `json:"root_signature_b64"`
	}
	if err := json.Unmarshal(raw, &typed); err != nil {
		return nil, fmt.Errorf("%w: typed decode: %v", ErrManifestMalformed, err)
	}
	if typed.RootSignatureB64 == "" {
		return nil, fmt.Errorf("%w: missing root_signature_b64", ErrManifestMalformed)
	}
	sig, err := base64.StdEncoding.DecodeString(typed.RootSignatureB64)
	if err != nil {
		return nil, fmt.Errorf("%w: root_signature_b64 not base64: %v", ErrManifestMalformed, err)
	}

	// Second decode: generic, so we can drop the signature field and
	// re-emit canonical JSON. UseNumber preserves number formatting.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic map[string]any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("%w: generic decode: %v", ErrManifestMalformed, err)
	}
	delete(generic, "root_signature_b64")
	canonical, err := canonicalJSON(generic)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize: %v", ErrManifestMalformed, err)
	}

	if err := mldsa.Verify(TrustRootPublicKey, canonical, sig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifestRootSignature, err)
	}

	// Index non-revoked leaves.
	keys := make(map[string][]byte, len(typed.PlatformKeys)+len(typed.TenantKeys))
	for _, e := range typed.PlatformKeys {
		if e.RevokedAtMs != nil {
			continue
		}
		pk, err := base64.StdEncoding.DecodeString(e.PublicKeyB64)
		if err != nil {
			return nil, fmt.Errorf("%w: platform key %q: %v", ErrManifestMalformed, e.KeyID, err)
		}
		keys[e.KeyID] = pk
	}
	for _, e := range typed.TenantKeys {
		if e.RevokedAtMs != nil {
			continue
		}
		pk, err := base64.StdEncoding.DecodeString(e.PublicKeyB64)
		if err != nil {
			return nil, fmt.Errorf("%w: tenant key %q: %v", ErrManifestMalformed, e.KeyID, err)
		}
		keys[e.KeyID] = pk
	}

	return &TrustManifest{
		Version:      typed.Version,
		GeneratedAt:  time.UnixMilli(typed.GeneratedAtMs).UTC(),
		Env:          typed.Env,
		ApprovedBy:   typed.ApprovedBy,
		RootKeyID:    typed.RootKeyID,
		SchemaNote:   typed.SchemaNote,
		PlatformKeys: typed.PlatformKeys,
		TenantKeys:   typed.TenantKeys,
		keys:         keys,
	}, nil
}

// canonicalJSON byte-for-byte mirrors internal/compliance/trust_store_loader.go
// canonicalJSON(): recursively sorted object keys, no insignificant
// whitespace, no HTML escape, numbers preserved as written.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		// trust_manifest_integer_only_canonical (2026-06-09 review C1):
		// Reject non-integer literals to keep canonical bytes byte-
		// identical to the extension's JS implementation. JS's
		// Number.parseFloat-roundtrip semantics diverge from Go's
		// json.Number-preserves-source on:
		//   - decimals ("1.0" vs "1")
		//   - exponents ("1e3" vs "1000")
		//   - values outside [-(2^53-1), 2^53-1]
		// The schema only uses int64 today; this assertion catches
		// future schema drift before it becomes a sig-verify divergence.
		s := val.String()
		// Match /^-?(0|[1-9]\d*)$/.
		if !isCanonicalIntegerLiteral(s) {
			return fmt.Errorf("canonicalJSON: non-integer number literal %q rejected (cross-language divergence risk)", s)
		}
		// Bound to JS's safe integer window so we don't sign something
		// JS would reject on read.
		if n, perr := val.Int64(); perr != nil || n > 9007199254740991 || n < -9007199254740991 {
			return fmt.Errorf("canonicalJSON: integer %q outside JS safe range", s)
		}
		buf.WriteString(s)
	case string:
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(val); err != nil {
			return err
		}
		// json.Encoder appends a newline; strip it.
		b := buf.Bytes()
		if len(b) > 0 && b[len(b)-1] == '\n' {
			buf.Truncate(buf.Len() - 1)
		}
	case []any:
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonicalJSON: unsupported type %T", v)
	}
	return nil
}

// manifestCache is the per-process cache used by LoadTrustManifest.
// Single instance for the package — customers usually want one
// manifest per binary, not one per call site. Thread-safe.
type manifestCache struct {
	mu       sync.RWMutex
	current  *TrustManifest
	storedAt time.Time
}

func (c *manifestCache) snapshot() *TrustManifest {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
}

func (c *manifestCache) snapshotWithAge() (*TrustManifest, time.Duration, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.current == nil {
		return nil, 0, false
	}
	return c.current, time.Since(c.storedAt), true
}

func (c *manifestCache) store(m *TrustManifest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = m
	c.storedAt = time.Now()
}

// ClearTrustManifestCache wipes the per-process cache. Intended for
// tests; production callers should not need this.
func ClearTrustManifestCache() {
	globalManifestCache.mu.Lock()
	defer globalManifestCache.mu.Unlock()
	globalManifestCache.current = nil
	globalManifestCache.storedAt = time.Time{}
}

var globalManifestCache = &manifestCache{}

// truncate returns a printable prefix of b suitable for embedding in
// error messages. Strips trailing newlines.
func truncate(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return strings.TrimRight(string(b), "\n\r")
}

// isCanonicalIntegerLiteral reports whether s matches /^-?(0|[1-9]\d*)$/ —
// i.e. a plain integer literal, no decimal point, no exponent, no leading
// zero (except the singleton "0"), no leading '+'. The trust manifest's
// canonical-JSON contract restricts every number to this form so the JS
// implementation can re-emit byte-identically through JSON.stringify on
// an IEEE-754 double without precision loss.
func isCanonicalIntegerLiteral(s string) bool {
	if len(s) == 0 {
		return false
	}
	i := 0
	if s[0] == '-' {
		if len(s) == 1 {
			return false
		}
		i = 1
	}
	if s[i] == '0' {
		return i+1 == len(s)
	}
	if s[i] < '1' || s[i] > '9' {
		return false
	}
	for j := i + 1; j < len(s); j++ {
		if s[j] < '0' || s[j] > '9' {
			return false
		}
	}
	return true
}
