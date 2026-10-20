// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// silence "unused" for synthBootstrap when nobody embeds it.
var _ = synthBootstrap{}

// --------------------------------------------------------------------
// Test harness: synthetic bootstrap key + manifest mint
// --------------------------------------------------------------------

// synthBootstrap holds a fresh ML-DSA-65 keypair the test can pass
// as the synthetic bootstrap set via withTrustManifestEmbeddedKeys.
// Returned by `synthBootstrapKey`.
type synthBootstrap struct {
	kid    string
	sign   func(msg []byte) []byte
	keyset []embeddedBootstrapKeyBlob
}

// synthBootstrapKey mints a fresh ML-DSA-65 keypair and returns it
// for injection via withTrustManifestEmbeddedKeys. The cleanup func
// is a no-op kept for call-site compatibility.
//
// Arch review H5: this used to mutate `bootstrapKeysDev` directly,
// which raced with any future `t.Parallel()` test. The new pattern
// passes the bootstrap set through the config so each test owns
// its own keyset — concurrency-safe, parallel-safe.
func synthBootstrapKey(t *testing.T) (kid string, sign func(msg []byte) []byte, cleanup func()) {
	t.Helper()
	scheme := mldsa65.Scheme()
	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("synthBootstrapKey: generate: %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("synthBootstrapKey: marshal pub: %v", err)
	}
	kid = "bootstrap-trust-manifest-dev-2026-v1"
	keyset := []embeddedBootstrapKeyBlob{{SigningKeyID: kid, PublicKey: pubBytes}}
	currentSynthKeyset.Store(&keyset)
	cleanup = func() { currentSynthKeyset.Store(&[]embeddedBootstrapKeyBlob{}) }

	sign = func(msg []byte) []byte {
		return scheme.Sign(priv, msg, nil)
	}
	return kid, sign, cleanup
}

// currentSynthKeyset holds the active synthetic keyset for tests
// that retrieve it via `synthKeysetForTest`. Atomic pointer keeps
// the read path lock-free; sequential setup/teardown in tests
// (no t.Parallel for this set today) means we never observe
// torn state.
var currentSynthKeyset atomic.Pointer[[]embeddedBootstrapKeyBlob]

// synthKeysetForTest returns the active synthetic bootstrap set,
// or nil if synthBootstrapKey wasn't called. Used by the
// verifyAndBuildTrustManifestV3 direct-call tests.
func synthKeysetForTest(t *testing.T) []embeddedBootstrapKeyBlob {
	t.Helper()
	if p := currentSynthKeyset.Load(); p != nil {
		return *p
	}
	return nil
}

// mintManifestPayload builds a valid manifest payload + one
// signing-key entry suitable for the happy path. Tests mutate the
// returned value before signing.
func mintManifestPayload(t *testing.T) (TrustManifestPayloadV1, []byte) {
	t.Helper()
	scheme := mldsa65.Scheme()
	pub, _, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("mintManifestPayload: generate: %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("mintManifestPayload: marshal: %v", err)
	}
	p := TrustManifestPayloadV1{
		Version:        1,
		ManifestSerial: 100,
		TenantID:       "comp_01HX9K2P3VQNRT8WZE7CMD8YH4",
		IssuedAtMs:     1_000_000,
		ExpiresAtMs:    2_000_000,
		Keys: []TrustManifestSignedKeyV1{
			{
				SigningKeyID: "kid_b59e64d6595cc207",
				Algorithm:    "ML-DSA-65",
				PublicKey:    pubBytes,
				ValidFromMs:  1_000_000,
				ValidUntilMs: 2_000_000,
			},
		},
	}
	return p, pubBytes
}

// buildWire converts a payload + bootstrap kid + signature into
// the JSON shape the URL fetcher consumes.
func buildWire(p TrustManifestPayloadV1, bootstrapKid string, sig []byte) trustManifestJSONWire {
	keys := make([]trustManifestJSONWireKey, 0, len(p.Keys))
	for _, k := range p.Keys {
		keys = append(keys, trustManifestJSONWireKey{
			SigningKeyID: k.SigningKeyID,
			Algorithm:    k.Algorithm,
			PublicKeyB64: base64.StdEncoding.EncodeToString(k.PublicKey),
			ValidFromMs:  k.ValidFromMs,
			ValidUntilMs: k.ValidUntilMs,
		})
	}
	return trustManifestJSONWire{
		Version:             p.Version,
		ManifestSerial:      p.ManifestSerial,
		TenantID:            p.TenantID,
		IssuedAtMs:          p.IssuedAtMs,
		ExpiresAtMs:         p.ExpiresAtMs,
		BootstrapSigningKey: bootstrapKid,
		Keys:                keys,
		Signature: trustManifestJSONSignature{
			Algorithm: "ML-DSA-65",
			SigB64:    base64.StdEncoding.EncodeToString(sig),
		},
	}
}

// fixedClockAt returns a clock function that always reports ts.
func fixedClockAt(ts int64) func() int64 { return func() int64 { return ts } }

// --------------------------------------------------------------------
// Happy path
// --------------------------------------------------------------------

func TestTrustManifestFromURL_HappyPath(t *testing.T) {
	bootKid, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	canonical, err := CanonicalBytesTrustManifestV1(payload)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sig := sign(canonical)
	wire := buildWire(payload, bootKid, sig)

	mf, err := verifyAndBuildTrustManifestV3(wire, trustManifestFromURLConfig{
		env:                           TrustManifestEnvDev,
		nowMs:                         fixedClockAt(payload.IssuedAtMs + 1),
		embeddedBootstrapKeysOverride: synthKeysetForTest(t),
	})
	if err != nil {
		t.Fatalf("verifyAndBuild: %v", err)
	}
	if mf.LoadedSerial() != payload.ManifestSerial {
		t.Errorf("LoadedSerial = %d, want %d", mf.LoadedSerial(), payload.ManifestSerial)
	}
	if mf.Env() != TrustManifestEnvDev {
		t.Errorf("Env = %q, want dev", mf.Env())
	}

	// Look up the embedded key.
	pk, err := mf.PublicKeyForSigningKeyID(context.Background(), "kid_b59e64d6595cc207")
	if err != nil {
		t.Fatalf("PublicKeyForSigningKeyID: %v", err)
	}
	if len(pk) == 0 {
		t.Error("PublicKeyForSigningKeyID returned empty key")
	}
}

// --------------------------------------------------------------------
// Adversarial fixtures (per spec adversarial set + AC)
// --------------------------------------------------------------------

// 1. Serial replay — fetched serial ≤ last-seen serial.
func TestTrustManifestFromURL_Adversarial_SerialReplay(t *testing.T) {
	bootKid, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	canonical, _ := CanonicalBytesTrustManifestV1(payload)
	sig := sign(canonical)
	wire := buildWire(payload, bootKid, sig)

	// last-seen serial = the manifest's serial → strict-greater
	// fails.
	lastSeen := payload.ManifestSerial
	_, err := verifyAndBuildTrustManifestV3(wire, trustManifestFromURLConfig{
		env:                           TrustManifestEnvDev,
		nowMs:                         fixedClockAt(payload.IssuedAtMs + 1),
		lastSeenSerial:                &lastSeen,
		embeddedBootstrapKeysOverride: synthKeysetForTest(t),
	})
	if !errors.Is(err, ErrManifestStaleV3) {
		t.Fatalf("expected ErrManifestStaleV3, got %v", err)
	}
}

//  2. Algorithm downgrade — manifest claims the outer signature is
//     "ML-DSA-44" (not in SupportedSignatureAlgorithmsV3).
func TestTrustManifestFromURL_Adversarial_AlgorithmDowngrade(t *testing.T) {
	bootKid, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	canonical, _ := CanonicalBytesTrustManifestV1(payload)
	sig := sign(canonical)
	wire := buildWire(payload, bootKid, sig)
	wire.Signature.Algorithm = "ML-DSA-44"

	_, err := verifyAndBuildTrustManifestV3(wire, trustManifestFromURLConfig{
		env:                           TrustManifestEnvDev,
		nowMs:                         fixedClockAt(payload.IssuedAtMs + 1),
		embeddedBootstrapKeysOverride: synthKeysetForTest(t),
	})
	if !errors.Is(err, ErrManifestSignatureInvalidV3) {
		t.Fatalf("expected ErrManifestSignatureInvalidV3, got %v", err)
	}
}

//  3. Bootstrap kid not in embedded set — attacker uses a name we
//     don't trust.
func TestTrustManifestFromURL_Adversarial_BootstrapKidUnknown(t *testing.T) {
	_, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	canonical, _ := CanonicalBytesTrustManifestV1(payload)
	sig := sign(canonical)
	wire := buildWire(payload, "bootstrap-attacker-stolen-2024-v1", sig)

	_, err := verifyAndBuildTrustManifestV3(wire, trustManifestFromURLConfig{
		env:                           TrustManifestEnvDev,
		nowMs:                         fixedClockAt(payload.IssuedAtMs + 1),
		embeddedBootstrapKeysOverride: synthKeysetForTest(t),
	})
	if !errors.Is(err, ErrManifestUnknownBootstrapKeyV3) {
		t.Fatalf("expected ErrManifestUnknownBootstrapKeyV3, got %v", err)
	}
}

// 4. Expired — now > expires_at.
func TestTrustManifestFromURL_Adversarial_Expired(t *testing.T) {
	bootKid, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	canonical, _ := CanonicalBytesTrustManifestV1(payload)
	sig := sign(canonical)
	wire := buildWire(payload, bootKid, sig)

	_, err := verifyAndBuildTrustManifestV3(wire, trustManifestFromURLConfig{
		env:                           TrustManifestEnvDev,
		nowMs:                         fixedClockAt(payload.ExpiresAtMs + 1),
		embeddedBootstrapKeysOverride: synthKeysetForTest(t),
	})
	if !errors.Is(err, ErrManifestExpiredV3) {
		t.Fatalf("expected ErrManifestExpiredV3, got %v", err)
	}
}

//  5. Signature scope too narrow — attacker swaps a manifest field
//     AFTER signing. The recomputed canonical bytes don't match the
//     sig.
func TestTrustManifestFromURL_Adversarial_SignatureScopeTooNarrow(t *testing.T) {
	bootKid, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	canonical, _ := CanonicalBytesTrustManifestV1(payload)
	sig := sign(canonical)
	wire := buildWire(payload, bootKid, sig)

	// Field-swap the tenant_id AFTER signing — sig was over the
	// original, the canonical re-encode will use the new value,
	// signature verify must fail.
	wire.TenantID = "comp_attacker_owned"

	_, err := verifyAndBuildTrustManifestV3(wire, trustManifestFromURLConfig{
		env:                           TrustManifestEnvDev,
		nowMs:                         fixedClockAt(payload.IssuedAtMs + 1),
		embeddedBootstrapKeysOverride: synthKeysetForTest(t),
	})
	if !errors.Is(err, ErrManifestSignatureInvalidV3) {
		t.Fatalf("expected ErrManifestSignatureInvalidV3, got %v", err)
	}
}

// Range too wide — expires_at - issued_at > 1 year.
func TestTrustManifestFromURL_Adversarial_RangeTooWide(t *testing.T) {
	bootKid, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	payload.ExpiresAtMs = payload.IssuedAtMs + MaxManifestValidityRangeMs + 1
	canonical, _ := CanonicalBytesTrustManifestV1(payload)
	sig := sign(canonical)
	wire := buildWire(payload, bootKid, sig)

	_, err := verifyAndBuildTrustManifestV3(wire, trustManifestFromURLConfig{
		env:                           TrustManifestEnvDev,
		nowMs:                         fixedClockAt(payload.IssuedAtMs + 1),
		embeddedBootstrapKeysOverride: synthKeysetForTest(t),
	})
	if !errors.Is(err, ErrManifestRangeUnreasonableV3) {
		t.Fatalf("expected ErrManifestRangeUnreasonableV3, got %v", err)
	}
}

// --------------------------------------------------------------------
// Validity-window enforcement (spec §8)
// --------------------------------------------------------------------

func TestTrustManifestFromURL_ValidityWindow_AcceptsInside(t *testing.T) {
	bootKid, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	canonical, _ := CanonicalBytesTrustManifestV1(payload)
	sig := sign(canonical)
	wire := buildWire(payload, bootKid, sig)

	mf, err := verifyAndBuildTrustManifestV3(wire, trustManifestFromURLConfig{
		env:                           TrustManifestEnvDev,
		nowMs:                         fixedClockAt(payload.IssuedAtMs + 1),
		embeddedBootstrapKeysOverride: synthKeysetForTest(t),
	})
	if err != nil {
		t.Fatalf("verifyAndBuild: %v", err)
	}
	entryTs := payload.IssuedAtMs + 1_000
	_, err = mf.PublicKeyForSigningKeyIDAtTime(context.Background(), "kid_b59e64d6595cc207", entryTs)
	if err != nil {
		t.Errorf("inside-window lookup failed: %v", err)
	}
}

func TestTrustManifestFromURL_ValidityWindow_RejectsBeforeWindow(t *testing.T) {
	bootKid, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	canonical, _ := CanonicalBytesTrustManifestV1(payload)
	sig := sign(canonical)
	wire := buildWire(payload, bootKid, sig)

	mf, err := verifyAndBuildTrustManifestV3(wire, trustManifestFromURLConfig{
		env:                           TrustManifestEnvDev,
		nowMs:                         fixedClockAt(payload.IssuedAtMs + 1),
		embeddedBootstrapKeysOverride: synthKeysetForTest(t),
	})
	if err != nil {
		t.Fatalf("verifyAndBuild: %v", err)
	}
	// Entry timestamp 1ms BEFORE the key's valid_from.
	entryTs := payload.Keys[0].ValidFromMs - 1
	_, err = mf.PublicKeyForSigningKeyIDAtTime(context.Background(), "kid_b59e64d6595cc207", entryTs)
	if !errors.Is(err, ErrKeyOutsideValidityWindowV3) {
		t.Errorf("expected ErrKeyOutsideValidityWindowV3, got %v", err)
	}
}

func TestTrustManifestFromURL_ValidityWindow_RejectsAtValidUntil(t *testing.T) {
	bootKid, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	canonical, _ := CanonicalBytesTrustManifestV1(payload)
	sig := sign(canonical)
	wire := buildWire(payload, bootKid, sig)

	mf, err := verifyAndBuildTrustManifestV3(wire, trustManifestFromURLConfig{
		env:                           TrustManifestEnvDev,
		nowMs:                         fixedClockAt(payload.IssuedAtMs + 1),
		embeddedBootstrapKeysOverride: synthKeysetForTest(t),
	})
	if err != nil {
		t.Fatalf("verifyAndBuild: %v", err)
	}
	// Window is half-open: [valid_from, valid_until). Entry AT
	// exactly valid_until is rejected — spec choice for unambiguous
	// rotation semantics.
	entryTs := payload.Keys[0].ValidUntilMs
	_, err = mf.PublicKeyForSigningKeyIDAtTime(context.Background(), "kid_b59e64d6595cc207", entryTs)
	if !errors.Is(err, ErrKeyOutsideValidityWindowV3) {
		t.Errorf("expected ErrKeyOutsideValidityWindowV3, got %v", err)
	}
}

// --------------------------------------------------------------------
// End-to-end HTTP fetch (httptest server)
// --------------------------------------------------------------------

func TestTrustManifestFromURL_HTTP_FetchHappyPath(t *testing.T) {
	bootKid, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	canonical, _ := CanonicalBytesTrustManifestV1(payload)
	sig := sign(canonical)
	wire := buildWire(payload, bootKid, sig)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(wire)
	}))
	defer server.Close()

	// httptest.NewTLSServer issues a self-signed cert; the default
	// http.Client refuses it. Inject the test server's client which
	// trusts its own cert.
	mf, err := NewTrustManifestFromURLV3(context.Background(), server.URL,
		WithTrustManifestEnv(TrustManifestEnvDev),
		WithTrustManifestHTTPClient(server.Client()),
		withTrustManifestNowMs(fixedClockAt(payload.IssuedAtMs+1)),
		WithTrustManifestAllowIPLiteral(true), // httptest server URL has an IP literal
		withTrustManifestEmbeddedKeys(synthKeysetForTest(t)),
	)
	if err != nil {
		t.Fatalf("NewTrustManifestFromURLV3: %v", err)
	}
	if mf.LoadedSerial() != payload.ManifestSerial {
		t.Errorf("LoadedSerial = %d", mf.LoadedSerial())
	}
}

func TestTrustManifestFromURL_HTTP_RejectsNonHTTPS(t *testing.T) {
	// URL validation runs before bootstrap check, so an http://
	// URL surfaces as ErrManifestUnreachableV3 regardless of
	// whether the bootstrap ceremony has run. Confirmed in this
	// test by NOT patching the bootstrap.
	_, err := NewTrustManifestFromURLV3(context.Background(), "http://example.com/manifest.json",
		WithTrustManifestEnv(TrustManifestEnvDev))
	if !errors.Is(err, ErrManifestUnreachableV3) {
		t.Errorf("expected ErrManifestUnreachableV3 on http://, got %v", err)
	}
}

func TestTrustManifestFromURL_HTTP_RejectsUserinfoURL(t *testing.T) {
	// Privacy review M14: userinfo URLs leak credentials to logs.
	// Refused at URL parse, before bootstrap check.
	_, err := NewTrustManifestFromURLV3(context.Background(),
		"https://user:pass@example.com/manifest.json",
		WithTrustManifestEnv(TrustManifestEnvDev))
	if !errors.Is(err, ErrManifestUnreachableV3) {
		t.Errorf("expected ErrManifestUnreachableV3 on userinfo URL, got %v", err)
	}
}

func TestTrustManifestFromURL_HTTP_RejectsIPLiteralByDefault(t *testing.T) {
	// Patch the bootstrap so we reach the SSRF check rather than
	// the placeholder check.
	_, _, cleanup := synthBootstrapKey(t)
	defer cleanup()
	_, err := NewTrustManifestFromURLV3(context.Background(), "https://192.0.2.1/manifest.json",
		WithTrustManifestEnv(TrustManifestEnvDev),
		withTrustManifestEmbeddedKeys(synthKeysetForTest(t)))
	if !errors.Is(err, ErrManifestUnreachableV3) {
		t.Errorf("expected ErrManifestUnreachableV3 on IP literal, got %v", err)
	}
}

func TestTrustManifestFromURL_HTTP_RejectsDangerousIPLiteralEvenWhenAllowed(t *testing.T) {
	// Security review H3: even when WithTrustManifestAllowIPLiteral
	// is opt-in, dangerous ranges (loopback / RFC1918 / link-local /
	// cloud-metadata) are still refused unless caller brings their
	// own HTTPClient.
	_, _, cleanup := synthBootstrapKey(t)
	defer cleanup()
	cases := []string{
		"https://127.0.0.1/m.json",       // loopback
		"https://169.254.169.254/m.json", // cloud metadata
		"https://10.0.0.1/m.json",        // RFC1918
		"https://[::1]/m.json",           // IPv6 loopback
		"https://100.64.0.1/m.json",      // CGNAT
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			_, err := NewTrustManifestFromURLV3(context.Background(), u,
				WithTrustManifestEnv(TrustManifestEnvDev),
				WithTrustManifestAllowIPLiteral(true),
				withTrustManifestEmbeddedKeys(synthKeysetForTest(t)))
			if !errors.Is(err, ErrManifestUnreachableV3) {
				t.Errorf("expected ErrManifestUnreachableV3 on dangerous IP %q, got %v", u, err)
			}
		})
	}
}

func TestTrustManifestFromURL_HTTP_RejectsOversizeBody(t *testing.T) {
	_, _, cleanup := synthBootstrapKey(t)
	defer cleanup()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// Stream more than the configured cap.
		_, _ = w.Write([]byte(strings.Repeat("x", 2000)))
	}))
	defer server.Close()

	_, err := NewTrustManifestFromURLV3(context.Background(), server.URL,
		WithTrustManifestEnv(TrustManifestEnvDev),
		WithTrustManifestHTTPClient(server.Client()),
		WithTrustManifestAllowIPLiteral(true),
		WithTrustManifestMaxResponseBytes(1024), // 1 KiB cap
		withTrustManifestEmbeddedKeys(synthKeysetForTest(t)),
	)
	if !errors.Is(err, ErrManifestUnreachableV3) {
		t.Errorf("expected ErrManifestUnreachableV3 on oversize, got %v", err)
	}
}

// --------------------------------------------------------------------
// Pre-ceremony state — IsBootstrapPlaceholder + fail-closed
// --------------------------------------------------------------------

func TestIsBootstrapPlaceholder_DefaultPreCeremony(t *testing.T) {
	// Pre-ceremony, every embedded set is all-zero placeholder.
	for _, env := range []TrustManifestEnv{TrustManifestEnvDev, TrustManifestEnvStaging, TrustManifestEnvProd} {
		if !IsBootstrapPlaceholder(env) {
			t.Errorf("env=%s: IsBootstrapPlaceholder() = false; ceremony has not run for this build but reported as real", env)
		}
	}
}

// --------------------------------------------------------------------
// Algorithm-agility filter — supported keys land, unsupported skipped
// --------------------------------------------------------------------

func TestTrustManifestFromURL_AlgFilter_SkipsUnsupportedSilently(t *testing.T) {
	bootKid, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	// Add a second key with an unsupported algorithm — should land
	// in canonical bytes (encoder is alg-agnostic) but be FILTERED
	// out of the loaded manifest (verifier is alg-strict).
	unsupportedPub := make([]byte, mldsa65PubkeySize) // junk bytes
	for i := range unsupportedPub {
		unsupportedPub[i] = 0xAB
	}
	payload.Keys = append(payload.Keys, TrustManifestSignedKeyV1{
		SigningKeyID: "kid_future_alg",
		Algorithm:    "ML-DSA-87", // not in SupportedSignatureAlgorithmsV3
		PublicKey:    unsupportedPub,
		ValidFromMs:  payload.IssuedAtMs,
		ValidUntilMs: payload.ExpiresAtMs,
	})
	canonical, _ := CanonicalBytesTrustManifestV1(payload)
	sig := sign(canonical)
	wire := buildWire(payload, bootKid, sig)

	mf, err := verifyAndBuildTrustManifestV3(wire, trustManifestFromURLConfig{
		env:                           TrustManifestEnvDev,
		nowMs:                         fixedClockAt(payload.IssuedAtMs + 1),
		embeddedBootstrapKeysOverride: synthKeysetForTest(t),
	})
	if err != nil {
		t.Fatalf("verifyAndBuild: %v", err)
	}

	if _, err := mf.PublicKeyForSigningKeyID(context.Background(), "kid_b59e64d6595cc207"); err != nil {
		t.Errorf("supported key not in loaded manifest: %v", err)
	}
	if _, err := mf.PublicKeyForSigningKeyID(context.Background(), "kid_future_alg"); err == nil {
		t.Error("unsupported-alg key should have been filtered out, but was loaded")
	}
}

func TestTrustManifestFromURL_AlgFilter_NoSupportedKeysFails(t *testing.T) {
	bootKid, sign, cleanup := synthBootstrapKey(t)
	defer cleanup()

	payload, _ := mintManifestPayload(t)
	// Replace the lone key with an unsupported one.
	payload.Keys[0].Algorithm = "ML-DSA-87"
	canonical, _ := CanonicalBytesTrustManifestV1(payload)
	sig := sign(canonical)
	wire := buildWire(payload, bootKid, sig)

	_, err := verifyAndBuildTrustManifestV3(wire, trustManifestFromURLConfig{
		env:                           TrustManifestEnvDev,
		nowMs:                         fixedClockAt(payload.IssuedAtMs + 1),
		embeddedBootstrapKeysOverride: synthKeysetForTest(t),
	})
	if !errors.Is(err, ErrManifestNoSupportedKeysV3) {
		t.Fatalf("expected ErrManifestNoSupportedKeysV3, got %v", err)
	}
}
