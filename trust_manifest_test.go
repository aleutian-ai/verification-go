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
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Tests use a test-generated ML-DSA-65 keypair instead of the
// fixture-pinned root, because the fixture is the dev real root
// (we don't have its private key in tests). Each test temporarily
// swaps TrustRootPublicKey, builds a manifest signed by the test
// keypair, and restores the original on cleanup.

// withTestRoot generates a fresh ML-DSA-65 keypair, swaps
// TrustRootPublicKey to the new pubkey for the duration of the test,
// and returns the test private key so the test can sign manifests.
func withTestRoot(t *testing.T) (priv mldsa65.PrivateKey) {
	t.Helper()
	scheme := mldsa65.Scheme()
	pub, sk, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}

	saved := TrustRootPublicKey
	TrustRootPublicKey = pubBytes
	t.Cleanup(func() {
		TrustRootPublicKey = saved
		ClearTrustManifestCache()
	})
	// Cast the abstract PrivateKey through type assertion.
	return *(sk.(*mldsa65.PrivateKey))
}

// buildSignedManifestBytes produces a JSON manifest signed by `priv`
// matching the canonical form the SDK verifies against.
func buildSignedManifestBytes(t *testing.T, priv mldsa65.PrivateKey, body map[string]any) []byte {
	t.Helper()
	// Compute canonical bytes over body sans root_signature_b64.
	canonical, err := canonicalJSON(body)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	sig := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(&priv, canonical, nil, false, sig)
	signed := make(map[string]any, len(body)+1)
	for k, v := range body {
		signed[k] = v
	}
	signed["root_signature_b64"] = base64.StdEncoding.EncodeToString(sig)
	out, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal signed: %v", err)
	}
	return out
}

// runServer mounts a handler serving the given manifest bytes.
func runServer(t *testing.T, body []byte, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
}

func minimalManifestBody(t *testing.T) map[string]any {
	t.Helper()
	// Use json.Number for the integer field so canonical re-serialization
	// matches what the server produced.
	dec := json.NewDecoder(bytes.NewReader([]byte(
		`{"version":7,"generated_at_ms":1700000000000,"env":"dev","approved_by":"test@example.com","root_key_id":"trust-root-mldsa65","schema_note":"test","platform_keys":[],"tenant_keys":[]}`)))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("decode minimal: %v", err)
	}
	return m
}

func TestLoadTrustManifest_HappyPath(t *testing.T) {
	priv := withTestRoot(t)
	body := minimalManifestBody(t)
	signed := buildSignedManifestBytes(t, priv, body)
	srv := runServer(t, signed, http.StatusOK)
	defer srv.Close()

	ctx := context.Background()
	m, err := LoadTrustManifest(ctx,
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithCacheTTL(0), // no cache for this test
	)
	if err != nil {
		t.Fatalf("LoadTrustManifest: %v", err)
	}
	if m.Version != 7 {
		t.Errorf("version = %d, want 7", m.Version)
	}
	if m.RootKeyID != "trust-root-mldsa65" {
		t.Errorf("root_key_id = %q", m.RootKeyID)
	}
	if m.Env != "dev" {
		t.Errorf("env = %q", m.Env)
	}
}

func TestLoadTrustManifest_IndexesLeafKeysAndIgnoresRevoked(t *testing.T) {
	priv := withTestRoot(t)
	body := minimalManifestBody(t)
	body["platform_keys"] = []any{
		map[string]any{
			"key_id": "active-1", "algorithm": "ML-DSA-65",
			"public_key_b64": base64.StdEncoding.EncodeToString([]byte("active-1-bytes")),
		},
		map[string]any{
			"key_id": "revoked-1", "algorithm": "ML-DSA-65",
			"public_key_b64": base64.StdEncoding.EncodeToString([]byte("revoked-bytes")),
			"revoked_at_ms":  json.Number("1700001000000"),
		},
	}
	signed := buildSignedManifestBytes(t, priv, body)
	srv := runServer(t, signed, http.StatusOK)
	defer srv.Close()

	m, err := LoadTrustManifest(context.Background(),
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithCacheTTL(0),
	)
	if err != nil {
		t.Fatalf("LoadTrustManifest: %v", err)
	}
	if _, ok := m.PublicKey("active-1"); !ok {
		t.Error("active-1 missing from PublicKey index")
	}
	if _, ok := m.PublicKey("revoked-1"); ok {
		t.Error("revoked-1 should be excluded from PublicKey index")
	}
	if ids := m.KeyIDs(); len(ids) != 1 || ids[0] != "active-1" {
		t.Errorf("KeyIDs() = %v, want [active-1]", ids)
	}
}

func TestLoadTrustManifest_SignatureMismatch_HardFail(t *testing.T) {
	withTestRoot(t)
	// Sign with a DIFFERENT key than the pinned root.
	scheme := mldsa65.Scheme()
	_, attackerSK, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("attacker key: %v", err)
	}
	body := minimalManifestBody(t)
	signed := buildSignedManifestBytes(t, *(attackerSK.(*mldsa65.PrivateKey)), body)
	srv := runServer(t, signed, http.StatusOK)
	defer srv.Close()

	_, err = LoadTrustManifest(context.Background(),
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithCacheTTL(0),
	)
	if err == nil {
		t.Fatal("expected signature mismatch error, got nil")
	}
	if !errors.Is(err, ErrManifestRootSignature) {
		t.Errorf("error %v does not wrap ErrManifestRootSignature", err)
	}
}

func TestLoadTrustManifest_NetworkError_AllowStale(t *testing.T) {
	priv := withTestRoot(t)
	body := minimalManifestBody(t)
	signed := buildSignedManifestBytes(t, priv, body)
	srv := runServer(t, signed, http.StatusOK)

	// Warm the cache.
	if _, err := LoadTrustManifest(context.Background(),
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithCacheTTL(0),
	); err != nil {
		t.Fatalf("warm: %v", err)
	}

	// Now kill the server and use AllowStale.
	srv.Close()
	m, err := LoadTrustManifest(context.Background(),
		WithBaseURL(srv.URL), // dead URL
		WithHTTPClient(&http.Client{Timeout: 50 * time.Millisecond}),
		WithCacheTTL(0),
		WithAllowStale(true),
	)
	if err != nil {
		t.Fatalf("AllowStale path should succeed with cached: %v", err)
	}
	if m == nil || m.Version != 7 {
		t.Errorf("expected cached manifest, got %v", m)
	}
}

func TestLoadTrustManifest_NetworkError_StrictFail(t *testing.T) {
	withTestRoot(t)
	ClearTrustManifestCache()
	// Point at a dead server.
	_, err := LoadTrustManifest(context.Background(),
		WithBaseURL("http://127.0.0.1:1"), // closed port
		WithHTTPClient(&http.Client{Timeout: 50 * time.Millisecond}),
		WithCacheTTL(0),
		// AllowStale not set → strict
	)
	if err == nil {
		t.Fatal("expected network error, got nil")
	}
	if !errors.Is(err, ErrManifestUnavailable) {
		t.Errorf("error %v does not wrap ErrManifestUnavailable", err)
	}
}

func TestLoadTrustManifest_OfflineOnly_NoCache_Errors(t *testing.T) {
	withTestRoot(t)
	ClearTrustManifestCache()
	_, err := LoadTrustManifest(context.Background(), WithOfflineOnly(true))
	if !errors.Is(err, ErrOfflineOnly) {
		t.Errorf("error %v does not wrap ErrOfflineOnly", err)
	}
}

func TestLoadTrustManifest_OfflineOnly_WithCache_ReturnsIt(t *testing.T) {
	priv := withTestRoot(t)
	body := minimalManifestBody(t)
	signed := buildSignedManifestBytes(t, priv, body)
	srv := runServer(t, signed, http.StatusOK)
	defer srv.Close()

	// Warm cache.
	if _, err := LoadTrustManifest(context.Background(),
		WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithCacheTTL(0),
	); err != nil {
		t.Fatalf("warm: %v", err)
	}
	// Offline call should return cached without touching network.
	m, err := LoadTrustManifest(context.Background(), WithOfflineOnly(true))
	if err != nil {
		t.Fatalf("offline-with-cache: %v", err)
	}
	if m.Version != 7 {
		t.Errorf("version = %d", m.Version)
	}
}

func TestLoadTrustManifest_CacheTTL_AvoidsRefetch(t *testing.T) {
	priv := withTestRoot(t)
	body := minimalManifestBody(t)
	signed := buildSignedManifestBytes(t, priv, body)

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(signed)
	}))
	defer srv.Close()

	ClearTrustManifestCache()
	for i := 0; i < 5; i++ {
		if _, err := LoadTrustManifest(context.Background(),
			WithBaseURL(srv.URL),
			WithHTTPClient(srv.Client()),
			WithCacheTTL(1*time.Hour),
		); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("server hit %d times, want 1 (TTL should have served cache for iters 2-5)", got)
	}
}

func TestLoadTrustManifest_PlaceholderRoot_Refuses(t *testing.T) {
	saved := TrustRootPublicKey
	defer func() { TrustRootPublicKey = saved }()
	TrustRootPublicKey = make([]byte, MLDSA65PublicKeySize) // all-zero placeholder

	_, err := LoadTrustManifest(context.Background(),
		WithBaseURL("http://does-not-matter"),
		WithCacheTTL(0),
	)
	if !errors.Is(err, ErrTrustRootPlaceholder) {
		t.Errorf("error %v does not wrap ErrTrustRootPlaceholder", err)
	}
}

func TestLoadTrustManifest_Non200_Errors(t *testing.T) {
	withTestRoot(t)
	ClearTrustManifestCache()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":"trust_manifest_unavailable"}`)
	}))
	defer srv.Close()

	_, err := LoadTrustManifest(context.Background(),
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithCacheTTL(0),
	)
	if !errors.Is(err, ErrManifestUnavailable) {
		t.Errorf("error %v does not wrap ErrManifestUnavailable", err)
	}
}

func TestLoadTrustManifest_MalformedBody_Errors(t *testing.T) {
	withTestRoot(t)
	ClearTrustManifestCache()
	srv := runServer(t, []byte("not json"), http.StatusOK)
	defer srv.Close()

	_, err := LoadTrustManifest(context.Background(),
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithCacheTTL(0),
	)
	if !errors.Is(err, ErrManifestMalformed) {
		t.Errorf("error %v does not wrap ErrManifestMalformed", err)
	}
}

func TestLoadTrustManifest_MissingSignature_Errors(t *testing.T) {
	withTestRoot(t)
	ClearTrustManifestCache()
	body := minimalManifestBody(t)
	// Don't sign — just emit bare JSON.
	raw, _ := json.Marshal(body)
	srv := runServer(t, raw, http.StatusOK)
	defer srv.Close()

	_, err := LoadTrustManifest(context.Background(),
		WithBaseURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithCacheTTL(0),
	)
	if !errors.Is(err, ErrManifestMalformed) {
		t.Errorf("error %v does not wrap ErrManifestMalformed (got %v)", err, err)
	}
}

// Sanity check: canonical JSON output must match the internal Go
// loader's emission byte-for-byte for a few representative inputs.
// This protects against drift between the two canonicalJSON copies.
func TestCanonicalJSON_StableShape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", `{}`, `{}`},
		{"single_string", `{"a":"b"}`, `{"a":"b"}`},
		{"sorted_keys", `{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{"nested_sort", `{"b":{"y":1,"x":2},"a":null}`, `{"a":null,"b":{"x":2,"y":1}}`},
		{"array_preserves_order", `{"k":[3,1,2]}`, `{"k":[3,1,2]}`},
		{"bools_and_null", `{"t":true,"f":false,"n":null}`, `{"f":false,"n":null,"t":true}`},
		// Non-ASCII should NOT be \u-escaped.
		{"utf8_inline", `{"k":"héllo"}`, `{"k":"héllo"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := json.NewDecoder(bytes.NewReader([]byte(tc.in)))
			dec.UseNumber()
			var v any
			if err := dec.Decode(&v); err != nil {
				t.Fatalf("decode: %v", err)
			}
			got, err := canonicalJSON(v)
			if err != nil {
				t.Fatalf("canonical: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTrustRoot_ActiveEnvNotEmpty(t *testing.T) {
	// Tag-agnostic invariant. Per-tag value asserted in
	// trust_root_buildtag_{dev,staging,prod}_test.go.
	if ActiveTrustEnv == "" {
		t.Fatal("ActiveTrustEnv is empty — no trust_root_*.go init() ran")
	}
	if len(TrustRootPublicKey) != MLDSA65PublicKeySize {
		t.Errorf("TrustRootPublicKey len = %d, want %d",
			len(TrustRootPublicKey), MLDSA65PublicKeySize)
	}
}

func TestIsTrustRootPlaceholder_DetectsZeroBytes(t *testing.T) {
	saved := TrustRootPublicKey
	defer func() { TrustRootPublicKey = saved }()

	TrustRootPublicKey = make([]byte, MLDSA65PublicKeySize)
	if !IsTrustRootPlaceholder() {
		t.Error("expected true for all-zero")
	}
	TrustRootPublicKey[0] = 1
	if IsTrustRootPlaceholder() {
		t.Error("expected false when non-zero byte present")
	}
}

// Ensure unused stdlib imports stay used as the file evolves.
var _ = fmt.Sprintf
