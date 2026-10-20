// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	ErrNetwork       = errors.New("network")
	ErrAPIAuth       = errors.New("api auth")
	ErrAPIKeyMissing = errors.New("api key missing")
)

const idempotencyBucketDuration = 5 * time.Minute

// DisclosureEmitRequest matches the proprietary build's input
// contract byte-for-byte at the wire layer.
type DisclosureEmitRequest struct {
	Endpoint           string
	APIKey             string
	BundleID           string
	Fingerprint        string
	UnsealedRowCount   int
	ResealMode         bool
	AuditorFingerprint string
	UnsealedAtMs       int64
	Now                func() time.Time
	HTTPClient         *http.Client
}

type DisclosureEmitResult struct {
	ChainEntryID   string
	IdempotencySig string
}

type disclosureRequest struct {
	EventType                      string `json:"event_type,omitempty"`
	BundleID                       string `json:"bundle_id"`
	DisclosureRequestSignatureHash string `json:"disclosure_request_signature_hash"`
	UnsealedRowCount               int    `json:"unsealed_row_count"`
	UnsealedAtMs                   int64  `json:"unsealed_at_ms"`
	SDKVersion                     string `json:"sdk_version"`
	SDKLanguage                    string `json:"sdk_language"`
	AuditorPubkeyFingerprint       string `json:"auditor_pubkey_fingerprint,omitempty"`
}

// Wire-level event-type discriminators. MUST match the proprietary
// build's constants byte-for-byte (cross-compat-tested).
const (
	eventTypeTier2ResealedForAuditor = "tier2_resealed_for_auditor"
)

type disclosureResponse struct {
	ChainEntryID string `json:"chain_entry_id"`
}

// EmitDisclosureEvent POSTs the disclosure event to audit-api. Body
// shape + idempotency hash are byte-identical to the proprietary
// build (golden vector test in test/cross_compat/ guards drift).
func EmitDisclosureEvent(ctx context.Context, req DisclosureEmitRequest) (*DisclosureEmitResult, error) {
	if req.Endpoint == "" {
		return nil, fmt.Errorf("%w: endpoint is empty", ErrNetwork)
	}
	if req.APIKey == "" {
		return nil, ErrAPIKeyMissing
	}
	if req.BundleID == "" {
		return nil, fmt.Errorf("%w: bundle_id is empty", ErrNetwork)
	}
	if req.Fingerprint == "" {
		return nil, fmt.Errorf("%w: fingerprint is empty", ErrNetwork)
	}
	if req.ResealMode && req.AuditorFingerprint == "" {
		return nil, fmt.Errorf("%w: reseal mode requires auditor_fingerprint", ErrNetwork)
	}
	if req.UnsealedAtMs <= 0 {
		return nil, fmt.Errorf("%w: unsealed_at_ms must be > 0 (audit-api validator requires it)", ErrNetwork)
	}
	if strings.ContainsRune(req.BundleID, '|') ||
		strings.ContainsRune(req.Fingerprint, '|') ||
		strings.ContainsRune(req.AuditorFingerprint, '|') {
		return nil, fmt.Errorf("%w: '|' is not permitted in bundle_id / fingerprint / auditor_fingerprint", ErrNetwork)
	}
	now := req.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	client := req.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	var idempSig string
	body := disclosureRequest{
		BundleID:         req.BundleID,
		UnsealedRowCount: req.UnsealedRowCount,
		UnsealedAtMs:     req.UnsealedAtMs,
		SDKVersion:       sdkVersion,
		SDKLanguage:      "go",
	}
	if req.ResealMode {
		idempSig = ResealIdempotencyHash(req.BundleID, req.Fingerprint, req.AuditorFingerprint, now())
		body.EventType = eventTypeTier2ResealedForAuditor
		body.AuditorPubkeyFingerprint = req.AuditorFingerprint
	} else {
		idempSig = DisclosureIdempotencyHash(req.BundleID, req.Fingerprint, now())
	}
	body.DisclosureRequestSignatureHash = idempSig
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal request: %v", ErrNetwork, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		req.Endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrNetwork, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+req.APIKey)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: POST %s: %v", ErrNetwork, req.Endpoint, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	switch {
	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%w: %d from audit-api", ErrAPIAuth, resp.StatusCode)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		excerpt := strings.TrimSpace(string(respBody))
		if len(excerpt) > 200 {
			excerpt = excerpt[:200] + "…"
		}
		return nil, fmt.Errorf("%w: HTTP %d from audit-api: %s",
			ErrNetwork, resp.StatusCode, excerpt)
	}

	var parsed disclosureResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("%w: parse response: %v", ErrNetwork, err)
	}
	if parsed.ChainEntryID == "" {
		return nil, fmt.Errorf("%w: audit-api returned empty chain_entry_id", ErrNetwork)
	}

	return &DisclosureEmitResult{
		ChainEntryID:   parsed.ChainEntryID,
		IdempotencySig: idempSig,
	}, nil
}

// DisclosureIdempotencyHash computes the same 5-minute idempotency
// hash as the proprietary build. Cross-compat test in
// test/cross_compat/sarenvelope_cross_compat_test.go asserts
// byte-identity.
func DisclosureIdempotencyHash(bundleID, fingerprint string, now time.Time) string {
	bucketMs := now.UTC().Truncate(idempotencyBucketDuration).UnixMilli()
	input := fmt.Sprintf("%s|%s|%d", bundleID, fingerprint, bucketMs)
	h := sha512.Sum512([]byte(input))
	// Full 128-char SHA-512 hex; matches audit-api's 128-char
	// validator in tier2_disclosure_handler.go. Aligned 2026-06-08
	// during the H follow-up.
	return hex.EncodeToString(h[:])
}

// ResealIdempotencyHash matches the proprietary build's reseal
// idempotency-hash format byte-for-byte
// (compliance_tier2_30d_followup_distinct_chain_event). Cross-compat
// test confirms identity.
func ResealIdempotencyHash(bundleID, customerFingerprint, auditorFingerprint string, now time.Time) string {
	bucketMs := now.UTC().Truncate(idempotencyBucketDuration).UnixMilli()
	input := fmt.Sprintf("%s|%s|%s|%d|reseal",
		bundleID, customerFingerprint, auditorFingerprint, bucketMs)
	h := sha512.Sum512([]byte(input))
	return hex.EncodeToString(h[:])
}

// ResolveAPIKey accepts "env:VAR" / "file:PATH" / literal — same
// spec as the proprietary build.
func ResolveAPIKey(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", ErrAPIKeyMissing
	}
	switch {
	case strings.HasPrefix(spec, "env:"):
		v := os.Getenv(strings.TrimPrefix(spec, "env:"))
		if v == "" {
			return "", fmt.Errorf("%w: env var %q is empty",
				ErrAPIKeyMissing, strings.TrimPrefix(spec, "env:"))
		}
		return v, nil
	case strings.HasPrefix(spec, "file:"):
		path := strings.TrimPrefix(spec, "file:")
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("%w: read api key file %q: %v",
				ErrAPIKeyMissing, path, err)
		}
		return strings.TrimSpace(string(b)), nil
	default:
		return strings.TrimSpace(spec), nil
	}
}

// sdkVersion is the version string emitted in the disclosure event
// payload. Stamped by build tooling in releases; this value is the
// development default.
const sdkVersion = "0.1.0-sdk-phaseC"
