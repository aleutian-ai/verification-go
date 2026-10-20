// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// Constants
// =============================================================================

const (
	// WebhookSignatureHeader is the HTTP header containing the signature.
	WebhookSignatureHeader = "X-Aleutian-Signature"

	// WebhookSignatureVersion is the current signature version.
	WebhookSignatureVersion = "v1"

	// WebhookDefaultTolerancePast is the maximum age of a valid signature.
	WebhookDefaultTolerancePast = 5 * time.Minute

	// WebhookDefaultToleranceFuture is the maximum future drift allowed.
	WebhookDefaultToleranceFuture = 30 * time.Second

	// webhookSecretLength is the required length of webhook secrets (32 bytes = 256 bits).
	webhookSecretLength = 32

	// maxSecretsForRotation is the maximum number of secrets allowed for rotation.
	maxSecretsForRotation = 10

	// maxTimestampYears is the maximum years in the future for timestamp validation.
	maxTimestampYears = 100
)

// =============================================================================
// Simple API (Recommended for most users)
// =============================================================================

// IsValidWebhook checks if a webhook request is valid.
//
// # Description
//
// This is the RECOMMENDED function for most users. It automatically:
//   - Extracts the signature header from the request
//   - Gets the raw body bytes
//   - Decodes your secret (accepts base64 or hex from dashboard)
//   - Verifies the signature with replay protection
//   - Returns false for any error (expired, invalid, etc.)
//
// NOTE: The request body is consumed and then restored for subsequent reads.
//
// # Inputs
//
//   - ctx: Context for cancellation (reserved for future use)
//   - r: The HTTP request to verify
//   - secret: The webhook secret (base64 or hex from dashboard)
//
// # Outputs
//
//   - bool: true if the webhook is valid
//
// # Example
//
//	func handleWebhook(w http.ResponseWriter, r *http.Request) {
//	    if !verification.IsValidWebhook(r.Context(), r, os.Getenv("WEBHOOK_SECRET")) {
//	        http.Error(w, "Invalid webhook", http.StatusUnauthorized)
//	        return
//	    }
//	    // Process verified webhook...
//	}
//
// # Limitations
//
//   - Only catches WebhookSignatureError; programming errors propagate as panics
//   - Uses default tolerance values (5 min past, 30 sec future)
func IsValidWebhook(ctx context.Context, r *http.Request, secret string) bool {
	// Read the body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	// Restore body for subsequent reads
	r.Body = io.NopCloser(bytes.NewReader(body))

	header := r.Header.Get(WebhookSignatureHeader)
	if header == "" {
		return false
	}

	secretBytes, err := DecodeSecret(secret)
	if err != nil {
		return false
	}

	err = VerifyWebhookSignature(ctx, header, body, secretBytes, DefaultWebhookVerifyOptions())
	if err != nil {
		// Only suppress expected verification errors
		var sigErr *WebhookSignatureError
		if errors.As(err, &sigErr) {
			return false
		}
		// Unexpected error - still return false
		return false
	}
	return true
}

// DecodeSecret auto-detects and decodes secret from dashboard (base64 or hex).
//
// # Description
//
// Accepts:
//   - Base64: Standard base64 that decodes to exactly 32 bytes
//   - Hex: 64 hex characters (decodes to 32 bytes)
//
// Copy-paste the secret exactly as shown in your Aleutian dashboard.
// The secret MUST decode to exactly 32 bytes (256 bits) for HMAC-SHA-512 security.
//
// # Inputs
//
//   - secret: The secret string from the dashboard
//
// # Outputs
//
//   - []byte: 32-byte decoded secret
//   - error: Non-nil if secret cannot be decoded to 32 bytes
//
// # Example
//
//	secretBytes, err := verification.DecodeSecret(os.Getenv("WEBHOOK_SECRET"))
//	if err != nil {
//	    log.Fatalf("invalid secret: %v", err)
//	}
func DecodeSecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)

	// Try base64 first
	if decoded, err := base64.StdEncoding.DecodeString(secret); err == nil {
		if len(decoded) == webhookSecretLength {
			return decoded, nil
		}
	}

	// Try hex (64 chars for 32 bytes)
	if decoded, err := hex.DecodeString(secret); err == nil {
		if len(decoded) == webhookSecretLength {
			return decoded, nil
		}
	}

	return nil, fmt.Errorf(
		"invalid webhook secret: must decode to exactly 32 bytes; " +
			"copy the exact secret from your Aleutian dashboard (Settings > Webhooks > Show Secret)",
	)
}

// =============================================================================
// Advanced API
// =============================================================================

// VerifyWebhookSignature verifies a webhook signature with a single secret.
//
// # Description
//
// Verifies that the webhook payload was signed by Aleutian using the
// customer's endpoint secret. Includes replay protection via timestamp
// validation.
//
// # Inputs
//
//   - ctx: Context for cancellation (reserved for future use)
//   - signatureHeader: Value of X-Aleutian-Signature header
//   - payload: Raw HTTP request body bytes (do NOT parse/re-serialize)
//   - secret: 256-bit webhook secret (exactly 32 bytes)
//   - opts: Verification options
//
// # Outputs
//
//   - error: nil if valid, WebhookSignatureError otherwise
//
// # Security Considerations
//
//   - CRITICAL: Use raw HTTP body bytes, NOT parsed/re-serialized JSON
//   - CRITICAL: Signature comparison is constant-time (crypto/hmac.Equal)
//   - CRITICAL: Secret must be exactly 32 bytes for HMAC-SHA-512 security
//
// # Example
//
//	func handleWebhook(w http.ResponseWriter, r *http.Request) {
//	    body, _ := io.ReadAll(r.Body)
//	    sig := r.Header.Get("X-Aleutian-Signature")
//
//	    err := verification.VerifyWebhookSignature(
//	        r.Context(),
//	        sig, body,
//	        []byte(os.Getenv("WEBHOOK_SECRET")),
//	        verification.DefaultWebhookVerifyOptions(),
//	    )
//	    if err != nil {
//	        http.Error(w, "Invalid signature", http.StatusUnauthorized)
//	        return
//	    }
//	    // Process verified webhook...
//	}
func VerifyWebhookSignature(ctx context.Context, signatureHeader string, payload, secret []byte, opts WebhookVerifyOptions) error {
	// Validate secret length (M-1)
	if len(secret) != webhookSecretLength {
		return ErrWebhookSecretTooShort
	}

	// Parse signature header with constant-time pattern (H-1)
	parts, err := parseWebhookSignature(signatureHeader)
	if err != nil {
		return err
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	// Validate timestamp bounds (L-3: reject absurd timestamps)
	maxFutureTime := now.Add(maxTimestampYears * 365 * 24 * time.Hour)
	sigTime := time.Unix(parts.Timestamp, 0)
	if sigTime.After(maxFutureTime) || parts.Timestamp < 0 {
		return ErrWebhookInvalidTimestamp
	}

	// Validate timestamp (replay protection)
	age := now.Sub(sigTime)

	tolerancePast := opts.TolerancePast
	if tolerancePast == 0 {
		tolerancePast = WebhookDefaultTolerancePast
	}
	toleranceFuture := opts.ToleranceFuture
	if toleranceFuture == 0 {
		toleranceFuture = WebhookDefaultToleranceFuture
	}

	// Skip tolerance checks if set to -1
	if tolerancePast > 0 && age > tolerancePast {
		return ErrWebhookExpired
	}
	if toleranceFuture > 0 && age < -toleranceFuture {
		return ErrWebhookFuture
	}

	// Compute expected signature
	expectedSig := computeWebhookSignatureHex(secret, parts.Timestamp, payload)

	// Constant-time comparison (CRITICAL for security)
	if !hmac.Equal([]byte(parts.Signature), []byte(expectedSig)) {
		return ErrWebhookInvalidSignature
	}

	return nil
}

// VerifyWebhookWithSecrets verifies with multiple secrets (for rotation).
//
// # Description
//
// During secret rotation, both old and new secrets may be valid.
// Returns the index of the matching secret, or -1 if none matched.
//
// SECURITY (H-5): Verifies against ALL secrets to prevent timing side-channel
// that would reveal which secret position matched.
//
// # Inputs
//
//   - ctx: Context for cancellation (reserved for future use)
//   - signatureHeader: Value of X-Aleutian-Signature header
//   - payload: Raw HTTP request body bytes
//   - secrets: List of 32-byte secrets to try (new secret first)
//   - opts: Verification options
//
// # Outputs
//
//   - int: Index of the matching secret, or -1 if none matched
//   - error: nil if valid, WebhookSignatureError otherwise
//
// # Example
//
//	secrets := [][]byte{
//	    []byte(os.Getenv("WEBHOOK_SECRET_NEW")),
//	    []byte(os.Getenv("WEBHOOK_SECRET_OLD")),
//	}
//	idx, err := verification.VerifyWebhookWithSecrets(ctx, sig, body, secrets, opts)
//	if err != nil {
//	    // Handle error
//	}
//	if idx == 1 {
//	    log.Println("Warning: matched old secret, rotation may be incomplete")
//	}
func VerifyWebhookWithSecrets(ctx context.Context, signatureHeader string, payload []byte, secrets [][]byte, opts WebhookVerifyOptions) (int, error) {
	if len(secrets) == 0 {
		return -1, ErrWebhookNoMatchingSecret
	}
	if len(secrets) > maxSecretsForRotation {
		return -1, fmt.Errorf("too many secrets: maximum %d, got %d", maxSecretsForRotation, len(secrets))
	}

	// Validate all secret lengths (M-1)
	for i, secret := range secrets {
		if len(secret) != webhookSecretLength {
			return -1, fmt.Errorf("secret at index %d: %w", i, ErrWebhookSecretTooShort)
		}
	}

	// Parse signature header
	parts, err := parseWebhookSignature(signatureHeader)
	if err != nil {
		return -1, err
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	// Validate timestamp bounds (L-3)
	maxFutureTime := now.Add(maxTimestampYears * 365 * 24 * time.Hour)
	sigTime := time.Unix(parts.Timestamp, 0)
	if sigTime.After(maxFutureTime) || parts.Timestamp < 0 {
		return -1, ErrWebhookInvalidTimestamp
	}

	// Validate timestamp
	age := now.Sub(sigTime)

	tolerancePast := opts.TolerancePast
	if tolerancePast == 0 {
		tolerancePast = WebhookDefaultTolerancePast
	}
	toleranceFuture := opts.ToleranceFuture
	if toleranceFuture == 0 {
		toleranceFuture = WebhookDefaultToleranceFuture
	}

	if tolerancePast > 0 && age > tolerancePast {
		return -1, ErrWebhookExpired
	}
	if toleranceFuture > 0 && age < -toleranceFuture {
		return -1, ErrWebhookFuture
	}

	// H-5: Verify ALL secrets to prevent timing side-channel.
	// Do NOT early-return on match.
	matchedIdx := -1
	for i, secret := range secrets {
		expectedSig := computeWebhookSignatureHex(secret, parts.Timestamp, payload)
		if hmac.Equal([]byte(parts.Signature), []byte(expectedSig)) {
			if matchedIdx < 0 {
				matchedIdx = i
			}
			// Continue checking remaining secrets to ensure constant time
		}
	}

	if matchedIdx < 0 {
		return -1, ErrWebhookNoMatchingSecret
	}
	return matchedIdx, nil
}

// ComputeWebhookSignature computes a webhook signature header (for testing).
//
// # Description
//
// Returns the full signature header value in the format: "t={ts},v1={hex}"
//
// This function is primarily intended for testing purposes. Production
// webhook signing is performed by Aleutian's servers.
//
// # Inputs
//
//   - secret: 32-byte webhook secret
//   - timestamp: Unix timestamp in seconds
//   - payload: Raw payload bytes
//
// # Outputs
//
//   - string: Full signature header value
//
// # Example
//
//	sig := verification.ComputeWebhookSignature(secret, time.Now().Unix(), payload)
//	// Returns: "t=1706097600,v1=a1b2c3d4..."
func ComputeWebhookSignature(secret []byte, timestamp int64, payload []byte) string {
	sig := computeWebhookSignatureHex(secret, timestamp, payload)
	return fmt.Sprintf("t=%d,%s=%s", timestamp, WebhookSignatureVersion, sig)
}

// =============================================================================
// Internal Functions
// =============================================================================

// computeWebhookSignatureHex computes just the hex signature portion.
func computeWebhookSignatureHex(secret []byte, timestamp int64, payload []byte) string {
	// Build signed payload: "{timestamp}.{payload}"
	tsStr := strconv.FormatInt(timestamp, 10)
	signedPayload := tsStr + "." + string(payload)

	mac := hmac.New(sha512.New, secret)
	mac.Write([]byte(signedPayload))
	return hex.EncodeToString(mac.Sum(nil))
}

// webhookSignatureParts contains the parsed components of a signature header.
type webhookSignatureParts struct {
	Timestamp int64
	Version   string
	Signature string
}

// parseWebhookSignature parses the signature header.
// H-1: Uses constant-time pattern - always performs full parse before returning errors.
// L-1: Error messages do not echo user-controlled input.
func parseWebhookSignature(header string) (webhookSignatureParts, error) {
	var parts webhookSignatureParts
	var parseErr error

	// Parse all fields before returning any error (constant-time pattern)
	segments := strings.Split(header, ",")
	segmentCountValid := len(segments) == 2

	var tsStr string
	var ts int64
	var tsErr error
	if segmentCountValid && strings.HasPrefix(segments[0], "t=") {
		tsStr = strings.TrimPrefix(segments[0], "t=")
		ts, tsErr = strconv.ParseInt(tsStr, 10, 64)
	}

	var version, signature string
	var versionValid, sigLenValid, sigHexValid bool
	if segmentCountValid && len(segments) > 1 {
		versionSig := segments[1]
		eqIdx := strings.Index(versionSig, "=")
		if eqIdx > 0 {
			version = versionSig[:eqIdx]
			signature = versionSig[eqIdx+1:]
			versionValid = version == WebhookSignatureVersion
			// 128 hex chars = 64-byte HMAC-SHA-512 output (cf.
			// computeWebhookSignatureHex below). Was 64 (SHA-256) before
			// the project-wide SHA-256 → SHA-512 upgrade; the producer
			// was upgraded but this parser check was missed — see
			// tickets/code_complete/dsar_triage_integration_e2e_1.md.
			sigLenValid = len(signature) == 128
			if sigLenValid {
				_, hexErr := hex.DecodeString(signature)
				sigHexValid = hexErr == nil
			}
		}
	}

	// Now determine the error (if any) - always after full parsing
	if !segmentCountValid {
		parseErr = ErrWebhookInvalidFormat
	} else if !strings.HasPrefix(segments[0], "t=") {
		parseErr = ErrWebhookInvalidFormat
	} else if tsErr != nil {
		parseErr = ErrWebhookInvalidTimestamp
	} else if !versionValid {
		// L-1: Don't echo user-controlled version string
		parseErr = ErrWebhookInvalidFormat
	} else if !sigLenValid || !sigHexValid {
		parseErr = ErrWebhookInvalidFormat
	}

	if parseErr != nil {
		return parts, parseErr
	}

	parts.Timestamp = ts
	parts.Version = version
	parts.Signature = signature
	return parts, nil
}
