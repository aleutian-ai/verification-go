// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"errors"
	"fmt"
)

// =============================================================================
// Anchor Verification Errors
// =============================================================================

var (
	// ErrInvalidSignature is returned when an anchor's ML-DSA-65 signature does not verify.
	ErrInvalidSignature = errors.New("verification: invalid signature")

	// ErrUnknownKeyID is returned when the public key ID in an anchor is not
	// found in the embedded key set.
	ErrUnknownKeyID = errors.New("verification: unknown public key ID")
)

// =============================================================================
// Chain Verification Errors
// =============================================================================

var (
	// ErrEmptyEntries is returned when chain verification is attempted with
	// an empty entries slice.
	ErrEmptyEntries = errors.New("verification: entries cannot be empty")
)

// =============================================================================
// Webhook Verification Errors
// =============================================================================

// WebhookSignatureError is returned when webhook signature verification fails.
// Use errors.Is() to check for specific error codes.
//
// # Example
//
//	if errors.Is(err, verification.ErrWebhookExpired) {
//	    // Handle expired signature
//	}
type WebhookSignatureError struct {
	Code    string
	Message string
}

// Error implements the error interface.
func (e *WebhookSignatureError) Error() string {
	return fmt.Sprintf("webhook signature error [%s]: %s", e.Code, e.Message)
}

// Is implements errors.Is for comparing error codes.
// Usage: errors.Is(err, ErrWebhookExpired)
func (e *WebhookSignatureError) Is(target error) bool {
	t, ok := target.(*WebhookSignatureError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// Webhook signature error codes.
// Use errors.Is(err, ErrWebhookExpired) for reliable checking.
var (
	// ErrWebhookInvalidFormat is returned when the signature header format is invalid.
	ErrWebhookInvalidFormat = &WebhookSignatureError{
		Code:    "INVALID_FORMAT",
		Message: "signature header format invalid",
	}

	// ErrWebhookInvalidTimestamp is returned when the timestamp cannot be parsed.
	ErrWebhookInvalidTimestamp = &WebhookSignatureError{
		Code:    "INVALID_TIMESTAMP",
		Message: "timestamp is not a valid integer",
	}

	// ErrWebhookExpired is returned when the signature timestamp is too old.
	ErrWebhookExpired = &WebhookSignatureError{
		Code:    "EXPIRED",
		Message: "signature timestamp too old",
	}

	// ErrWebhookFuture is returned when the signature timestamp is too far in the future.
	ErrWebhookFuture = &WebhookSignatureError{
		Code:    "FUTURE",
		Message: "signature timestamp too far in future",
	}

	// ErrWebhookInvalidSignature is returned when the HMAC signature does not match.
	ErrWebhookInvalidSignature = &WebhookSignatureError{
		Code:    "INVALID_SIGNATURE",
		Message: "signature does not match",
	}

	// ErrWebhookNoMatchingSecret is returned when none of the provided secrets
	// produce a valid signature (for multi-secret rotation scenarios).
	ErrWebhookNoMatchingSecret = &WebhookSignatureError{
		Code:    "NO_MATCHING_SECRET",
		Message: "no secret produced a valid signature",
	}

	// ErrWebhookSecretTooShort is returned when the secret is not exactly 32 bytes.
	ErrWebhookSecretTooShort = &WebhookSignatureError{
		Code:    "SECRET_TOO_SHORT",
		Message: "secret must be exactly 32 bytes",
	}
)
