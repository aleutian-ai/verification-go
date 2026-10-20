// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"errors"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	// Verify sentinel errors are properly defined
	sentinelErrors := []error{
		ErrInvalidSignature,
		ErrUnknownKeyID,
		ErrEmptyEntries,
	}

	for _, err := range sentinelErrors {
		if err == nil {
			t.Errorf("sentinel error should not be nil")
		}
		if err.Error() == "" {
			t.Errorf("sentinel error message should not be empty")
		}
	}
}

func TestWebhookSignatureErrorIsMethod(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{
			name:   "same error",
			err:    ErrWebhookExpired,
			target: ErrWebhookExpired,
			want:   true,
		},
		{
			name:   "different webhook error",
			err:    ErrWebhookExpired,
			target: ErrWebhookFuture,
			want:   false,
		},
		{
			name:   "same code different message",
			err:    &WebhookSignatureError{Code: "EXPIRED", Message: "custom message"},
			target: ErrWebhookExpired,
			want:   true,
		},
		{
			name:   "against non-webhook error",
			err:    ErrWebhookExpired,
			target: ErrInvalidSignature,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errors.Is(tt.err, tt.target)
			if got != tt.want {
				t.Errorf("errors.Is(%v, %v) = %v, want %v", tt.err, tt.target, got, tt.want)
			}
		})
	}
}

func TestWebhookSignatureErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		err      *WebhookSignatureError
		contains string
	}{
		{
			name:     "expired",
			err:      ErrWebhookExpired,
			contains: "EXPIRED",
		},
		{
			name:     "future",
			err:      ErrWebhookFuture,
			contains: "FUTURE",
		},
		{
			name:     "invalid format",
			err:      ErrWebhookInvalidFormat,
			contains: "INVALID_FORMAT",
		},
		{
			name:     "invalid signature",
			err:      ErrWebhookInvalidSignature,
			contains: "INVALID_SIGNATURE",
		},
		{
			name:     "no matching secret",
			err:      ErrWebhookNoMatchingSecret,
			contains: "NO_MATCHING_SECRET",
		},
		{
			name:     "secret too short",
			err:      ErrWebhookSecretTooShort,
			contains: "SECRET_TOO_SHORT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if msg == "" {
				t.Errorf("error message should not be empty")
			}
			// Check that error code is in the message
			found := false
			for i := 0; i <= len(msg)-len(tt.contains); i++ {
				if msg[i:i+len(tt.contains)] == tt.contains {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("error message %q should contain %q", msg, tt.contains)
			}
		})
	}
}
