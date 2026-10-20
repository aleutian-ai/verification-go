// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test vectors from internal/webhook/webhook_signer.go.
// Rebaked 2026-05-16 under SHA-512 (project_crypto_upgrade) — signatures
// are 128 hex chars (HMAC-SHA-512 output). Track:
// tickets/code_complete/dsar_triage_integration_e2e_1.md
var webhookTestVectors = []struct {
	name              string
	secretHex         string
	timestamp         int64
	payload           string
	expectedSignature string
}{
	{
		name:              "basic_empty_data",
		secretHex:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		timestamp:         1706097600,
		payload:           `{"id":"evt_01h5a2b3","type":"anchor.published","data":{}}`,
		expectedSignature: "t=1706097600,v1=9b050aec7ebcf5810395fd346e182af95a5750d61714f6dd0f5d03b00f1134b16da5bf77445cda2d5ce56bb0daa85675c7d8360d127056b892b5b481c07169f8",
	},
	{
		name:              "unicode_in_payload",
		secretHex:         "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		timestamp:         1706097601,
		payload:           `{"id":"evt_01h5a2b4","type":"anchor.published","data":{"note":"中文"}}`,
		expectedSignature: "t=1706097601,v1=282f5dc5df3244c3db51a9ee884502670af7809467af9822a623207ee524eb48cc2c02639c059631c2a2886cea98c10d49ccd6297bd818ce8cb9c6e8bb3ae23a",
	},
	{
		name:              "special_characters",
		secretHex:         "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		timestamp:         1706097602,
		payload:           `{"id":"evt_01h5a2b5","data":{"url":"https://example.com/?a=1&b=2"}}`,
		expectedSignature: "t=1706097602,v1=c5fa4bb559f9896df2d7cd065e94ee386b9e0b035d6fbcc95136eaa70796e215ab06adffb74a80b82abc86b9484c2d89764e8d345d85fa0fcc8009232ca02873",
	},
	{
		name:              "empty_object",
		secretHex:         "1111111111111111111111111111111111111111111111111111111111111111",
		timestamp:         1706097603,
		payload:           `{}`,
		expectedSignature: "t=1706097603,v1=69f32eb3e08a549b840af0f7a7e2696e4fa56f47681f99b67ac2ea0e7ced8eea68726828a99879fc1ad057de716a7f9417e8860be6b73cf45e4d6624f81b6b35",
	},
	{
		name:              "max_timestamp",
		secretHex:         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		timestamp:         9999999999,
		payload:           `{"id":"evt_max"}`,
		expectedSignature: "t=9999999999,v1=8f8eecc369783571254ea0dc05b4feab17cf8393eb8a8351dfb484194646217a91770e7e9dfe2b55befb84e02c27d08e400ba64dd28259b726c91dcad56fb4e6",
	},
}

func TestComputeWebhookSignature(t *testing.T) {
	for _, tv := range webhookTestVectors {
		t.Run(tv.name, func(t *testing.T) {
			secret, err := hex.DecodeString(tv.secretHex)
			if err != nil {
				t.Fatalf("failed to decode secret: %v", err)
			}

			sig := ComputeWebhookSignature(secret, tv.timestamp, []byte(tv.payload))
			if sig != tv.expectedSignature {
				t.Errorf("signature mismatch:\n  got:  %s\n  want: %s", sig, tv.expectedSignature)
			}
		})
	}
}

func TestVerifyWebhookSignature(t *testing.T) {
	ctx := context.Background()

	for _, tv := range webhookTestVectors {
		t.Run(tv.name, func(t *testing.T) {
			secret, _ := hex.DecodeString(tv.secretHex)

			// Override Now to match the test vector timestamp
			opts := WebhookVerifyOptions{
				Now: time.Unix(tv.timestamp, 0),
			}

			err := VerifyWebhookSignature(ctx, tv.expectedSignature, []byte(tv.payload), secret, opts)
			if err != nil {
				t.Errorf("verification failed: %v", err)
			}
		})
	}
}

func TestVerifyWebhookSignatureErrors(t *testing.T) {
	ctx := context.Background()
	secret, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	payload := []byte(`{"test": true}`)
	timestamp := int64(1706097600)
	validSig := ComputeWebhookSignature(secret, timestamp, payload)

	tests := []struct {
		name      string
		signature string
		payload   []byte
		secret    []byte
		opts      WebhookVerifyOptions
		wantErr   error
	}{
		{
			name:      "valid signature",
			signature: validSig,
			payload:   payload,
			secret:    secret,
			opts:      WebhookVerifyOptions{Now: time.Unix(timestamp, 0)},
			wantErr:   nil,
		},
		{
			name:      "expired signature",
			signature: validSig,
			payload:   payload,
			secret:    secret,
			opts:      WebhookVerifyOptions{Now: time.Unix(timestamp+400, 0)}, // 400 sec > 5 min
			wantErr:   ErrWebhookExpired,
		},
		{
			name:      "future signature",
			signature: validSig,
			payload:   payload,
			secret:    secret,
			opts:      WebhookVerifyOptions{Now: time.Unix(timestamp-60, 0)}, // 60 sec in future > 30 sec tolerance
			wantErr:   ErrWebhookFuture,
		},
		{
			name:      "invalid format - no comma",
			signature: "t=1234567890v1=abcd1234",
			payload:   payload,
			secret:    secret,
			opts:      WebhookVerifyOptions{Now: time.Unix(timestamp, 0)},
			wantErr:   ErrWebhookInvalidFormat,
		},
		{
			name:      "invalid format - wrong version",
			signature: "t=1234567890,v2=abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			payload:   payload,
			secret:    secret,
			opts:      WebhookVerifyOptions{Now: time.Unix(timestamp, 0)},
			wantErr:   ErrWebhookInvalidFormat,
		},
		{
			name:      "invalid timestamp",
			signature: "t=notanumber,v1=abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			payload:   payload,
			secret:    secret,
			opts:      WebhookVerifyOptions{Now: time.Unix(timestamp, 0)},
			wantErr:   ErrWebhookInvalidTimestamp,
		},
		{
			name:      "wrong signature",
			signature: "t=1706097600,v1=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			payload:   payload,
			secret:    secret,
			opts:      WebhookVerifyOptions{Now: time.Unix(1706097600, 0)},
			wantErr:   ErrWebhookInvalidSignature,
		},
		{
			name:      "secret too short",
			signature: validSig,
			payload:   payload,
			secret:    []byte("tooshort"),
			opts:      WebhookVerifyOptions{Now: time.Unix(timestamp, 0)},
			wantErr:   ErrWebhookSecretTooShort,
		},
		{
			name:      "tampered payload",
			signature: validSig,
			payload:   []byte(`{"test": false}`),
			secret:    secret,
			opts:      WebhookVerifyOptions{Now: time.Unix(timestamp, 0)},
			wantErr:   ErrWebhookInvalidSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyWebhookSignature(ctx, tt.signature, tt.payload, tt.secret, tt.opts)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestVerifyWebhookWithSecrets(t *testing.T) {
	ctx := context.Background()
	secret1, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	secret2, _ := hex.DecodeString("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	payload := []byte(`{"test": true}`)
	timestamp := int64(1706097600)

	// Sign with secret2
	sig := ComputeWebhookSignature(secret2, timestamp, payload)
	opts := WebhookVerifyOptions{Now: time.Unix(timestamp, 0)}

	t.Run("matches second secret", func(t *testing.T) {
		secrets := [][]byte{secret1, secret2}
		idx, err := VerifyWebhookWithSecrets(ctx, sig, payload, secrets, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if idx != 1 {
			t.Errorf("expected index 1, got %d", idx)
		}
	})

	t.Run("matches first secret", func(t *testing.T) {
		sig1 := ComputeWebhookSignature(secret1, timestamp, payload)
		secrets := [][]byte{secret1, secret2}
		idx, err := VerifyWebhookWithSecrets(ctx, sig1, payload, secrets, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if idx != 0 {
			t.Errorf("expected index 0, got %d", idx)
		}
	})

	t.Run("no matching secret", func(t *testing.T) {
		wrongSecret, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		wrongSig := ComputeWebhookSignature(wrongSecret, timestamp, payload)
		secrets := [][]byte{secret1, secret2}
		_, err := VerifyWebhookWithSecrets(ctx, wrongSig, payload, secrets, opts)
		if !errors.Is(err, ErrWebhookNoMatchingSecret) {
			t.Errorf("expected ErrWebhookNoMatchingSecret, got %v", err)
		}
	})

	t.Run("empty secrets list", func(t *testing.T) {
		_, err := VerifyWebhookWithSecrets(ctx, sig, payload, [][]byte{}, opts)
		if !errors.Is(err, ErrWebhookNoMatchingSecret) {
			t.Errorf("expected ErrWebhookNoMatchingSecret, got %v", err)
		}
	})

	t.Run("too many secrets", func(t *testing.T) {
		tooManySecrets := make([][]byte, 11)
		for i := range tooManySecrets {
			tooManySecrets[i] = secret1
		}
		_, err := VerifyWebhookWithSecrets(ctx, sig, payload, tooManySecrets, opts)
		if err == nil {
			t.Errorf("expected error for too many secrets")
		}
	})
}

func TestDecodeSecret(t *testing.T) {
	// Valid 32-byte secret in hex (64 chars)
	hexSecret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Valid 32-byte secret in base64
	expectedBytes, _ := hex.DecodeString(hexSecret)
	// base64Secret := base64.StdEncoding.EncodeToString(expectedBytes)

	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{
			name:    "valid hex",
			input:   hexSecret,
			wantLen: 32,
			wantErr: false,
		},
		{
			name:    "valid hex with whitespace",
			input:   "  " + hexSecret + "  ",
			wantLen: 32,
			wantErr: false,
		},
		{
			name:    "invalid - too short",
			input:   "0123456789abcdef",
			wantLen: 0,
			wantErr: true,
		},
		{
			name:    "invalid - not hex or base64",
			input:   "not-a-valid-secret!!!",
			wantLen: 0,
			wantErr: true,
		},
		{
			name:    "invalid - empty",
			input:   "",
			wantLen: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeSecret(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(result) != tt.wantLen {
					t.Errorf("expected length %d, got %d", tt.wantLen, len(result))
				}
				if tt.wantLen == 32 && !bytes.Equal(result, expectedBytes) {
					t.Errorf("decoded bytes don't match expected")
				}
			}
		})
	}
}

func TestIsValidWebhook(t *testing.T) {
	ctx := context.Background()
	secretHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	secret, _ := hex.DecodeString(secretHex)
	payload := []byte(`{"test": true}`)
	timestamp := time.Now().Unix()
	sig := ComputeWebhookSignature(secret, timestamp, payload)

	t.Run("valid webhook", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
		req.Header.Set(WebhookSignatureHeader, sig)

		valid := IsValidWebhook(ctx, req, secretHex)
		if !valid {
			t.Errorf("expected valid webhook")
		}

		// Verify body can still be read
		body, _ := io.ReadAll(req.Body)
		if !bytes.Equal(body, payload) {
			t.Errorf("body not restored after verification")
		}
	})

	t.Run("missing signature header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))

		valid := IsValidWebhook(ctx, req, secretHex)
		if valid {
			t.Errorf("expected invalid webhook (missing header)")
		}
	})

	t.Run("invalid secret", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
		req.Header.Set(WebhookSignatureHeader, sig)

		valid := IsValidWebhook(ctx, req, "invalid-secret")
		if valid {
			t.Errorf("expected invalid webhook (bad secret)")
		}
	})

	t.Run("tampered payload", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte(`{"test": false}`)))
		req.Header.Set(WebhookSignatureHeader, sig)

		valid := IsValidWebhook(ctx, req, secretHex)
		if valid {
			t.Errorf("expected invalid webhook (tampered)")
		}
	})
}

func TestWebhookSignatureErrorIs(t *testing.T) {
	err := ErrWebhookExpired

	if !errors.Is(err, ErrWebhookExpired) {
		t.Errorf("errors.Is(ErrWebhookExpired, ErrWebhookExpired) = false")
	}

	if errors.Is(err, ErrWebhookFuture) {
		t.Errorf("errors.Is(ErrWebhookExpired, ErrWebhookFuture) = true")
	}

	// Test wrapped error
	wrapped := &WebhookSignatureError{Code: "EXPIRED", Message: "different message"}
	if !errors.Is(wrapped, ErrWebhookExpired) {
		t.Errorf("errors.Is(wrapped, ErrWebhookExpired) = false")
	}
}

func TestTimestampBoundsValidation(t *testing.T) {
	ctx := context.Background()
	secret, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	payload := []byte(`{"test": true}`)

	t.Run("negative timestamp", func(t *testing.T) {
		sig := "t=-1,v1=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		err := VerifyWebhookSignature(ctx, sig, payload, secret, DefaultWebhookVerifyOptions())
		if !errors.Is(err, ErrWebhookInvalidTimestamp) {
			t.Errorf("expected ErrWebhookInvalidTimestamp for negative timestamp, got %v", err)
		}
	})

	t.Run("far future timestamp", func(t *testing.T) {
		// Timestamp 200 years in the future
		futureTs := time.Now().Add(200 * 365 * 24 * time.Hour).Unix()
		sig := ComputeWebhookSignature(secret, futureTs, payload)
		err := VerifyWebhookSignature(ctx, sig, payload, secret, DefaultWebhookVerifyOptions())
		if !errors.Is(err, ErrWebhookInvalidTimestamp) {
			t.Errorf("expected ErrWebhookInvalidTimestamp for far future timestamp, got %v", err)
		}
	})
}
