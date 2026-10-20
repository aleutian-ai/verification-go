// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package mldsa_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aleutian-ai/verification-go/mldsa"
)

// vectorFile mirrors the schema of sdk/testdata/mldsa_vectors.json.
type vectorFile struct {
	Version   string    `json:"version"`
	Generator string    `json:"generator"`
	Vectors   []vectorT `json:"vectors"`
}

type vectorT struct {
	ID           string `json:"id"`
	PublicKeyB64 string `json:"public_key_b64"`
	MessageB64   string `json:"message_b64"`
	SignatureB64 string `json:"signature_b64"`
	Expected     string `json:"expected"`
	Source       string `json:"source"`
	Reason       string `json:"reason,omitempty"`
}

// vectorsPath resolves the shared vector file relative to this test's
// location. The test runs from sdk/verification-go/mldsa, and the vectors
// live at sdk/testdata/mldsa_vectors.json; this module tests its own copy,
// ../testdata/shared/mldsa_vectors.json, so it passes outside the monorepo
// (scripts/publish-sdks.sh refuses a copy that differs).
func vectorsPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "testdata", "shared", "mldsa_vectors.json")
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile(vectorsPath(t))
	if err != nil {
		t.Fatalf("read vector file: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vector file: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatalf("vector file is empty")
	}
	return vf
}

// TestMLDSAVectors runs every vector in the shared KAT file through
// mldsa.Verify and asserts that the outcome matches the `expected` field.
// This is the cross-SDK parity gate's Go half.
func TestMLDSAVectors(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Vectors {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			pk, err := base64.StdEncoding.DecodeString(v.PublicKeyB64)
			if err != nil {
				t.Fatalf("decode public_key_b64: %v", err)
			}
			msg, err := base64.StdEncoding.DecodeString(v.MessageB64)
			if err != nil {
				t.Fatalf("decode message_b64: %v", err)
			}
			sig, err := base64.StdEncoding.DecodeString(v.SignatureB64)
			if err != nil {
				t.Fatalf("decode signature_b64: %v", err)
			}

			got := mldsa.Verify(pk, msg, sig)
			switch v.Expected {
			case "valid":
				if got != nil {
					t.Fatalf("expected valid, got error: %v", got)
				}
			case "invalid":
				if got == nil {
					t.Fatalf("expected invalid, got nil error (reason=%q)", v.Reason)
				}
			default:
				t.Fatalf("unknown expected value %q", v.Expected)
			}
		})
	}
}

// TestVerify_ErrorSentinels asserts the exact sentinel errors surface through
// the public API, so callers can branch with errors.Is. These conditions are
// not individually covered by the JSON vectors because they probe input
// validation rather than cryptographic outcomes.
func TestVerify_ErrorSentinels(t *testing.T) {
	// Load a known-valid vector to reuse its bytes.
	vf := loadVectors(t)
	var good vectorT
	for _, v := range vf.Vectors {
		if v.Expected == "valid" {
			good = v
			break
		}
	}
	if good.ID == "" {
		t.Fatal("no valid vector available to derive sentinel tests from")
	}
	pk, _ := base64.StdEncoding.DecodeString(good.PublicKeyB64)
	msg, _ := base64.StdEncoding.DecodeString(good.MessageB64)
	sig, _ := base64.StdEncoding.DecodeString(good.SignatureB64)

	t.Run("wrong public key length", func(t *testing.T) {
		err := mldsa.Verify(pk[:len(pk)-1], msg, sig)
		if !errors.Is(err, mldsa.ErrInvalidPublicKey) {
			t.Fatalf("want ErrInvalidPublicKey, got %v", err)
		}
	})

	t.Run("wrong signature length", func(t *testing.T) {
		err := mldsa.Verify(pk, msg, sig[:len(sig)-1])
		if !errors.Is(err, mldsa.ErrInvalidSignatureLength) {
			t.Fatalf("want ErrInvalidSignatureLength, got %v", err)
		}
	})

	t.Run("verification failure returns sentinel", func(t *testing.T) {
		// Flip a byte in the signature.
		bad := append([]byte{}, sig...)
		bad[0] ^= 0xFF
		err := mldsa.Verify(pk, msg, bad)
		if !errors.Is(err, mldsa.ErrSignatureVerificationFailed) {
			t.Fatalf("want ErrSignatureVerificationFailed, got %v", err)
		}
	})
}
