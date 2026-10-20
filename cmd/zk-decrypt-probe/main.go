// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0
//
// zk-decrypt-probe is a dev validation utility (throwaway, not shipped).
//
// It decrypts a raw ingest ".enc" zero-knowledge payload using the customer's
// X-Wing private seed, entirely through the PUBLIC verification SDK. This
// proves the zero-knowledge property end-to-end: Aleutian's own server returns
// ErrCannotDecrypt for these payloads (the data key is wrapped to the
// customer's public key), so only the holder of the private seed can recover
// the plaintext.
//
// The seed is read from STDIN so it never lands on disk or in argv:
//
//	op read "op://aleutian-xwing-keys/aleutian-xwing-duncan-dev-primary/privkey_pem" | \
//	  go run ./cmd/zk-decrypt-probe /path/to/payload.enc
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	verification "github.com/aleutian-ai/verification-go"
)

// encPayload mirrors the on-disk ingest envelope (internal/storage EncryptedPayload).
type encPayload struct {
	Version          int    `json:"version"`
	EncryptionMode   string `json:"encryption_mode"`
	CompanyID        string `json:"company_id"`
	EntryID          string `json:"entry_id"`
	KeyVersion       string `json:"key_version"`
	EncryptedDataKey string `json:"encrypted_data_key"`
	IV               string `json:"iv"`
	Ciphertext       string `json:"ciphertext"`
	AuthTag          string `json:"auth_tag"`
}

// buildAAD replicates internal/storage.buildAAD exactly. The GCM tag is bound
// to companyID+entryID; any deviation here yields an AEAD failure on Open.
func buildAAD(companyID, entryID string) []byte {
	buf := make([]byte, 0, 8+len(companyID)+len(entryID))
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(companyID)))
	buf = append(buf, companyID...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(entryID)))
	buf = append(buf, entryID...)
	return buf
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: op read \"op://.../privkey_pem\" | zk-decrypt-probe <payload.enc>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run(encPath string) error {
	// 1. Load the .enc payload.
	raw, err := os.ReadFile(encPath)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	var p encPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("parse payload JSON: %w", err)
	}
	if p.EncryptionMode != "zero-knowledge" {
		return fmt.Errorf("payload is not zero-knowledge mode (got %q)", p.EncryptionMode)
	}

	// 2. Read the X-Wing private seed PEM from stdin (never touches disk/argv).
	pemBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read seed from stdin: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("no PEM block on stdin — pipe `op read \"op://.../privkey_pem\" | ...`")
	}
	if len(block.Bytes) != 32 {
		return fmt.Errorf("seed length = %d, want 32 (passphrase-wrapped seeds unsupported here)", len(block.Bytes))
	}
	priv, err := verification.NewXWINGPrivateKey(block.Bytes) // zeroes block.Bytes
	if err != nil {
		return fmt.Errorf("construct private key: %w", err)
	}
	defer priv.Zeroize()

	// 3. KEM-unwrap the data key → 32-byte AES key. THIS is the step only the
	//    private-seed holder can perform; the server returns ErrCannotDecrypt.
	wrapped, err := base64.StdEncoding.DecodeString(p.EncryptedDataKey)
	if err != nil {
		return fmt.Errorf("decode encrypted_data_key: %w", err)
	}
	unwrapper := &verification.HybridKEMUnwrapper{}
	ss, err := unwrapper.Unwrap(context.Background(), wrapped, priv)
	if err != nil {
		return fmt.Errorf("KEM unwrap failed (wrong key or tampered blob): %w", err)
	}
	defer ss.Zeroize()

	// 4. AES-256-GCM open: key=ss, nonce=iv, ct=ciphertext||auth_tag, aad=buildAAD.
	iv, err := base64.StdEncoding.DecodeString(p.IV)
	if err != nil {
		return fmt.Errorf("decode iv: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(p.Ciphertext)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}
	tag, err := base64.StdEncoding.DecodeString(p.AuthTag)
	if err != nil {
		return fmt.Errorf("decode auth_tag: %w", err)
	}
	full := make([]byte, 0, len(ct)+len(tag))
	full = append(full, ct...)
	full = append(full, tag...)

	aesBlock, err := aes.NewCipher(ss[:])
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, full, buildAAD(p.CompanyID, p.EntryID))
	if err != nil {
		return fmt.Errorf("AES-GCM open failed (wrong key / AAD mismatch / tampered): %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n✓ DECRYPTED %d bytes  company=%s  entry=%s\n", len(plaintext), p.CompanyID, p.EntryID)
	fmt.Fprintln(os.Stderr, "───── plaintext below ─────")
	os.Stdout.Write(plaintext)
	fmt.Fprintln(os.Stderr)
	return nil
}
