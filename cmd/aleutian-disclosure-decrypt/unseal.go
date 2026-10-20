// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aleutian-ai/verification-go/sarenvelope"
	"github.com/cloudflare/circl/kem/xwing"
)

// Sentinel errors for the unseal pipeline. main.go's
// mapErrorToExitCode dispatches on these via errors.Is. Match the
// proprietary build's sentinels semantically (the wire-format text
// differs only by the "sdk:" prefix).
var (
	ErrStructural       = errors.New("structural")
	ErrSeedFile         = errors.New("seed file")
	ErrOutputPermission = errors.New("output permission")
	ErrNoMatchingKey    = errors.New("no matching key")
	ErrAEADFailure      = errors.New("aead failure")
)

const (
	manifestPathInZip   = "manifest.json"
	contentTierForensic = "tier_2_forensic"
)

// UnsealRequest is the public input contract to Unseal.
type UnsealRequest struct {
	BundlePath       string
	SeedPath         string
	OutDir           string
	SkipBundleVerify bool

	// SeedPassphraseEnvVar names the env var holding the passphrase
	// for a wrapped seed (PEM type ALEUTIAN PASSPHRASE-WRAPPED PRIVATE
	// KEY). When empty AND the seed is wrapped, Unseal prompts on the
	// controlling terminal. Ignored when the seed is unwrapped.
	SeedPassphraseEnvVar string

	// Verbose, when true, emits per-envelope progress lines to
	// VerboseSink. Output contains row_id + status; NEVER payload bytes.
	Verbose     bool
	VerboseSink io.Writer

	// ResealPubkeyPath, when non-empty, switches Unseal into
	// reseal-ephemeral mode. Mirrors the proprietary build.
	ResealPubkeyPath string
}

// UnsealResult is the public output of a successful Unseal.
type UnsealResult struct {
	UnsealedCount      int
	Fingerprint        string
	OutputPath         string
	BundleID           string
	ReportEndpoint     string
	ResealMode         bool
	AuditorFingerprint string
}

// Unseal is the top-level orchestrator.
//
// # Pipeline
//
//  1. Read seed (raw PEM only in the SDK first cut; wrapped seeds
//     return a helpful error).
//  2. Derive fingerprint from the seed.
//  3. Open bundle ZIP + parse manifest.json.
//  4. Verify bundle ML-DSA-65 signature (unless SkipBundleVerify).
//  5. Structural validation of manifest (Forensic tier only).
//  6. Filter sealed_envelopes_index by fingerprint match.
//  7. For each match: read .bin file, verify SHA-512, call
//     sarenvelope.Open.
//  8. Write recovered payloads as JSONL.
func Unseal(req UnsealRequest) (*UnsealResult, error) {
	seed, err := readSeedSource(req.SeedPath, req.SeedPassphraseEnvVar)
	if err != nil {
		return nil, err // already ErrSeedFile-wrapped
	}
	defer zeroize(seed)

	fingerprint, err := fingerprintFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("%w: derive fingerprint: %v", ErrSeedFile, err)
	}

	zr, err := zip.OpenReader(req.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("%w: open bundle: %v", ErrStructural, err)
	}
	defer zr.Close()

	manifestBytes, err := readZipFile(&zr.Reader, manifestPathInZip)
	if err != nil {
		return nil, fmt.Errorf("%w: read manifest: %v", ErrStructural, err)
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: parse manifest: %v", ErrStructural, err)
	}

	if !req.SkipBundleVerify {
		if vErr := VerifyBundleSignature(&zr.Reader, m.SigningKeyID, manifestBytes); vErr != nil {
			return nil, vErr
		}
	}

	if m.ContentTier != contentTierForensic {
		return nil, fmt.Errorf("%w: bundle content_tier=%q; only %q is supported",
			ErrStructural, m.ContentTier, contentTierForensic)
	}
	if m.Tier2 == nil {
		return nil, fmt.Errorf("%w: Forensic bundle missing tier2 block", ErrStructural)
	}
	if m.BundleID == "" {
		return nil, fmt.Errorf("%w: manifest.bundle_id is empty", ErrStructural)
	}

	const maxSealedEnvelopes = 1_000_000
	if len(m.Tier2.SealedEnvelopesIndex) > maxSealedEnvelopes {
		return nil, fmt.Errorf("%w: sealed_envelopes_index has %d entries (cap %d)",
			ErrStructural, len(m.Tier2.SealedEnvelopesIndex), maxSealedEnvelopes)
	}
	matches := filterEnvelopesByFingerprint(m.Tier2.SealedEnvelopesIndex, fingerprint)
	if len(matches) == 0 {
		return nil, ErrNoMatchingKey
	}

	if err := os.MkdirAll(req.OutDir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create out dir: %v", ErrOutputPermission, err)
	}

	// Branch on reseal mode. In reseal mode plaintext is decrypted,
	// immediately re-encrypted under the auditor's pubkey, and the
	// resealed envelope is written to disk — plaintext NEVER hits
	// the filesystem.
	resealMode := req.ResealPubkeyPath != ""
	var (
		outputPath string
		outFile    *os.File
		enc        *json.Encoder
		rc         *resealContext
	)
	if resealMode {
		var rcErr error
		rc, rcErr = newResealContext(req.OutDir, m.BundleID, m.CompanyID, req.ResealPubkeyPath)
		if rcErr != nil {
			return nil, rcErr
		}
		outputPath = rc.outDir
	} else {
		outputPath = filepath.Join(req.OutDir, m.BundleID+".jsonl")
		f, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, fmt.Errorf("%w: open out file: %v", ErrOutputPermission, err)
		}
		outFile = f
		defer outFile.Close()
		enc = json.NewEncoder(outFile)
	}

	verboseSink := req.VerboseSink
	if !req.Verbose || verboseSink == nil {
		verboseSink = io.Discard
	}

	unsealedCount := 0
	for _, ref := range matches {
		// Defense-in-depth path validation — see validateBundlePath
		// below. The bundle ML-DSA-65 signature attests ref.Path; this
		// guard hardens the --skip-verify and future-writer paths.
		if err := validateBundlePath(ref.Path); err != nil {
			return nil, fmt.Errorf("%w: envelope path %q: %v", ErrStructural, ref.Path, err)
		}
		envBytes, readErr := readZipFile(&zr.Reader, ref.Path)
		if readErr != nil {
			return nil, fmt.Errorf("%w: read envelope %q: %v",
				ErrStructural, ref.Path, readErr)
		}
		actualHash := sha512Hex(envBytes)
		if actualHash != ref.SHA512 {
			return nil, fmt.Errorf("%w: envelope %q SHA-512 mismatch (manifest=%s, actual=%s)",
				ErrStructural, ref.Path, ref.SHA512, actualHash)
		}
		plaintext, openErr := sarenvelope.Open(envBytes, seed)
		if openErr != nil {
			if isSarEnvelopeStructuralError(openErr) {
				return nil, fmt.Errorf("%w: envelope %q: %v",
					ErrStructural, ref.Path, openErr)
			}
			return nil, ErrAEADFailure
		}

		// Reseal mode: re-encrypt + write resealed envelope. NEVER
		// writes plaintext. Zeroize on the way out (always).
		if resealMode {
			if _, rerr := rc.reseal(ref.RowID, plaintext); rerr != nil {
				zeroize(plaintext)
				return nil, rerr
			}
			fmt.Fprintf(verboseSink, "reseal: row=%s match=true status=ok\n", ref.RowID)
			zeroize(plaintext)
			unsealedCount++
			continue
		}

		// Default mode: write the recovered payload as one JSONL row.
		row := unsealedRow{RowID: ref.RowID}
		if json.Valid(plaintext) {
			row.Payload = json.RawMessage(plaintext)
		} else {
			row.PayloadB64 = base64.StdEncoding.EncodeToString(plaintext)
		}
		if err := enc.Encode(row); err != nil {
			zeroize(plaintext)
			_ = outFile.Close()
			_ = os.Remove(outputPath)
			return nil, fmt.Errorf("%w: write row %q: %v",
				ErrOutputPermission, ref.RowID, err)
		}
		zeroize(plaintext)
		fmt.Fprintf(verboseSink, "unseal: row=%s match=true status=ok\n", ref.RowID)
		unsealedCount++
	}

	if !resealMode {
		if err := outFile.Sync(); err != nil {
			return nil, fmt.Errorf("%w: sync out file: %v", ErrOutputPermission, err)
		}
	}

	result := &UnsealResult{
		UnsealedCount:  unsealedCount,
		Fingerprint:    fingerprint,
		OutputPath:     outputPath,
		BundleID:       m.BundleID,
		ReportEndpoint: m.ReportEndpoint,
		ResealMode:     resealMode,
	}
	if resealMode {
		result.AuditorFingerprint = rc.auditorFingerprint
	}
	return result, nil
}

// unsealedRow is the JSONL row shape. Exactly one of Payload /
// PayloadB64 is populated.
type unsealedRow struct {
	RowID      string          `json:"row_id"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	PayloadB64 string          `json:"payload_b64,omitempty"`
}

// readSeedPEM is retained for the --print-fingerprint path, which
// reads the seed file directly without unwrap. New callers should
// use readSeedSource (which detects wrapped vs. raw + handles
// passphrases).
//
// As of compliance_tier2_30c_followup_sdk_seedwrap, the SDK build
// DOES support passphrase-wrapped seeds via readSeedSource. This
// function still rejects them — it's the unwrap-isn't-wired path
// (--print-fingerprint), where requiring a passphrase to read a
// fingerprint would be poor UX.
func readSeedPEM(path string) ([]byte, error) {
	var (
		pemBytes []byte
		err      error
	)
	if path == "-" {
		pemBytes, err = io.ReadAll(io.LimitReader(os.Stdin, 64*1024))
		if err != nil {
			return nil, fmt.Errorf("%w: read seed from stdin: %v", ErrSeedFile, err)
		}
	} else {
		pemBytes, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: read %q: %v", ErrSeedFile, path, err)
		}
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%w: not a valid PEM file", ErrSeedFile)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%w: trailing data after PEM block", ErrSeedFile)
	}
	switch block.Type {
	case xwingPrivateKeyPEMType,
		xwingPrivateKeyPEMTypePrimary,
		xwingPrivateKeyPEMTypeBackup:
		// OK
	case passphraseWrappedPEMType:
		return nil, fmt.Errorf("%w: passphrase-wrapped seed is not supported in the SDK build; "+
			"pre-unwrap with the proprietary `aleutian-disclosure-decrypt` build or `aleutian-keygen --unwrap`",
			ErrSeedFile)
	default:
		return nil, fmt.Errorf("%w: unexpected PEM block type %q", ErrSeedFile, block.Type)
	}
	if len(block.Bytes) != sarenvelope.XWingSeedSize {
		return nil, fmt.Errorf("%w: seed is %d bytes, expected %d",
			ErrSeedFile, len(block.Bytes), sarenvelope.XWingSeedSize)
	}
	out := make([]byte, len(block.Bytes))
	copy(out, block.Bytes)
	return out, nil
}

// fingerprintFromSeed derives the X-Wing pubkey from the seed and
// runs it through sarenvelope.Fingerprint.
func fingerprintFromSeed(seed []byte) (string, error) {
	if len(seed) != sarenvelope.XWingSeedSize {
		return "", fmt.Errorf("seed must be %d bytes", sarenvelope.XWingSeedSize)
	}
	scheme := xwing.Scheme()
	pub, _ := scheme.DeriveKeyPair(seed)
	rawPub, err := pub.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("marshal pubkey: %v", err)
	}
	return sarenvelope.Fingerprint(rawPub)
}

func filterEnvelopesByFingerprint(refs []Tier2SealedEnvRef, want string) []Tier2SealedEnvRef {
	out := make([]Tier2SealedEnvRef, 0, len(refs))
	for _, r := range refs {
		if r.PubkeyFingerprint == want {
			out = append(out, r)
		}
	}
	return out
}

// maxZipEntryBytes caps any single ZIP entry to bound memory under a
// malicious manifest. Mirrors the proprietary build.
const maxZipEntryBytes = 64 * 1024 * 1024

func readZipFile(zr *zip.Reader, name string) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			b, err := io.ReadAll(io.LimitReader(rc, maxZipEntryBytes+1))
			if err != nil {
				return nil, err
			}
			if len(b) > maxZipEntryBytes {
				return nil, fmt.Errorf("zip entry %q exceeds %d-byte cap", name, maxZipEntryBytes)
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("file %q not in bundle", name)
}

func sha512Hex(b []byte) string {
	h := sha512.Sum512(b)
	return hex.EncodeToString(h[:])
}

// isSarEnvelopeStructuralError classifies an sdk-sarenvelope.Open
// error as pre-AEAD structural (return ErrStructural) vs AEAD-class
// (return ErrAEADFailure to keep the oracle-safe message consistent).
func isSarEnvelopeStructuralError(err error) bool {
	switch {
	case errors.Is(err, sarenvelope.ErrInvalidEnvelope),
		errors.Is(err, sarenvelope.ErrUnsupportedVersion),
		errors.Is(err, sarenvelope.ErrUnsupportedAlg),
		errors.Is(err, sarenvelope.ErrUnsupportedAEAD),
		errors.Is(err, sarenvelope.ErrInvalidPrivkeySize):
		return true
	default:
		return false
	}
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// validateBundlePath rejects manifest-referenced paths that would
// escape the bundle ZIP root via "../" traversal or absolute paths.
// Mirrors the proprietary implementation byte-for-byte.
func validateBundlePath(p string) error {
	if p == "" {
		return fmt.Errorf("empty path")
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return fmt.Errorf("absolute paths are rejected")
	}
	clean := filepath.ToSlash(filepath.Clean(p))
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return fmt.Errorf("path traversal (..) is rejected")
	}
	return nil
}
