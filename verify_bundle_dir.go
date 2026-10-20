// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aleutian-ai/verification-go/mldsa"
)

// Bundle layout constants. These MUST byte-match the producer
// (internal/export_builder/stages/final + finaldeps/zipper.go).
const (
	bundleManifestFile  = "manifest.json"
	bundleSignatureFile = "signature.bin"
	bundleTrustManifest = "trust_manifest/manifest.json"
	mldsa65BundleSigLen = 3309
	bundleSignatureAlg  = "ML-DSA-65"
)

// Resource bounds — the bundle directory is UNTRUSTED (an adversary may have
// modified it), so every read is capped (A3). Genuine tier-1 chain bundles are
// KB–low-MB; these ceilings are generous headroom, not tuning knobs.
const (
	maxBundleManifestBytes = 32 << 20  // 32 MiB — manifest.json is normally a few KB
	maxBundleFileBytes     = 1 << 30   // 1 GiB per listed evidence file
	maxBundleFileCount     = 1_000_000 // files[] entry ceiling
)

// ErrBundleInvalid is the sentinel wrapped by every negative
// VerifyBundleDir verdict (bad signature, root mismatch, content-hash
// mismatch, missing/extra file). Structural/IO problems return their own
// wrapped errors distinct from this.
var ErrBundleInvalid = errors.New("bundle verification failed")

// BundleManifest is the subset of an export bundle's manifest.json the
// verifier needs. The signature is computed over the RAW manifest.json
// bytes, so this struct is only used for field access after the signature
// has authenticated those bytes.
type BundleManifest struct {
	BundleID      string            `json:"bundle_id"`
	CompanyID     string            `json:"company_id"`
	FormatVersion int               `json:"format_version"`
	ManifestRoot  string            `json:"manifest_root"`
	SignatureAlg  string            `json:"signature_alg"`
	SigningKeyID  string            `json:"signing_key_id"`
	Files         []BundleFileEntry `json:"files"`
}

// BundleVerifyResult is the structured verdict from VerifyBundleDir.
type BundleVerifyResult struct {
	// Valid is true only when the signature verified, manifest_root
	// recomputed, every listed file re-hashed correctly, and no unlisted
	// file was present.
	Valid bool
	// BundleID echoes the manifest's bundle_id (best-effort; set even on
	// some failure paths once the manifest parses).
	BundleID string
	// FilesChecked is the number of files[] entries whose bytes were
	// re-hashed and matched.
	FilesChecked int
	// Reason is a human-readable failure summary; empty when Valid.
	Reason string
}

// VerifyBundleDir offline-verifies an unpacked export bundle directory:
// it proves the delivered files are byte-for-byte the ones Aleutian signed,
// using only the bundle's own trust_manifest snapshot (zero network).
//
// # Description
//
// Checks, in order (fail-closed at the first failure):
//
//  1. Read manifest.json.
//  2. Verify the ML-DSA-65 signature (signature.bin) over the RAW
//     manifest.json bytes, using the signing key resolved from the
//     bundle's trust_manifest/manifest.json snapshot. This authenticates
//     the manifest — including its manifest_root field.
//  3. Recompute manifest_root from files[] (v2 recipe) and assert it equals
//     the signed field. This binds files[] to the signature.
//  4. For every files[] entry: the file exists and its SHA-512 matches.
//  5. Reject any on-disk file NOT in files[] (except manifest.json +
//     signature.bin, which cannot be self-attested).
//
// A PASS means: the bundle is exactly what Aleutian signed, provable
// without trusting Aleutian at verify time.
//
// # Inputs
//
//   - dir: path to the unpacked bundle root (contains manifest.json,
//     signature.bin, trust_manifest/, chain_extracts/, anchors/).
//
// # Outputs
//
//   - BundleVerifyResult: Valid + detail. On a verification failure Valid
//     is false and the returned error wraps ErrBundleInvalid.
//   - error: ErrBundleInvalid (verification), or a structural/IO error.
//
// # Example
//
//	res, err := verification.VerifyBundleDir("./")
//	if err != nil { log.Fatal(err) }
//	// res.Valid == true
//
// # Limitations
//
//   - Verifies bundle AUTHENTICITY + COMPLETENESS (signature + manifest_root
//   - per-file hash). Per-entry chain/anchor replay (re-verifying each
//     leaf signature + chain links inside chain_extracts/*.jsonl) is a
//     separate deeper layer (0b_2b) that reuses VerifyChainOffline /
//     VerifyAnchorLocally.
//   - Trust in the signing key rests on the bundle's trust_manifest
//     snapshot; ParseAndVerifyTrustManifest checks that snapshot's own root
//     signature.
//
// # Assumptions
//
//   - The producer signs the exact bytes written to manifest.json.
//   - The bundle was produced with the v2 manifest_root recipe.
func VerifyBundleDir(dir string) (BundleVerifyResult, error) {
	var res BundleVerifyResult

	manifestBytes, err := readFileCapped(filepath.Join(dir, bundleManifestFile), maxBundleManifestBytes)
	if err != nil {
		return res, fmt.Errorf("read %s: %w", bundleManifestFile, err)
	}
	var man BundleManifest
	if err := json.Unmarshal(manifestBytes, &man); err != nil {
		return res, fmt.Errorf("parse %s: %w", bundleManifestFile, err)
	}
	res.BundleID = man.BundleID

	// setInvalid records a verification-verdict reason (only for
	// ErrBundleInvalid-class failures) and returns the wrapped error. IO /
	// structural errors deliberately do NOT set Reason (they are not a
	// tamper verdict) — the CLI keys its exit code off ErrBundleInvalid (C1).
	setInvalid := func(reason string) (BundleVerifyResult, error) {
		res.Reason = reason
		return res, fmt.Errorf("%w: %s", ErrBundleInvalid, reason)
	}

	// 1b. Structural sanity: algorithm + file-count ceiling.
	if man.SignatureAlg != "" && man.SignatureAlg != bundleSignatureAlg {
		return setInvalid(fmt.Sprintf("unsupported signature_alg %q (want %s)", man.SignatureAlg, bundleSignatureAlg))
	}
	if len(man.Files) > maxBundleFileCount {
		return setInvalid(fmt.Sprintf("files[] has %d entries, exceeds cap %d", len(man.Files), maxBundleFileCount))
	}

	// 2. Signature over the raw manifest bytes. A verification failure sets the
	// verdict Reason; an IO/structural failure propagates without a Reason (C1).
	if err := verifyBundleSignature(dir, man.SigningKeyID, manifestBytes); err != nil {
		if errors.Is(err, ErrBundleInvalid) {
			res.Reason = err.Error()
		}
		return res, err
	}

	// 3. Recompute manifest_root and bind files[] to the signature.
	root, err := ComputeBundleManifestRoot(man.Files)
	if err != nil {
		return setInvalid(fmt.Sprintf("recompute manifest_root: %v", err))
	}
	if root != man.ManifestRoot {
		return setInvalid("manifest_root mismatch: files[] does not match the signed root")
	}

	// 4. Re-hash every listed file against disk. Each path is validated to stay
	// inside the bundle (A1) and each file must be a regular file, not a symlink
	// (A2), and within the size cap (A3). Duplicate paths are rejected (D1).
	listed := make(map[string]struct{}, len(man.Files))
	for _, f := range man.Files {
		if _, dup := listed[f.Path]; dup {
			return setInvalid(fmt.Sprintf("duplicate path in files[]: %s", f.Path))
		}
		listed[f.Path] = struct{}{}

		safe, perr := safeBundlePath(dir, f.Path)
		if perr != nil {
			return setInvalid(fmt.Sprintf("unsafe file path %q: %v", f.Path, perr))
		}
		got, herr := hashRegularFileCapped(safe, maxBundleFileBytes)
		if herr != nil {
			return setInvalid(fmt.Sprintf("hash %s: %v", f.Path, herr))
		}
		if got != f.SHA512 {
			return setInvalid(fmt.Sprintf("content-hash mismatch for %s", f.Path))
		}
		res.FilesChecked++
	}

	// 5. Reject any on-disk file not in files[] (except the two anchors).
	extra, ferr := unlistedBundleFile(dir, listed)
	if ferr != nil {
		return res, ferr
	}
	if extra != "" {
		return setInvalid(fmt.Sprintf("unlisted file present in bundle: %s", extra))
	}

	res.Valid = true
	return res, nil
}

// verifyBundleSignature verifies signature.bin over manifestBytes using the
// key resolved from the bundle's trust_manifest snapshot.
func verifyBundleSignature(dir, signingKeyID string, manifestBytes []byte) error {
	if signingKeyID == "" {
		return fmt.Errorf("%w: manifest signing_key_id is empty", ErrBundleInvalid)
	}
	sig, err := os.ReadFile(filepath.Join(dir, bundleSignatureFile))
	if err != nil {
		return fmt.Errorf("read %s: %w", bundleSignatureFile, err)
	}
	if len(sig) != mldsa65BundleSigLen {
		return fmt.Errorf("%w: %s is %d bytes, expected %d (ML-DSA-65)",
			ErrBundleInvalid, bundleSignatureFile, len(sig), mldsa65BundleSigLen)
	}
	tmBytes, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(bundleTrustManifest)))
	if err != nil {
		return fmt.Errorf("read %s: %w", bundleTrustManifest, err)
	}
	tm, err := ParseAndVerifyTrustManifest(tmBytes)
	if err != nil {
		return fmt.Errorf("%w: trust manifest: %v", ErrBundleInvalid, err)
	}
	pub, ok := tm.PublicKey(signingKeyID)
	if !ok {
		return fmt.Errorf("%w: signing key %q not in trust manifest (or revoked)",
			ErrBundleInvalid, signingKeyID)
	}
	if err := mldsa.Verify(pub, manifestBytes, sig); err != nil {
		return fmt.Errorf("%w: signature does not verify for key %q: %v",
			ErrBundleInvalid, signingKeyID, err)
	}
	return nil
}

// unlistedBundleFile returns the on-disk files (bundle-relative, forward-slash)
// that are not in listed and are not one of the two verification anchors, plus
// any symlink encountered (a symlink anywhere in the bundle is itself an
// integrity violation — it makes "the file at this path" ambiguous). Empty
// string means the on-disk set exactly matches the inventory. filepath.Walk
// uses Lstat, so symlinked directories are not descended.
func unlistedBundleFile(dir string, listed map[string]struct{}) (string, error) {
	var found []string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		// A symlink (or any non-regular file) is rejected outright even if its
		// name is listed — regular-file-ness of listed paths is also enforced
		// in hashRegularFileCapped, but catching it here covers the anchors too.
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			found = append(found, rel+" (non-regular file)")
			return nil
		}
		if rel == bundleManifestFile || rel == bundleSignatureFile {
			return nil
		}
		if _, ok := listed[rel]; !ok {
			found = append(found, rel)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("walk bundle dir: %w", err)
	}
	if len(found) == 0 {
		return "", nil
	}
	sort.Strings(found)
	return strings.Join(found, ", "), nil
}

// safeBundlePath validates that a manifest-supplied bundle-relative path stays
// inside dir and joins it to an absolute filesystem path (A1). It rejects empty,
// absolute, NUL-bearing, and traversal (`..`) paths — an attacker who controls
// the manifest must not be able to point the verifier at a file outside the
// bundle.
func safeBundlePath(dir, relSlash string) (string, error) {
	if relSlash == "" {
		return "", errors.New("empty path")
	}
	if strings.ContainsRune(relSlash, '\x00') {
		return "", errors.New("path contains NUL")
	}
	rel := filepath.FromSlash(relSlash)
	if filepath.IsAbs(rel) {
		return "", errors.New("path is absolute")
	}
	joined := filepath.Join(dir, rel)
	// Join cleans `..`; confirm the result did not escape dir.
	back, err := filepath.Rel(dir, joined)
	if err != nil {
		return "", err
	}
	if back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes the bundle directory")
	}
	return joined, nil
}

// hashRegularFileCapped returns the lowercase-hex SHA-512 of a file's contents,
// refusing anything that is not a regular file (symlink/device/dir — A2) or
// that exceeds cap bytes (A3). It streams through the hasher so a large file is
// never fully buffered.
func hashRegularFileCapped(path string, cap int64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a regular file (symlink or special file)")
	}
	if info.Size() > cap {
		return "", fmt.Errorf("file is %d bytes, exceeds cap %d", info.Size(), cap)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha512.New()
	if _, err := io.CopyN(h, f, info.Size()); err != nil && err != io.EOF {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readFileCapped reads at most cap+1 bytes and errors if the file exceeds cap.
func readFileCapped(path string, cap int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, cap+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > cap {
		return nil, fmt.Errorf("file exceeds cap %d bytes", cap)
	}
	return b, nil
}
