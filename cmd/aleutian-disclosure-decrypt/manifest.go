// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

// Manifest is the subset of manifest.json the SDK CLI consumes.
// Mirrors AleutianEnterprise/internal/export_builder/manifest.Manifest
// but defined locally so the SDK has no proprietary dependencies.
// Field tag stability is part of the customer-facing contract; any
// change here is a wire-format break.
type Manifest struct {
	BundleID         string      `json:"bundle_id"`
	CompanyID        string      `json:"company_id"`
	ContentTier      string      `json:"content_tier"`
	FormatVersion    int         `json:"format_version"`
	Framework        string      `json:"framework"`
	GeneratedAtMs    int64       `json:"generated_at_ms"`
	ManifestRoot     string      `json:"manifest_root"`
	PeriodEndMs      int64       `json:"period_end_ms"`
	PeriodStartMs    int64       `json:"period_start_ms"`
	ProducerVersion  string      `json:"producer_version"`
	ReportEndpoint   string      `json:"report_endpoint"`
	SignatureAlg     string      `json:"signature_alg"`
	SigningKeyID     string      `json:"signing_key_id"`
	Tier2            *Tier2Block `json:"tier2,omitempty"`
	TrustManifestRev string      `json:"trust_manifest_rev"`
	Version          string      `json:"version"`

	// ControlMapVersion + Files are present in the producer's
	// canonical form but the SDK CLI does not consume them. Tagged so
	// JSON DisallowUnknownFields does not reject them.
	ControlMapVersion string      `json:"control_map_version,omitempty"`
	Files             []FileEntry `json:"files,omitempty"`
}

// FileEntry mirrors the producer's manifest.FileEntry. The SDK CLI
// does not introspect it but must accept it in the JSON.
type FileEntry struct {
	Bytes    int64  `json:"bytes"`
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	RowCount *int64 `json:"row_count,omitempty"`
	SHA512   string `json:"sha512"`
}

// Tier2Block mirrors the producer's manifest.Tier2Block.
type Tier2Block struct {
	AEADAlgorithm        string              `json:"aead_algorithm"`
	CEKEnvelopes         []any               `json:"cek_envelopes"` // Standard-mode; not consumed by Forensic CLI
	KDFAlgorithm         string              `json:"kdf_algorithm"`
	KEMAlgorithm         string              `json:"kem_algorithm"`
	Mode                 string              `json:"mode"`
	PubkeySet            []Tier2PubkeyEntry  `json:"pubkey_set"`
	SealedEnvelopesIndex []Tier2SealedEnvRef `json:"sealed_envelopes_index"`
}

// Tier2PubkeyEntry mirrors manifest.Tier2PubkeyEntry.
type Tier2PubkeyEntry struct {
	Fingerprint     string `json:"fingerprint"`
	IntendedPurpose string `json:"intended_purpose"`
	RegisteredAtMs  int64  `json:"registered_at_ms"`
	Status          string `json:"status"`
}

// Tier2SealedEnvRef mirrors manifest.Tier2SealedEnvRef. One entry
// per (row × recipient) tuple in Forensic mode.
type Tier2SealedEnvRef struct {
	Path              string `json:"path"`
	PubkeyFingerprint string `json:"pubkey_fingerprint"`
	RowID             string `json:"row_id"`
	SHA512            string `json:"sha512"`
}

// X-Wing seed-PEM block types accepted by the SDK CLI. Mirrors the
// proprietary constants in AleutianEnterprise/internal/provisioning/
// keygen_pem.go; defined locally so the SDK has no proprietary
// dependencies.
const (
	xwingPrivateKeyPEMType        = "ALEUTIAN XWING PRIVATE KEY"
	xwingPrivateKeyPEMTypePrimary = "ALEUTIAN XWING PRIMARY PRIVATE KEY"
	xwingPrivateKeyPEMTypeBackup  = "ALEUTIAN XWING BACKUP PRIVATE KEY"

	// passphraseWrappedPEMType is recognized so the SDK CLI can fail
	// with a helpful message ("not supported in SDK build; use
	// proprietary CLI to pre-unwrap") instead of a generic PEM-type
	// rejection. The actual seedwrap.Unwrap logic is NOT mirrored in
	// the SDK first cut.
	passphraseWrappedPEMType = "ALEUTIAN PASSPHRASE-WRAPPED PRIVATE KEY"
)
