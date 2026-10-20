// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// golden-vector-gen builds the canonical golden-vectors JSON file that
// CV-09 cross-language tests consume.
//
// # Usage
//
//	go run ./cmd/golden-vector-gen
//
// Writes `integration/compliance_verify_vector_tests/golden_vectors.json`.
//
// The Go SDK is the source of truth for canonical byte sequences; Python
// and JS sibling SDK tests consume this file and assert byte-identical
// output. Any drift between SDKs surfaces as a test failure in the
// language that drifted.
package main

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/aleutian-ai/verification-go/frameworks"
)

type goldenVectors struct {
	FormatVersion            int                              `json:"format_version"`
	SpecReference            string                           `json:"spec_reference"`
	Description              string                           `json:"description"`
	SyntheticFramework       frameworkVector                  `json:"synthetic_framework"`
	VerifiedLineCases        []verifiedLineCase               `json:"verified_line_cases"`
	ExplainBlockSoc2Snapshot string                           `json:"explain_block_soc2_snapshot"`
	EmbeddedControlsHashes   map[string]embeddedFrameworkHash `json:"embedded_controls_hashes"`
	DomainPrefix             string                           `json:"domain_prefix"`
	MaxControlsJSONBytes     int                              `json:"max_controls_json_bytes"`
	V2DeprecationWarning     string                           `json:"v2_deprecation_warning"`
	DefaultEvidencePaths     []evidencePathCase               `json:"default_evidence_paths"`
}

type evidencePathCase struct {
	FrameworkID string `json:"framework_id"`
	ControlID   string `json:"control_id"`
	Expected    string `json:"expected"`
}

type frameworkVector struct {
	Input                          frameworks.Framework `json:"input"`
	ExpectedCanonicalJSONOnWire    string               `json:"expected_canonical_json_on_wire"`
	ExpectedCanonicalBytesHashHex  string               `json:"expected_canonical_bytes_hash_hex"`
	ExpectedDomainPrefixedBytesB64 string               `json:"expected_domain_prefixed_bytes_b64"`
	Note                           string               `json:"note"`
}

type verifiedLineCase struct {
	Framework string `json:"framework"`
	Version   string `json:"version"`
	Expected  string `json:"expected"`
}

type embeddedFrameworkHash struct {
	SizeBytes     int    `json:"size_bytes"`
	FileSHA512    string `json:"file_sha512_hex"`
	SelfAttestHex string `json:"controls_sha512_hex_self_attestation"`
}

// synthFixture is the hand-pinned test framework. Its expected
// canonical encoding is asserted by every SDK. If this fixture or its
// expected encoding ever needs to change, ALL three SDK tests must be
// updated in the same commit — that's the whole point.
func synthFixture() frameworks.Framework {
	return frameworks.Framework{
		AleutianSnapshotAt:   "2026-03-01",
		FrameworkID:          frameworks.FrameworkID("f1"),
		FrameworkPublishedAt: "2017-04-30",
		VersionID:            frameworks.VersionID("f1@20260301"),
		Controls: []frameworks.Control{
			{
				ID:              "C1",
				Title:           "T & U < V > W",
				Category:        "cat",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "p",
				WhatWeDontProve: "q",
			},
		},
		ControlsOutOfScope: []frameworks.OutOfScopeControl{
			{ID: "X", Reason: "r"},
		},
		ControlsSHA512Hex: "",
	}
}

func main() {
	synth := synthFixture()
	canonOnWire, err := frameworks.CanonicalJSONOnWire(synth)
	must("canonical on-wire", err)
	hashInput, err := frameworks.CanonicalBytesForHashing(synth)
	must("canonical bytes for hashing", err)
	hashSum := sha512.Sum512(hashInput)

	vlCases := []verifiedLineCase{}
	for _, c := range []struct{ name, version string }{
		{"SOC 2", "soc2-2017@20260531"},
		{"GDPR", "gdpr@20260531"},
		{"EU-AI-Act", "eu-ai-act@20260531"},
		{"HIPAA", "hipaa@20260531"},
		{"", ""},
	} {
		got := frameworks.FormatVerifiedLine(c.name, frameworks.VersionID(c.version))
		vlCases = append(vlCases, verifiedLineCase{
			Framework: c.name,
			Version:   c.version,
			Expected:  got,
		})
	}

	soc2, err := frameworks.LoadFromEmbedded("soc2-2017@20260531")
	must("load SOC 2", err)
	explain := frameworks.FormatExplainBlock(soc2)

	embedded := map[string]embeddedFrameworkHash{}
	versions := []string{}
	for _, v := range frameworks.Latest {
		versions = append(versions, string(v))
	}
	sort.Strings(versions)
	for _, vid := range versions {
		f, err := frameworks.LoadFromEmbedded(frameworks.VersionID(vid))
		must("load "+vid, err)
		bytes, err := frameworks.CanonicalJSONOnWire(f)
		must("canonical "+vid, err)
		sum := sha512.Sum512(bytes)
		embedded[vid] = embeddedFrameworkHash{
			SizeBytes:     len(bytes),
			FileSHA512:    hex.EncodeToString(sum[:]),
			SelfAttestHex: f.ControlsSHA512Hex,
		}
	}

	evidencePaths := []evidencePathCase{
		{FrameworkID: "soc2-2017", ControlID: "CC6.1", Expected: frameworks.DefaultEvidencePath(frameworks.SOC2_2017, "CC6.1")},
		{FrameworkID: "hipaa", ControlID: "§164.312(b)", Expected: frameworks.DefaultEvidencePath(frameworks.HIPAA, "§164.312(b)")},
		{FrameworkID: "gdpr", ControlID: "Art.5(1)(f)", Expected: frameworks.DefaultEvidencePath(frameworks.GDPR, "Art.5(1)(f)")},
		{FrameworkID: "nist-800-53", ControlID: "AU-10", Expected: frameworks.DefaultEvidencePath(frameworks.NIST_800_53, "AU-10")},
		{FrameworkID: "ccpa-cpra", ControlID: "§1798.110", Expected: frameworks.DefaultEvidencePath(frameworks.CCPA_CPRA, "§1798.110")},
	}

	out := goldenVectors{
		FormatVersion: 2,
		SpecReference: "compliance_versioning_09_cross_language_golden_vectors",
		Description: "Cross-language byte-identity contract for the frameworks " +
			"package. Go is the source of truth for these byte sequences; " +
			"Python and JS sibling SDK tests assert against this file. Any " +
			"divergence is a structural break in CV-09's contract. " +
			"format_version=2 adds CV-05d default_evidence_paths and CV-05e " +
			"v2_deprecation_warning.",
		SyntheticFramework: frameworkVector{
			Input:                          synth,
			ExpectedCanonicalJSONOnWire:    string(canonOnWire),
			ExpectedCanonicalBytesHashHex:  hex.EncodeToString(hashSum[:]),
			ExpectedDomainPrefixedBytesB64: base64Std(hashInput),
			Note: "input.controls_sha512_hex is empty; the expected hash " +
				"is SHA-512 of DOMAIN_PREFIX || canonicalJSON(input). " +
				"expected_canonical_json_on_wire is canonicalJSON(input) " +
				"with the empty hash field included verbatim.",
		},
		VerifiedLineCases:        vlCases,
		ExplainBlockSoc2Snapshot: explain,
		EmbeddedControlsHashes:   embedded,
		DomainPrefix:             frameworks.DomainPrefix,
		MaxControlsJSONBytes:     frameworks.MaxControlsJSONBytes,
		V2DeprecationWarning:     frameworks.V2DeprecationWarning,
		DefaultEvidencePaths:     evidencePaths,
	}

	body, err := json.MarshalIndent(out, "", "  ")
	must("marshal", err)

	outPath, err := outputPath()
	must("resolve output path", err)
	if err := os.WriteFile(outPath, append(body, '\n'), 0o644); err != nil {
		must("write", err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", outPath, len(body)+1)
}

func base64Std(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func outputPath() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed")
	}
	// thisFile = .../sdk/verification-go/cmd/golden-vector-gen/main.go
	// repo root = .../
	cmdDir := filepath.Dir(thisFile)
	verGoDir := filepath.Dir(filepath.Dir(cmdDir))
	sdkRoot := filepath.Dir(verGoDir)
	repoRoot := filepath.Dir(sdkRoot)
	out := filepath.Join(repoRoot, "integration", "compliance_verify_vector_tests", "golden_vectors.json")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return "", err
	}
	return out, nil
}

func must(label string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", label, err)
		os.Exit(1)
	}
}
