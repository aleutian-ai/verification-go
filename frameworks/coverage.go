// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// ErrControlCoverageMissing indicates one or more operating-status
// controls do not have a corresponding evidence file in the bundle.
// SDK verify step 9 raises this; bundle producers MUST ensure every
// operating control has evidence.
var ErrControlCoverageMissing = errors.New("frameworks: operating-status controls missing evidence in bundle")

// CoverageResult is the structured outcome of CoverageCheck.
//
// # Description
//
// Missing lists in-scope, operating-status controls whose evidence
// path was not found in the bundle filesystem. Skipped lists
// designed- or roadmap-status controls — these are NOT required by
// the coverage check (epic lock 7 status-versioning rule).
type CoverageResult struct {
	// Missing lists the IDs of operating-status controls that have no
	// evidence file at their expected path.
	Missing []string

	// SkippedDesigned lists designed-status controls (informational —
	// not part of the coverage assertion).
	SkippedDesigned []string

	// SkippedRoadmap lists roadmap-status controls (informational —
	// not part of the coverage assertion).
	SkippedRoadmap []string
}

// EvidencePathResolver maps a (framework_id, control_id) pair to the
// expected path inside the bundle filesystem. Producers may use
// non-default layouts; the resolver lets a caller override the
// default convention.
type EvidencePathResolver func(frameworkID FrameworkID, controlID string) string

// DefaultEvidencePath returns the conventional in-bundle path for a
// control's evidence file.
//
// # Description
//
// Format: "chain_extracts/<framework_id_lowered>_<control_id_sanitized>.jsonl"
//
// Sanitization on the control ID:
//   - lowercased
//   - "/" and " " replaced with "_"
//   - "§" replaced with "sec_" (HIPAA-style § prefixes)
//   - "(" and ")" stripped
//
// Examples:
//
//	soc2-2017 + CC6.1               -> chain_extracts/soc2-2017_cc6.1.jsonl
//	hipaa     + §164.312(b)         -> chain_extracts/hipaa_sec_164.312b.jsonl
//	gdpr      + Art.5(1)(f)         -> chain_extracts/gdpr_art.51f.jsonl
//
// This is the producer-facing convention. CV-04's PinForBundle
// follows this format; CV-05's bundle verifier consumes it. A producer
// shipping a non-default layout supplies an EvidencePathResolver
// instead.
func DefaultEvidencePath(frameworkID FrameworkID, controlID string) string {
	clean := strings.ToLower(controlID)
	clean = strings.ReplaceAll(clean, "§", "sec_")
	clean = strings.ReplaceAll(clean, "/", "_")
	clean = strings.ReplaceAll(clean, " ", "_")
	clean = strings.ReplaceAll(clean, "(", "")
	clean = strings.ReplaceAll(clean, ")", "")
	return fmt.Sprintf("chain_extracts/%s_%s.jsonl", strings.ToLower(string(frameworkID)), clean)
}

// CoverageCheck asserts that every operating-status control in f has
// a corresponding evidence file in bundleFS.
//
// # Description
//
// SDK verify step 9's second half. Verifier flow:
//
//	fwk, err := frameworks.LoadFrameworkFromBundle(bundleFS, manifest.FrameworkVersion)
//	if err != nil { return err }
//	result, err := frameworks.CoverageCheck(fwk, bundleFS, nil)
//	if errors.Is(err, frameworks.ErrControlCoverageMissing) {
//	    return fmt.Errorf("bundle missing evidence for %v: %w", result.Missing, err)
//	}
//
// Designed and roadmap status controls are NOT required (epic lock 7
// status-versioning rule). A producer who ships an
// operating-status-only bundle is conformant; the coverage check
// only fires on missing operating evidence.
//
// # Inputs
//
//   - f: the loaded framework (post LoadFrameworkFromBundle).
//   - bundleFS: the bundle's io/fs.FS (same as LoadFrameworkFromBundle).
//   - resolver: optional override for the path convention. Pass nil
//     for DefaultEvidencePath.
//
// # Outputs
//
//   - CoverageResult: Missing populated only when error is non-nil.
//   - error: ErrControlCoverageMissing if any operating control lacks
//     evidence; nil otherwise.
//
// # Limitations
//
//   - The check is path-existence only. It does NOT verify the
//     evidence file's contents (that is the chain verifier's job, not
//     the framework loader's).
//   - Out-of-scope controls (ControlsOutOfScope list) are not
//     checked — by definition the chain is not their evidence.
func CoverageCheck(f Framework, bundleFS fs.FS, resolver EvidencePathResolver) (CoverageResult, error) {
	if resolver == nil {
		resolver = DefaultEvidencePath
	}
	var result CoverageResult
	for _, c := range f.Controls {
		switch c.Status {
		case StatusOperating:
			path := resolver(f.FrameworkID, c.ID)
			if _, err := fs.Stat(bundleFS, path); err != nil {
				result.Missing = append(result.Missing, c.ID)
			}
		case StatusDesigned:
			result.SkippedDesigned = append(result.SkippedDesigned, c.ID)
		case StatusRoadmap:
			result.SkippedRoadmap = append(result.SkippedRoadmap, c.ID)
		}
	}
	if len(result.Missing) > 0 {
		return result, fmt.Errorf("%w: %v", ErrControlCoverageMissing, result.Missing)
	}
	return result, nil
}
