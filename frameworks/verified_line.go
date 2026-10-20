// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

import "fmt"

// FormatVerifiedLine returns the single-line VERIFIED output the
// SDK CLI emits on successful bundle verification.
//
// # Description
//
// Locked format (CV-08, 2026-05-31):
//
//	VERIFIED · <framework_display_name> / <version_id>
//
// Examples:
//
//	VERIFIED · SOC 2 / soc2-2017@20260531
//	VERIFIED · HIPAA / hipaa@20260531
//
// For legacy v2 bundles (no framework_version pinned), pass empty
// strings — the function returns `VERIFIED` with no suffix, matching
// the backward-compat contract from compliance_bundle_format_spec.md.
//
// All three SDKs (Go, Python, JS) MUST emit byte-identical strings
// for the same inputs so that auditor working papers can be diffed
// across SDK languages. CV-09 will enforce this with golden vectors.
//
// # Inputs
//
//   - frameworkDisplayName: human-readable framework name from the
//     bundle manifest (e.g. "SOC 2", "GDPR", "EU-AI-Act"). May be
//     empty for legacy v2 bundles.
//   - version: the CV-02 framework_version string
//     ("<framework_id>@<YYYYMMDD>"). May be empty for legacy v2 bundles.
//
// # Outputs
//
//   - string: the formatted VERIFIED line, suitable to print to
//     stdout. No trailing newline.
//
// # Limitations
//
//   - If only one of (frameworkDisplayName, version) is empty, the
//     function still emits `VERIFIED · <name> / <version>` because
//     mixed empty/populated is a producer bug worth surfacing as
//     visible breakage, not silent normalization.
func FormatVerifiedLine(frameworkDisplayName string, version VersionID) string {
	if frameworkDisplayName == "" && version == "" {
		return "VERIFIED"
	}
	return fmt.Sprintf("VERIFIED · %s / %s", frameworkDisplayName, string(version))
}

// FormatExplainBlock returns the per-bundle detail block the SDK CLI
// emits when called with --explain.
//
// # Description
//
// Locked format (CV-08, 2026-05-31):
//
//	Framework:              <framework_id>
//	Version:                <version_id>
//	Framework published at: <framework_published_at>
//	Aleutian snapshot at:   <aleutian_snapshot_at>
//	In-scope controls:      <n>
//	Out-of-scope controls:  <n>
//
// Both date fields are surfaced separately so an auditor sees both
// the standard's effective text date and Aleutian's snapshot date.
// No trailing newline.
//
// # Inputs
//
//   - f: the Framework loaded from the bundle (post step 9).
//
// # Outputs
//
//   - string: the formatted multi-line --explain block.
func FormatExplainBlock(f Framework) string {
	return fmt.Sprintf(
		"Framework:              %s\nVersion:                %s\nFramework published at: %s\nAleutian snapshot at:   %s\nIn-scope controls:      %d\nOut-of-scope controls:  %d",
		f.FrameworkID,
		f.VersionID,
		f.FrameworkPublishedAt,
		f.AleutianSnapshotAt,
		len(f.Controls),
		len(f.ControlsOutOfScope),
	)
}
