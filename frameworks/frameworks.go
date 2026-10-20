// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package frameworks defines the typed schema for Aleutian's versioned
// compliance control maps and exposes a loader that verifies each map's
// SHA-512 self-attestation hash before returning it.
//
// Aleutian is an AI evidentiary audit trail product, not a compliance
// product. Each control map ships a scope-bounded view of a framework:
// only controls for which a cryptographic event chain is *relevant
// evidence* are included. Every Control carries WhatWeProve and
// WhatWeDontProve strings so the boundary is explicit. Controls that
// are NOT chain-evidenced (board governance, vendor management, etc.)
// are listed in ControlsOutOfScope so an auditor sees exactly what the
// bundle does and does not claim.
//
// See ticket compliance_versioning_00_epic, lock 9, for the scope
// contract.
package frameworks

// FrameworkID is the stable, opaque identifier for a compliance
// framework (e.g. "soc2-2017", "gdpr", "hipaa"). Bundles pin to a
// (FrameworkID, VersionID) pair via the framework_version manifest
// field; SDK verifiers look up the embedded slice by VersionID.
type FrameworkID string

// VersionID is the dated snapshot of a framework's control map, in the
// form "<framework_id>@<YYYYMMDD>" (e.g. "soc2-2017@20260301").
//
// # Description
//
// Every shipped controls.json carries its own VersionID. Once a
// version directory ships in a bundle, it is sealed forever — never
// edited, never deleted. Any correction creates a new dated version.
// This is the durable evidence contract: a bundle produced today must
// remain verifiable for the life of its retention (7 years prod) even
// as the framework evolves.
type VersionID string

// ControlStatus mirrors the website's 🟢 🟡 🔵 markers on
// aleutian.ai/compliance.
//
// # Description
//
//   - operating — control is in production today; the bundle coverage
//     check REQUIRES evidence for it.
//   - designed — control is fully designed but not yet operating; the
//     coverage check does NOT require evidence.
//   - roadmap — future capability; not part of the coverage check at all.
//
// # Limitations
//
//   - Status changes trigger a new dated framework version (see
//     compliance_versioning_19_status_field_versioning_policy).
//   - Unknown status strings are rejected at load time so older SDKs
//     fail fast against future-status JSON rather than silently
//     miscategorizing.
type ControlStatus string

const (
	StatusOperating ControlStatus = "operating"
	StatusDesigned  ControlStatus = "designed"
	StatusRoadmap   ControlStatus = "roadmap"
)

// IsKnown reports whether s is one of the three locked status values.
//
// # Description
//
// Loader uses IsKnown to enforce the forward-compatibility rule: a
// bundle that ships with a status value this SDK doesn't recognize
// fails closed at load time. Better to refuse to verify than to
// silently treat an unknown status as if it were "operating".
//
// # Inputs
//
//   - s: a status string read from controls.json.
//
// # Outputs
//
//   - bool: true if s is operating, designed, or roadmap.
func (s ControlStatus) IsKnown() bool {
	switch s {
	case StatusOperating, StatusDesigned, StatusRoadmap:
		return true
	}
	return false
}

// Control is a single in-scope compliance control entry.
//
// # Description
//
// Per epic lock 9, every in-scope control entry MUST populate
// WhatWeProve and WhatWeDontProve. These two strings are the
// product's honesty contract: WhatWeProve states the mathematical
// claim the chain demonstrates; WhatWeDontProve states the boundary
// (what an auditor must establish through means other than the chain).
type Control struct {
	ID              string        `json:"id"`
	Title           string        `json:"title"`
	Category        string        `json:"category"`
	Status          ControlStatus `json:"status"`
	WhatWeProve     string        `json:"what_we_prove"`
	WhatWeDontProve string        `json:"what_we_dont_prove"`
}

// OutOfScopeControl names a control that is NOT chain-evidenced.
//
// # Description
//
// Listing out-of-scope controls in the framework manifest is the
// counterpart to WhatWeDontProve at the framework level: it tells the
// auditor "these controls exist in the framework, and we are
// deliberately not making evidence claims about them."
type OutOfScopeControl struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// Framework is a fully-loaded, self-attested control map for one
// versioned snapshot of one compliance framework.
//
// # Description
//
// Fields appear in alphabetical order in the JSON encoding for
// canonical reproducibility (RFC 8785 shape). ControlsSHA512Hex covers
// the canonical bytes of the entire object with ControlsSHA512Hex
// itself excluded — see CanonicalBytesForHashing.
//
// # Limitations
//
//   - FrameworkPublishedAt and AleutianSnapshotAt are ISO-8601 date
//     strings, not time.Time. Date strings serialize byte-stably
//     across languages; time.Time encoders vary.
//   - Once a Framework instance has been shipped in a customer bundle,
//     its underlying controls.json is immutable. Mutating Controls or
//     ControlsOutOfScope at runtime invalidates the self-attestation.
type Framework struct {
	AleutianSnapshotAt   string              `json:"aleutian_snapshot_at"`
	Controls             []Control           `json:"controls"`
	ControlsOutOfScope   []OutOfScopeControl `json:"controls_out_of_scope"`
	ControlsSHA512Hex    string              `json:"controls_sha512_hex"`
	FrameworkID          FrameworkID         `json:"framework_id"`
	FrameworkPublishedAt string              `json:"framework_published_at"`
	VersionID            VersionID           `json:"version_id"`
}
