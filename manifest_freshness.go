// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"fmt"
	"time"
)

// ManifestFreshnessMaxAgeDays is the soft-warn threshold (ADR-029 §D5).
//
// A trust manifest whose age exceeds this many days is reported as
// STALE. Staleness is advisory only in v1 — it NEVER changes signature
// validity and NEVER fails a verification. The threshold exists so the
// offline "CISO motion" (`aleutian-verify --manifest`) surfaces the fact
// that a key revoked more recently than the manifest's generation date
// cannot be reflected in the verdict.
const ManifestFreshnessMaxAgeDays = 30

// ManifestFreshness is the structured freshness verdict for a trust
// manifest, computed against a reference "now".
//
// # Description
//
// The trust manifest is root-signed and carries a monotonic Version and
// a GeneratedAtMs wall-clock stamp. A verifier holding a manifest can
// only reflect revocations known AT its generation date: a key revoked
// afterwards is invisible ("the CRL problem" for offline verification).
// ManifestFreshness makes that limitation explicit rather than emitting a
// bare "valid".
//
// All fields are advisory in v1 (ADR-029 §D5): they inform the verdict
// string and let a STATEFUL caller act on RollbackDetected, but the SDK
// never converts any of them into a hard verification failure.
type ManifestFreshness struct {
	// Version is the manifest's monotonic version integer.
	Version int64
	// GeneratedAtMs is the manifest's generation wall-clock time
	// (UnixMilli, UTC), as root-signed into the manifest.
	GeneratedAtMs int64
	// AgeDays is floor((now - GeneratedAtMs) / 1 day), clamped to 0 for a
	// manifest whose generation stamp is in the future relative to now
	// (clock skew / a freshly minted manifest).
	AgeDays int64
	// Stale is true when AgeDays > ManifestFreshnessMaxAgeDays. Advisory
	// only — never gates validity.
	Stale bool
	// RollbackDetected is true only for a STATEFUL evaluation (a
	// non-negative lastSeenVersion was supplied) where the manifest's
	// Version is LOWER than the last version this verifier saw — i.e. a
	// suppressed/rolled-back manifest update that could hide a revocation.
	// A stateless one-shot verifier (npx-style) cannot detect this and
	// always reports false; its only defense is the reported date.
	RollbackDetected bool
}

// EvaluateManifestFreshness computes the advisory freshness verdict for a
// trust manifest.
//
// # Description
//
// Pure function over the manifest's signed Version + GeneratedAtMs and a
// caller-supplied reference clock. Never fetches, never mutates, never
// fails. Mirrors the Python (evaluate_manifest_freshness) and JS
// (evaluateManifestFreshness) SDK helpers byte-for-byte via the shared
// golden vectors in sdk/testdata/manifest_freshness_golden.json.
//
// # Inputs
//
//   - version: the manifest's monotonic Version integer.
//   - generatedAtMs: the manifest's GeneratedAtMs (UnixMilli, UTC).
//   - nowMs: reference clock (UnixMilli, UTC); typically time.Now().
//   - lastSeenVersion: the highest manifest Version this verifier has
//     previously observed, for anti-rollback. Pass a NEGATIVE value
//     (e.g. -1) for a STATELESS verifier that keeps no history — rollback
//     detection is then disabled.
//
// # Outputs
//
//   - ManifestFreshness: the structured, advisory verdict.
//
// # Example
//
//	f := verification.EvaluateManifestFreshness(m.Version, m.GeneratedAt.UnixMilli(), time.Now().UnixMilli(), -1)
//	fmt.Println(f.VerdictLine())
//
// # Limitations
//
//   - Day granularity: AgeDays is a floor of whole days; sub-day skew is
//     not reflected.
//   - Rollback detection requires the caller to persist lastSeenVersion;
//     the SDK does not itself keep cross-process state.
//
// # Assumptions
//
//   - version/generatedAtMs originate from a manifest whose root
//     signature the caller has ALREADY verified. Freshness is orthogonal
//     to authenticity; this helper assumes the inputs are authentic.
func EvaluateManifestFreshness(version, generatedAtMs, nowMs, lastSeenVersion int64) ManifestFreshness {
	const msPerDay = int64(24 * 60 * 60 * 1000)

	ageMs := nowMs - generatedAtMs
	var ageDays int64
	if ageMs > 0 {
		ageDays = ageMs / msPerDay
	}

	return ManifestFreshness{
		Version:          version,
		GeneratedAtMs:    generatedAtMs,
		AgeDays:          ageDays,
		Stale:            ageDays > ManifestFreshnessMaxAgeDays,
		RollbackDetected: lastSeenVersion >= 0 && version < lastSeenVersion,
	}
}

// GeneratedDate returns the manifest generation date as a UTC YYYY-MM-DD
// string. This is the exact date form embedded in the verdict line and is
// byte-identical across the Go/Python/JS SDKs.
func (f ManifestFreshness) GeneratedDate() string {
	return time.UnixMilli(f.GeneratedAtMs).UTC().Format("2006-01-02")
}

// RevocationNote returns the freshness caveat clause WITHOUT asserting
// signature validity:
//
//	Revocation checked against trust manifest v{N} dated {YYYY-MM-DD} —
//	a key revoked after that date is not reflected.
//
// with ` [WARNING: manifest is {AgeDays} days old]` appended when Stale.
//
// Use this in a context that reports manifest freshness but does NOT
// itself establish that a signature verified — e.g. the offline chain CLI,
// which checks chain continuity + anchor binding, not signatures against
// the manifest. Byte-identical across the three SDKs (golden-asserted).
func (f ManifestFreshness) RevocationNote() string {
	note := fmt.Sprintf(
		"Revocation checked against trust manifest v%d dated %s — a key revoked after that date is not reflected.",
		f.Version, f.GeneratedDate(),
	)
	if f.Stale {
		note += fmt.Sprintf(" [WARNING: manifest is %d days old]", f.AgeDays)
	}
	return note
}

// VerdictLine returns the exact ADR-029 §D5 customer-facing verdict line
// for a VALID signature.
//
// # Description
//
// The canonical string is:
//
//	Signature valid. Revocation checked against trust manifest v{N} dated
//	{YYYY-MM-DD} — a key revoked after that date is not reflected.
//
// When the manifest is Stale, ` [WARNING: manifest is {AgeDays} days old]`
// is appended. The line is byte-identical across all three SDKs (asserted
// by the shared golden vectors) and never emits a bare "valid" — the
// revocation-freshness caveat is always present.
//
// Only emit this where signature validity has ALREADY been established;
// for freshness reporting that does not assert a verified signature, use
// RevocationNote.
//
// RollbackDetected is NOT reflected in this line: it is a separate signal
// a stateful caller acts on (e.g. rejecting a rolled-back manifest before
// it ever reaches a verdict). In v1 the SDK never hard-fails on it.
//
// # Outputs
//
//   - string: the verdict line described above.
func (f ManifestFreshness) VerdictLine() string {
	return "Signature valid. " + f.RevocationNote()
}
