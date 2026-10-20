// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command aleutian-verify offline-verifies an Aleutian audit-chain
// export.
//
// # Mission
//
// The Go SDK shipping point for the Phase F cross-language smoke. Same
// CLI surface, same JSON output contract, same exit codes as the
// Python (aleutian_verification.__main__) and JS
// (sdk/verification-js/src/cli) SDK CLIs. The smoke diffs all three
// outputs over the same input — disagreement is a HARD FAIL.
//
// # Subcommands
//
//   - verify --anchor PATH --entries PATH [--max-entries N]
//
// # Output contract (LOCKED across Python + JS + Go SDKs)
//
//	{
//	  "status":        "valid" | "invalid",
//	  "chain_length":  int,
//	  "interface":     "go-sdk",
//	  "bundle_sha256": "<sha256 hex of entries file>",
//	  "reason":        string  (only when status="invalid"),
//	  "breaks":        []      (only when status="invalid")
//	}
//
// Top-level keys sorted alphabetically + serialized as a single line
// so cross-SDK byte-diff is meaningful.
//
// # Exit codes
//
//	0 valid
//	1 invalid (chain verify returned valid=false)
//	2 usage error
//	3 IO / parse error
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	sdk "github.com/aleutian-ai/verification-go"
)

const interfaceName = "go-sdk"

// Stable exit codes. Scripts depend on these.
const (
	exitValid     = 0
	exitInvalid   = 1
	exitUsage     = 2
	exitIOOrParse = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point. Split out from main() so unit tests
// can exercise the CLI in-process and capture stdout.
func run(argv []string, stdout, stderr io.Writer) int {
	if len(argv) == 0 {
		printUsage(stderr)
		return exitUsage
	}
	switch argv[0] {
	case "-h", "--help":
		printUsage(stderr)
		return exitValid
	case "verify":
		return runVerify(argv[1:], stdout, stderr)
	case "bundle":
		return runBundle(argv[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", argv[0])
		printUsage(stderr)
		return exitUsage
	}
}

func runVerify(argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		anchorPath   string
		entriesPath  string
		manifestPath string
		maxEntries   int
	)
	var prevAnchorHash string
	fs.StringVar(&anchorPath, "anchor", "", "Path to anchor JSON file")
	fs.StringVar(&entriesPath, "entries", "", "Path to exported entries JSON")
	fs.StringVar(&prevAnchorHash, "previous-anchor-hash", "",
		"Hex chain_hash of the anchor preceding --anchor (required for non-genesis anchors; "+
			"genesis anchors auto-fill from SeedAnchorHash)")
	fs.StringVar(&manifestPath, "manifest", "",
		"Optional path to a published trust-manifest JSON. When set, its root signature is "+
			"verified offline and a freshness advisory (version/date/age) is added to the output. "+
			"Advisory only — never changes the exit code.")
	fs.IntVar(&maxEntries, "max-entries", 0, "Cap entries processed (0 = no cap)")
	if err := fs.Parse(argv); err != nil {
		return exitUsage
	}
	if anchorPath == "" || entriesPath == "" {
		fmt.Fprintln(stderr, "--anchor and --entries are required")
		return exitUsage
	}

	// Optional offline manifest freshness advisory. Computed once and
	// attached to EVERY output path. Advisory only: a manifest failure
	// (unreadable / bad root signature) is surfaced in the manifest block
	// but NEVER changes the exit code, which is driven by chain verify.
	manifestBlock := loadManifestAdvisory(manifestPath)
	emitR := func(r resultOut) {
		r.Manifest = manifestBlock
		emit(stdout, r)
	}

	bundleSha := safeSHA256(entriesPath)

	anchor, err := sdk.LoadAnchor(anchorPath)
	if err != nil {
		emitR(resultOut{
			Status:       "invalid",
			ChainLength:  0,
			BundleSHA256: bundleSha,
			Reason:       fmt.Sprintf("load anchor: %v", err),
		})
		return exitIOOrParse
	}
	entries, err := sdk.LoadExportedEntries(entriesPath)
	if err != nil {
		emitR(resultOut{
			Status:       "invalid",
			ChainLength:  0,
			BundleSHA256: bundleSha,
			Reason:       fmt.Sprintf("load entries: %v", err),
		})
		return exitIOOrParse
	}

	res, err := sdk.VerifyChainOffline(context.Background(), entries, sdk.ChainVerifyOptions{
		Anchor:             &anchor,
		PreviousAnchorHash: prevAnchorHash,
		MaxEntries:         maxEntries,
		MaxBreaks:          100,
	})
	if err != nil {
		// Empty entries is the only error VerifyChainOffline returns
		// (everything else folds into result.Valid=false).
		if errors.Is(err, sdk.ErrEmptyEntries) {
			emitR(resultOut{
				Status:       "invalid",
				ChainLength:  0,
				BundleSHA256: bundleSha,
				Reason:       "entries are empty",
			})
			return exitInvalid
		}
		emitR(resultOut{
			Status:       "invalid",
			ChainLength:  0,
			BundleSHA256: bundleSha,
			Reason:       fmt.Sprintf("verify: %v", err),
		})
		return exitIOOrParse
	}

	if res.Valid {
		emitR(resultOut{
			Status:       "valid",
			ChainLength:  res.EntriesVerified,
			BundleSHA256: bundleSha,
		})
		return exitValid
	}

	reason := "unspecified verification failure"
	var breaks []breakOut
	if len(res.Breaks) > 0 {
		first := res.Breaks[0]
		reason = fmt.Sprintf("%s at position %d", first.BreakType, first.Position)
		breaks = make([]breakOut, 0, len(res.Breaks))
		for _, b := range res.Breaks {
			breaks = append(breaks, breakOut{
				Position:  b.Position,
				EntryID:   b.EntryID,
				BreakType: b.BreakType,
			})
		}
	}
	emitR(resultOut{
		Status:       "invalid",
		ChainLength:  res.EntriesVerified,
		BundleSHA256: bundleSha,
		Reason:       reason,
		Breaks:       breaks,
	})
	return exitInvalid
}

// resultOut is the locked JSON contract. JSON tags pin field names so
// renaming a Go field doesn't break the cross-SDK byte-diff.
type resultOut struct {
	BundleSHA256 string       `json:"bundle_sha256"`
	ChainLength  int          `json:"chain_length"`
	Interface    string       `json:"interface"`
	Manifest     *manifestOut `json:"manifest,omitempty"`
	Status       string       `json:"status"`
	Reason       string       `json:"reason,omitempty"`
	Breaks       []breakOut   `json:"breaks,omitempty"`
}

type breakOut struct {
	BreakType string `json:"break_type"`
	EntryID   string `json:"entry_id"`
	Position  int    `json:"position"`
}

// manifestOut is the optional offline trust-manifest freshness advisory
// (chainlinker_modernization_12f_e / ADR-029 §D5). Present only when
// --manifest is supplied. Fields mirror the Python + JS SDK CLIs.
//
// On a manifest load/verify failure, only Error is populated; the chain
// verdict and exit code are unaffected (freshness is advisory).
type manifestOut struct {
	Version        int64
	GeneratedAt    string
	AgeDays        int64
	Stale          bool
	RevocationNote string
	Error          string
}

// MarshalJSON emits either the error shape ({"error": ...}) or the full
// success shape, matching the Python + JS CLIs' field presence exactly. A
// plain struct with omitempty would silently DROP the common non-stale
// case (stale=false, age_days=0), diverging from the other two SDKs which
// always emit those fields (per-ticket review finding).
func (m manifestOut) MarshalJSON() ([]byte, error) {
	if m.Error != "" {
		return json.Marshal(struct {
			Error string `json:"error"`
		}{m.Error})
	}
	return json.Marshal(struct {
		Version        int64  `json:"version"`
		GeneratedAt    string `json:"generated_at"`
		AgeDays        int64  `json:"age_days"`
		Stale          bool   `json:"stale"`
		RevocationNote string `json:"revocation_note"`
	}{m.Version, m.GeneratedAt, m.AgeDays, m.Stale, m.RevocationNote})
}

// loadManifestAdvisory reads + root-signature-verifies a published trust
// manifest from a local path (offline; no network) and returns its
// freshness advisory. Returns nil when no path is supplied. A failure is
// captured in the Error field rather than surfaced as a process error —
// freshness is advisory and must never change the exit code.
//
// The CLI is a one-shot stateless verifier, so lastSeenVersion is -1
// (rollback detection disabled; see EvaluateManifestFreshness).
func loadManifestAdvisory(path string) *manifestOut {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return &manifestOut{Error: fmt.Sprintf("read manifest: %v", err)}
	}
	m, err := sdk.ParseAndVerifyTrustManifest(raw)
	if err != nil {
		return &manifestOut{Error: fmt.Sprintf("verify manifest: %v", err)}
	}
	f := sdk.EvaluateManifestFreshness(m.Version, m.GeneratedAt.UnixMilli(), time.Now().UTC().UnixMilli(), -1)
	return &manifestOut{
		Version:        f.Version,
		GeneratedAt:    f.GeneratedDate(),
		AgeDays:        f.AgeDays,
		Stale:          f.Stale,
		RevocationNote: f.RevocationNote(),
	}
}

// emit marshals + writes one JSON line. encoding/json already emits
// struct fields in declaration order, so we declare them alphabetically
// in resultOut to match Python+JS.
func emit(w io.Writer, r resultOut) {
	r.Interface = interfaceName
	b, _ := json.Marshal(r)
	fmt.Fprintln(w, string(b))
}

// safeSHA256 hashes the entries file. Returns empty string if the
// file is unreadable — hashing is never the failure mode.
func safeSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: aleutian-verify verify --anchor PATH --entries PATH [--max-entries N]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Verify an extracted chain export (anchor + entries JSON).")
	fmt.Fprintln(w, "Emits a single JSON line to stdout matching the locked Phase F contract.")
	fmt.Fprintln(w, "Exit 0 = valid, 1 = invalid, 2 = usage error, 3 = IO/parse error.")
}
