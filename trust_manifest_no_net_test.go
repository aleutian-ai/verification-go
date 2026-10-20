// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoNetworkImportsOutsideAllowlist enforces invariant 1 of
// `sdk_privacy_invariants_spec`: the verification SDK does not make
// network calls unless the caller explicitly opted in via a
// from-url-style constructor.
//
// # What it does
//
// Walks every .go file under sdk/verification-go/ EXCLUDING the
// allowlist below, parses it via go/ast, and fails if it imports
// any of the network packages in `bannedImports` below. This
// catches a class of footguns where a future contributor
// accidentally adds an http.Get() to chain.go and turns the
// verifier into a privacy-leak surface.
//
// # The allowlist
//
// Each entry must be justified by an actual customer-facing
// network operation. If you add a file here, leave a one-line
// comment explaining the operation and link the ticket that
// authorized it.
//
// # Scope tightened (Arch review H6)
//
// Previously this test only scanned `net` and `net/http`. A
// contributor who pulled in `golang.org/x/net/*`, `nhooyr.io/websocket`,
// or any other third-party transport defeated it. The banned set
// below is the union of every transport package the SDK module
// could legitimately reach for; new ones must be added explicitly
// or refused at the allowlist layer.
func TestNoNetworkImportsOutsideAllowlist(t *testing.T) {
	// Each allowlist entry is a path RELATIVE to the SDK module
	// root (i.e., relative to this test file's directory).
	allowlist := map[string]string{
		// `trust_manifest_from_url_v3.go` is THE intentional
		// network surface this allowlist exists to define. Per
		// `sdk_trust_manifest_from_url_go`.
		"trust_manifest_from_url_v3.go": "trust_manifest_from_url ticket — primary network entry point",

		// `trust_manifest.go` is the older (pre-v1-spec) SAR
		// trust-manifest loader. Same network operation; the
		// v3 from-url path supersedes it but the old one stays
		// in-tree for backwards compat until customers cut
		// over.
		"trust_manifest.go": "legacy SAR trust-manifest loader (pre-v1-spec)",

		// `webhook.go` exports webhook-signature verification
		// helpers that take http.Request types. It does NOT
		// itself make network calls — it consumes a request the
		// CALLER fetched. The import is for type signatures
		// only.
		"webhook.go": "type signatures for caller-supplied http.Request — no network calls made",

		// `cmd/aleutian-disclosure-decrypt/emit.go` is the
		// disclosure-event emit pipeline (compliance_tier2_30
		// Phase B / C1). It POSTs to the customer-side
		// `audit-api` to record an unseal. Legitimate per the
		// disclosure-CLI design doc; runs in a separate binary
		// from the library SDK.
		"cmd/aleutian-disclosure-decrypt/emit.go": "disclosure event chain emit (compliance_tier2_30)",
	}

	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	// Banned import paths. Anything that can open a socket, send a
	// packet, or otherwise initiate IO with a remote endpoint.
	// Crypto/tls is technically only banned if used to initiate a
	// connection (Dial); type signatures are fine. The allowlisted
	// files use these legitimately.
	bannedImports := map[string]bool{
		// Standard library
		"net":           true,
		"net/http":      true,
		"net/http/cgi":  true,
		"net/http/fcgi": true,
		"net/rpc":       true,
		"net/smtp":      true,
		"net/textproto": true,
		"crypto/tls":    true,
		// golang.org/x/* network packages
		"golang.org/x/net":           true,
		"golang.org/x/net/http2":     true,
		"golang.org/x/net/http3":     true,
		"golang.org/x/net/ipv4":      true,
		"golang.org/x/net/ipv6":      true,
		"golang.org/x/net/proxy":     true,
		"golang.org/x/net/websocket": true,
		// Common third-party transport libraries
		"github.com/valyala/fasthttp":  true,
		"nhooyr.io/websocket":          true,
		"github.com/gorilla/websocket": true,
		"github.com/go-resty/resty":    true,
	}

	fset := token.NewFileSet()
	var violations []string

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip non-Go files, test files (tests can import what
		// they want), and node_modules-style nested vendoring.
		if d.IsDir() {
			name := d.Name()
			if name == "node_modules" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// Normalize to forward slashes for the allowlist match
		// (works on macOS / Linux; the SDK ships POSIX-only).
		rel = filepath.ToSlash(rel)
		if _, ok := allowlist[rel]; ok {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			// Parsing failures shouldn't be silent — surface
			// them so a malformed file is flagged but doesn't
			// prevent the rest of the scan.
			t.Logf("warn: parse %s: %v", rel, err)
			return nil
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if bannedImports[path] {
				violations = append(violations, fmt.Sprintf("%s imports %q (not in allowlist)", rel, path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(violations) > 0 {
		t.Fatalf("SDK files import network packages outside the allowlist:\n  - %s\n\nIf the import is intentional, add an allowlist entry to %s with a ticket reference.",
			strings.Join(violations, "\n  - "),
			"trust_manifest_no_net_test.go")
	}
}
