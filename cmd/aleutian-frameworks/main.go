// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// aleutian-frameworks is a small introspection CLI for the embedded
// compliance framework control maps.
//
// # Usage
//
//	aleutian-frameworks list
//	aleutian-frameworks show <version_id>
//	aleutian-frameworks verify <path/to/controls.json>
//
// # Subcommands
//
//   - list: print every entry in the LATEST registry, one per line as
//     "<framework_id>\t<version_id>"
//   - show: load the embedded framework for <version_id> and print its
//     FormatExplainBlock output (multi-line, same shape an auditor sees
//     from `aleutian-verify --explain` once that CLI ships)
//   - verify: load a standalone controls.json file from disk, verify
//     its self-attestation hash, and print the explain block on success
//
// This CLI does NOT verify compliance bundles end-to-end — the full
// bundle verifier is downstream (export_bundle_job_* + the
// `aleutian-verify` follow-up). It exists so the compliance team and
// auditors can inspect what Aleutian claims for any embedded framework
// version without booting a bundle, and so the framework-side helpers
// (FormatExplainBlock, LoadFromEmbedded, LoadFromReader) have a real
// reference binary that exercises them.
package main

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/aleutian-ai/verification-go/frameworks"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "list":
		listFrameworks(os.Stdout)
	case "show":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: aleutian-frameworks show <version_id>")
			os.Exit(2)
		}
		if err := showFramework(os.Stdout, frameworks.VersionID(os.Args[2])); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "verify":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: aleutian-frameworks verify <path/to/controls.json>")
			os.Exit(2)
		}
		if err := verifyControlsFile(os.Stdout, os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage(os.Stdout)
	default:
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, `aleutian-frameworks — introspect embedded compliance framework control maps

usage:
  aleutian-frameworks list
  aleutian-frameworks show <version_id>
  aleutian-frameworks verify <path/to/controls.json>

examples:
  aleutian-frameworks list
  aleutian-frameworks show soc2-2017@20260531
  aleutian-frameworks verify ./controls.json`)
}

func listFrameworks(w *os.File) {
	type row struct {
		fid string
		vid string
	}
	rows := make([]row, 0, len(frameworks.Latest))
	for fid, vid := range frameworks.Latest {
		rows = append(rows, row{string(fid), string(vid)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].fid < rows[j].fid })
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\n", r.fid, r.vid)
	}
}

func showFramework(w *os.File, vid frameworks.VersionID) error {
	f, err := frameworks.LoadFromEmbedded(vid)
	if err != nil {
		if errors.Is(err, frameworks.ErrUnknownVersion) {
			return fmt.Errorf("unknown framework version %q (run `aleutian-frameworks list` to see the available set)", vid)
		}
		return fmt.Errorf("load %q: %w", vid, err)
	}
	fmt.Fprintln(w, frameworks.FormatExplainBlock(f))
	return nil
}

func verifyControlsFile(w *os.File, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	f, err := frameworks.LoadFromReader(file)
	if err != nil {
		return fmt.Errorf("verify %s: %w", path, err)
	}
	fmt.Fprintln(w, "OK")
	fmt.Fprintln(w, frameworks.FormatExplainBlock(f))
	return nil
}
