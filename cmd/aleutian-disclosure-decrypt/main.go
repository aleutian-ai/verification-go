// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	cliName  = "aleutian-disclosure-decrypt"
	cliUsage = `Usage:
  ` + cliName + ` <bundle.zip> --seed <path> --out <dir> [flags]

REQUIRED:
  --seed <path>     Path to X-Wing private seed PEM. Raw or
                    passphrase-wrapped (PEM type ALEUTIAN
                    PASSPHRASE-WRAPPED PRIVATE KEY) both supported.
                    Pass "-" to read from stdin (recommended; keeps
                    the seed out of the filesystem):
                      op read "op://Vault/.../privkey_pem" | \
                        aleutian-disclosure-decrypt bundle.zip --seed - --out ./out/
                    For wrapped seeds, supply the passphrase via
                    --seed-passphrase-env <VAR> (CI) or omit to be
                    prompted on the controlling terminal.
  --out <dir>       Output directory for unsealed JSONL (created if missing).

DISCLOSURE EMIT:
  --api-key <spec>  API key spec for the audit-api disclosure emit:
                      env:VAR    read the key from env var VAR
                      file:PATH  read the key from PATH (trimmed)
                      <literal>  use the value verbatim
                    Required unless --skip-emit is set. The literal
                    form puts the key on the process command line;
                    avoid in CI.
  --endpoint <url>  Override the audit-api endpoint
                    (default: manifest.report_endpoint inside the bundle).
  --skip-emit       Skip the chain emit. Plaintext is still written;
                    only the audit-trail entry is omitted.

VERIFICATION:
  --skip-verify     Skip bundle ML-DSA-65 signature verification.
                    Production bundles must verify; this flag exists
                    for dev fixtures only.

EXIT CODES:
  0   success
  1   structural error
  2   no envelope matches the supplied seed
  3   AEAD failure (wrong key or tampered ciphertext)
  4   network error during disclosure emit (plaintext IS on disk)
  5   seed file error
  6   output directory not writable
  7   API auth/authz error
  99  internal error`
)

func main() {
	exitCode := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(exitCode)
}

func run(argv []string, stdout, stderr *os.File) int {
	bundlePath := ""
	rest := argv
	if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
		bundlePath = argv[0]
		rest = argv[1:]
	}

	fs := flag.NewFlagSet(cliName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, cliUsage)
	}
	var (
		seedPath         string
		outDir           string
		apiKeySpec       string
		endpointOverride string
		skipEmit         bool
		skipBundleVerify bool
		printFingerprint bool
		pubkeyPath       string
		verbose          bool
		jsonOutput       bool
		resealPubkeyPath string
	)
	fs.StringVar(&seedPath, "seed", "", "Path to X-Wing private seed PEM (required)")
	var seedPassphraseEnv string
	fs.StringVar(&seedPassphraseEnv, "seed-passphrase-env", "",
		"Env var holding the passphrase for a wrapped seed (PEM type "+
			"ALEUTIAN PASSPHRASE-WRAPPED PRIVATE KEY). Omit to prompt on "+
			"the controlling terminal.")
	fs.StringVar(&outDir, "out", "", "Output directory for unsealed JSONL (required)")
	fs.StringVar(&apiKeySpec, "api-key", "", "API key spec for audit-api emit (env:VAR / file:PATH / <literal>)")
	fs.StringVar(&endpointOverride, "endpoint", "", "Override the audit-api endpoint")
	fs.BoolVar(&skipEmit, "skip-emit", false, "Bypass the disclosure chain emit")
	fs.BoolVar(&skipBundleVerify, "skip-verify", false, "Bypass bundle ML-DSA-65 signature verification (dev fixtures only)")
	fs.BoolVar(&printFingerprint, "print-fingerprint", false, "Print the seed/pubkey fingerprint and exit (no bundle required)")
	fs.StringVar(&pubkeyPath, "pubkey", "", "Path to X-Wing public key PEM (only with --print-fingerprint)")
	fs.BoolVar(&verbose, "verbose", false, "Emit per-envelope progress lines to stderr (never payload bytes)")
	fs.BoolVar(&jsonOutput, "json", false, "Emit a stable structured summary on stdout instead of human text")
	fs.StringVar(&resealPubkeyPath, "reseal-ephemeral", "",
		"Path to auditor X-Wing public key PEM. Re-encrypts each row under "+
			"this key and writes sealed envelopes under <--out>/resealed/. "+
			"NEVER writes plaintext to disk.")

	if err := fs.Parse(rest); err != nil {
		return ExitStructural
	}

	if printFingerprint {
		return runPrintFingerprint(seedPath, pubkeyPath, bundlePath, outDir,
			apiKeySpec, endpointOverride, skipEmit, skipBundleVerify,
			resealPubkeyPath, stdout, stderr)
	}

	if bundlePath == "" {
		fmt.Fprintln(stderr, "exactly one positional argument required: <bundle.zip>")
		fs.Usage()
		return ExitStructural
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments after flags")
		fs.Usage()
		return ExitStructural
	}
	if seedPath == "" {
		fmt.Fprintln(stderr, "--seed is required")
		return ExitStructural
	}
	if outDir == "" {
		fmt.Fprintln(stderr, "--out is required")
		return ExitStructural
	}

	var apiKey string
	if !skipEmit {
		k, err := ResolveAPIKey(apiKeySpec)
		if err != nil {
			fmt.Fprintf(stderr, "api-key: %v\n", err)
			fmt.Fprintln(stderr, "tip: pass --skip-emit if the audit-trail emit should be skipped")
			return ExitAPIAuth
		}
		apiKey = k
		spec := strings.TrimSpace(apiKeySpec)
		if spec != "" && !strings.HasPrefix(spec, "env:") && !strings.HasPrefix(spec, "file:") {
			fmt.Fprintln(stderr, "WARN: --api-key was passed as a literal value; it is visible to ps/proc/cmdline. Use env:VAR or file:PATH in CI.")
		}
	}

	if skipBundleVerify {
		fmt.Fprintln(stderr, "WARN: --skip-verify is set; bundle signature is NOT being verified. Do not use against production bundles.")
	}
	if !skipBundleVerify && TrustRootIsPlaceholder() {
		fmt.Fprintln(stderr, "WARN: this SDK build ships a placeholder trust-root pubkey; trust manifest root_signature_b64 is accepted on faith. Bundle ML-DSA-65 signature verify still applies. Upgrade to a post-ceremony SDK release to enable root pinning.")
	}

	res, err := Unseal(UnsealRequest{
		BundlePath:           bundlePath,
		SeedPath:             seedPath,
		SeedPassphraseEnvVar: seedPassphraseEnv,
		OutDir:               outDir,
		SkipBundleVerify:     skipBundleVerify,
		Verbose:              verbose,
		VerboseSink:          stderr,
		ResealPubkeyPath:     resealPubkeyPath,
	})
	if err != nil {
		return mapErrorToExitCode(err, stderr)
	}

	if jsonOutput {
		emitJSONSummary(stdout, res, "")
	} else if res.ResealMode {
		fmt.Fprintf(stdout, "OK: resealed %d envelopes for fingerprint %s under auditor key %s\n",
			res.UnsealedCount, res.Fingerprint, res.AuditorFingerprint)
		fmt.Fprintf(stdout, "Resealed envelopes: %s\n", res.OutputPath)
		fmt.Fprintln(stdout, "No plaintext was written to disk.")
	} else {
		fmt.Fprintf(stdout, "OK: unsealed %d envelopes for fingerprint %s\n", res.UnsealedCount, res.Fingerprint)
		fmt.Fprintf(stdout, "Output: %s\n", res.OutputPath)
		fmt.Fprintln(stdout, "Plaintext written to disk. Treat as sensitive.")
	}

	if skipEmit {
		fmt.Fprintln(stderr, "WARN: --skip-emit is set; no disclosure chain entry was written.")
		return ExitOK
	}

	endpoint := endpointOverride
	if endpoint == "" {
		endpoint = res.ReportEndpoint
	}
	if endpoint == "" {
		fmt.Fprintln(stderr, "emit: no endpoint (manifest.report_endpoint is empty and --endpoint was not supplied)")
		fmt.Fprintln(stderr, "tip: pass --endpoint <url> or --skip-emit")
		return ExitNetwork
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	emitRes, eerr := EmitDisclosureEvent(ctx, DisclosureEmitRequest{
		Endpoint:           endpoint,
		APIKey:             apiKey,
		BundleID:           res.BundleID,
		Fingerprint:        res.Fingerprint,
		UnsealedRowCount:   res.UnsealedCount,
		ResealMode:         res.ResealMode,
		AuditorFingerprint: res.AuditorFingerprint,
		UnsealedAtMs:       time.Now().UTC().UnixMilli(),
	})
	if eerr != nil {
		fmt.Fprintln(stderr, "WARN: disclosure chain emit failed. Plaintext IS on disk; only the audit trail is missing.")
		fmt.Fprintf(stderr, "      %v\n", eerr)
		fmt.Fprintln(stderr, "      Re-running within the same 5-min window will retry idempotently.")
		return mapEmitErrorToExitCode(eerr)
	}

	if jsonOutput {
		emitJSONSummary(stdout, res, emitRes.ChainEntryID)
	} else {
		fmt.Fprintf(stdout, "Chain entry: %s\n", emitRes.ChainEntryID)
	}
	return ExitOK
}

// runPrintFingerprint is the SDK CLI's --print-fingerprint subcommand
// entry point. Mirrors the proprietary build's signature; rejects any
// combination with bundle-processing flags.
func runPrintFingerprint(
	seedPath, pubkeyPath, bundlePath, outDir, apiKeySpec, endpointOverride string,
	skipEmit, skipBundleVerify bool, resealPubkeyPath string,
	stdout, stderr *os.File,
) int {
	if bundlePath != "" || outDir != "" || apiKeySpec != "" ||
		endpointOverride != "" || skipEmit || skipBundleVerify ||
		resealPubkeyPath != "" {
		fmt.Fprintln(stderr, "--print-fingerprint must not be combined with bundle-processing flags "+
			"(<bundle.zip>, --out, --api-key, --endpoint, --skip-emit, --skip-verify, --reseal-ephemeral)")
		return ExitStructural
	}
	fp, err := PrintFingerprint(PrintFingerprintRequest{
		SeedPath:   seedPath,
		PubkeyPath: pubkeyPath,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%s\n", err)
		if errors.Is(err, ErrSeedFile) {
			return ExitSeedFileError
		}
		return ExitInternal
	}
	fmt.Fprintln(stdout, fp)
	return ExitOK
}

// emitJSONSummary writes a stable structured-output record to stdout.
// Schema matches the proprietary build (cross-build parity).
func emitJSONSummary(stdout *os.File, res *UnsealResult, chainEntryID string) {
	type out struct {
		BundleID           string `json:"bundle_id"`
		Fingerprint        string `json:"fingerprint"`
		UnsealedCount      int    `json:"unsealed_count"`
		OutputPath         string `json:"output_path"`
		ResealMode         bool   `json:"reseal_mode"`
		AuditorFingerprint string `json:"auditor_fingerprint,omitempty"`
		ChainEntryID       string `json:"chain_entry_id,omitempty"`
	}
	b, _ := json.Marshal(out{
		BundleID:           res.BundleID,
		Fingerprint:        res.Fingerprint,
		UnsealedCount:      res.UnsealedCount,
		OutputPath:         res.OutputPath,
		ResealMode:         res.ResealMode,
		AuditorFingerprint: res.AuditorFingerprint,
		ChainEntryID:       chainEntryID,
	})
	fmt.Fprintln(stdout, string(b))
}

// mapErrorToExitCode translates an Unseal error to its exit code.
// The wrong-key / no-matching-key paths share the same user-facing
// message to deny a fingerprint oracle — identical contract to the
// proprietary build.
func mapErrorToExitCode(err error, stderr *os.File) int {
	switch {
	case errors.Is(err, ErrStructural):
		fmt.Fprintf(stderr, "%s\n", err)
		return ExitStructural
	case errors.Is(err, ErrSeedFile):
		fmt.Fprintf(stderr, "%s\n", err)
		return ExitSeedFileError
	case errors.Is(err, ErrOutputPermission):
		fmt.Fprintf(stderr, "%s\n", err)
		return ExitOutputPermission
	case errors.Is(err, ErrNoMatchingKey):
		fmt.Fprintln(stderr, oracleSafeMessage)
		return ExitNoMatchingKey
	case errors.Is(err, ErrAEADFailure):
		fmt.Fprintln(stderr, oracleSafeMessage)
		return ExitAEADFailure
	default:
		fmt.Fprintf(stderr, "internal error: %v\n", err)
		return ExitInternal
	}
}

func mapEmitErrorToExitCode(err error) int {
	switch {
	case errors.Is(err, ErrAPIKeyMissing), errors.Is(err, ErrAPIAuth):
		return ExitAPIAuth
	case errors.Is(err, ErrNetwork):
		return ExitNetwork
	default:
		return ExitInternal
	}
}

const oracleSafeMessage = "this seed does not match any envelope in this bundle"
