// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Command aleutian-disclosure-decrypt unseals a Tier-2 Forensic
// compliance bundle on the customer's machine using their X-Wing
// private seed. This is the Apache-2.0 SDK build, distributed via
// `go install github.com/aleutian-ai/verification-go/cmd/aleutian-disclosure-decrypt@latest`.
//
// # Pipeline
//
//  1. Parse flags + strip leading positional bundle path.
//  2. Resolve --api-key (fail-fast unless --skip-emit).
//  3. Open the bundle ZIP, parse manifest.json, verify the bundle's
//     ML-DSA-65 signature against the embedded trust manifest BEFORE
//     reading any envelope file.
//  4. Derive the seed's pubkey fingerprint, filter the manifest's
//     tier2.sealed_envelopes_index for matching envelopes.
//  5. For each match: verify SHA-512 against manifest, call
//     github.com/aleutian-ai/verification-go/sarenvelope.Open, write
//     the recovered payload as one JSONL row.
//  6. POST a pii_disclosure_to_auditor event to
//     manifest.report_endpoint (5-min idempotency hash).
//
// # SDK build vs proprietary build
//
// This SDK build is BYTE-IDENTICAL at the wire-format level to the
// proprietary cmd/aleutian-disclosure-decrypt in the Aleutian
// monorepo, enforced by the cross-compat golden vector tests at
// AleutianEnterprise/test/cross_compat/.
//
// Feature parity with the proprietary build:
//
//   - --reseal-ephemeral mode is supported as of follow-up F2
//     (compliance_tier2_30d_followup_sdk_reseal). Resealed envelopes
//     are byte-identical to the proprietary build, enforced by the
//     bidirectional cross-compat tests at
//     AleutianEnterprise/test/cross_compat/.
//
// Differences from the proprietary build:
//
//   - None as of compliance_tier2_30c_followup_sdk_seedwrap closure
//     (2026-06-09). The SDK now supports passphrase-wrapped seeds via
//     `--seed-passphrase-env` using the
//     `github.com/aleutian-ai/verification-go/seedwrap` package, which
//     both builds share.
//
// # Flags
//
//   - <bundle.zip>              (positional) Path to the compliance
//     bundle ZIP.
//   - --out PATH                Output directory. Created if missing.
//   - --seed PATH               Path to the raw-PEM X-Wing private
//     seed (passphrase-wrapped seeds are NOT supported in the SDK
//     build — see "Differences from the proprietary build" above).
//   - --api-key SPEC            env:VAR / file:PATH / <literal>.
//     The literal form prints a runtime WARN — it leaks into
//     ps/proc/cmdline. Prefer env:VAR in CI.
//   - --endpoint URL            Override manifest.report_endpoint
//     for the disclosure-event emit.
//   - --skip-emit               Skip the chain-emit POST. Plaintext
//     stays on disk; audit trail is missing.
//   - --skip-verify             Bypass the bundle ML-DSA-65
//     signature verify (dev fixtures only).
//   - --reseal-ephemeral PATH   Auditor X-Wing public key PEM.
//     Re-encrypts each opened row under that key and writes the
//     resealed envelope to <out>/resealed/. NEVER writes plaintext
//     to disk. Emits a distinct compliance.tier2_resealed_for_auditor
//     chain event.
//   - --print-fingerprint       Print the customer-pubkey
//     fingerprint derived from --seed and exit (no decryption).
//   - --verbose                 Emit per-envelope progress lines to
//     stderr; never payload bytes.
//   - --json                    Emit a stable structured summary on
//     stdout instead of human text.
//
// # Exit codes
//
// See exit_codes.go. Stable across SDK + proprietary releases.
package main
