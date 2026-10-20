// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package verification provides offline verification for Aleutian audit chain
// data: anchors, chain hashes, tombstones, V3 chain entries, export bundles and
// webhook signatures.
//
// # Overview
//
// This SDK lets a customer check the integrity and authenticity of their audit
// data without network access to Aleutian:
//
//	anchor.json   ──▶ VerifyAnchorLocally   ML-DSA-65 (FIPS 204) over the
//	                                        anchor's canonical JSON
//	entries.json  ──▶ VerifyChainOffline    chain hash v2: SHA-512 over
//	                                        "aleutian.chain.v2:" and the links
//	V3 entry      ──▶ VerifyChainEntryV3    ML-DSA-65 over a SHA-512 content
//	                                        hash, keys from a trust manifest
//	webhook       ──▶ VerifyWebhookSignature  HMAC-SHA-512
//
// The chain and anchor formats are specified in the open-source module
// github.com/aleutian-ai/proof (docs/format-spec.md), which is the reference
// implementation and verifies every format the platform writes. This SDK
// covers chain format v2 and anchors v1 to v4. It does not read chain format
// v4, v7 anchors or proof's bundle v2; for those, use proof.
//
// # Anchor Verification
//
// Anchors are signed checkpoints that attest to the state of an audit chain at
// a point in time. [VerifyAnchorLocally] checks an anchor's ML-DSA-65
// signature with an embedded public key, or one you pass in:
//
//	anchor, _ := verification.LoadAnchor("anchor.json")
//	if err := verification.VerifyAnchorLocally(ctx, anchor, nil); err != nil {
//	    log.Fatalf("anchor verification failed: %v", err)
//	}
//
// # Chain Hash Verification
//
// Chain hashes link audit entries into an append-only chain. Use
// [ComputeChainHash] to recompute one hash and [VerifyChainOffline] for a
// whole chain:
//
//	entries, _ := verification.LoadExportedEntries("export.json")
//	anchor, _ := verification.LoadAnchor("anchor.json")
//	result, err := verification.VerifyChainOffline(ctx, entries, verification.ChainVerifyOptions{
//	    Anchor:             &anchor,
//	    PreviousAnchorHash: verification.SeedAnchorHash, // for the first anchor; else the prior anchor's ChainHash
//	})
//	if err != nil {
//	    log.Fatalf("chain verification failed: %v", err)
//	}
//	if !result.Valid {
//	    log.Printf("found %d breaks in chain", len(result.Breaks))
//	}
//
// # Webhook Verification
//
// Webhooks are signed with HMAC-SHA-512. Use [IsValidWebhook] for simple
// validation or [VerifyWebhookSignature] for detailed control:
//
//	func handleWebhook(w http.ResponseWriter, r *http.Request) {
//	    if !verification.IsValidWebhook(r.Context(), r, os.Getenv("WEBHOOK_SECRET")) {
//	        http.Error(w, "Invalid webhook", http.StatusUnauthorized)
//	        return
//	    }
//	    // Process verified webhook...
//	}
//
// # Tombstone Detection
//
// A tombstone replaces an erased entry in the chain and keeps that entry's
// chain hash. Use [IsTombstone] to detect one:
//
//	for _, entry := range entries {
//	    if verification.IsTombstone(entry.EntryType, entry.EntryID) {
//	        // Handle tombstone entry
//	    }
//	}
//
// A tombstone's chain hash is taken as stored, so nothing links the entries
// before it to the ones after it. Entries up to the last tombstone are not
// verified by the chain (proof's format-spec §5.5).
//
// # Security Properties
//
//   - Signatures are ML-DSA-65 (FIPS 204), through github.com/cloudflare/circl
//   - Hashes are SHA-512; webhooks are HMAC-SHA-512, compared in constant time
//   - Webhook replay protection through timestamp validation
//   - No network access required, except for the optional runtime fetch of a
//     trust manifest ([NewTrustManifestFromURLV3])
//
// # Privacy Considerations
//
//   - Anchor.CompanyID identifies whose chain it is
//   - OfflineBreak.EntryID may correlate to personal data
//   - Do not log full anchors or verification results in production
//
// # Cross-SDK Compatibility
//
// The Python (aleutian-verification) and JavaScript (@aleutian/verification)
// SDKs produce identical output for chain hashes, webhook signatures and
// canonical JSON. The test vectors in testdata/ are shared across all of them.
//
// # V3 chain entry verification (chain_d, shipped 2026-05-11)
//
// The V3 chain extends Aleutian's audit surface to SAR (GDPR Art. 15/17
// Data Subject Access Request) events alongside the existing consent /
// processing-mode / expiry events. V3 uses ML-DSA-65 (FIPS 204
// post-quantum signatures) instead of v2's Ed25519.
//
// V3 verification entry point.
//
// # Production path — runtime-fetched trust manifest
//
// Customers usually obtain the trust manifest at runtime from a
// per-tenant URL the producer publishes:
//
//	manifest, err := verification.NewTrustManifestFromURLV3(ctx,
//	    "https://trust.<tenant>.example.com/aleutian/manifest.json",
//	    verification.WithTrustManifestEnv(verification.TrustManifestEnvProd),
//	    verification.WithTrustManifestLastSeenSerial(lastSeen), // anti-rollback
//	)
//	if err != nil { /* err carries a typed sentinel — see Err...V3 */ }
//
// The manifest is signed by Aleutian's bootstrap key (embedded in
// this SDK build) and lists the per-tenant chainAnchor signing keys
// with explicit validity windows. `VerifyChainEntryV3` calls into
// the manifest's timed lookup, so a chain entry whose timestamp
// falls outside a key's [valid_from_ms, valid_until_ms) window is
// rejected automatically (spec §8 backdating defense).
//
// # Advanced path — static map of pubkeys
//
// For tests, single-tenant deployments, or any scenario where the
// caller already has the pubkeys in hand:
//
//	manifest, err := verification.NewTrustManifestFromMapV3(map[string][]byte{
//	    "anchor-signer-2026-v1": publicKeyBytes,
//	})
//	if err != nil { /* operator misconfiguration */ }
//
// The map-backed manifest has no concept of validity windows, so
// `VerifyChainEntryV3` falls back to the unchecked pubkey lookup.
// Use this only when window enforcement is genuinely not needed.
//
//	entry := verification.SARFulfilledEntryV3{
//	    CompanyID:       "comp_01HK7AAAAAAAAAAAAAAAAAAAAA",
//	    EntryType:       verification.EventTypeSARFulfilledV3,
//	    SigningKeyID:    "anchor-signer-2026-v1",
//	    TimestampMs:     1715000000000,
//	    FulfillmentKind: verification.SARFulfillmentKindAccessV3,
//	    LegalBasis:      verification.LegalBasisFulfillArt15AccessV3,
//	    ManifestRoot:    "<SHA-512 hex of the export manifest>",
//	    RequestID:       "01HK7BBBBBBBBBBBBBBBBBBBBB",
//	    // ... + IntentEntryID, IdempotencyKeyHash, TombstoneCount
//	}
//
//	err = verification.VerifyChainEntryV3(ctx, entry,
//	    rowContentHashHex,   // 128 lowercase hex chars (SHA-512)
//	    rowSignatureBase64,  // ML-DSA-65 signature in standard base64
//	    manifest)
//	switch {
//	case err == nil:
//	    // verified
//	case errors.Is(err, verification.ErrSignatureInvalidV3):
//	    // forgery indicator
//	case errors.Is(err, verification.ErrContentHashMismatchV3):
//	    // entry payload tampered post-signing
//	case errors.Is(err, verification.ErrKeyNotInTrustManifestV3):
//	    // operator manifest freshness issue
//	}
//
// Error strings are intentionally content-agnostic (chain_d H2) — they
// surface only the sentinel and a function tag. For ops dashboards
// needing structured access (claimed/computed hashes, signing_key_id),
// use the typed errors in errors_v3.go via [errors.As].
//
// V3 cross-SDK golden vectors live at testdata/v3_golden_sar_*.json
// and are byte-identical to the producer-side fixtures in
// internal/consent/testdata/. Python and JavaScript SDK ports MUST
// read these fixtures and assert byte-equality on their re-encode.
//
// # Module dependencies
//
// This SDK depends on golang.org/x/crypto, golang.org/x/text/unicode/norm (V3
// NFC normalization) and github.com/cloudflare/circl (ML-DSA-65).
//
// # License
//
// Apache-2.0, every file. See LICENSE.
package verification
