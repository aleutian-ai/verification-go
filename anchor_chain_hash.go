// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"crypto/sha512"
	"encoding/hex"
)

// =============================================================================
// Anchor Chain Hash (anchor-of-anchors domain)
// =============================================================================
//
// The audit chain uses TWO distinct SHA-512 domain separators:
//
//   - "aleutian.chain.v2:"  — per-entry chain links (see ComputeChainHash).
//                              Stored in audit_entries.chain_hash.
//   - "aleutian.anchor.v2:" — anchor-of-anchors chain (see this file).
//                              Stored in anchors.chain_hash. Binds an anchor
//                              to its tip entry AND to the previous anchor.
//
// An anchor's chain_hash is NOT the tip entry's chain_hash; it is a domain-
// separated SHA-512 over (previousAnchorHash, companyID, startEntryID,
// endEntryID, tipChainHash). Verifiers MUST recompute this and compare,
// not assume byte-equality with the tip.

// AnchorChainDomainV2 is the SHA-512 domain separator for the anchor-of-
// anchors chain. Must be byte-identical across Go/Python/JS SDKs.
const AnchorChainDomainV2 = "aleutian.anchor.v2:"

// SeedAnchorHash is the genesis previousAnchorHash used as input to
// ComputeAnchorChainHash for the very first anchor in a company's chain.
//
// # Description
//
// Computed once as SHA-512("aleutian.anchor.seed.v2"). Byte-identical to
// the producer constant at internal/storage/verification_types.go:44.
//
// # Computation
//
//	echo -n "aleutian.anchor.seed.v2" | sha512sum
//	=> 03443d96d3b369839f63f98b712463efba04c00551822743108d60c5f291627859ff0b7dc29f99e3c847b07b0b18bb385426c744847c1b070563f8dd07271f27
//
// # Use
//
// Callers verifying a genesis anchor (one whose PreviousAnchorID is the
// all-zeros sentinel) pass SeedAnchorHash as the previousAnchorHash input
// to ComputeAnchorChainHash. For non-genesis anchors, callers must supply
// the actual previous anchor's chain_hash.
const SeedAnchorHash = "03443d96d3b369839f63f98b712463efba04c00551822743108d60c5f291627859ff0b7dc29f99e3c847b07b0b18bb385426c744847c1b070563f8dd07271f27"

// SeedAnchorID is the sentinel PreviousAnchorID indicating a genesis anchor.
// Byte-identical to internal/storage/verification_types.go:18.
const SeedAnchorID = "anchor_00000000-0000-0000-0000-000000000000"

// ComputeAnchorChainHash binds an anchor to its tip entry and to the
// previous anchor in the anchor-of-anchors chain.
//
// # Description
//
// Returns hex-encoded SHA-512 over a domain-separated, pipe-delimited
// concatenation of the inputs. Byte-identical to the producer at
// internal/chainlinker/anchor_generator.go:758-777.
//
// # Inputs
//
//   - previousAnchorHash: The prior anchor's chain_hash, or SeedAnchorHash
//     for a genesis anchor (PreviousAnchorID == SeedAnchorID).
//   - companyID: The company_id field of the anchor being computed.
//   - startEntryID: anchor.Range.StartEntryID.
//   - endEntryID:   anchor.Range.EndEntryID.
//   - tipChainHash: The chain_hash of the entry identified by endEntryID,
//     as computed by walking the per-entry chain (NOT the stored value if
//     verifying against potentially tampered data — the verifier walks and
//     recomputes).
//
// # Outputs
//
//   - string: Hex-encoded 128-char SHA-512 digest.
//
// # Cross-Language Compatibility
//
// Python (sdk/verification-python):
//
//	import hashlib
//	data = (b"aleutian.anchor.v2:" + prev_hash.encode() + b"|" +
//	        company_id.encode() + b"|" + start_id.encode() + b"|" +
//	        end_id.encode() + b"|" + tip_chain_hash.encode())
//	hashlib.sha512(data).hexdigest()
//
// JS (sdk/verification-js):
//
//	import { createHash } from "crypto";
//	const h = createHash("sha512");
//	h.update("aleutian.anchor.v2:");
//	h.update(prevHash); h.update("|");
//	h.update(companyID); h.update("|");
//	h.update(startID); h.update("|");
//	h.update(endID); h.update("|");
//	h.update(tipChainHash);
//	h.digest("hex");
//
// # Thread Safety
//
// Stateless; safe for concurrent use.
//
// # Assumptions
//
//   - All inputs are valid UTF-8 strings.
//   - previousAnchorHash is 128 hex chars (a prior anchor's chain_hash) or
//     SeedAnchorHash for genesis.
func ComputeAnchorChainHash(
	previousAnchorHash string,
	companyID string,
	startEntryID string,
	endEntryID string,
	tipChainHash string,
) string {
	h := sha512.New()
	h.Write([]byte(AnchorChainDomainV2))
	h.Write([]byte(previousAnchorHash))
	h.Write([]byte("|"))
	h.Write([]byte(companyID))
	h.Write([]byte("|"))
	h.Write([]byte(startEntryID))
	h.Write([]byte("|"))
	h.Write([]byte(endEntryID))
	h.Write([]byte("|"))
	h.Write([]byte(tipChainHash))
	return hex.EncodeToString(h.Sum(nil))
}
