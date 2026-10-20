# verification-go

Offline verification of Aleutian audit data, in Go: anchors, chains, V3 chain
entries, export bundles and webhook signatures. Apache-2.0.

```console
$ go install github.com/aleutian-ai/verification-go/cmd/aleutian-verify@v0.5.0
$ aleutian-verify bundle ./export-bundle
```

Install by exact version, as above, so the verifier you run is the one you
meant: `@latest` can change under you.

## What it verifies

| | How |
|---|---|
| anchors (v1–v4) | ML-DSA-65 (FIPS 204) over the anchor's canonical JSON, with an embedded or supplied public key |
| chains (format v2) | SHA-512 chain hashes, recomputed link by link; tombstones detected |
| V3 chain entries | ML-DSA-65 over a SHA-512 content hash, with keys from a signed trust manifest |
| export bundles | `aleutian-verify bundle <dir>` checks a bundle directory as the platform writes it |
| webhooks | HMAC-SHA-512, compared in constant time |
| Tier-2 disclosures | `aleutian-disclosure-decrypt` unseals an X-Wing–wrapped disclosure with your key |

The formats are specified in the open-source module
[`github.com/aleutian-ai/proof`](https://github.com/aleutian-ai/proof)
(`docs/format-spec.md`). proof is the reference implementation and also reads
the newer formats this SDK does not: chain format v4, v7 anchors and proof's
bundle v2. The Python (`aleutian-verification`) and JavaScript
(`@aleutian/verification`) SDKs agree with this one on the shared test vectors
in `testdata/`.

## As a library

```go
import verification "github.com/aleutian-ai/verification-go"

entries, _ := verification.LoadExportedEntries("export.json")
anchor, _ := verification.LoadAnchor("anchor.json")
result, err := verification.VerifyChainOffline(ctx, entries, verification.ChainVerifyOptions{
    Anchor:             &anchor,
    PreviousAnchorHash: verification.SeedAnchorHash,
})
```

`go doc github.com/aleutian-ai/verification-go` has the rest.

## Commands

| Command | For |
|---|---|
| `aleutian-verify` | verify a chain export, or an export bundle directory |
| `aleutian-release-verify` | verify a downloaded release's `SHA256SUMS` and its signature |
| `aleutian-disclosure-decrypt` | unseal a Tier-2 disclosure |
| `aleutian-frameworks` | inspect the embedded compliance framework definitions |

The others under `cmd/` (`aleutian-release-ceremony-validate`,
`frameworks-seedgen`, `golden-vector-gen`, `zk-decrypt-probe`) are maintainer
tools.

## Source

This repository is published from `sdk/verification-go` in Aleutian's
platform repository: one commit per release, without the private history.
Report a security issue as [proof's SECURITY.md](https://github.com/aleutian-ai/proof/blob/main/SECURITY.md)
describes.
