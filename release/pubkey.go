// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package release exposes the Aleutian release-signing public key
// and the VerifyChecksums primitive customers use to verify the
// authenticity of downloaded release artifacts.
//
// # Why this exists
//
// Customers who `curl -fL https://releases.aleutian.ai/tier2/aleutian-disclosure-decrypt_*`
// can verify their download against SHA256SUMS — but SHA256SUMS
// itself is a plaintext file in a public bucket. Without
// SHA256SUMS.sig + this verifier, an attacker who compromised the
// bucket could substitute their own binary AND their own SHA256SUMS
// and a naive customer would verify-and-trust.
//
// This package embeds the ML-DSA-65 release-signing public key so
// `aleutian-release-verify` (or any caller importing this SDK) can
// verify SHA256SUMS.sig before trusting any hash inside SHA256SUMS.
//
// # Key rotation
//
// When the release key rotates, a new release of the SDK ships with
// the new pubkey in this constant. Old binaries verifiable with the
// old key remain verifiable for a retention window (operator publishes
// both old + new SDK versions; old SDK versions stay accessible via
// `go install ...@v0.X.Y` until the deprecation window closes).
package release

// ReleasePubkeyV1 is the 1952-byte raw ML-DSA-65 public key for
// Aleutian's release-signing key version 1.
//
// PLACEHOLDER: this is an all-zero pubkey awaiting the release-key
// ceremony (operator action — see
// docs/runbooks/release_disclosure_decrypt.md). Until the ceremony
// runs, IsPlaceholder() returns true and VerifyChecksums refuses
// to verify any signature (fail-closed: never accept a sig under an
// unset key).
//
// Once the ceremony runs, this constant is replaced with the
// exported KMS public key bytes (hex-encoded for compile-time
// embedding via Go's untyped string → []byte conversion in the
// init block below).
const releasePubkeyV1HexPlaceholder = "4b24b1af6921d5197332596151a345849072ed44ffcc9d7f590a9e23d11ad525b617c5f07cf98eee225f4760a0679f56f9dbdc571dba5e4578b41c12a6897fdf688221c5ece164ebb907c3b792214b8f14158290e6edd01d703d3cbaaf25c5495b2aa6b30ca8d6d2c7739ac6e04bda975b2a0cf476109f8ac5c39f4fab567d677feed05d51be97ab5923dca8810e8742de8a4450c180fb16c644ffe79d25dec0c03ff0681ad16c268a0c859f608b8ad0a3f88f2eab8df6887e7e4968189f96ebee46c0b35c45905a975b581f40be88122cb554c89579171335004f7012ab4bacc41230b409f65bc9ff22edb0179becb7556ef58ea71879e513ee3dc97e25a744deee8060e604053e9603bd60910b60bc3e75e3d43cf834932547d2b056e699042a6d991d7b8ce8ed913af96c9689549fbb13082ab9546bdd321cb1150dbc48aa9ef25ceadbc01f47661ca1599a8b46e059be0f5d1ddf0a8b4cc7faa5801755e47adbc14a0fed9bde43d9eda23db6291472afc53c3c8a210bf5e44e2ed4e9f93a2703c6304efe14891c59f4d644be84a4d7f318be84245f099e294225b722965f2fe7d615a858937f8cabd142124aa7df4e5ba0434d7cc84bcf7fa1a0d6545583bd6d9d38bbe4b50bdb8bdbc9bf3fca98c830b5bc7aa321713ae76fa6eb0f93512bb88fc7b9e01266d9ea9910cda37663b67a65eb21789ef9b8005fa0b2fa860f0c400d3bd1bee8f8d2b2004b993f4453fd5091853ff85a632cb7addce3b3cda5c845114ca1dda7781f2bf6178b8b1927167a8ae8365a68956d565081a3f0b10dcdf24ab3122e10b61d3610e6eacce8401ad45999ad0e4dc9391b4a4c3952ee0662d1fc8acdc676f4691eeb616f8b94ddcf071eaa261eb0bf4bc728d6bfb0a647a0a0fd706a4c2b0c8277990ae15a6df8d42bc964e1f034fe08829aa5cb3ed54ebaf24ba3718176f145ce73672122aaff7c248230dfbd05a301a5a370ea9599e8526e94f3e6a73938c5efef623150c677f6f5a978b42370426c7e977cf6f84c1a3ef42cf4c7efc236dc87c251a9039c7abebed0592c9a231b9bba426c3a8693f538d7b3c3d8b855dabd3b7f3e9bb299ef82fc9fe9e2bff6dfa20869edcb11ac2218f887e7265fa36f072498d4ed5c3a7326e5f8d0057d5ad114e7535b9463e2bcaed16250cd371760197b9175e90fc3c9dbbf729c2df8be6575c43d385bd61d5d5fb755dc04a521477484d5a9330cfce1e894d532866693cf2ab99d447f6e436e58b64db8122536366afefd09c17f19d4bdd22e53bcda11ae8ace8fb0372d8c7dfc85139663693c305cabf6ef64714d50fe61b6cf0daba34a143c495970e2bfab07ed03ae574da7cc92eec9d8859c08a2e8a026f83981482210111fa75aefd593d46f71396b2699c7833a5ade1de43dde7292d6ab6ffc1ac5ddf4e8893fe27bf432861b0f0cfae008308a2f2df80b2ab5158a29104735cc21aa5195697ddbd914e681b3db8814390cd968a59fdad1330daad1a796443d2f13c9ae2ed3394dc5e5daa661acf8a7248abe8a2da21f35350b12c0e7b500d3959350d36bde9f1e0b1de3e78dd4169c8edae2fedd1f945973c0e053cb552f07c5f3069bc0d0bb3c41a20e8dbac0294be97c5fb3b2892d4c6ba65ab50dc2b03dc75ec483b757d1b67452b9aa59a851ef1a976c0984afdc982416cd74451c6511ffe524f740651ffdde418c68669cc4bd5b7916062befae6e75a0362d0280b4a607a40e954e4e6a934e17f9d5eade3b09cc4f84b8d0b4e34760be2f98702b2658c54d2f864882bb88c49a6efd41237925728404925368844a33e8fa542263eab9035dad52eaa9c4cca519a0d52a3b512b225a44a42c2669c970bbb0f666f7f86ca2a11712ff58171b0ddbbb70743331e679a5c9dd7c9e5fc1120cb5eef71840e8afe55899579159da7f4580ce281a03a09dafd81eb58a4dbf9c0533f255bc0556255fef6a01b7cead1c3374e336e9de896ede5a915d7d41cef314201f4d43c3740f79e238968f17890dee334da25b2b7b3a7f64ee3bff967a0268075a63e06f1e2bf7b8dec501ea61d4be9586de2b796227b293a27901cdff2cb24c9340931b33027bc4a0a495e8a4cbd5705f6796333c6f7e48a1c07fc6264573aa13e3d671ddaf977e8baa332139147b73c93599c6357b7d9f92e0d2ca9a97bd8d380c2c5197367d01a71598939e8b6ba6b5425aa5c53ff44b8b21dde5d10329ff3b60ec6fec425096681a4fd2931b5cd1b84d19c8a0eb944e2782f8f0792885d9b0780c220c0cfd68eaa3299c17399bc6a4414a639c3aad6ac2b1edd9bfe754bb8a81cf96392214409343596786dd38d4886ec885c5426d71e777db9b864e2e22e3587144618a52e2b2da7289336f4d700a0cee9ade61145544d8ca94edb3a2f40a3b6885e93ac152d57a751ac33affcef02604fa6fc9030a76edfdc0af8e9380705235e3bb85f76c722dea56c8626d0745d697be673c8016877d9c550d371bdf89b28698b101960266c33d248584554d984b35f81afc738a2302c62453e1082f52f4f8024698b6bb9183e85210c3b3acc516679f12731937d0414d8797f5f6805c924ea9ed27e8d85ab5cad1dcd01d10fb684754de7a6721425dd5c26fe8d72f6b20c2f432c7d41b16f4a209fb2db0b029832b61f7f6c81a978394754b5f495574e01f9b4438834bfa8dcb58f249c3946338852bca1e481baa5c6e1cb8c30105d6e53109f5d0224b65913395aa4902"

// ReleasePubkey returns the active release-signing public key. Empty
// until the operator runs the release-key ceremony. Callers should
// check IsPlaceholder() before trusting any verify result.
//
// # Outputs
//
//   - []byte: 1952-byte raw ML-DSA-65 public key, or an all-zero
//     1952-byte slice when the ceremony has not run.
func ReleasePubkey() []byte {
	if releasePubkeyV1HexPlaceholder == "" {
		// Pre-ceremony: return all zeros. VerifyChecksums detects
		// this and refuses to claim success.
		return make([]byte, 1952)
	}
	return decodeHex(releasePubkeyV1HexPlaceholder)
}

// IsPlaceholder reports whether the embedded release pubkey is still
// the all-zero placeholder. Used by VerifyChecksums to fail-closed
// before the ceremony runs.
func IsPlaceholder() bool {
	for _, b := range ReleasePubkey() {
		if b != 0 {
			return false
		}
	}
	return true
}

// decodeHex is a tiny lowercase-hex decoder used to inflate the
// embedded pubkey constant at runtime. Lives here so the rest of
// the package has zero stdlib hex import (keeps the dependency
// graph tight for the no-cgo customer build).
func decodeHex(s string) []byte {
	if len(s)%2 != 0 {
		return nil
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := hexNibble(s[i])
		lo := hexNibble(s[i+1])
		if hi < 0 || lo < 0 {
			return nil
		}
		out[i/2] = byte(hi<<4 | lo)
	}
	return out
}

func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
