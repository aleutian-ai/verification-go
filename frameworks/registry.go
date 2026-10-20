// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

// Latest maps each FrameworkID to its currently-current VersionID.
//
// # Description
//
// Producers consult Latest at bundle finalization time to pin a
// framework_version into the manifest. SDK verifiers do NOT consult
// Latest — they read the framework_version that the bundle ships with,
// keeping old bundles verifiable forever even after newer versions
// supersede them in this registry.
//
// # Limitations
//
//   - Each seed PR (CV-03, CV-11 through CV-18) adds its FrameworkID
//     entry to this map alongside its controls.json + framework_ids.go
//     constant.
//   - Producer must treat Latest as read-only — mutating it at runtime
//     defeats the "pin once at finalize" contract. (Caveat documented
//     2026-05-31: at worst, mutation pins a different already-shipped
//     version into a future bundle; the bundle still self-attests.)
var Latest = map[FrameworkID]VersionID{
	SOC2_2017:      "soc2-2017@20260531",
	GDPR:           "gdpr@20260531",
	EU_AI_ACT:      "eu-ai-act@20260531",
	HIPAA:          "hipaa@20260531",
	NIST_CSF_V1_1:  "nist-csf-v1.1@20260531",
	NIST_800_53:    "nist-800-53@20260531",
	ISO_27001_2022: "iso-27001-2022@20260531",
	PCI_DSS_V4:     "pci-dss-v4@20260531",
	CCPA_CPRA:      "ccpa-cpra@20260531",
}
