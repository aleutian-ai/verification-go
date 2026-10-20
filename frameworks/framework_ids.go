// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

// Stable FrameworkID constants. Seed tickets (03, 11–18) each add
// their FrameworkID here and a corresponding `Latest` entry in
// registry.go.
//
// IDs use lowercase-kebab form with the standard year suffix where
// the standard's year matters (e.g. soc2-2017 vs. SOC 2 generally;
// iso-27001-2022 vs. iso-27001-2013).
const (
	// SOC2_2017 — AICPA Trust Services Criteria 2017 (TSP Section
	// 100, with 2018 updates incorporated by reference). CV-03.
	SOC2_2017 FrameworkID = "soc2-2017"

	// GDPR — General Data Protection Regulation 2016/679. CV-11.
	GDPR FrameworkID = "gdpr"

	// EU_AI_ACT — Regulation (EU) 2024/1689 laying down harmonised
	// rules on artificial intelligence. CV-12.
	EU_AI_ACT FrameworkID = "eu-ai-act"

	// HIPAA — Health Insurance Portability and Accountability Act,
	// Security Rule subpart C of 45 CFR Part 164. CV-13.
	HIPAA FrameworkID = "hipaa"

	// NIST_CSF_V1_1 — NIST Cybersecurity Framework v1.1 (2018-04-16).
	// The version suffix is part of the FrameworkID because v1.1's
	// control IDs (PR.PT-1, DE.AE-3, DE.CM-1, DE.CM-3, etc.) do not
	// carry forward to CSF 2.0 (2024-02-26), where the Protect /
	// Detect function structure was renumbered. Pinning the version
	// in the ID prevents bundle ambiguity. CV-14.
	NIST_CSF_V1_1 FrameworkID = "nist-csf-v1.1"

	// NIST_800_53 — NIST SP 800-53 Rev. 5. CV-15.
	NIST_800_53 FrameworkID = "nist-800-53"

	// ISO_27001_2022 — ISO/IEC 27001:2022. The year suffix
	// distinguishes from ISO/IEC 27001:2013. CV-16.
	ISO_27001_2022 FrameworkID = "iso-27001-2022"

	// PCI_DSS_V4 — Payment Card Industry Data Security Standard
	// v4.0. The major-version suffix distinguishes from v3.x. CV-17.
	PCI_DSS_V4 FrameworkID = "pci-dss-v4"

	// CCPA_CPRA — California Consumer Privacy Act of 2018 + California
	// Privacy Rights Act of 2020 amendments. Bundled together per
	// aleutian.ai/compliance framing. CV-18.
	CCPA_CPRA FrameworkID = "ccpa-cpra"
)
