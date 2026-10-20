// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// frameworks-seedgen builds the canonical controls.json files that
// the frameworks package embeds.
//
// # Usage
//
//	go run ./cmd/frameworks-seedgen <framework_id>
//	go run ./cmd/frameworks-seedgen --all
//
// Each seed has a builder function below. The generator constructs the
// Framework struct in code, computes the SHA-512 self-attestation hash
// over the domain-prefixed canonical bytes, populates
// ControlsSHA512Hex, then writes the canonical bytes to
// frameworks/<framework_id>/v_<YYYYMMDD>/controls.json.
//
// Once a controls.json file ships in a customer bundle, its version
// directory is immutable (epic lock 5). Re-running the generator over
// an existing file MUST produce byte-identical output; any change
// requires a new dated version per CV-19.
package main

import (
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/aleutian-ai/verification-go/frameworks"
)

type seed struct {
	id      string
	version string
	build   func() frameworks.Framework
}

func main() {
	all := flag.Bool("all", false, "regenerate every seed")
	flag.Parse()
	args := flag.Args()

	seeds := registerSeeds()

	var targets []seed
	switch {
	case *all:
		targets = seeds
	case len(args) == 1:
		for _, s := range seeds {
			if s.id == args[0] {
				targets = append(targets, s)
				break
			}
		}
		if len(targets) == 0 {
			fmt.Fprintf(os.Stderr, "unknown framework_id %q. Known: %s\n", args[0], listKnown(seeds))
			os.Exit(2)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: frameworks-seedgen <framework_id> | --all")
		fmt.Fprintf(os.Stderr, "known: %s\n", listKnown(seeds))
		os.Exit(2)
	}

	for _, s := range targets {
		if err := generate(s); err != nil {
			fmt.Fprintf(os.Stderr, "%s@%s: %v\n", s.id, s.version, err)
			os.Exit(1)
		}
		fmt.Printf("wrote frameworks/%s/v_%s/controls.json\n", s.id, s.version)
	}
}

func generate(s seed) error {
	f := s.build()

	hashInput, err := frameworks.CanonicalBytesForHashing(f)
	if err != nil {
		return fmt.Errorf("canonical bytes for hashing: %w", err)
	}
	sum := sha512.Sum512(hashInput)
	f.ControlsSHA512Hex = hex.EncodeToString(sum[:])

	onWire, err := frameworks.CanonicalJSONOnWire(f)
	if err != nil {
		return fmt.Errorf("canonical bytes on-wire: %w", err)
	}

	targets, err := sdkEmbedTargets(s)
	if err != nil {
		return err
	}

	// Write the SAME byte-stable on-wire encoding into every SDK
	// tree's embed directory. Atomic write per target.
	for _, t := range targets {
		if err := atomicWriteFile(t.path, onWire); err != nil {
			return fmt.Errorf("%s: %w", t.label, err)
		}
		fmt.Printf("  -> %s\n", t.relPath)
	}
	return nil
}

// sdkTarget is one SDK's embed location for a seed.
type sdkTarget struct {
	label   string // "go" / "python" / "js" — for diagnostics
	path    string // absolute path
	relPath string // relative path printed in the success line
}

// sdkEmbedTargets returns every SDK embed location that exists for
// this seed. The Go target is mandatory (the source of truth);
// Python + JS targets are skipped when their SDK trees aren't present
// in this checkout.
func sdkEmbedTargets(s seed) ([]sdkTarget, error) {
	sdkRoot, err := sdkRootDir()
	if err != nil {
		return nil, err
	}

	candidates := []struct {
		label    string
		treeRoot string // parent of which the seed dir lives in
	}{
		{"go", filepath.Join(sdkRoot, "verification-go", "frameworks")},
		{"python", filepath.Join(sdkRoot, "verification-python", "src", "aleutian_verification", "frameworks", "embedded")},
		{"js", filepath.Join(sdkRoot, "verification-js", "src", "frameworks", "embedded")},
	}

	var targets []sdkTarget
	for _, c := range candidates {
		// The tree root must exist for us to consider this SDK
		// installed. We do NOT auto-create SDK subpackages; that's
		// the job of the per-SDK parity ticket (CV-05b for Python,
		// CV-05c for JS).
		if _, err := os.Stat(c.treeRoot); err != nil {
			if c.label == "go" {
				return nil, fmt.Errorf("Go frameworks tree not found at %s: %w", c.treeRoot, err)
			}
			// Python/JS skipped silently when absent.
			continue
		}
		dir := filepath.Join(c.treeRoot, s.id, "v_"+s.version)
		path := filepath.Join(dir, "controls.json")
		rel, err := filepath.Rel(sdkRoot, path)
		if err != nil {
			rel = path
		}
		targets = append(targets, sdkTarget{label: c.label, path: path, relPath: rel})
	}
	return targets, nil
}

// atomicWriteFile creates parent dirs, writes to a sibling tmp file,
// chmods to 0644, and renames into place. Prevents crash-mid-write
// corruption of shipped immutable seeds.
func atomicWriteFile(finalPath string, payload []byte) error {
	dir := filepath.Dir(finalPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".controls.json.tmp.*")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, finalPath, err)
	}
	return nil
}

// sdkRootDir resolves the absolute path to the `sdk/` directory by
// walking up from this main.go's compiled location.
func sdkRootDir() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed; cannot locate sdk root")
	}
	// thisFile = .../sdk/verification-go/cmd/frameworks-seedgen/main.go
	// sdkRoot  = .../sdk
	cmdDir := filepath.Dir(thisFile)
	verGoDir := filepath.Dir(filepath.Dir(cmdDir))
	sdkRoot := filepath.Dir(verGoDir)
	if filepath.Base(sdkRoot) != "sdk" {
		return "", fmt.Errorf("expected sdk/ at %s; got %q", sdkRoot, filepath.Base(sdkRoot))
	}
	return sdkRoot, nil
}

func listKnown(seeds []seed) string {
	ids := make([]string, 0, len(seeds))
	for _, s := range seeds {
		ids = append(ids, s.id+"@"+s.version)
	}
	sort.Strings(ids)
	return strings.Join(ids, ", ")
}

func registerSeeds() []seed {
	return []seed{
		{id: "soc2-2017", version: "20260531", build: buildSOC2_2017_20260531},
		{id: "gdpr", version: "20260531", build: buildGDPR_20260531},
		{id: "eu-ai-act", version: "20260531", build: buildEUAIAct_20260531},
		{id: "hipaa", version: "20260531", build: buildHIPAA_20260531},
		{id: "nist-csf-v1.1", version: "20260531", build: buildNISTCSF_20260531},
		{id: "nist-800-53", version: "20260531", build: buildNIST80053_20260531},
		{id: "iso-27001-2022", version: "20260531", build: buildISO270012022_20260531},
		{id: "pci-dss-v4", version: "20260531", build: buildPCIDSSv4_20260531},
		{id: "ccpa-cpra", version: "20260531", build: buildCCPACPRA_20260531},
	}
}

// buildSOC2_2017_20260531 — SOC 2 Trust Services Criteria 2017, scoped
// to the controls for which a cryptographic event chain is relevant
// evidence per epic lock 9. CV-03 ticket carries the full rationale.
func buildSOC2_2017_20260531() frameworks.Framework {
	return frameworks.Framework{
		AleutianSnapshotAt:   "2026-05-31",
		FrameworkID:          frameworks.SOC2_2017,
		FrameworkPublishedAt: "2017-04-30",
		VersionID:            "soc2-2017@20260531",
		Controls: []frameworks.Control{
			{
				ID:              "CC6.1",
				Title:           "Logical access security software, infrastructure, and architectures",
				Category:        "common_criteria",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Every logical-access event affecting in-scope systems is hash-linked, signed under a customer-bound key, and timestamp-anchored. The resulting chain is tamper-evident: any after-the-fact insertion, deletion, or reordering is mathematically detectable.",
				WhatWeDontProve: "That the access-control policies enforcing those events are well-designed, that the right principals had the right entitlements, or that the system architecture itself satisfies the criterion. The chain is the audit log; it does not substitute for the access-control system being audited.",
			},
			{
				ID:              "CC6.6",
				Title:           "Logical access security measures restrict access to information assets",
				Category:        "common_criteria",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Enforcement decisions (allow/deny) recorded by in-scope systems are present in the chain in the order they occurred, with cryptographic anchoring that proves no decision was retroactively edited or omitted.",
				WhatWeDontProve: "That the enforcement decisions themselves were correct. The chain records what the system decided, not whether the decision matched policy.",
			},
			{
				ID:              "CC6.7",
				Title:           "Restrict transmission, movement, and removal of information",
				Category:        "common_criteria",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Data-movement and data-egress events emitted by in-scope systems are recorded with stable cryptographic ordering and signed timestamps. An auditor can confirm what was transmitted, when, and that the log has not been edited since.",
				WhatWeDontProve: "Whether transmissions were authorized, whether their destinations were appropriate, or whether the data being moved was the data that should have been moved. The chain is evidence of recording, not of correctness.",
			},
			{
				ID:              "CC7.2",
				Title:           "Detect anomalies via monitoring of system components and operations",
				Category:        "common_criteria",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Anomaly-detection events surfaced by the customer's monitoring infrastructure and submitted to Aleutian are stored with tamper-evident ordering. An auditor can reconstruct the exact sequence and timing of what was detected.",
				WhatWeDontProve: "That the monitoring infrastructure detected the right things, that the detection thresholds were appropriate, or that nothing was missed. The chain is silent about events that were never emitted to it.",
			},
			{
				ID:              "CC7.3",
				Title:           "Detect security events and understand their nature",
				Category:        "common_criteria",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Security events submitted to the chain carry signed timestamps and stable ordering, so an auditor can establish what was detected and in what sequence. The chain is admissible evidence of the detection event itself.",
				WhatWeDontProve: "That the events were correctly classified as security events, that the response was timely, or that the right people were notified. Those are downstream of detection.",
			},
			{
				ID:              "CC7.4",
				Title:           "Respond to identified security incidents",
				Category:        "common_criteria",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Incident-response actions logged to the chain (assignment, status changes, remediation events, closeout) are stored with tamper-evident ordering. An auditor can reconstruct the exact response sequence and verify no step was later edited.",
				WhatWeDontProve: "That the response was appropriate, complete, or timely. The chain records what was done; whether what was done was the right thing is the auditor's call.",
			},
		},
		ControlsOutOfScope: []frameworks.OutOfScopeControl{
			{ID: "CC1.x", Reason: "control environment (board oversight, integrity, ethics) is organizational, not chain-evidenced"},
			{ID: "CC2.x", Reason: "communication and information practices are process-level, not chain-evidenced"},
			{ID: "CC3.x", Reason: "risk assessment is a process, not a logged event"},
			{ID: "CC4.x", Reason: "monitoring meta-controls; CC7.x covers the concrete chain-evidenced overlap"},
			{ID: "CC5.x", Reason: "control activities are process design, not chain-evidenced"},
			{ID: "CC6.2", Reason: "access onboarding is an HR process, not a chain-logged event"},
			{ID: "CC6.3", Reason: "periodic access reviews are a process, not chain-evidenced"},
			{ID: "CC6.4", Reason: "physical access controls are out of scope for a cryptographic audit chain"},
			{ID: "CC6.5", Reason: "physical media disposal is out of scope for a cryptographic audit chain"},
			{ID: "CC8.x", Reason: "change management is a process; specific changes may be logged elsewhere but the management of change is not chain-evidenced"},
			{ID: "CC9.x", Reason: "risk mitigation activities are process-level, not chain-evidenced"},
			{ID: "A1.x", Reason: "availability evidence (uptime, RTO/RPO attainment) is not surfaced by an event chain"},
			{ID: "C1.x", Reason: "confidentiality classification policy is not chain-evidenced; access events to classified data are covered under CC6.x"},
			{ID: "PI1.x", Reason: "processing integrity is application-correctness, not chain-evidenced"},
			{ID: "P1-P8", Reason: "privacy series is heavily process-driven; specific privacy-event logging may be covered in framework-specific seeds (GDPR, CCPA/CPRA)"},
		},
	}
}

// =============================================================================
// CV-11 — GDPR (Reg. 2016/679)
// =============================================================================

func buildGDPR_20260531() frameworks.Framework {
	return frameworks.Framework{
		AleutianSnapshotAt:   "2026-05-31",
		FrameworkID:          frameworks.GDPR,
		FrameworkPublishedAt: "2016-05-04", // OJ L 119 publication (consistent with EU AI Act using OJ publication date)
		VersionID:            "gdpr@20260531",
		Controls: []frameworks.Control{
			{
				ID:              "Art.5(1)(f)",
				Title:           "Integrity and confidentiality of processing",
				Category:        "principle",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Every processing event affecting in-scope personal data is hash-linked, signed, and timestamp-anchored, producing a tamper-evident record an auditor can verify offline. Any retroactive edit or omission is mathematically detectable.",
				WhatWeDontProve: "That the underlying processing was lawful, that the technical and organizational measures were appropriate to the risk, or that confidentiality of the data itself was preserved. The chain is the audit trail, not the security control.",
			},
			{
				ID:              "Art.5(2)",
				Title:           "Accountability — controller must be able to demonstrate compliance with Art. 5(1)",
				Category:        "principle",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Aleutian's chain provides the controller with cryptographic evidence of processing events — tamper-evident ordering, signed timestamps, and offline-verifiable integrity — that an authority, DPO, or auditor can use to demonstrate compliance with Art. 5(1) principles. The chain converts the controller's processing history into a substrate they can produce on demand.",
				WhatWeDontProve: "That the demonstrated processing was itself Art. 5(1)-compliant. The chain is the demonstrability mechanism; whether what it demonstrates actually satisfies the principles (lawfulness, purpose limitation, data minimization, etc.) is the controller's substantive obligation.",
			},
			{
				ID:              "Art.32",
				Title:           "Security of processing — logging subset",
				Category:        "controller_obligation",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Security-relevant events the controller emits to the chain (access decisions, integrity checks, suspected breaches) are stored with tamper-evident ordering and signed timestamps.",
				WhatWeDontProve: "That the security measures themselves were appropriate, that encryption was correctly applied, or that resilience requirements were met. The chain records the evidence of monitoring; it is not the monitoring system.",
			},
		},
		ControlsOutOfScope: []frameworks.OutOfScopeControl{
			{ID: "Art.6", Reason: "lawfulness of processing is a legal determination, not chain-evidenced"},
			{ID: "Art.30", Reason: "records of processing activities (RoPA) is a static document describing categories of processing — the chain may host supporting evidence for individual processing events but does not satisfy the Art.30 record-keeping obligation itself"},
			{ID: "Art.7", Reason: "valid consent is a policy/UX question; the chain logs consent events, not their validity"},
			{ID: "Art.9", Reason: "special-category data lawful-basis is a legal determination"},
			{ID: "Art.12-14", Reason: "notice and transparency obligations are document-level, not chain-evidenced"},
			{ID: "Art.15-22", Reason: "data subject rights are workflow obligations; specific request handling is covered under DSAR features, not as a GDPR control claim here"},
			{ID: "Art.17", Reason: "erasure is a workflow obligation; deletion-cert evidence is a separate audit primitive, not a GDPR control claim here"},
			{ID: "Art.25", Reason: "data protection by design and by default is an architectural posture, not chain-evidenced"},
			{ID: "Art.28", Reason: "processor contracts are document-level, not chain-evidenced"},
			{ID: "Art.33-34", Reason: "breach notification is a workflow obligation; specific notifications may be logged but the obligation is procedural"},
			{ID: "Art.35", Reason: "DPIA is a document-level assessment, not chain-evidenced"},
			{ID: "Art.37-39", Reason: "DPO appointment, position, and tasks are organizational, not chain-evidenced"},
			{ID: "Art.44-49", Reason: "international transfer mechanisms are legal/contractual, not chain-evidenced"},
		},
	}
}

// =============================================================================
// CV-12 — EU AI Act (Reg. 2024/1689)
// =============================================================================

func buildEUAIAct_20260531() frameworks.Framework {
	return frameworks.Framework{
		AleutianSnapshotAt:   "2026-05-31",
		FrameworkID:          frameworks.EU_AI_ACT,
		FrameworkPublishedAt: "2024-07-12",
		VersionID:            "eu-ai-act@20260531",
		Controls: []frameworks.Control{
			{
				ID:              "Art.12",
				Title:           "Record-keeping — automatic logging for high-risk AI systems",
				Category:        "high_risk_obligation",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Events emitted by an in-scope high-risk AI system to the chain are stored with tamper-evident ordering, signed timestamps, and cryptographic anchoring. An auditor or notified body can reconstruct the exact sequence of events for the duration of the retention period (per Art. 19, ≥6 months unless otherwise specified).",
				WhatWeDontProve: "That the AI system itself is conformant with Art. 6 risk classification, Art. 9 risk management, Art. 10 data governance, Art. 13 transparency, Art. 14 human oversight, or Art. 15 accuracy and robustness. The chain is the logging substrate; it does not substitute for the conformity assessment.",
			},
		},
		ControlsOutOfScope: []frameworks.OutOfScopeControl{
			{ID: "Art.6-7", Reason: "risk classification of AI systems is a legal/technical determination, not chain-evidenced"},
			{ID: "Art.9", Reason: "risk management system is a process-level obligation"},
			{ID: "Art.10", Reason: "data and data governance for training/validation/testing is an upstream data-quality concern"},
			{ID: "Art.11", Reason: "technical documentation is document-level, not chain-evidenced"},
			{ID: "Art.13", Reason: "transparency to deployers is a documentation/UX obligation"},
			{ID: "Art.14", Reason: "human oversight design is architectural, not chain-evidenced (specific human-oversight events may be logged but the oversight design is not)"},
			{ID: "Art.15", Reason: "accuracy, robustness, and cybersecurity testing is a pre-deployment assessment"},
			{ID: "Art.17", Reason: "quality management system is an organizational process"},
			{ID: "Art.19", Reason: "log retention duration is the controller's obligation; we provide the durable substrate but do not enforce a minimum retention"},
			{ID: "Art.43", Reason: "conformity assessment procedures are external/notified-body activities"},
			{ID: "Art.47", Reason: "EU declaration of conformity is a document-level artifact"},
			{ID: "Art.72", Reason: "post-market monitoring system is a process obligation"},
		},
	}
}

// =============================================================================
// CV-13 — HIPAA Security Rule (45 CFR §164.3xx)
// =============================================================================

func buildHIPAA_20260531() frameworks.Framework {
	return frameworks.Framework{
		AleutianSnapshotAt:   "2026-05-31",
		FrameworkID:          frameworks.HIPAA,
		FrameworkPublishedAt: "2013-01-25", // Omnibus Rule final publication
		VersionID:            "hipaa@20260531",
		Controls: []frameworks.Control{
			{
				ID:              "§164.312(b)",
				Title:           "Audit controls — hardware, software, and procedural mechanisms that record activity in systems that contain or use ePHI",
				Category:        "technical_safeguard",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Activity events submitted by in-scope systems containing or using ePHI are recorded with tamper-evident ordering, signed timestamps, and cryptographic anchoring. An auditor or OCR investigator can verify the recorded activity has not been altered since logging.",
				WhatWeDontProve: "That all relevant activity was emitted, that the audit-control mechanism design is appropriate, or that the right activity types were chosen for logging. The chain receives what is emitted to it; coverage is the covered entity's design call.",
			},
			{
				ID:              "§164.312(c)(1)",
				Title:           "Integrity — protect ePHI from improper alteration or destruction (audit-log integrity only)",
				Category:        "technical_safeguard",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "The chain itself is integrity-protected: hash-linking + signature anchoring make any after-the-fact alteration of recorded events detectable. For events that include ePHI integrity-check results, the chain preserves the result with tamper-evident ordering.",
				WhatWeDontProve: "That ePHI in primary storage was protected from alteration. The chain attests integrity OF the audit log; protecting the underlying ePHI is the covered entity's responsibility outside the chain.",
			},
			{
				ID:              "§164.308(a)(1)(ii)(D)",
				Title:           "Information system activity review",
				Category:        "administrative_safeguard",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Records of information-system-activity review events (who reviewed what, when, what action they took) submitted to the chain are stored with tamper-evident ordering. An auditor can verify the review actually happened on the date claimed.",
				WhatWeDontProve: "That the review was substantive, that the right activities were reviewed, or that follow-up actions were adequate. The chain records the review; the policy and rigor of the review are the covered entity's call.",
			},
			{
				ID:              "§164.308(a)(5)(ii)(C)",
				Title:           "Log-in monitoring",
				Category:        "administrative_safeguard",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Log-in events (successful and failed) submitted to the chain are stored with stable cryptographic ordering and signed timestamps. An auditor can reconstruct authentication patterns over the retention period.",
				WhatWeDontProve: "That the monitoring detects anomalies, that failed log-ins trigger appropriate response, or that the authentication system itself is correctly designed.",
			},
		},
		ControlsOutOfScope: []frameworks.OutOfScopeControl{
			{ID: "§164.308(a)(1)(i)", Reason: "security management process design is administrative/organizational"},
			{ID: "§164.308(a)(2)", Reason: "assigned security responsibility is an organizational role assignment"},
			{ID: "§164.308(a)(3)", Reason: "workforce security (authorization, supervision, termination) is HR/process-level"},
			{ID: "§164.308(a)(4)", Reason: "information access management (authorization policy) is process-level"},
			{ID: "§164.308(a)(5)", Reason: "security awareness and training (except log-in monitoring above) is organizational"},
			{ID: "§164.308(a)(6)", Reason: "security incident procedures are workflow-level (specific incidents may be logged elsewhere)"},
			{ID: "§164.308(a)(7)", Reason: "contingency plan and data backup are operational design"},
			{ID: "§164.308(a)(8)", Reason: "periodic security evaluation is a process, not chain-evidenced"},
			{ID: "§164.310", Reason: "physical safeguards (facility access, workstation use, device controls) are out of scope for a cryptographic audit chain"},
			{ID: "§164.312(a)(2)(i)", Reason: "unique user identification is an identity-system property; the chain records the identifier in events but does not enforce uniqueness"},
			{ID: "§164.312(a)(2)(ii)", Reason: "emergency access procedure design is operational, not chain-evidenced"},
			{ID: "§164.312(a)(2)(iii)", Reason: "automatic logoff is an authentication-system feature, not chain-evidenced"},
			{ID: "§164.312(a)(2)(iv)", Reason: "encryption and decryption of ePHI at rest is system-level, not chain-evidenced"},
			{ID: "§164.312(d)", Reason: "person or entity authentication is an identity-system property"},
			{ID: "§164.312(e)", Reason: "transmission security is a transport-layer concern (encryption in transit, integrity controls); specific transmission events may be logged"},
			{ID: "§164.314", Reason: "Business Associate Agreement requirements are contractual"},
			{ID: "§164.316", Reason: "policies, procedures, and documentation are document-level"},
		},
	}
}

// =============================================================================
// CV-14 — NIST CSF v1.1
// =============================================================================

func buildNISTCSF_20260531() frameworks.Framework {
	return frameworks.Framework{
		AleutianSnapshotAt:   "2026-05-31",
		FrameworkID:          frameworks.NIST_CSF_V1_1,
		FrameworkPublishedAt: "2018-04-16", // v1.1 publication
		VersionID:            "nist-csf-v1.1@20260531",
		Controls: []frameworks.Control{
			{
				ID:              "PR.PT-1",
				Title:           "Audit/log records are determined, documented, implemented, and reviewed in accordance with policy",
				Category:        "protect",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Audit and log records submitted to the chain are stored with tamper-evident ordering, signed timestamps, and cryptographic anchoring. The records' implementation and accessibility for review are mathematically attestable.",
				WhatWeDontProve: "That the audit policy itself was well-designed, that the right records were chosen for logging, or that review actually happened with adequate rigor.",
			},
			{
				ID:              "DE.AE-3",
				Title:           "Event data are collected and correlated from multiple sources and sensors",
				Category:        "detect",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Event data submitted to the chain — including data from multiple distinct sources — is stored with stable cryptographic ordering, allowing post-hoc correlation by an auditor. Each source's submissions are attributable and ordered.",
				WhatWeDontProve: "That all relevant sources were instrumented, that correlation logic was correct, or that anomalies were detected at the right time. The chain is the substrate for correlation, not the correlator.",
			},
			{
				ID:              "DE.CM-1",
				Title:           "The network is monitored to detect potential cybersecurity events",
				Category:        "detect",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Network-monitoring events submitted to the chain are stored with tamper-evident ordering and signed timestamps. An auditor can reconstruct what the monitoring system observed and when.",
				WhatWeDontProve: "That the monitoring coverage was adequate, that detections were timely, or that the monitoring system was correctly configured.",
			},
			{
				ID:              "DE.CM-3",
				Title:           "Personnel activity is monitored to detect potential cybersecurity events",
				Category:        "detect",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Personnel-activity events submitted to the chain are stored with stable ordering and signed timestamps. An auditor can verify what activity was observed and that the observation record has not been altered.",
				WhatWeDontProve: "That all relevant personnel activity was monitored, that monitoring respected applicable employment-law constraints, or that detected events triggered appropriate response.",
			},
		},
		ControlsOutOfScope: []frameworks.OutOfScopeControl{
			{ID: "ID.AM-*", Reason: "asset management is inventory/governance, not chain-evidenced"},
			{ID: "ID.BE-*", Reason: "business environment is organizational context"},
			{ID: "ID.GV-*", Reason: "governance is policy-level"},
			{ID: "ID.RA-*", Reason: "risk assessment is a process"},
			{ID: "ID.RM-*", Reason: "risk management strategy is organizational"},
			{ID: "ID.SC-*", Reason: "supply chain risk management is contractual/procedural"},
			{ID: "PR.AC-*", Reason: "access control design is system-level (specific access events covered under PR.PT-1)"},
			{ID: "PR.AT-*", Reason: "awareness and training is organizational"},
			{ID: "PR.DS-*", Reason: "data security policy is document-level"},
			{ID: "PR.IP-*", Reason: "information protection processes are operational design"},
			{ID: "PR.MA-*", Reason: "maintenance activities are operational"},
			{ID: "PR.PT-2", Reason: "removable media protection is physical/operational"},
			{ID: "PR.PT-3", Reason: "least functionality is system-configuration"},
			{ID: "PR.PT-4", Reason: "communications and control networks are network-architecture"},
			{ID: "PR.PT-5", Reason: "mechanisms are implemented to achieve resilience — operational"},
			{ID: "DE.AE-1", Reason: "baseline of network operations is a definition, not chain-evidenced"},
			{ID: "DE.AE-2", Reason: "detected events analysis is an analyst activity"},
			{ID: "DE.AE-4", Reason: "event impact determination is an analyst judgment"},
			{ID: "DE.AE-5", Reason: "incident alert thresholds are configuration"},
			{ID: "DE.CM-2", Reason: "physical environment monitoring is out of scope for a cryptographic audit chain"},
			{ID: "DE.CM-4 to 8", Reason: "specific malicious-code, mobile-code, external-service-provider, unauthorized-personnel/connections, and vulnerability-scan monitoring designs are tool-level"},
			{ID: "DE.DP-*", Reason: "detection processes (roles, accountability, testing) are operational"},
			{ID: "RS.RP-*", Reason: "response planning is procedural"},
			{ID: "RS.CO-*", Reason: "communications coordination is procedural"},
			{ID: "RS.AN-*", Reason: "analysis is an analyst activity"},
			{ID: "RS.MI-*", Reason: "mitigation execution may be logged but planning is procedural"},
			{ID: "RS.IM-*", Reason: "response improvements are lessons-learned activities"},
			{ID: "RC.RP-*", Reason: "recovery planning is procedural"},
			{ID: "RC.IM-*", Reason: "recovery improvements are lessons-learned activities"},
			{ID: "RC.CO-*", Reason: "recovery communications coordination is procedural"},
		},
	}
}

// =============================================================================
// CV-15 — NIST SP 800-53 Rev. 5
// =============================================================================

func buildNIST80053_20260531() frameworks.Framework {
	return frameworks.Framework{
		AleutianSnapshotAt:   "2026-05-31",
		FrameworkID:          frameworks.NIST_800_53,
		FrameworkPublishedAt: "2020-09-23",
		VersionID:            "nist-800-53@20260531",
		Controls: []frameworks.Control{
			{
				ID:              "AU-2",
				Title:           "Event logging — organization-defined event types are selected for logging",
				Category:        "audit_and_accountability",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Events submitted to the chain are stored with tamper-evident ordering, signed timestamps, and cryptographic anchoring. The event-logging implementation is verifiable end-to-end.",
				WhatWeDontProve: "That the selection of event types was appropriate to the system or organization-defined needs. The chain receives what is configured to be sent.",
			},
			{
				ID:              "AU-3",
				Title:           "Content of audit records — required information fields are present",
				Category:        "audit_and_accountability",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "The chain preserves the exact content of each audit record as submitted, with no possibility of after-the-fact field modification. An auditor can verify the record content has not been altered.",
				WhatWeDontProve: "That the submitted records contained all the required content fields per organization policy. The chain is content-agnostic; field-completeness is the emitter's responsibility.",
			},
			{
				ID:              "AU-6",
				Title:           "Audit record review, analysis, and reporting",
				Category:        "audit_and_accountability",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Review and analysis events (who reviewed which records, when, what was reported) submitted to the chain are stored with tamper-evident ordering. The review actually happened as recorded.",
				WhatWeDontProve: "That the review was substantive, that anomalies were correctly identified, or that reports were actioned. The chain attests the activity; the rigor is the organization's call.",
			},
			{
				ID:              "AU-9",
				Title:           "Protection of audit information — audit records and audit logging tools are protected from unauthorized access, modification, and deletion",
				Category:        "audit_and_accountability",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Once submitted to the chain, audit records cannot be modified or deleted without producing a mathematically detectable break in the hash-linked chain. Modification or deletion is fail-loud, not silent.",
				WhatWeDontProve: "That audit records were protected during the path from emitter to chain. The chain enforces immutability from the point of inclusion forward.",
			},
			{
				ID:              "AU-10",
				Title:           "Non-repudiation — actions cannot be plausibly denied",
				Category:        "audit_and_accountability",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Events in the chain are signed under customer-bound keys. An auditor can mathematically attribute each event to the signing identity; absent a claim of key compromise, the identity cannot plausibly deny the event's authenticity.",
				WhatWeDontProve: "That the human or system principal whose key signed the event was the actual originator of the underlying action. The chain non-repudiates the cryptographic emission; the upstream identity binding (and the integrity of the signing key itself) is the organization's responsibility.",
			},
			{
				ID:              "AU-12",
				Title:           "Audit record generation — capability to generate audit records exists",
				Category:        "audit_and_accountability",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "The chain attests that audit records were generated and recorded, with provable timestamps and ordering. Generation capability is exercised end-to-end.",
				WhatWeDontProve: "That every required event type was wired to emit records. The chain receives submissions; the generation configuration is the system owner's responsibility.",
			},
		},
		ControlsOutOfScope: []frameworks.OutOfScopeControl{
			{ID: "AC-*", Reason: "access control family is policy-level (specific access events may be logged but the access control system is not chain-evidenced)"},
			{ID: "AT-*", Reason: "awareness and training is organizational"},
			{ID: "CA-*", Reason: "assessment, authorization, and monitoring is process-level (overlaps with AU-6 above)"},
			{ID: "CM-*", Reason: "configuration management is operational"},
			{ID: "CP-*", Reason: "contingency planning is procedural"},
			{ID: "IA-*", Reason: "identification and authentication is system-level"},
			{ID: "IR-*", Reason: "incident response is procedural (specific incident events may be logged)"},
			{ID: "MA-*", Reason: "maintenance is operational"},
			{ID: "MP-*", Reason: "media protection is physical/operational"},
			{ID: "PE-*", Reason: "physical and environmental protection is physical"},
			{ID: "PL-*", Reason: "planning is procedural"},
			{ID: "PS-*", Reason: "personnel security is HR-level"},
			{ID: "RA-*", Reason: "risk assessment is procedural"},
			{ID: "SA-*", Reason: "system and services acquisition is contractual"},
			{ID: "SC-*", Reason: "system and communications protection is system-level"},
			{ID: "SI-*", Reason: "system and information integrity is system-level (SI-7 software integrity may overlap with AU-9 but is system-level)"},
			{ID: "SR-*", Reason: "supply chain risk management is contractual"},
			{ID: "PT-*", Reason: "PII processing and transparency is policy-level"},
		},
	}
}

// =============================================================================
// CV-16 — ISO/IEC 27001:2022
// =============================================================================

func buildISO270012022_20260531() frameworks.Framework {
	return frameworks.Framework{
		AleutianSnapshotAt:   "2026-05-31",
		FrameworkID:          frameworks.ISO_27001_2022,
		FrameworkPublishedAt: "2022-10-25",
		VersionID:            "iso-27001-2022@20260531",
		Controls: []frameworks.Control{
			{
				ID:              "A.5.33",
				Title:           "Protection of records",
				Category:        "organizational",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Records submitted to the chain are stored with tamper-evident ordering and cryptographic anchoring. They cannot be modified, deleted, or falsified without mathematically detectable evidence.",
				WhatWeDontProve: "That records held outside the chain (filesystem, primary databases) are protected. The chain protects records from the point of inclusion forward.",
			},
			{
				ID:              "A.8.15",
				Title:           "Logging",
				Category:        "technological",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Logs submitted to the chain are stored with tamper-evident ordering, signed timestamps, and cryptographic anchoring. An auditor can verify the recorded logs are exactly as emitted.",
				WhatWeDontProve: "That the logging was correctly configured to capture relevant events, that retention duration was appropriate, or that the log content was complete.",
			},
			{
				ID:              "A.8.16",
				Title:           "Monitoring activities",
				Category:        "technological",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Monitoring-activity events submitted to the chain are recorded with stable cryptographic ordering and signed timestamps. An auditor can reconstruct the exact monitoring sequence.",
				WhatWeDontProve: "That monitoring coverage was adequate, that the right behaviors were monitored, or that responses to anomalies were timely.",
			},
			{
				ID:              "A.8.17",
				Title:           "Clock synchronisation",
				Category:        "technological",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Events submitted to the chain carry server-attested timestamps from synchronized clocks. The relative ordering of events is mathematically stable.",
				WhatWeDontProve: "That client-side timestamps embedded in event payloads accurately reflect wall-clock time at the emitter. The chain attests the time of inclusion, not the time of the underlying action.",
			},
		},
		ControlsOutOfScope: []frameworks.OutOfScopeControl{
			{ID: "A.5.1-5.32", Reason: "organizational controls (policies, roles, contacts, intelligence, etc.) are document- and process-level"},
			{ID: "A.5.34", Reason: "privacy and protection of PII is policy-level"},
			{ID: "A.5.35-5.37", Reason: "independent review, compliance, and documented operating procedures are procedural"},
			{ID: "A.6.*", Reason: "people controls (screening, terms, awareness, disciplinary, NDAs, remote working, reporting) are HR-level"},
			{ID: "A.7.*", Reason: "physical controls (perimeters, entry, supplies, working areas, equipment, etc.) are physical"},
			{ID: "A.8.1-8.14", Reason: "user endpoint, access rights, source-code access, capacity, etc. are system-configuration; specific access events may be logged"},
			{ID: "A.8.18-8.34", Reason: "vulnerability management, change management, capacity, malware protection, masking, leakage prevention, backup, redundancy, network controls, services, segregation, web filtering, cryptography, secure development, etc. are operational design"},
		},
	}
}

// =============================================================================
// CV-17 — PCI DSS v4.0
// =============================================================================

func buildPCIDSSv4_20260531() frameworks.Framework {
	return frameworks.Framework{
		AleutianSnapshotAt:   "2026-05-31",
		FrameworkID:          frameworks.PCI_DSS_V4,
		FrameworkPublishedAt: "2022-03-31",
		VersionID:            "pci-dss-v4@20260531",
		Controls: []frameworks.Control{
			{
				ID:              "10.2",
				Title:           "Audit logs are implemented to support detection of anomalies and suspicious activity",
				Category:        "logging_and_monitoring",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Audit log events emitted by the in-scope cardholder data environment to the chain are stored with tamper-evident ordering, signed timestamps, and cryptographic anchoring.",
				WhatWeDontProve: "That the logging is correctly scoped to the cardholder data environment, that all required event types are captured, or that detection of anomalies was timely.",
			},
			{
				ID:              "10.2.1",
				Title:           "Audit logs capture required event types",
				Category:        "logging_and_monitoring",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Events of all submitted types are preserved in the chain with their original content intact and ordering stable. An assessor can verify which event types are reaching the chain.",
				WhatWeDontProve: "That every required event type was wired for emission. The chain receives what is sent; coverage configuration is the entity's responsibility.",
			},
			{
				ID:              "10.3",
				Title:           "Audit logs are protected from destruction and unauthorized modifications",
				Category:        "logging_and_monitoring",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Once a log entry enters the chain, destruction or modification produces a mathematically detectable break. The protection is enforced cryptographically, not by access control alone.",
				WhatWeDontProve: "That logs were protected during transmission from emitter to the chain. From the point of inclusion forward, integrity is enforced.",
			},
			{
				ID:              "10.4.1",
				Title:           "Audit log reviews are performed at the defined frequency (daily for specified event categories under v4.0)",
				Category:        "logging_and_monitoring",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Review events (who reviewed, when, what time range was covered) submitted to the chain are stored with stable ordering and signed timestamps. An assessor can confirm review activity actually happened on the dates claimed.",
				WhatWeDontProve: "That the review was substantive or that all events were actually examined. Under v4.0's targeted-risk-analysis allowance for non-critical assets (10.4.2), frequency for broader scope may be entity-determined; the chain records the review activity as performed.",
			},
			{
				ID:              "10.5",
				Title:           "Audit log history is retained and available for analysis",
				Category:        "logging_and_monitoring",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Chain entries are retained for the contracted retention period (default 7 years prod), accessible for assessor analysis, with verifiable integrity throughout.",
				WhatWeDontProve: "That the entity's retention configuration itself meets the PCI v4.0 Req 10.5.1 minimum (at least 12 months total with at least the most recent 3 months immediately available for analysis). Aleutian provides the durable substrate; meeting the duration target is the entity's configuration.",
			},
			{
				ID:              "12.10.5",
				Title:           "Security incident response includes alerts from security monitoring systems",
				Category:        "incident_response",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Incident-response events (alert receipt, triage, action, closure) submitted to the chain are stored with tamper-evident ordering and signed timestamps.",
				WhatWeDontProve: "That the response was timely or adequate. The chain records the response activity; the adequacy is the incident-response team's domain.",
			},
			{
				ID:              "10.7",
				Title:           "Failures of critical security control systems are detected, alerted, and addressed promptly",
				Category:        "logging_and_monitoring",
				Status:          frameworks.StatusDesigned,
				WhatWeProve:     "When critical-control-system failure events are emitted to the chain (alongside detection and remediation events), the chain stores them with tamper-evident ordering. The design supports failure-recording, not failure-detection.",
				WhatWeDontProve: "That critical security control systems are correctly identified and instrumented for failure detection in the first place. This control is marked designed (not operating) because automatic failure detection across the entity's systems is not yet a turnkey Aleutian capability — only the recording substrate is.",
			},
		},
		ControlsOutOfScope: []frameworks.OutOfScopeControl{
			{ID: "Req.1", Reason: "network security controls (firewalls, segmentation) are network-architecture"},
			{ID: "Req.2", Reason: "secure configurations are system-level"},
			{ID: "Req.3", Reason: "protect stored account data (encryption at rest, masking) is data-handling"},
			{ID: "Req.4", Reason: "protect cardholder data in transit is transport-layer"},
			{ID: "Req.5", Reason: "anti-malware is endpoint/tooling"},
			{ID: "Req.6", Reason: "secure development is SDLC"},
			{ID: "Req.7", Reason: "restrict access by need-to-know is access-control policy"},
			{ID: "Req.8", Reason: "identify users and authenticate access is identity-system"},
			{ID: "Req.9", Reason: "physical access is physical"},
			{ID: "Req.11", Reason: "test security of systems and networks (penetration testing, IDS, change detection) is assurance activity"},
			{ID: "Req.12.1-12.9", Reason: "information security program management is organizational (12.10.5 incident response above is the relevant chain-evidenced subset)"},
		},
	}
}

// =============================================================================
// CV-18 — CCPA / CPRA
// =============================================================================

func buildCCPACPRA_20260531() frameworks.Framework {
	return frameworks.Framework{
		AleutianSnapshotAt:   "2026-05-31",
		FrameworkID:          frameworks.CCPA_CPRA,
		FrameworkPublishedAt: "2020-11-03", // CPRA enactment
		VersionID:            "ccpa-cpra@20260531",
		Controls: []frameworks.Control{
			{
				ID:              "§1798.110",
				Title:           "Right to Know — consumer requests for categories and specific pieces of personal information collected",
				Category:        "consumer_right",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Right-to-know requests received, acknowledged, and fulfilled (or denied) by the business are recorded in the chain with tamper-evident ordering and signed timestamps. The request log is the evidence of compliance with the 45-day response window.",
				WhatWeDontProve: "That the disclosed categories and specific pieces of personal information were complete or accurate. The chain attests the response; the contents are the business's responsibility.",
			},
			{
				ID:              "§1798.105",
				Title:           "Right to Delete — consumer requests for deletion of personal information",
				Category:        "consumer_right",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Right-to-delete requests and the business's response (deletion confirmation, exemption claim, denial) submitted to the chain are stored with tamper-evident ordering and signed timestamps. When the business also submits service-provider deletion confirmations, those are preserved alongside with the same integrity guarantees.",
				WhatWeDontProve: "That deletion was technically complete across all systems (the chain attests the workflow; physical deletion is the business's act). Whether an exemption was correctly claimed is a legal determination.",
			},
			{
				ID:              "§1798.106",
				Title:           "Right to Correct — consumer requests for correction of inaccurate personal information",
				Category:        "consumer_right",
				Status:          frameworks.StatusOperating,
				WhatWeProve:     "Right-to-correct requests and the business's correction or denial response submitted to the chain are stored with tamper-evident ordering and signed timestamps.",
				WhatWeDontProve: "That the underlying personal information was actually corrected in primary storage, or that the business's determination of inaccuracy was sound.",
			},
		},
		ControlsOutOfScope: []frameworks.OutOfScopeControl{
			{ID: "§1798.100", Reason: "general duties at the point of collection (notice) are document-level"},
			{ID: "§1798.115", Reason: "right to know about sale or sharing — overlaps with §1798.110 above; sale-specific opt-out is workflow-level"},
			{ID: "§1798.120", Reason: "right to opt-out of sale or sharing is configuration- and process-level"},
			{ID: "§1798.121", Reason: "right to limit use and disclosure of sensitive PI is policy- and config-level"},
			{ID: "§1798.125", Reason: "non-discrimination is a business policy"},
			{ID: "§1798.130", Reason: "notice, disclosure, correction, and deletion mechanisms are UX and policy"},
			{ID: "§1798.135", Reason: "methods for limiting sale, sharing, and use of PI are UX"},
			{ID: "§1798.140", Reason: "definitions"},
			{ID: "§1798.145", Reason: "exemptions"},
			{ID: "§1798.150", Reason: "personal information security breach — breach handling is procedural"},
			{ID: "§1798.155", Reason: "enforcement and penalty provisions"},
			{ID: "§1798.185", Reason: "regulations (procedural)"},
		},
	}
}
