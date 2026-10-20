// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// dsar_chain_d H5: reflection-based field-set assertions for the
// v3 SAR entry structs.
//
// # Why this test exists
//
// The privacy posture for v3 SAR entries (pqc_05c §4 + OQ-11) is
// load-bearing: NO actor pseudonyms, NO email-derived hashes, NO
// schema_version. The struct doc-comments document this, but doc-
// comments are honor-system — a future PR that adds, say, an
// `ActorPseudonym` field would compile, pass the encoder tests,
// and silently break the actor-anonymity invariant that customer
// verifier UIs (and downstream privacy guarantees) depend on.
//
// This test FAILS CI when the field set of any v3 SAR entry
// struct drifts from the locked list. To intentionally add or
// remove a field, the contributor MUST update this test in the
// same PR — which forces a deliberate design conversation.
//
// # Locked field sets (per pqc_05c v3 §4.5–§4.8 + chain_b)
//
// Header (every entry): CompanyID, EntryType, SigningKeyID,
// TimestampMs.
//
// Bodies, alphabetical per §4 (post-PD5: idempotency_key_hash dropped):
//   - sar_intent: ReasonHash, RequestID, SARType, Scope, SourceChannel
//   - sar_acknowledged: IntentEntryID, RequestID
//   - sar_fulfilled: FulfillmentKind, IntentEntryID, LegalBasis,
//     ManifestRoot, RequestID, TombstoneCount
//   - sar_rejected: IntentEntryID, LegalBasis, RationaleHash,
//     RequestID

func TestH5_FieldSetLocked_SARIntentEntryV3(t *testing.T) {
	t.Parallel()
	want := []string{
		// header (4)
		"CompanyID", "EntryType", "SigningKeyID", "TimestampMs",
		// body (6, alphabetical) — PIIDigestKeyVersion added by
		// pii_hmac_key_rotation_R4 (alphabetical-first, emit-iff-non-empty).
		"PIIDigestKeyVersion", "ReasonHash", "RequestID", "SARType", "Scope", "SourceChannel",
	}
	assertFieldSet(t, SARIntentEntryV3{}, want)
}

func TestH5_FieldSetLocked_SARAcknowledgedEntryV3(t *testing.T) {
	t.Parallel()
	want := []string{
		"CompanyID", "EntryType", "SigningKeyID", "TimestampMs",
		"IntentEntryID", "RequestID",
	}
	assertFieldSet(t, SARAcknowledgedEntryV3{}, want)
}

func TestH5_FieldSetLocked_SARFulfilledEntryV3(t *testing.T) {
	t.Parallel()
	want := []string{
		"CompanyID", "EntryType", "SigningKeyID", "TimestampMs",
		// certificate_id added 2026-05-16 by dsar_fulfill_b_pre_02e
		// as alphabetical-first body field (per pqc_05c v3 §4.7).
		"CertificateID",
		"FulfillmentKind", "IntentEntryID",
		"LegalBasis", "ManifestRoot", "RequestID", "TombstoneCount",
	}
	assertFieldSet(t, SARFulfilledEntryV3{}, want)
}

func TestH5_FieldSetLocked_SARRejectedEntryV3(t *testing.T) {
	t.Parallel()
	want := []string{
		"CompanyID", "EntryType", "SigningKeyID", "TimestampMs",
		"IntentEntryID", "LegalBasis",
		// PIIDigestKeyVersion added by pii_hmac_key_rotation_R4.
		"PIIDigestKeyVersion", "RationaleHash", "RequestID",
	}
	assertFieldSet(t, SARRejectedEntryV3{}, want)
}

func TestH5_FieldSetLocked_SARExtendedEntryV3(t *testing.T) {
	t.Parallel()
	want := []string{
		"CompanyID", "EntryType", "SigningKeyID", "TimestampMs",
		"IntentEntryID", "RequestID",
		// PIIDigestKeyVersion added by pii_hmac_key_rotation_R4.
		"ExtendedDueAtMs", "PIIDigestKeyVersion", "ReasonHash",
	}
	assertFieldSet(t, SARExtendedEntryV3{}, want)
}

// TestH5_NoForbiddenFieldsAnywhere is a belt-and-suspenders check:
// across all 4 entry structs, no field name matches a forbidden
// substring (`actor`, `email`, `pseudonym`, `schema`). Anchors
// OQ-11 + OQ-13.
func TestH5_NoForbiddenFieldsAnywhere(t *testing.T) {
	t.Parallel()
	forbidden := []string{"actor", "email", "pseudonym", "schema"}
	entries := []interface{}{
		SARIntentEntryV3{},
		SARAcknowledgedEntryV3{},
		SARFulfilledEntryV3{},
		SARRejectedEntryV3{},
	}
	for _, e := range entries {
		typ := reflect.TypeOf(e)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			lower := strings.ToLower(f.Name)
			for _, banned := range forbidden {
				if strings.Contains(lower, banned) {
					t.Errorf("%s contains forbidden field %s (matches %q) — OQ-11/OQ-13 regression",
						typ.Name(), f.Name, banned)
				}
			}
		}
	}
}

func assertFieldSet(t *testing.T, v interface{}, want []string) {
	t.Helper()
	typ := reflect.TypeOf(v)
	got := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	sortedGot := append([]string(nil), got...)
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedGot)
	sort.Strings(sortedWant)
	if !reflect.DeepEqual(sortedGot, sortedWant) {
		t.Errorf("%s field set drift:\n got:  %v\n want: %v",
			typ.Name(), sortedGot, sortedWant)
	}
}
