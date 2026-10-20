// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// validFixture returns a Framework whose ControlsSHA512Hex is
// correctly computed via the domain-prefixed canonical bytes.
func validFixture(t *testing.T) Framework {
	t.Helper()
	f := Framework{
		AleutianSnapshotAt:   "2026-03-01",
		FrameworkID:          "test-framework",
		FrameworkPublishedAt: "2017-04-30",
		VersionID:            "test-framework@20260301",
		Controls: []Control{
			{
				ID:              "CC1.1",
				Title:           "Audit logging of access events",
				Category:        "common_criteria",
				Status:          StatusOperating,
				WhatWeProve:     "Every access event is hash-linked, signed, and timestamp-anchored.",
				WhatWeDontProve: "That the events themselves were the right events to monitor.",
			},
		},
		ControlsOutOfScope: []OutOfScopeControl{
			{ID: "CC0.1", Reason: "board governance — not chain-evidenced"},
		},
	}
	bytes, err := CanonicalBytesForHashing(f)
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	sum := sha512.Sum512(bytes)
	f.ControlsSHA512Hex = hex.EncodeToString(sum[:])
	return f
}

// encode returns the on-wire JSON bytes for f with the hash field
// populated. canonicalJSON of f (which already carries the computed
// hash) is what gets shipped to disk.
func encode(t *testing.T, f Framework) string {
	t.Helper()
	bytes, err := canonicalJSON(f)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	return string(bytes)
}

func TestLoadFromReader(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(f *Framework, raw *string)
		wantErr error
	}{
		{
			name:    "happy path",
			mutate:  func(_ *Framework, _ *string) {},
			wantErr: nil,
		},
		{
			name: "attestation mismatch — single byte flipped in title",
			mutate: func(_ *Framework, raw *string) {
				*raw = strings.Replace(*raw, "Audit logging", "AudiX logging", 1)
			},
			wantErr: ErrAttestationMismatch,
		},
		{
			name: "attestation mismatch — out-of-scope reason tampered",
			mutate: func(_ *Framework, raw *string) {
				*raw = strings.Replace(*raw, "not chain-evidenced", "fully evidenced", 1)
			},
			wantErr: ErrAttestationMismatch,
		},
		{
			name: "unknown status",
			mutate: func(f *Framework, _ *string) {
				f.Controls[0].Status = "blessed"
			},
			wantErr: ErrUnknownStatus,
		},
		{
			name: "malformed JSON",
			mutate: func(_ *Framework, raw *string) {
				*raw = "{not json"
			},
			wantErr: ErrMalformedJSON,
		},
		{
			name: "unknown JSON field at top level",
			mutate: func(_ *Framework, raw *string) {
				*raw = strings.Replace(*raw, `"framework_id"`, `"surprise":"x","framework_id"`, 1)
			},
			wantErr: ErrMalformedJSON,
		},
		{
			name: "unknown JSON field inside Control (nested DisallowUnknownFields)",
			mutate: func(_ *Framework, raw *string) {
				*raw = strings.Replace(*raw, `"category"`, `"effective_from":"2026-04-01","category"`, 1)
			},
			wantErr: ErrMalformedJSON,
		},
		{
			name: "uppercase hex rejected",
			mutate: func(_ *Framework, raw *string) {
				// hash field is the LAST string-typed top-level field
				// in alphabetical order before non-string fields;
				// safe to uppercase its first hex digit.
				idx := strings.Index(*raw, `"controls_sha512_hex":"`)
				if idx < 0 {
					t.Fatalf("hash field not in raw")
				}
				start := idx + len(`"controls_sha512_hex":"`)
				b := []byte(*raw)
				if b[start] >= 'a' && b[start] <= 'f' {
					b[start] = b[start] - 'a' + 'A'
				} else {
					b[start] = 'A'
				}
				*raw = string(b)
			},
			wantErr: ErrHashFormat,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := validFixture(t)
			if tc.name == "unknown status" {
				// re-encode WITHOUT recomputing hash so the status
				// check fires; the hash will also mismatch but
				// status is checked first.
				tc.mutate(&f, nil)
				raw := encode(t, f)
				_, err := LoadFromReader(strings.NewReader(raw))
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got err=%v, want %v", err, tc.wantErr)
				}
				return
			}
			raw := encode(t, f)
			tc.mutate(&f, &raw)
			_, err := LoadFromReader(strings.NewReader(raw))
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got err=%v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestLoadFromReader_SizeCap(t *testing.T) {
	// Build a 1 MiB+1 byte JSON payload by padding a valid framework's
	// title with junk. The size check fires before parse, so it does
	// not need to be valid JSON beyond having >MaxControlsJSONBytes
	// bytes.
	padding := strings.Repeat("x", MaxControlsJSONBytes+1)
	_, err := LoadFromReader(strings.NewReader(padding))
	if !errors.Is(err, ErrSizeExceeded) {
		t.Fatalf("got err=%v, want ErrSizeExceeded", err)
	}
}

func TestLoadFromReader_HappyPathRoundTrip(t *testing.T) {
	f := validFixture(t)
	raw := encode(t, f)
	loaded, err := LoadFromReader(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.FrameworkID != f.FrameworkID {
		t.Errorf("framework_id: got %q want %q", loaded.FrameworkID, f.FrameworkID)
	}
	if loaded.VersionID != f.VersionID {
		t.Errorf("version_id: got %q want %q", loaded.VersionID, f.VersionID)
	}
	if len(loaded.Controls) != 1 {
		t.Fatalf("controls: got %d want 1", len(loaded.Controls))
	}
	if loaded.Controls[0].WhatWeProve == "" || loaded.Controls[0].WhatWeDontProve == "" {
		t.Errorf("epic lock 9: WhatWeProve/WhatWeDontProve must round-trip; got %+v", loaded.Controls[0])
	}
	if loaded.Controls[0].Status != StatusOperating {
		t.Errorf("status round-trip: got %q want %q", loaded.Controls[0].Status, StatusOperating)
	}
	if len(loaded.ControlsOutOfScope) != 1 {
		t.Fatalf("controls_out_of_scope: got %d want 1", len(loaded.ControlsOutOfScope))
	}
}

func TestCanonicalBytesForHashing_DomainPrefixIncluded(t *testing.T) {
	f := validFixture(t)
	out, err := CanonicalBytesForHashing(f)
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	if !strings.HasPrefix(string(out), DomainPrefix) {
		t.Fatalf("canonical bytes must start with %q; got prefix %q", DomainPrefix, string(out[:min(len(out), len(DomainPrefix))]))
	}
	// Sanity: a Framework with the prefix removed from the hash input
	// must produce a different hash than one with it included.
	jsonOnly, err := canonicalJSON(Framework{
		AleutianSnapshotAt:   f.AleutianSnapshotAt,
		FrameworkID:          f.FrameworkID,
		FrameworkPublishedAt: f.FrameworkPublishedAt,
		VersionID:            f.VersionID,
		Controls:             f.Controls,
		ControlsOutOfScope:   f.ControlsOutOfScope,
		ControlsSHA512Hex:    "",
	})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if string(out) == string(jsonOnly) {
		t.Errorf("domain prefix must materially change hash input")
	}
}

func TestLoadFromEmbedded_UnknownVersion(t *testing.T) {
	// CV-01 ships embedded as a zero-value embed.FS. Every lookup
	// must return ErrUnknownVersion until seed 03 lands the //go:embed
	// directive.
	tests := []VersionID{
		"soc2-2017@20260301",
		"gdpr@20260301",
		"malformed-no-at",
		"",
		"@",
		"x@",
		"@x",
	}
	for _, v := range tests {
		v := v
		t.Run(string(v), func(t *testing.T) {
			_, err := LoadFromEmbedded(v)
			if !errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("got err=%v, want ErrUnknownVersion", err)
			}
		})
	}
}

func TestControlStatus_IsKnown(t *testing.T) {
	tests := []struct {
		s    ControlStatus
		want bool
	}{
		{StatusOperating, true},
		{StatusDesigned, true},
		{StatusRoadmap, true},
		{"", false},
		{"blessed", false},
		{"OPERATING", false}, // case-sensitive by design
	}
	for _, tc := range tests {
		if got := tc.s.IsKnown(); got != tc.want {
			t.Errorf("IsKnown(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestLatest_PopulatedWithSOC2AsOfCV03(t *testing.T) {
	// CV-03 adds the SOC 2 entry. CV-11 through CV-18 will add the
	// remaining eight launch frameworks; this test tightens as each
	// lands.
	want, ok := Latest[SOC2_2017]
	if !ok {
		t.Fatalf("Latest must contain SOC2_2017 after CV-03; got %v", Latest)
	}
	if want != "soc2-2017@20260531" {
		t.Errorf("Latest[SOC2_2017] = %q; want %q", want, "soc2-2017@20260531")
	}
}

func TestLoadFromEmbedded_AllLatest(t *testing.T) {
	// Every entry in Latest must round-trip through the embed.FS,
	// pass self-attestation, and satisfy lock 9 (non-empty
	// what_we_prove + what_we_dont_prove on every in-scope control,
	// non-empty controls_out_of_scope).
	if len(Latest) != 9 {
		t.Fatalf("Latest should hold all 9 launch frameworks after CV-18; got %d", len(Latest))
	}
	for fid, vid := range Latest {
		fid, vid := fid, vid
		t.Run(string(fid), func(t *testing.T) {
			f, err := LoadFromEmbedded(vid)
			if err != nil {
				t.Fatalf("LoadFromEmbedded(%q): %v", vid, err)
			}
			if f.FrameworkID != fid {
				t.Errorf("framework_id: got %q want %q", f.FrameworkID, fid)
			}
			if f.VersionID != vid {
				t.Errorf("version_id: got %q want %q", f.VersionID, vid)
			}
			if len(f.Controls) == 0 {
				t.Fatal("expected ≥1 in-scope control")
			}
			if len(f.ControlsOutOfScope) == 0 {
				t.Fatal("epic lock 9: out-of-scope list must be non-empty")
			}
			for i, c := range f.Controls {
				if c.WhatWeProve == "" {
					t.Errorf("controls[%d].what_we_prove empty", i)
				}
				if c.WhatWeDontProve == "" {
					t.Errorf("controls[%d].what_we_dont_prove empty", i)
				}
				if !c.Status.IsKnown() {
					t.Errorf("controls[%d].status %q unknown", i, c.Status)
				}
			}
		})
	}
}

func TestLoadFromEmbedded_SOC2_2017(t *testing.T) {
	// CV-03 ships frameworks/soc2-2017/v_20260531/controls.json.
	// LoadFromEmbedded must round-trip it: pull from embed.FS, parse,
	// verify self-attestation hash, verify all statuses are known.
	f, err := LoadFromEmbedded("soc2-2017@20260531")
	if err != nil {
		t.Fatalf("LoadFromEmbedded(soc2-2017@20260531): %v", err)
	}
	if f.FrameworkID != SOC2_2017 {
		t.Errorf("framework_id: got %q want %q", f.FrameworkID, SOC2_2017)
	}
	if f.VersionID != "soc2-2017@20260531" {
		t.Errorf("version_id: got %q want %q", f.VersionID, "soc2-2017@20260531")
	}
	if len(f.Controls) == 0 {
		t.Fatal("expected ≥1 in-scope control, got 0")
	}
	if len(f.ControlsOutOfScope) == 0 {
		t.Fatal("epic lock 9: out-of-scope list must be non-empty for SOC 2 seed")
	}
	for i, c := range f.Controls {
		if c.WhatWeProve == "" {
			t.Errorf("controls[%d].what_we_prove must be populated (lock 9)", i)
		}
		if c.WhatWeDontProve == "" {
			t.Errorf("controls[%d].what_we_dont_prove must be populated (lock 9)", i)
		}
		if !c.Status.IsKnown() {
			t.Errorf("controls[%d].status %q must be a known value", i, c.Status)
		}
	}
}

func TestErrFrameworkVersionMismatch_Declared(t *testing.T) {
	// Sentinel declared in CV-01 so CV-05 (SDK verify step-9
	// cross-check) and the Python / JS sibling SDKs converge on the
	// same error. Loader itself does not raise it.
	if ErrFrameworkVersionMismatch == nil {
		t.Fatal("ErrFrameworkVersionMismatch must be a non-nil sentinel")
	}
	if !strings.Contains(ErrFrameworkVersionMismatch.Error(), "framework_version") {
		t.Errorf("sentinel message should mention framework_version; got %q", ErrFrameworkVersionMismatch.Error())
	}
}

func TestCanonicalJSON_PythonByteIdentity(t *testing.T) {
	// Pin the canonical encoding to a known byte string. This vector
	// MUST byte-match what Python emits for the same Framework via:
	//   json.dumps(framework_dict, sort_keys=True, ensure_ascii=False,
	//              separators=(",", ":"))
	// CV-09 cross-language golden vectors will re-verify this against
	// real Python/JS SDKs. For now, this anchors the Go side so any
	// future change to canonicalJSON is loud.
	f := Framework{
		AleutianSnapshotAt:   "2026-03-01",
		FrameworkID:          "f1",
		FrameworkPublishedAt: "2017-04-30",
		VersionID:            "f1@20260301",
		Controls: []Control{{
			ID:              "C1",
			Title:           "T & U < V > W",
			Category:        "cat",
			Status:          StatusOperating,
			WhatWeProve:     "p",
			WhatWeDontProve: "q",
		}},
		ControlsOutOfScope: []OutOfScopeControl{{ID: "X", Reason: "r"}},
		ControlsSHA512Hex:  "",
	}
	got, err := canonicalJSON(f)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	want := `{"aleutian_snapshot_at":"2026-03-01","controls":[{"category":"cat","id":"C1","status":"operating","title":"T & U < V > W","what_we_dont_prove":"q","what_we_prove":"p"}],"controls_out_of_scope":[{"id":"X","reason":"r"}],"controls_sha512_hex":"","framework_id":"f1","framework_published_at":"2017-04-30","version_id":"f1@20260301"}`
	if string(got) != want {
		t.Errorf("canonical bytes diverge from Python json.dumps byte-identity contract\n got:  %s\nwant:  %s", got, want)
	}
}

func TestCanonicalJSON_UnicodeRawUTF8(t *testing.T) {
	// ensure_ascii=False: characters ≥ U+0020 emit as raw UTF-8,
	// not \uXXXX escape sequences.
	f := validFixture(t)
	f.Controls[0].Title = "Étoile · 日本語"
	bytes, err := canonicalJSON(f)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if !strings.Contains(string(bytes), "Étoile · 日本語") {
		t.Errorf("unicode must round-trip as raw UTF-8 (no \\uXXXX escapes); got %s", bytes)
	}
}

func TestCanonicalJSON_ControlCharEscape(t *testing.T) {
	// Characters below U+0020 (other than the short-escape set) use
	// \uXXXX with lowercase hex (matches Python json output).
	f := validFixture(t)
	f.Controls[0].Title = "x" + string([]byte{0x01}) + "y"
	bytes, err := canonicalJSON(f)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if !strings.Contains(string(bytes), `\u0001`) {
		t.Errorf("0x01 must escape as \\u0001 lowercase; got %s", bytes)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
