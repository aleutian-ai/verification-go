// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

// fakeBundle returns an fs.FS whose only entry is the SOC 2 framework
// at the canonical bundle path. Mirrors what a real bundle ZIP would
// produce.
func fakeBundle(t *testing.T, manifestVersion VersionID, contents []byte) fstest.MapFS {
	t.Helper()
	return fstest.MapFS{
		string(bundlePathFor(manifestVersion)): &fstest.MapFile{
			Data: contents,
		},
	}
}

func TestLoadFrameworkFromBundle_HappyPath(t *testing.T) {
	// Use the SOC 2 seed as the embedded contents — producer would
	// have called PinForBundle to get these bytes at finalize time.
	entry, err := PinForBundle(SOC2_2017)
	if err != nil {
		t.Fatalf("PinForBundle: %v", err)
	}
	bundle := fakeBundle(t, entry.VersionID, entry.Contents)

	loaded, err := LoadFrameworkFromBundle(bundle, entry.VersionID)
	if err != nil {
		t.Fatalf("LoadFrameworkFromBundle: %v", err)
	}
	if loaded.FrameworkID != SOC2_2017 {
		t.Errorf("framework_id: got %q want %q", loaded.FrameworkID, SOC2_2017)
	}
	if loaded.VersionID != entry.VersionID {
		t.Errorf("version_id: got %q want %q", loaded.VersionID, entry.VersionID)
	}
}

func TestLoadFrameworkFromBundle_MissingFile(t *testing.T) {
	// Bundle declares a framework_version but ships no controls.json.
	emptyBundle := fstest.MapFS{}
	_, err := LoadFrameworkFromBundle(emptyBundle, "soc2-2017@20260531")
	if !errors.Is(err, ErrFrameworkMissing) {
		t.Fatalf("got err=%v, want ErrFrameworkMissing", err)
	}
}

func TestLoadFrameworkFromBundle_VersionMismatch(t *testing.T) {
	// Bundle ships SOC 2 controls.json but the manifest pins a
	// different (e.g. spoofed) framework_version. This is the
	// CV-02 step-9 cross-check attack surface.
	entry, err := PinForBundle(SOC2_2017)
	if err != nil {
		t.Fatalf("PinForBundle: %v", err)
	}
	// File ships at the SOC 2 path, but we ask for a different
	// version. The mismatch surfaces as ErrFrameworkMissing (the
	// path the asked-for version maps to doesn't exist).
	bundle := fakeBundle(t, entry.VersionID, entry.Contents)
	_, err = LoadFrameworkFromBundle(bundle, "gdpr@20260531")
	if !errors.Is(err, ErrFrameworkMissing) {
		t.Fatalf("got err=%v, want ErrFrameworkMissing", err)
	}

	// Now the trickier case: bundle ships a controls.json at the
	// gdpr path, but that file's internal version_id is SOC 2's.
	// This is the producer-bug-or-tampering case CV-02 explicitly
	// guards against.
	spoofPath := bundlePathFor("gdpr@20260531")
	spoofBundle := fstest.MapFS{
		spoofPath: &fstest.MapFile{Data: entry.Contents}, // SOC 2 bytes at GDPR path
	}
	_, err = LoadFrameworkFromBundle(spoofBundle, "gdpr@20260531")
	if !errors.Is(err, ErrFrameworkVersionMismatch) {
		t.Fatalf("got err=%v, want ErrFrameworkVersionMismatch", err)
	}
}

func TestLoadFrameworkFromBundle_MalformedFile(t *testing.T) {
	// Bundle ships a controls.json that fails LoadFromReader.
	garbage := []byte(`{"this":"is not a valid framework"}`)
	bundle := fakeBundle(t, "soc2-2017@20260531", garbage)
	_, err := LoadFrameworkFromBundle(bundle, "soc2-2017@20260531")
	if err == nil {
		t.Fatal("expected error for malformed controls.json; got nil")
	}
	// Specific sentinel depends on which validation step the
	// garbage trips first. The contract is: NOT
	// ErrFrameworkVersionMismatch (the file isn't even loadable, so
	// we can't get as far as cross-check).
	if errors.Is(err, ErrFrameworkVersionMismatch) {
		t.Errorf("got ErrFrameworkVersionMismatch; expected an earlier load failure")
	}
}

func TestLoadFrameworkFromBundle_TamperedContents(t *testing.T) {
	// Producer pinned the correct version, but bundle contents have
	// been edited after the producer's signature would have covered
	// them. The self-attestation hash fails — the framework's own
	// integrity check catches the tampering before we even reach
	// the cross-check.
	entry, err := PinForBundle(SOC2_2017)
	if err != nil {
		t.Fatalf("PinForBundle: %v", err)
	}
	// Flip one character inside one of the control titles. This
	// invalidates the controls_sha512_hex self-attestation.
	tampered := strings.Replace(string(entry.Contents), "Logical access", "AudiX access", 1)
	bundle := fakeBundle(t, entry.VersionID, []byte(tampered))

	_, err = LoadFrameworkFromBundle(bundle, entry.VersionID)
	if !errors.Is(err, ErrAttestationMismatch) {
		t.Fatalf("got err=%v, want ErrAttestationMismatch (self-attestation should catch the tampering)", err)
	}
}
