// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"errors"
	"fmt"
	"io/fs"
)

// LoadFrameworkFromBundle implements the load-and-cross-check half of
// SDK verify step 9 per compliance_bundle_format_spec.md (CV-02
// amendment).
//
// # Description
//
// Step 9 has two halves:
//
//  1. Load the framework from the bundle (not from this SDK's
//     embedded registry) and cross-check that the framework's
//     internal version_id matches the version pinned in the
//     manifest. THIS function does (1).
//
//  2. Run the coverage check: every operating-status control must
//     have a corresponding evidence artifact in the bundle. That
//     half lives in a sibling primitive (filed as a follow-up
//     ticket) because it depends on the bundle's evidence-file
//     layout convention, which is owned by the producer that
//     emits the bundle.
//
// Self-containment contract: the SDK reads the framework from the
// bundle's bytes, not from this package's embedded registry. That is
// why we accept an fs.FS rather than looking up the version in
// Latest. Bundles produced years ago must remain verifiable by an
// SDK that has since moved its Latest pin forward.
//
// # Inputs
//
//   - bundleFS: an io/fs.FS rooted at the bundle's contents.
//     *zip.Reader satisfies this; so do os.DirFS for extracted
//     bundles and embed.FS for test fixtures.
//   - manifestFrameworkVersion: the value of manifest.framework_version,
//     which the producer pinned at finalize time per CV-04.
//
// # Outputs
//
//   - Framework: loaded, self-attestation verified, version
//     cross-check passed.
//   - error: ErrFrameworkMissing if the expected path is absent;
//     ErrFrameworkVersionMismatch if manifest's
//     framework_version != loaded version_id; any wrapped
//     LoadFromReader error (ErrAttestationMismatch,
//     ErrUnknownStatus, ErrMalformedJSON, ErrSizeExceeded,
//     ErrHashFormat) if the embedded file is malformed.
//
// # Example
//
//	// In the bundle verifier:
//	fwk, err := frameworks.LoadFrameworkFromBundle(zipReader, manifest.FrameworkVersion)
//	switch {
//	case errors.Is(err, frameworks.ErrFrameworkMissing):
//	    return ErrBundleMalformed
//	case errors.Is(err, frameworks.ErrFrameworkVersionMismatch):
//	    return ErrBundleTampered
//	case err != nil:
//	    return fmt.Errorf("framework load: %w", err)
//	}
//	// Hand fwk to the coverage-check primitive (CV-05 follow-up).
//
// # Limitations
//
//   - Does NOT consult Latest. The bundle's own controls.json is
//     authoritative; that's the entire point of the
//     self-containment contract.
//   - Does NOT perform the coverage check. Filed as a follow-up
//     ticket (compliance_versioning_05d).
//
// # Assumptions
//
//   - manifestFrameworkVersion has already been validated as a
//     well-formed VersionID by the outer bundle verifier (e.g.
//     non-empty, contains '@'). Defense in depth: this function
//     handles malformed inputs gracefully via the path lookup
//     returning fs.ErrNotExist.
func LoadFrameworkFromBundle(bundleFS fs.FS, manifestFrameworkVersion VersionID) (Framework, error) {
	bundlePath := bundlePathFor(manifestFrameworkVersion)

	file, err := bundleFS.Open(bundlePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Framework{}, fmt.Errorf("%w: %s", ErrFrameworkMissing, bundlePath)
		}
		return Framework{}, fmt.Errorf("open bundle entry %s: %w", bundlePath, err)
	}
	defer func() { _ = file.Close() }()

	loaded, err := LoadFromReader(file)
	if err != nil {
		return Framework{}, fmt.Errorf("load %s: %w", bundlePath, err)
	}

	if loaded.VersionID != manifestFrameworkVersion {
		return Framework{}, fmt.Errorf(
			"%w: manifest=%q controls.json=%q",
			ErrFrameworkVersionMismatch,
			manifestFrameworkVersion,
			loaded.VersionID,
		)
	}

	return loaded, nil
}
