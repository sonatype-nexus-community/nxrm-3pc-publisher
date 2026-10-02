/**
 * Copyright (c) 2019-present Sonatype, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package cyclonedx handles splitting vendor-authored CycloneDX documents into
// SBOM and VEX documents per Sonatype's Third-Party Component Catalog spec.
package cyclonedx

import (
	"io"
	"log/slog"
	"net/url"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

// Split parses a single vendor-authored CycloneDX document (containing both
// components and vulnerabilities) and derives an SBOM document and zero or one
// VEX document. Returns nil for vex if the source has no vulnerabilities.
//
// The SBOM preserves the source's serialNumber; the VEX gets a new distinct
// serialNumber (VEX is a separate BOM). Vulnerability affects refs are
// rewritten to BOM-Links pointing at the SBOM when they look like plain
// bom-refs (not already fully-qualified URNs). logger must not be nil.
func Split(logger *slog.Logger, r io.Reader) (sbom *cdx.BOM, vex *cdx.BOM, err error) {
	var source cdx.BOM
	decoder := cdx.NewBOMDecoder(r, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&source); err != nil {
		return nil, nil, err
	}

	// CycloneDX requires version >= 1; a source that omits it decodes as 0.
	// Normalise here so the SBOM, and the BOM-Links that reference it, agree.
	sbomVersion := source.Version
	if sbomVersion < 1 {
		sbomVersion = 1
	}

	sbom = &cdx.BOM{
		BOMFormat:       source.BOMFormat,
		SpecVersion:     source.SpecVersion,
		SerialNumber:    source.SerialNumber,
		Version:         sbomVersion,
		Metadata:        source.Metadata,
		Components:      withMetadataComponent(logger, source.Components, source.Metadata),
		Dependencies:    source.Dependencies,
		Vulnerabilities: nil,
	}

	if source.Vulnerabilities == nil || len(*source.Vulnerabilities) == 0 {
		return sbom, nil, nil
	}

	vexSerial := "urn:uuid:" + uuid.New().String()
	vex = &cdx.BOM{
		BOMFormat:       source.BOMFormat,
		SpecVersion:     source.SpecVersion,
		SerialNumber:    vexSerial,
		Version:         1,
		Vulnerabilities: copyVulnerabilities(logger, source.Vulnerabilities, sbom),
	}
	// Carry the vendor document's timestamp so VEXFilename is stable across
	// re-publishes of the same component (the bucket skips existing keys).
	if source.Metadata != nil && source.Metadata.Timestamp != "" {
		vex.Metadata = &cdx.Metadata{Timestamp: source.Metadata.Timestamp}
	}

	return sbom, vex, nil
}

// withMetadataComponent folds metadata.component into the SBOM's components
// list when components is empty/nil. CycloneDX allows a BOM describing a
// single library to declare its subject only via metadata.component rather
// than the top-level components array; Sonatype's cataloging still needs
// that component in components[] to be recognized as an SBOM entry.
func withMetadataComponent(logger *slog.Logger, components *[]cdx.Component, metadata *cdx.Metadata) *[]cdx.Component {
	if components != nil && len(*components) > 0 {
		return components
	}
	if metadata == nil || metadata.Component == nil {
		logger.Warn("CycloneDX document has no components[] and no metadata.component; SBOM will have zero components")
		return components
	}
	return &[]cdx.Component{*metadata.Component}
}

// copyVulnerabilities deep-copies vulnerabilities and rewrites affects refs
// to BOM-Links where appropriate.
func copyVulnerabilities(logger *slog.Logger, vulns *[]cdx.Vulnerability, sbom *cdx.BOM) *[]cdx.Vulnerability {
	if vulns == nil {
		return nil
	}

	result := make([]cdx.Vulnerability, len(*vulns))
	for i, v := range *vulns {
		result[i] = v
		if v.Affects != nil {
			affects := make([]cdx.Affects, len(*v.Affects))
			for j, a := range *v.Affects {
				affects[j] = a
				affects[j].Ref = rewriteRefToBOMLink(logger, a.Ref, sbom)
			}
			result[i].Affects = &affects
		}
	}

	return &result
}

// rewriteRefToBOMLink rewrites a plain bom-ref to a BOM-Link URN pointing at
// the SBOM. If the ref already looks like a URN (starts with urn:cdx: or
// urn:uuid:), it's returned unchanged.
func rewriteRefToBOMLink(logger *slog.Logger, ref string, sbom *cdx.BOM) string {
	if ref == "" {
		return ref
	}

	if len(ref) >= 8 && ref[:8] == "urn:cdx:" {
		return ref
	}
	if len(ref) >= 9 && ref[:9] == "urn:uuid:" {
		return ref
	}

	sbomSerial := sbom.SerialNumber
	if sbomSerial == "" {
		logger.Warn("vulnerability affects ref left unrewritten: SBOM has no serialNumber", "ref", ref)
		return ref
	}
	const uuidPrefix = "urn:uuid:"
	if len(sbomSerial) >= len(uuidPrefix) && sbomSerial[:len(uuidPrefix)] == uuidPrefix {
		sbomSerial = sbomSerial[len(uuidPrefix):]
	}

	sbomVersion := 1
	if sbom.Version != 0 {
		sbomVersion = sbom.Version
	}

	escapedRef := url.QueryEscape(ref)
	return "urn:cdx:" + sbomSerial + "/" + itoa(sbomVersion) + "#" + escapedRef
}

// itoa converts int to string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}

	var negative bool
	if n < 0 {
		negative = true
		n = -n
	}

	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}

	if negative {
		digits = append([]byte{'-'}, digits...)
	}

	return string(digits)
}
