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

package cyclonedx

import (
	"log/slog"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// SBOMFilename returns "<name>-<version>.bom.json" per the spec's SBOM
// naming convention.
func SBOMFilename(name, version string) string {
	return name + "-" + version + ".bom.json"
}

// VEXFilename returns the spec-conformant VEX filename for a given VEX BOM:
//   - exactly one vulnerability -> "<CVE-ID>-<ISO8601-timestamp>.bom.json"
//   - zero or multiple vulnerabilities -> "<ISO8601-timestamp>.bom.json"
//
// The timestamp comes from the VEX BOM's Metadata.Timestamp if set and
// parseable as RFC3339, otherwise time.Now().UTC() formatted the same way.
// logger must not be nil.
func VEXFilename(logger *slog.Logger, vex *cdx.BOM) string {
	timestamp := extractTimestamp(logger, vex)

	if vex.Vulnerabilities != nil && len(*vex.Vulnerabilities) == 1 {
		vuln := (*vex.Vulnerabilities)[0]
		if vuln.ID != "" {
			return vuln.ID + "-" + timestamp + ".bom.json"
		}
	}

	return timestamp + ".bom.json"
}

// extractTimestamp returns the timestamp to use for VEX naming.
func extractTimestamp(logger *slog.Logger, vex *cdx.BOM) string {
	if vex.Metadata != nil && vex.Metadata.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, vex.Metadata.Timestamp); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
		logger.Warn("VEX metadata timestamp unparseable, using current time instead", "timestamp", vex.Metadata.Timestamp)
	}

	return time.Now().UTC().Format(time.RFC3339)
}
