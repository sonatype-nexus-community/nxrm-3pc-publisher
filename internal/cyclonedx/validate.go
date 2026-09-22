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
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ValidateSBOM checks that bom has the required fields for a Sonatype
// Third-Party Component Catalog SBOM: BOMFormat, SpecVersion, SerialNumber
// all non-empty; every entry in *Components has Name, Version, Type
// (non-empty/non-zero), and BOMRef non-empty; Licenses present (at least one
// license somewhere across the components).
func ValidateSBOM(bom *cdx.BOM) error {
	if bom == nil {
		return fmt.Errorf("BOM is nil")
	}

	if bom.BOMFormat == "" {
		return fmt.Errorf("BOMFormat is required")
	}

	if bom.SpecVersion == 0 {
		return fmt.Errorf("SpecVersion is required")
	}

	if bom.SerialNumber == "" {
		return fmt.Errorf("SerialNumber is required")
	}

	if bom.Components == nil || len(*bom.Components) == 0 {
		return fmt.Errorf("Components is required and must not be empty")
	}

	hasLicenses := false
	for i, comp := range *bom.Components {
		if comp.Name == "" {
			return fmt.Errorf("component %d: Name is required", i)
		}
		if comp.Version == "" {
			return fmt.Errorf("component %d: Version is required", i)
		}
		if comp.Type == "" {
			return fmt.Errorf("component %d: Type is required", i)
		}
		if comp.BOMRef == "" {
			return fmt.Errorf("component %d: BOMRef is required", i)
		}
		if comp.Licenses != nil && len(*comp.Licenses) > 0 {
			hasLicenses = true
		}
	}

	if !hasLicenses {
		return fmt.Errorf("at least one license is required across components")
	}

	return nil
}

// ValidateVEX checks that vex has BOMFormat, SpecVersion, SerialNumber
// non-empty, and every entry in *Vulnerabilities has ID non-empty,
// Analysis.State non-empty, and at least one entry in *Affects with a
// non-empty Ref.
func ValidateVEX(vex *cdx.BOM) error {
	if vex == nil {
		return fmt.Errorf("VEX BOM is nil")
	}

	if vex.BOMFormat == "" {
		return fmt.Errorf("BOMFormat is required")
	}

	if vex.SpecVersion == 0 {
		return fmt.Errorf("SpecVersion is required")
	}

	if vex.SerialNumber == "" {
		return fmt.Errorf("SerialNumber is required")
	}

	if vex.Vulnerabilities == nil || len(*vex.Vulnerabilities) == 0 {
		return fmt.Errorf("Vulnerabilities is required and must not be empty")
	}

	for i, vuln := range *vex.Vulnerabilities {
		if vuln.ID == "" {
			return fmt.Errorf("vulnerability %d: ID is required", i)
		}

		if vuln.Analysis == nil || vuln.Analysis.State == "" {
			return fmt.Errorf("vulnerability %d: Analysis.State is required", i)
		}

		if vuln.Affects == nil || len(*vuln.Affects) == 0 {
			return fmt.Errorf("vulnerability %d: Affects is required and must not be empty", i)
		}

		for j, affect := range *vuln.Affects {
			if affect.Ref == "" {
				return fmt.Errorf("vulnerability %d: affects[%d].Ref is required", i, j)
			}
		}
	}

	return nil
}
