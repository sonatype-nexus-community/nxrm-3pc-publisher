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
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// checkSpecVersion enforces the CycloneDX versions the catalog accepts
// (1.6 and 1.7). It applies to both SBOM and VEX documents.
func checkSpecVersion(v cdx.SpecVersion) error {
	switch v {
	case cdx.SpecVersion1_6, cdx.SpecVersion1_7:
		return nil
	case 0:
		return fmt.Errorf("SpecVersion is required (must be 1.6 or 1.7)")
	default:
		return fmt.Errorf("SpecVersion %s is not supported (must be 1.6 or 1.7)", v)
	}
}

// ValidateSBOM checks that bom meets the Sonatype Third-Party Component
// Catalog SBOM requirements: BOMFormat, SerialNumber non-empty; SpecVersion
// 1.6 or 1.7; and every entry in *Components has Name, Version, Type,
// BOMRef and at least one license. For the "maven" ecosystem every component
// must also declare a Group, as the package manager requires one.
//
// A component without pedigree.ancestors is logged as a warning rather than
// rejected: ancestors apply to patched or forked components, and the
// catalog treats them as an expectation, not a hard requirement.
// logger must not be nil.
func ValidateSBOM(logger *slog.Logger, bom *cdx.BOM, ecosystem string) error {
	if bom == nil {
		return fmt.Errorf("BOM is nil")
	}

	if bom.BOMFormat == "" {
		return fmt.Errorf("BOMFormat is required")
	}

	if err := checkSpecVersion(bom.SpecVersion); err != nil {
		return err
	}

	if bom.SerialNumber == "" {
		return fmt.Errorf("SerialNumber is required")
	}

	if bom.Components == nil || len(*bom.Components) == 0 {
		return fmt.Errorf("components is required and must not be empty")
	}

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
		if comp.Licenses == nil || len(*comp.Licenses) == 0 {
			return fmt.Errorf("component %d (%s): at least one license is required", i, comp.Name)
		}
		if ecosystem == "maven" && comp.Group == "" {
			return fmt.Errorf("component %d (%s): Group is required for the maven ecosystem", i, comp.Name)
		}
		if comp.Pedigree == nil || comp.Pedigree.Ancestors == nil || len(*comp.Pedigree.Ancestors) == 0 {
			logger.Warn("SBOM component has no pedigree.ancestors; the catalog uses them to find newly disclosed upstream vulnerabilities", "component", comp.Name, "version", comp.Version)
		}
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

	if err := checkSpecVersion(vex.SpecVersion); err != nil {
		return err
	}

	if vex.SerialNumber == "" {
		return fmt.Errorf("SerialNumber is required")
	}

	if vex.Vulnerabilities == nil || len(*vex.Vulnerabilities) == 0 {
		return fmt.Errorf("vulnerabilities is required and must not be empty")
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
