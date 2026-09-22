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
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateSBOM(t *testing.T) {
	t.Run("valid SBOM passes", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Components: &[]cdx.Component{
				{
					BOMRef:   "pkg:maven/test/component@1.0.0",
					Name:     "component",
					Version:  "1.0.0",
					Type:     cdx.ComponentTypeLibrary,
					Licenses: &cdx.Licenses{{License: &cdx.License{ID: "Apache-2.0"}}},
				},
			},
		}

		err := ValidateSBOM(bom)
		assert.NoError(t, err)
	})

	t.Run("nil BOM fails", func(t *testing.T) {
		err := ValidateSBOM(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil")
	})

	t.Run("missing BOMFormat fails", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Components: &[]cdx.Component{
				{
					BOMRef:  "test",
					Name:    "component",
					Version: "1.0.0",
					Type:    cdx.ComponentTypeLibrary,
				},
			},
		}

		err := ValidateSBOM(bom)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "BOMFormat")
	})

	t.Run("missing SpecVersion fails", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Components: &[]cdx.Component{
				{
					BOMRef:  "test",
					Name:    "component",
					Version: "1.0.0",
					Type:    cdx.ComponentTypeLibrary,
				},
			},
		}

		err := ValidateSBOM(bom)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SpecVersion")
	})

	t.Run("missing SerialNumber fails", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_5,
			Components: &[]cdx.Component{
				{
					BOMRef:  "test",
					Name:    "component",
					Version: "1.0.0",
					Type:    cdx.ComponentTypeLibrary,
				},
			},
		}

		err := ValidateSBOM(bom)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SerialNumber")
	})

	t.Run("missing Components fails", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		}

		err := ValidateSBOM(bom)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Components")
	})

	t.Run("component missing Name fails", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Components: &[]cdx.Component{
				{
					BOMRef:  "test",
					Version: "1.0.0",
					Type:    cdx.ComponentTypeLibrary,
				},
			},
		}

		err := ValidateSBOM(bom)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Name")
	})

	t.Run("component missing Version fails", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Components: &[]cdx.Component{
				{
					BOMRef: "test",
					Name:   "component",
					Type:   cdx.ComponentTypeLibrary,
				},
			},
		}

		err := ValidateSBOM(bom)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Version")
	})

	t.Run("component missing Type fails", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Components: &[]cdx.Component{
				{
					BOMRef:  "test",
					Name:    "component",
					Version: "1.0.0",
				},
			},
		}

		err := ValidateSBOM(bom)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Type")
	})

	t.Run("component missing BOMRef fails", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Components: &[]cdx.Component{
				{
					Name:    "component",
					Version: "1.0.0",
					Type:    cdx.ComponentTypeLibrary,
				},
			},
		}

		err := ValidateSBOM(bom)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "BOMRef")
	})

	t.Run("missing Licenses fails", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Components: &[]cdx.Component{
				{
					BOMRef:  "test",
					Name:    "component",
					Version: "1.0.0",
					Type:    cdx.ComponentTypeLibrary,
				},
			},
		}

		err := ValidateSBOM(bom)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "license")
	})
}

func TestValidateVEX(t *testing.T) {
	t.Run("valid VEX passes", func(t *testing.T) {
		vex := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID: "CVE-2026-99999",
					Analysis: &cdx.VulnerabilityAnalysis{
						State: cdx.IASResolved,
					},
					Affects: &[]cdx.Affects{
						{Ref: "pkg:maven/test/component@1.0.0"},
					},
				},
			},
		}

		err := ValidateVEX(vex)
		assert.NoError(t, err)
	})

	t.Run("nil VEX fails", func(t *testing.T) {
		err := ValidateVEX(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil")
	})

	t.Run("missing BOMFormat fails", func(t *testing.T) {
		vex := &cdx.BOM{
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID:       "CVE-2026-99999",
					Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolved},
					Affects:  &[]cdx.Affects{{Ref: "test"}},
				},
			},
		}

		err := ValidateVEX(vex)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "BOMFormat")
	})

	t.Run("missing SpecVersion fails", func(t *testing.T) {
		vex := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID:       "CVE-2026-99999",
					Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolved},
					Affects:  &[]cdx.Affects{{Ref: "test"}},
				},
			},
		}

		err := ValidateVEX(vex)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SpecVersion")
	})

	t.Run("missing SerialNumber fails", func(t *testing.T) {
		vex := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_5,
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID:       "CVE-2026-99999",
					Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolved},
					Affects:  &[]cdx.Affects{{Ref: "test"}},
				},
			},
		}

		err := ValidateVEX(vex)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SerialNumber")
	})

	t.Run("missing Vulnerabilities fails", func(t *testing.T) {
		vex := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		}

		err := ValidateVEX(vex)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Vulnerabilities")
	})

	t.Run("vulnerability missing ID fails", func(t *testing.T) {
		vex := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolved},
					Affects:  &[]cdx.Affects{{Ref: "test"}},
				},
			},
		}

		err := ValidateVEX(vex)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ID")
	})

	t.Run("vulnerability missing Analysis.State fails", func(t *testing.T) {
		vex := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID:      "CVE-2026-99999",
					Affects: &[]cdx.Affects{{Ref: "test"}},
				},
			},
		}

		err := ValidateVEX(vex)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Analysis.State")
	})

	t.Run("vulnerability missing Affects fails", func(t *testing.T) {
		vex := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID:       "CVE-2026-99999",
					Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolved},
				},
			},
		}

		err := ValidateVEX(vex)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Affects")
	})

	t.Run("affects missing Ref fails", func(t *testing.T) {
		vex := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID:       "CVE-2026-99999",
					Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolved},
					Affects:  &[]cdx.Affects{{Ref: ""}},
				},
			},
		}

		err := ValidateVEX(vex)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Ref")
	})
}
