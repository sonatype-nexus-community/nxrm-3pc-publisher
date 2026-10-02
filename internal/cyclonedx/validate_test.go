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
	"bytes"
	"log/slog"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validSBOM returns a minimal SBOM that satisfies every ValidateSBOM rule, so
// each test case can break exactly one thing.
func validSBOM() *cdx.BOM {
	return &cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_6,
		SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		Components: &[]cdx.Component{
			{
				BOMRef:   "pkg:maven/org.example/component@1.0.0",
				Group:    "org.example",
				Name:     "component",
				Version:  "1.0.0",
				Type:     cdx.ComponentTypeLibrary,
				Licenses: &cdx.Licenses{{License: &cdx.License{ID: "Apache-2.0"}}},
				Pedigree: &cdx.Pedigree{Ancestors: &[]cdx.Component{{Name: "component", Version: "1.0.0-upstream"}}},
			},
		},
	}
}

func TestValidateSBOM(t *testing.T) {
	t.Run("valid SBOM passes", func(t *testing.T) {
		assert.NoError(t, ValidateSBOM(discardLogger(), validSBOM(), "maven"))
	})

	t.Run("nil BOM fails", func(t *testing.T) {
		err := ValidateSBOM(discardLogger(), nil, "maven")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil")
	})

	cases := []struct {
		name    string
		mutate  func(b *cdx.BOM)
		wantErr string
	}{
		{"missing BOMFormat", func(b *cdx.BOM) { b.BOMFormat = "" }, "BOMFormat"},
		{"missing SpecVersion", func(b *cdx.BOM) { b.SpecVersion = 0 }, "SpecVersion"},
		{"SpecVersion 1.5 is rejected", func(b *cdx.BOM) { b.SpecVersion = cdx.SpecVersion1_5 }, "not supported"},
		{"SpecVersion 1.4 is rejected", func(b *cdx.BOM) { b.SpecVersion = cdx.SpecVersion1_4 }, "not supported"},
		{"missing SerialNumber", func(b *cdx.BOM) { b.SerialNumber = "" }, "SerialNumber"},
		{"missing Components", func(b *cdx.BOM) { b.Components = nil }, "components"},
		{"component missing Name", func(b *cdx.BOM) { (*b.Components)[0].Name = "" }, "Name"},
		{"component missing Version", func(b *cdx.BOM) { (*b.Components)[0].Version = "" }, "Version"},
		{"component missing Type", func(b *cdx.BOM) { (*b.Components)[0].Type = "" }, "Type"},
		{"component missing BOMRef", func(b *cdx.BOM) { (*b.Components)[0].BOMRef = "" }, "BOMRef"},
		{"component missing Licenses", func(b *cdx.BOM) { (*b.Components)[0].Licenses = nil }, "license"},
		{"component with empty Licenses", func(b *cdx.BOM) { (*b.Components)[0].Licenses = &cdx.Licenses{} }, "license"},
		{"maven component missing Group", func(b *cdx.BOM) { (*b.Components)[0].Group = "" }, "Group"},
	}
	for _, tc := range cases {
		t.Run(tc.name+" fails", func(t *testing.T) {
			bom := validSBOM()
			tc.mutate(bom)
			err := ValidateSBOM(discardLogger(), bom, "maven")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	t.Run("SpecVersion 1.7 passes", func(t *testing.T) {
		bom := validSBOM()
		bom.SpecVersion = cdx.SpecVersion1_7
		assert.NoError(t, ValidateSBOM(discardLogger(), bom, "maven"))
	})

	t.Run("every component needs licenses, not just one", func(t *testing.T) {
		bom := validSBOM()
		*bom.Components = append(*bom.Components, cdx.Component{
			BOMRef: "b", Group: "org.example", Name: "b", Version: "1", Type: cdx.ComponentTypeLibrary,
		})
		err := ValidateSBOM(discardLogger(), bom, "maven")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "license")
	})

	t.Run("Group is not required outside maven", func(t *testing.T) {
		bom := validSBOM()
		(*bom.Components)[0].Group = ""
		assert.NoError(t, ValidateSBOM(discardLogger(), bom, "npm"))
	})

	t.Run("missing pedigree.ancestors warns but passes", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		bom := validSBOM()
		(*bom.Components)[0].Pedigree = nil

		require.NoError(t, ValidateSBOM(logger, bom, "maven"))
		assert.Contains(t, buf.String(), "level=WARN")
		assert.Contains(t, buf.String(), "pedigree.ancestors")
	})

	t.Run("present pedigree.ancestors does not warn", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		require.NoError(t, ValidateSBOM(logger, validSBOM(), "maven"))
		assert.Empty(t, buf.String())
	})
}

func TestValidateVEX(t *testing.T) {
	t.Run("valid VEX passes", func(t *testing.T) {
		vex := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_6,
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
			SpecVersion:  cdx.SpecVersion1_6,
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

	t.Run("unsupported SpecVersion fails", func(t *testing.T) {
		vex := &cdx.BOM{
			BOMFormat:    "CycloneDX",
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
		assert.Contains(t, err.Error(), "not supported")
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
			SpecVersion: cdx.SpecVersion1_6,
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
			SpecVersion:  cdx.SpecVersion1_6,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		}

		err := ValidateVEX(vex)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "vulnerabilities")
	})

	t.Run("vulnerability missing ID fails", func(t *testing.T) {
		vex := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_6,
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
			SpecVersion:  cdx.SpecVersion1_6,
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
			SpecVersion:  cdx.SpecVersion1_6,
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
			SpecVersion:  cdx.SpecVersion1_6,
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
