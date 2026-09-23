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
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplit(t *testing.T) {
	t.Run("splits components and vulnerabilities correctly", func(t *testing.T) {
		source := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:0f2c9a6e-71c4-4d8b-9e3a-5b6d1f0a2c44",
			Version:      1,
			Components: &[]cdx.Component{
				{
					BOMRef:  "pkg:maven/org.springframework.boot/spring-boot@4.1.1-patched-1",
					Name:    "spring-boot",
					Version: "4.1.1-patched-1",
					Type:    cdx.ComponentTypeLibrary,
				},
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID: "CVE-2026-99999",
					Affects: &[]cdx.Affects{
						{Ref: "pkg:maven/org.springframework.boot/spring-boot@4.1.1-patched-1"},
					},
				},
			},
		}

		jsonBytes := mustMarshalBOM(t, source)
		sbom, vex, err := Split(bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, sbom)
		require.NotNil(t, vex)

		assert.Equal(t, "CycloneDX", sbom.BOMFormat)
		assert.Equal(t, cdx.SpecVersion1_5, sbom.SpecVersion)
		assert.Equal(t, "urn:uuid:0f2c9a6e-71c4-4d8b-9e3a-5b6d1f0a2c44", sbom.SerialNumber)
		assert.NotNil(t, sbom.Components)
		assert.Len(t, *sbom.Components, 1)
		assert.Nil(t, sbom.Vulnerabilities)

		assert.Equal(t, "CycloneDX", vex.BOMFormat)
		assert.Equal(t, cdx.SpecVersion1_5, vex.SpecVersion)
		assert.NotEqual(t, sbom.SerialNumber, vex.SerialNumber)
		assert.True(t, strings.HasPrefix(vex.SerialNumber, "urn:uuid:"))
		assert.NotNil(t, vex.Vulnerabilities)
		assert.Len(t, *vex.Vulnerabilities, 1)
	})

	t.Run("VEX gets distinct serial number from SBOM", func(t *testing.T) {
		source := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Version:      1,
			Vulnerabilities: &[]cdx.Vulnerability{
				{ID: "CVE-2026-00001"},
			},
		}

		jsonBytes := mustMarshalBOM(t, source)
		sbom, vex, err := Split(bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, sbom)
		require.NotNil(t, vex)

		assert.Equal(t, source.SerialNumber, sbom.SerialNumber)
		assert.NotEqual(t, sbom.SerialNumber, vex.SerialNumber)
		assert.True(t, strings.HasPrefix(vex.SerialNumber, "urn:uuid:"))
	})

	t.Run("BOM-Link ref rewriting produces exact escaped format", func(t *testing.T) {
		source := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:0f2c9a6e-71c4-4d8b-9e3a-5b6d1f0a2c44",
			Version:      1,
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID: "CVE-2026-99999",
					Affects: &[]cdx.Affects{
						{Ref: "pkg:maven/org.springframework.boot/spring-boot@4.1.1-patched-1"},
					},
				},
			},
		}

		jsonBytes := mustMarshalBOM(t, source)
		sbom, vex, err := Split(bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, sbom)
		require.NotNil(t, vex)
		require.NotNil(t, vex.Vulnerabilities)

		expectedRef := "urn:cdx:0f2c9a6e-71c4-4d8b-9e3a-5b6d1f0a2c44/1#pkg%3Amaven%2Forg.springframework.boot%2Fspring-boot%404.1.1-patched-1"
		actualRef := (*(*vex.Vulnerabilities)[0].Affects)[0].Ref
		assert.Equal(t, expectedRef, actualRef, "BOM-Link should have exact URL escaping (%%3A for :, %%2F for /, %%40 for @)")
	})

	t.Run("split with zero vulnerabilities returns nil VEX", func(t *testing.T) {
		source := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Version:      1,
			Components: &[]cdx.Component{
				{
					BOMRef:  "test-component",
					Name:    "test",
					Version: "1.0.0",
					Type:    cdx.ComponentTypeLibrary,
				},
			},
		}

		jsonBytes := mustMarshalBOM(t, source)
		sbom, vex, err := Split(bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, sbom)
		assert.Nil(t, vex)
	})

	t.Run("leaves existing URN refs unchanged", func(t *testing.T) {
		source := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Version:      1,
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID: "CVE-2026-00001",
					Affects: &[]cdx.Affects{
						{Ref: "urn:cdx:existing-ref/1#something"},
						{Ref: "urn:uuid:already-a-uuid-ref"},
					},
				},
			},
		}

		jsonBytes := mustMarshalBOM(t, source)
		_, vex, err := Split(bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, vex)

		assert.Equal(t, "urn:cdx:existing-ref/1#something", (*(*vex.Vulnerabilities)[0].Affects)[0].Ref)
		assert.Equal(t, "urn:uuid:already-a-uuid-ref", (*(*vex.Vulnerabilities)[0].Affects)[1].Ref)
	})

	t.Run("folds metadata.component into components when components is empty", func(t *testing.T) {
		source := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_7,
			SerialNumber: "urn:uuid:65a2d699-7681-3085-85e4-be6c32110d50",
			Version:      1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:  "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.13.5.1-osera-00007",
					Type:    cdx.ComponentTypeLibrary,
					Group:   "com.fasterxml.jackson.core",
					Name:    "jackson-core",
					Version: "2.13.5.1-osera-00007",
					Licenses: &cdx.Licenses{
						{License: &cdx.License{ID: "Apache-2.0"}},
					},
				},
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID: "CVE-2025-52999",
					Affects: &[]cdx.Affects{
						{Ref: "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.13.5.1-osera-00007"},
					},
				},
			},
		}

		jsonBytes := mustMarshalBOM(t, source)
		sbom, vex, err := Split(bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, sbom)
		require.NotNil(t, sbom.Components)
		require.Len(t, *sbom.Components, 1)
		assert.Equal(t, "jackson-core", (*sbom.Components)[0].Name)

		require.NoError(t, ValidateSBOM(sbom))

		require.NotNil(t, vex)
		require.NotNil(t, vex.Vulnerabilities)
		gotRef := (*(*vex.Vulnerabilities)[0].Affects)[0].Ref
		assert.Equal(t, "urn:cdx:65a2d699-7681-3085-85e4-be6c32110d50/1#pkg%3Amaven%2Fcom.fasterxml.jackson.core%2Fjackson-core%402.13.5.1-osera-00007", gotRef)
	})

	t.Run("does not override a non-empty components list with metadata.component", func(t *testing.T) {
		source := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_5,
			SerialNumber: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			Version:      1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{Name: "should-not-appear", Type: cdx.ComponentTypeLibrary},
			},
			Components: &[]cdx.Component{
				{BOMRef: "test-component", Name: "actual-component", Version: "1.0.0", Type: cdx.ComponentTypeLibrary},
			},
		}

		jsonBytes := mustMarshalBOM(t, source)
		sbom, _, err := Split(bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, sbom.Components)
		require.Len(t, *sbom.Components, 1)
		assert.Equal(t, "actual-component", (*sbom.Components)[0].Name)
	})
}

func mustMarshalBOM(t *testing.T, bom *cdx.BOM) []byte {
	t.Helper()
	var buf bytes.Buffer
	encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	err := encoder.Encode(bom)
	require.NoError(t, err)
	return buf.Bytes()
}
