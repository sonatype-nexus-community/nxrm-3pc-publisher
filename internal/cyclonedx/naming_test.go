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
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestSBOMFilename(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "jackson-core",
			version:  "2.13.5.1-osera-00001",
			expected: "jackson-core-2.13.5.1-osera-00001.bom.json",
		},
		{
			name:     "spring-boot",
			version:  "4.1.1-patched-1",
			expected: "spring-boot-4.1.1-patched-1.bom.json",
		},
		{
			name:     "simple",
			version:  "1.0.0",
			expected: "simple-1.0.0.bom.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SBOMFilename(tt.name, tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVEXFilename(t *testing.T) {
	t.Run("single CVE produces CVE-timestamp format", func(t *testing.T) {
		vex := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Timestamp: "2026-08-28T00:00:00Z",
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{ID: "CVE-2026-99999"},
			},
		}

		result := VEXFilename(vex)
		assert.Equal(t, "CVE-2026-99999-2026-08-28T00:00:00Z.bom.json", result)
	})

	t.Run("multiple CVEs produces timestamp-only format", func(t *testing.T) {
		vex := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Timestamp: "2026-08-28T00:00:00Z",
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{ID: "CVE-2026-99998"},
				{ID: "CVE-2026-99999"},
			},
		}

		result := VEXFilename(vex)
		assert.Equal(t, "2026-08-28T00:00:00Z.bom.json", result)
	})

	t.Run("zero CVEs produces timestamp-only format", func(t *testing.T) {
		vex := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Timestamp: "2026-08-28T00:00:00Z",
			},
			Vulnerabilities: &[]cdx.Vulnerability{},
		}

		result := VEXFilename(vex)
		assert.Equal(t, "2026-08-28T00:00:00Z.bom.json", result)
	})

	t.Run("uses current time when metadata timestamp missing", func(t *testing.T) {
		vex := &cdx.BOM{
			Vulnerabilities: &[]cdx.Vulnerability{
				{ID: "CVE-2026-99999"},
			},
		}

		result := VEXFilename(vex)
		assert.True(t, strings.HasPrefix(result, "CVE-2026-99999-"))
		assert.True(t, strings.HasSuffix(result, ".bom.json"))
	})

	t.Run("uses current time when metadata timestamp unparseable", func(t *testing.T) {
		vex := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Timestamp: "invalid-timestamp",
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{ID: "CVE-2026-99999"},
			},
		}

		result := VEXFilename(vex)
		assert.True(t, strings.HasPrefix(result, "CVE-2026-99999-"))
		assert.True(t, strings.HasSuffix(result, ".bom.json"))
	})
}
