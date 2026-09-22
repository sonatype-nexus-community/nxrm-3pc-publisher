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

// Package model holds the domain types shared across this tool's pipeline
// stages (NXRM resolution, bundle assembly, CycloneDX handling, S3 upload).
// Keeping these in one package avoids each stage inventing its own
// incompatible view of "a component" or "an asset".
package model

// Asset is a single file NXRM holds for a Component: a binary (jar, pom,
// tgz, ...), or the vendor-authored CycloneDX document.
type Asset struct {
	// Path is the NXRM asset path, e.g.
	// "/com/fasterxml/jackson/core/jackson-core/2.13.5.1-osera-00001/jackson-core-2.13.5.1-osera-00001.jar".
	Path string
	// Filename is the base name of Path, e.g. "jackson-core-2.13.5.1-osera-00001.jar".
	Filename string
	// DownloadURL is the NXRM asset download URL used to fetch content.
	DownloadURL string
	// Checksums maps algorithm name (as NXRM reports it, e.g. "sha1", "sha256") to hex digest.
	Checksums map[string]string
}

// Component is a single NXRM component version resolved with its full asset
// list, ready for bundle assembly and CycloneDX processing.
type Component struct {
	// Repository is the NXRM repository name this component was resolved from.
	Repository string
	// Format is NXRM's own format identifier, e.g. "maven2", "npm".
	Format string
	// Group is the component's group/namespace coordinate (e.g. Maven groupId).
	// Empty when the ecosystem has no namespace concept (e.g. plain npm package).
	Group string
	Name  string
	// Version is the full NXRM component version, e.g. "2.13.5.1-osera-00001".
	Version string
	Assets  []Asset
}

// FindAssetBySuffix returns the first asset whose filename ends with suffix,
// or false if none match. Used to locate the vendor's CycloneDX asset
// (matched against a per-format sbomSuffix, e.g. "-cyclonedx.json").
func (c Component) FindAssetBySuffix(suffix string) (Asset, bool) {
	for _, a := range c.Assets {
		if len(a.Filename) >= len(suffix) && a.Filename[len(a.Filename)-len(suffix):] == suffix {
			return a, true
		}
	}
	return Asset{}, false
}
