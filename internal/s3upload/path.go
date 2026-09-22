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

// Package s3upload handles S3 path construction and idempotent uploads for
// the Third-Party Component Catalog. Path keys are built from ecosystem,
// optional namespace, name, and version segments per the spec, with the
// namespace segment omitted entirely (not left as empty) when absent.
package s3upload

import (
	"path"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/config"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/model"
)

// BundlePath returns the S3 key for a component's archive bundle:
// "packages/<ecosystem>/<namespace>/<name>/<version>/<name>-<version>.zip"
// (namespace segment omitted entirely when namespace is empty).
func BundlePath(ecosystem, namespace, name, version string) string {
	filename := name + "-" + version + ".zip"
	if namespace == "" {
		return path.Join("packages", ecosystem, name, version, filename)
	}
	return path.Join("packages", ecosystem, namespace, name, version, filename)
}

// SBOMPath returns the S3 key for a component's SBOM peer file, using the
// same prefix as BundlePath but with filename "<name>-<version>.bom.json".
func SBOMPath(ecosystem, namespace, name, version string) string {
	filename := name + "-" + version + ".bom.json"
	if namespace == "" {
		return path.Join("packages", ecosystem, name, version, filename)
	}
	return path.Join("packages", ecosystem, namespace, name, version, filename)
}

// VEXPath returns the S3 key for a VEX document: "vex/<filename>".
func VEXPath(filename string) string {
	return path.Join("vex", filename)
}

// Namespace returns the S3 path namespace segment for a component, per its
// repository config: comp.Group if repoCfg.NamespaceFromGroup is true and
// comp.Group is non-empty, otherwise "" (no namespace segment).
func Namespace(comp model.Component, repoCfg config.Repository) string {
	if repoCfg.NamespaceFromGroup && comp.Group != "" {
		return comp.Group
	}
	return ""
}
