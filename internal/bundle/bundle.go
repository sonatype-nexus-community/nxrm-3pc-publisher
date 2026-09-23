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

// Package bundle assembles a flat .zip component archive from a resolved NXRM
// component, applying per-format include rules to select which assets belong
// in the bundle. The resulting zip is ready for S3 upload.
package bundle

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/config"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/model"
)

// Assemble creates a flat zip archive containing the component's binary
// assets that match the include rules, plus the derived SBOM document named
// per the spec's SBOM naming convention (see cyclonedx.SBOMFilename). It
// returns the zip bytes, the bundle filename (<name>-<version>.zip), and any
// error encountered.
//
// The fetch function is called with each asset's download URL to retrieve its
// content. It must return an io.ReadCloser that the caller closes.
func Assemble(
	ctx context.Context,
	comp model.Component,
	rule config.FormatRule,
	fetch func(ctx context.Context, downloadURL string) (io.ReadCloser, error),
	sbomFilename string,
	sbomJSON []byte,
) (*bytes.Buffer, string, error) {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	for _, asset := range comp.Assets {
		if shouldInclude(asset.Filename, rule) {
			rc, err := fetch(ctx, asset.DownloadURL)
			if err != nil {
				return nil, "", fmt.Errorf("fetching asset %q: %w", asset.Filename, err)
			}

			err = func() error {
				defer func() { _ = rc.Close() }()
				fw, err := w.Create(asset.Filename)
				if err != nil {
					return fmt.Errorf("creating zip entry for %q: %w", asset.Filename, err)
				}
				if _, err := io.Copy(fw, rc); err != nil {
					return fmt.Errorf("writing asset %q to zip: %w", asset.Filename, err)
				}
				return nil
			}()

			if err != nil {
				return nil, "", err
			}
		}
	}

	if sbomFilename != "" {
		fw, err := w.Create(sbomFilename)
		if err != nil {
			return nil, "", fmt.Errorf("creating zip entry for %q: %w", sbomFilename, err)
		}
		if _, err := fw.Write(sbomJSON); err != nil {
			return nil, "", fmt.Errorf("writing SBOM %q to zip: %w", sbomFilename, err)
		}
	}

	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("closing zip: %w", err)
	}

	filename := fmt.Sprintf("%s-%s.zip", comp.Name, comp.Version)
	return buf, filename, nil
}

func shouldInclude(filename string, rule config.FormatRule) bool {
	if rule.SBOMSuffix != "" && strings.HasSuffix(filename, rule.SBOMSuffix) {
		return false
	}

	for _, suffix := range rule.IncludeAssetSuffixes {
		if strings.HasSuffix(filename, suffix) {
			return true
		}
	}
	return false
}
