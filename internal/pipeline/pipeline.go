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

// Package pipeline orchestrates the shared publish pipeline used by all
// three trigger modes (serve/publish/backfill), per ARCHITECTURE.md §3:
// resolve a component's assets, assemble the flat bundle, split the vendor's
// CycloneDX document into SBOM/VEX, validate everything, then upload to S3.
//
// Validation failures (and any other per-component error) are returned to
// the caller rather than causing the pipeline to retry or abort other
// components — per ARCHITECTURE.md §7/§12, the caller (serve/publish/backfill)
// decides whether to log-and-skip or fail the run.
package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/bundle"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/config"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/cyclonedx"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/model"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/s3upload"
)

// Result summarizes what happened when publishing one component: which S3
// objects were uploaded vs. already present (skipped as a no-op under the
// bucket's immutability/idempotency rules), for caller-side logging.
type Result struct {
	BundleKey     string
	BundleSkipped bool
	SBOMKey       string
	SBOMSkipped   bool
	VEXKey        string // empty if the component had no vulnerabilities
	VEXSkipped    bool
}

// Uploader is the subset of *s3upload.Uploader's behavior Publish needs,
// extracted as an interface so tests can substitute a fake instead of
// talking to real S3. *s3upload.Uploader satisfies this automatically.
type Uploader interface {
	Upload(ctx context.Context, key string, data io.Reader, contentType string) (skipped bool, err error)
}

var _ Uploader = (*s3upload.Uploader)(nil)

// FetchFunc retrieves the content of an NXRM asset by its download URL.
// Satisfied by (*nxrm.Client).FetchAssetContent; accepting it as a function
// value (rather than the concrete *nxrm.Client) lets tests substitute a fake
// without a live NXRM server.
type FetchFunc func(ctx context.Context, downloadURL string) (io.ReadCloser, error)

// Publish runs the full pipeline for a single already-resolved component:
// fetch the vendor's CycloneDX asset, assemble the bundle, split SBOM/VEX,
// validate, and upload all produced objects to S3.
//
// fetch is used only to retrieve asset content (comp.Assets already holds
// the resolved coordinates/asset list from an earlier NXRM lookup); repoCfg
// and formatRule come from this component's repository/format configuration.
func Publish(ctx context.Context, fetch FetchFunc, comp model.Component, repoCfg config.Repository, formatRule config.FormatRule, uploader Uploader) (Result, error) {
	sbomAsset, ok := comp.FindAssetBySuffix(formatRule.SBOMSuffix)
	if !ok {
		return Result{}, fmt.Errorf("component %s/%s@%s: no CycloneDX asset found with suffix %q", comp.Name, comp.Version, comp.Format, formatRule.SBOMSuffix)
	}

	sbomContent, err := fetch(ctx, sbomAsset.DownloadURL)
	if err != nil {
		return Result{}, fmt.Errorf("fetching CycloneDX asset %q: %w", sbomAsset.Filename, err)
	}
	defer func() { _ = sbomContent.Close() }()

	sbom, vex, err := cyclonedx.Split(sbomContent)
	if err != nil {
		return Result{}, fmt.Errorf("splitting CycloneDX document %q: %w", sbomAsset.Filename, err)
	}

	if err := cyclonedx.ValidateSBOM(sbom); err != nil {
		return Result{}, fmt.Errorf("validating SBOM for %s@%s: %w", comp.Name, comp.Version, err)
	}
	if vex != nil {
		if err := cyclonedx.ValidateVEX(vex); err != nil {
			return Result{}, fmt.Errorf("validating VEX for %s@%s: %w", comp.Name, comp.Version, err)
		}
	}

	bundleBuf, bundleFilename, err := bundle.Assemble(ctx, comp, formatRule, fetch)
	if err != nil {
		return Result{}, fmt.Errorf("assembling bundle for %s@%s: %w", comp.Name, comp.Version, err)
	}
	if bundleFilename == "" {
		return Result{}, fmt.Errorf("assembling bundle for %s@%s: empty bundle filename", comp.Name, comp.Version)
	}

	namespace := s3upload.Namespace(comp, repoCfg)
	var result Result

	result.BundleKey = s3upload.BundlePath(repoCfg.Ecosystem, namespace, comp.Name, comp.Version)
	result.BundleSkipped, err = uploader.Upload(ctx, result.BundleKey, bundleBuf, "application/zip")
	if err != nil {
		return Result{}, fmt.Errorf("uploading bundle to %q: %w", result.BundleKey, err)
	}

	sbomJSON, err := encodeBOM(sbom)
	if err != nil {
		return Result{}, fmt.Errorf("encoding SBOM for %s@%s: %w", comp.Name, comp.Version, err)
	}
	result.SBOMKey = s3upload.SBOMPath(repoCfg.Ecosystem, namespace, comp.Name, comp.Version)
	result.SBOMSkipped, err = uploader.Upload(ctx, result.SBOMKey, bytes.NewReader(sbomJSON), "application/json")
	if err != nil {
		return Result{}, fmt.Errorf("uploading SBOM to %q: %w", result.SBOMKey, err)
	}

	if vex != nil {
		vexJSON, err := encodeBOM(vex)
		if err != nil {
			return Result{}, fmt.Errorf("encoding VEX for %s@%s: %w", comp.Name, comp.Version, err)
		}
		vexFilename := cyclonedx.VEXFilename(vex)
		result.VEXKey = s3upload.VEXPath(vexFilename)
		result.VEXSkipped, err = uploader.Upload(ctx, result.VEXKey, bytes.NewReader(vexJSON), "application/json")
		if err != nil {
			return Result{}, fmt.Errorf("uploading VEX to %q: %w", result.VEXKey, err)
		}
	}

	return result, nil
}

func encodeBOM(bom *cdx.BOM) ([]byte, error) {
	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).Encode(bom); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
