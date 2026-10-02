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
	"log/slog"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/bundle"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/config"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/cyclonedx"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/model"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/s3upload"
)

// Result summarizes what happened when publishing one component: which S3
// objects were uploaded vs. already present (skipped as a no-op under the
// bucket's immutability/idempotency rules), for caller-side logging. The
// SBOM is embedded in the bundle .zip (see BundleKey), not uploaded as its
// own S3 object.
type Result struct {
	BundleKey     string
	BundleSkipped bool
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
// logger must not be nil. Publish itself never logs the error it returns
// (per this tool's "log once, at the handling point" convention -- see
// internal/logging); the caller decides whether to skip-and-continue or
// abort, and logs there.
func Publish(ctx context.Context, logger *slog.Logger, fetch FetchFunc, comp model.Component, repoCfg config.Repository, formatRule config.FormatRule, uploader Uploader) (Result, error) {
	if missing := missingRequiredAssets(comp, formatRule); len(missing) > 0 {
		return Result{}, fmt.Errorf("component %s/%s@%s: required assets missing (no asset ending in %s)", comp.Name, comp.Version, comp.Format, strings.Join(missing, ", "))
	}

	sbomAsset, ok := comp.FindAssetBySuffix(formatRule.SBOMSuffix)
	if !ok {
		return Result{}, fmt.Errorf("component %s/%s@%s: no CycloneDX asset found with suffix %q", comp.Name, comp.Version, comp.Format, formatRule.SBOMSuffix)
	}
	logger.Info("found vendor CycloneDX asset", "component", comp.Name, "version", comp.Version, "filename", sbomAsset.Filename)

	sbomContent, err := fetch(ctx, sbomAsset.DownloadURL)
	if err != nil {
		return Result{}, fmt.Errorf("fetching CycloneDX asset %q: %w", sbomAsset.Filename, err)
	}
	defer func() { _ = sbomContent.Close() }()
	logger.Info("fetched CycloneDX asset content", "component", comp.Name, "version", comp.Version)

	sbom, vex, err := cyclonedx.Split(logger, sbomContent)
	if err != nil {
		return Result{}, fmt.Errorf("splitting CycloneDX document %q: %w", sbomAsset.Filename, err)
	}
	if vex != nil {
		logger.Info("split CycloneDX document into SBOM and VEX", "component", comp.Name, "version", comp.Version)
	} else {
		logger.Info("split CycloneDX document into SBOM; no vulnerabilities found, no VEX produced", "component", comp.Name, "version", comp.Version)
	}

	if err := cyclonedx.ValidateSBOM(logger, sbom, repoCfg.Ecosystem); err != nil {
		return Result{}, fmt.Errorf("validating SBOM for %s@%s: %w", comp.Name, comp.Version, err)
	}
	logger.Info("validated SBOM", "component", comp.Name, "version", comp.Version)
	if vex != nil {
		if err := cyclonedx.ValidateVEX(vex); err != nil {
			return Result{}, fmt.Errorf("validating VEX for %s@%s: %w", comp.Name, comp.Version, err)
		}
		logger.Info("validated VEX", "component", comp.Name, "version", comp.Version)
	}

	sbomJSON, err := encodeBOM(sbom)
	if err != nil {
		return Result{}, fmt.Errorf("encoding SBOM for %s@%s: %w", comp.Name, comp.Version, err)
	}
	sbomFilename := cyclonedx.SBOMFilename(comp.Name, comp.Version)

	bundleBuf, bundleFilename, err := bundle.Assemble(ctx, logger, comp, formatRule, fetch, sbomFilename, sbomJSON)
	if err != nil {
		return Result{}, fmt.Errorf("assembling bundle for %s@%s: %w", comp.Name, comp.Version, err)
	}
	if bundleFilename == "" {
		return Result{}, fmt.Errorf("assembling bundle for %s@%s: empty bundle filename", comp.Name, comp.Version)
	}
	logger.Info("assembled bundle", "component", comp.Name, "version", comp.Version, "filename", bundleFilename)

	namespace := s3upload.Namespace(comp, repoCfg)
	var result Result

	result.BundleKey = s3upload.BundlePath(repoCfg.Ecosystem, namespace, comp.Name, comp.Version)
	result.BundleSkipped, err = uploader.Upload(ctx, result.BundleKey, bundleBuf, "application/zip")
	if err != nil {
		return Result{}, fmt.Errorf("uploading bundle to %q: %w", result.BundleKey, err)
	}
	logger.Info("uploaded bundle", "key", result.BundleKey, "skipped", result.BundleSkipped)

	if vex != nil {
		vexJSON, err := encodeBOM(vex)
		if err != nil {
			return Result{}, fmt.Errorf("encoding VEX for %s@%s: %w", comp.Name, comp.Version, err)
		}
		vexFilename := cyclonedx.VEXFilename(logger, vex)
		result.VEXKey = s3upload.VEXPath(vexFilename)
		result.VEXSkipped, err = uploader.Upload(ctx, result.VEXKey, bytes.NewReader(vexJSON), "application/json")
		if err != nil {
			return Result{}, fmt.Errorf("uploading VEX to %q: %w", result.VEXKey, err)
		}
		logger.Info("uploaded VEX", "key", result.VEXKey, "skipped", result.VEXSkipped)
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

// missingRequiredAssets returns the configured required suffixes for which
// comp has no matching asset. Checksum/signature companions such as
// "x.jar.sha1" do not satisfy a ".jar" requirement because matching is by
// suffix.
func missingRequiredAssets(comp model.Component, rule config.FormatRule) []string {
	var missing []string
	for _, suffix := range rule.RequiredAssetSuffixes {
		if _, ok := comp.FindAssetBySuffix(suffix); !ok {
			missing = append(missing, strconv.Quote(suffix))
		}
	}
	return missing
}
