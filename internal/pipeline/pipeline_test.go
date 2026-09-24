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

package pipeline

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/config"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/model"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func assertZipContains(t *testing.T, zipBytes []byte, wantFile string) {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("reading zip: %v", err)
	}
	for _, f := range r.File {
		if f.Name == wantFile {
			return
		}
	}
	t.Fatalf("expected zip to contain %q", wantFile)
}

type fakeUploader struct {
	uploaded map[string][]byte
	skip     map[string]bool
	failKey  string
}

func newFakeUploader() *fakeUploader {
	return &fakeUploader{uploaded: map[string][]byte{}, skip: map[string]bool{}}
}

func (f *fakeUploader) Upload(_ context.Context, key string, data io.Reader, _ string) (bool, error) {
	if key == f.failKey {
		return false, fmt.Errorf("simulated upload failure for %s", key)
	}
	if f.skip[key] {
		return true, nil
	}
	b, err := io.ReadAll(data)
	if err != nil {
		return false, err
	}
	f.uploaded[key] = b
	return false, nil
}

func validCycloneDXJSON(t *testing.T, withVuln bool) []byte {
	t.Helper()
	bom := &cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_6,
		SerialNumber: "urn:uuid:0f2c9a6e-71c4-4d8b-9e3a-5b6d1f0a2c44",
		Version:      1,
		Components: &[]cdx.Component{
			{
				BOMRef:  "pkg:maven/org.example/widget@1.0.0",
				Name:    "widget",
				Version: "1.0.0",
				Type:    cdx.ComponentTypeLibrary,
				Licenses: &cdx.Licenses{
					{License: &cdx.License{ID: "Apache-2.0"}},
				},
			},
		},
	}
	if withVuln {
		bom.Vulnerabilities = &[]cdx.Vulnerability{
			{
				ID:       "CVE-2026-99999",
				Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolved},
				Affects: &[]cdx.Affects{
					{Ref: "pkg:maven/org.example/widget@1.0.0"},
				},
			},
		}
	}

	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).Encode(bom); err != nil {
		t.Fatalf("encoding fixture BOM: %v", err)
	}
	return buf.Bytes()
}

func testComponent(sbomJSON []byte) model.Component {
	return model.Component{
		Repository: "maven-releases",
		Format:     "maven2",
		Group:      "org.example",
		Name:       "widget",
		Version:    "1.0.0",
		Assets: []model.Asset{
			{Filename: "widget-1.0.0.jar", DownloadURL: "https://nexus.example.com/widget-1.0.0.jar"},
			{Filename: "widget-1.0.0-cyclonedx.json", DownloadURL: "https://nexus.example.com/widget-1.0.0-cyclonedx.json"},
		},
	}
}

func fetchFrom(assets map[string][]byte) FetchFunc {
	return func(_ context.Context, downloadURL string) (io.ReadCloser, error) {
		data, ok := assets[downloadURL]
		if !ok {
			return nil, fmt.Errorf("no fixture for %s", downloadURL)
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
}

func testRepoAndRule() (config.Repository, config.FormatRule) {
	repoCfg := config.Repository{Ecosystem: "maven", NamespaceFromGroup: true}
	rule := config.FormatRule{
		IncludeAssetSuffixes: []string{".jar"},
		SBOMSuffix:           "-cyclonedx.json",
	}
	return repoCfg, rule
}

func TestPublish_withVulnerabilities(t *testing.T) {
	sbomJSON := validCycloneDXJSON(t, true)
	comp := testComponent(sbomJSON)
	assets := map[string][]byte{
		"https://nexus.example.com/widget-1.0.0.jar":            []byte("jar-content"),
		"https://nexus.example.com/widget-1.0.0-cyclonedx.json": sbomJSON,
	}
	repoCfg, rule := testRepoAndRule()
	uploader := newFakeUploader()

	result, err := Publish(context.Background(), discardLogger(), fetchFrom(assets), comp, repoCfg, rule, uploader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.BundleKey != "packages/maven/org.example/widget/1.0.0/widget-1.0.0.zip" {
		t.Errorf("BundleKey = %q", result.BundleKey)
	}
	if result.VEXKey == "" {
		t.Error("expected non-empty VEXKey when source has vulnerabilities")
	}

	bundleBytes, ok := uploader.uploaded[result.BundleKey]
	if !ok {
		t.Fatal("expected bundle to be uploaded")
	}
	assertZipContains(t, bundleBytes, "widget-1.0.0.bom.json")

	if _, ok := uploader.uploaded[result.VEXKey]; !ok {
		t.Error("expected VEX to be uploaded")
	}
}

func TestPublish_withoutVulnerabilities(t *testing.T) {
	sbomJSON := validCycloneDXJSON(t, false)
	comp := testComponent(sbomJSON)
	assets := map[string][]byte{
		"https://nexus.example.com/widget-1.0.0.jar":            []byte("jar-content"),
		"https://nexus.example.com/widget-1.0.0-cyclonedx.json": sbomJSON,
	}
	repoCfg, rule := testRepoAndRule()
	uploader := newFakeUploader()

	result, err := Publish(context.Background(), discardLogger(), fetchFrom(assets), comp, repoCfg, rule, uploader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.VEXKey != "" {
		t.Errorf("expected empty VEXKey when source has no vulnerabilities, got %q", result.VEXKey)
	}
}

func TestPublish_missingSBOMAsset(t *testing.T) {
	comp := model.Component{
		Name:    "widget",
		Version: "1.0.0",
		Assets: []model.Asset{
			{Filename: "widget-1.0.0.jar", DownloadURL: "https://nexus.example.com/widget-1.0.0.jar"},
		},
	}
	repoCfg, rule := testRepoAndRule()
	uploader := newFakeUploader()

	_, err := Publish(context.Background(), discardLogger(), fetchFrom(nil), comp, repoCfg, rule, uploader)
	if err == nil {
		t.Fatal("expected error when no CycloneDX asset is present")
	}
}

func TestPublish_invalidSBOMFailsValidation(t *testing.T) {
	invalidJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"widget"}]}`)
	comp := testComponent(invalidJSON)
	assets := map[string][]byte{
		"https://nexus.example.com/widget-1.0.0.jar":            []byte("jar-content"),
		"https://nexus.example.com/widget-1.0.0-cyclonedx.json": invalidJSON,
	}
	repoCfg, rule := testRepoAndRule()
	uploader := newFakeUploader()

	_, err := Publish(context.Background(), discardLogger(), fetchFrom(assets), comp, repoCfg, rule, uploader)
	if err == nil {
		t.Fatal("expected validation error for SBOM missing serialNumber/licenses")
	}
}

func TestPublish_uploadFailurePropagates(t *testing.T) {
	sbomJSON := validCycloneDXJSON(t, false)
	comp := testComponent(sbomJSON)
	assets := map[string][]byte{
		"https://nexus.example.com/widget-1.0.0.jar":            []byte("jar-content"),
		"https://nexus.example.com/widget-1.0.0-cyclonedx.json": sbomJSON,
	}
	repoCfg, rule := testRepoAndRule()
	uploader := newFakeUploader()
	uploader.failKey = "packages/maven/org.example/widget/1.0.0/widget-1.0.0.zip"

	_, err := Publish(context.Background(), discardLogger(), fetchFrom(assets), comp, repoCfg, rule, uploader)
	if err == nil {
		t.Fatal("expected error to propagate from failed bundle upload")
	}
}

func TestPublish_skipsAlreadyUploadedObjects(t *testing.T) {
	sbomJSON := validCycloneDXJSON(t, false)
	comp := testComponent(sbomJSON)
	assets := map[string][]byte{
		"https://nexus.example.com/widget-1.0.0.jar":            []byte("jar-content"),
		"https://nexus.example.com/widget-1.0.0-cyclonedx.json": sbomJSON,
	}
	repoCfg, rule := testRepoAndRule()
	uploader := newFakeUploader()
	uploader.skip["packages/maven/org.example/widget/1.0.0/widget-1.0.0.zip"] = true

	result, err := Publish(context.Background(), discardLogger(), fetchFrom(assets), comp, repoCfg, rule, uploader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.BundleSkipped {
		t.Error("expected BundleSkipped to be true")
	}
}
