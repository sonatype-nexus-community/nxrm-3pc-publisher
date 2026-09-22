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

package bundle

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/config"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/model"
)

func TestAssemble(t *testing.T) {
	tests := []struct {
		name           string
		component      model.Component
		rule           config.FormatRule
		fetchContent   map[string]string
		fetchErr       map[string]error
		wantFilename   string
		wantFiles      []string
		wantFileCount  int
		wantErr        bool
		wantErrContent string
	}{
		{
			name: "include matching assets and exclude SBOM",
			component: model.Component{
				Name:    "spring-boot",
				Version: "4.1.1-patched-1",
				Assets: []model.Asset{
					{Filename: "spring-boot-4.1.1-patched-1.jar", DownloadURL: "http://example.com/spring-boot.jar"},
					{Filename: "spring-boot-4.1.1-patched-1.pom", DownloadURL: "http://example.com/spring-boot.pom"},
					{Filename: "spring-boot-4.1.1-patched-1-cyclonedx.json", DownloadURL: "http://example.com/sbom.json"},
					{Filename: "spring-boot-4.1.1-patched-1-sources.jar", DownloadURL: "http://example.com/sources.jar"},
				},
			},
			rule: config.FormatRule{
				IncludeAssetSuffixes: []string{".jar", ".pom"},
				SBOMSuffix:           "-cyclonedx.json",
			},
			fetchContent: map[string]string{
				"http://example.com/spring-boot.jar": "jar-content",
				"http://example.com/spring-boot.pom": "pom-content",
				"http://example.com/sources.jar":     "sources-content",
			},
			wantFilename:  "spring-boot-4.1.1-patched-1.zip",
			wantFiles:     []string{"spring-boot-4.1.1-patched-1.jar", "spring-boot-4.1.1-patched-1.pom", "spring-boot-4.1.1-patched-1-sources.jar"},
			wantFileCount: 3,
		},
		{
			name: "exclude SBOM even if suffix matches include pattern",
			component: model.Component{
				Name:    "mylib",
				Version: "1.0.0",
				Assets: []model.Asset{
					{Filename: "mylib-1.0.0.jar", DownloadURL: "http://example.com/mylib.jar"},
					{Filename: "mylib-1.0.0-cyclonedx.json", DownloadURL: "http://example.com/sbom.json"},
				},
			},
			rule: config.FormatRule{
				IncludeAssetSuffixes: []string{".jar", ".json"},
				SBOMSuffix:           "-cyclonedx.json",
			},
			fetchContent: map[string]string{
				"http://example.com/mylib.jar": "jar-content",
			},
			wantFilename:  "mylib-1.0.0.zip",
			wantFiles:     []string{"mylib-1.0.0.jar"},
			wantFileCount: 1,
		},
		{
			name: "flat structure without path separators",
			component: model.Component{
				Name:    "mylib",
				Version: "2.0.0",
				Assets: []model.Asset{
					{Filename: "mylib-2.0.0.jar", DownloadURL: "http://example.com/mylib.jar"},
				},
			},
			rule: config.FormatRule{
				IncludeAssetSuffixes: []string{".jar"},
				SBOMSuffix:           "-cyclonedx.json",
			},
			fetchContent: map[string]string{
				"http://example.com/mylib.jar": "jar-content",
			},
			wantFilename:  "mylib-2.0.0.zip",
			wantFiles:     []string{"mylib-2.0.0.jar"},
			wantFileCount: 1,
		},
		{
			name: "empty zip when no assets match",
			component: model.Component{
				Name:    "emptylib",
				Version: "0.0.1",
				Assets: []model.Asset{
					{Filename: "emptylib-0.0.1.war", DownloadURL: "http://example.com/emptylib.war"},
				},
			},
			rule: config.FormatRule{
				IncludeAssetSuffixes: []string{".jar"},
				SBOMSuffix:           "-cyclonedx.json",
			},
			fetchContent:  map[string]string{},
			wantFilename:  "emptylib-0.0.1.zip",
			wantFileCount: 0,
		},
		{
			name: "empty zip when include suffixes empty",
			component: model.Component{
				Name:    "somerlib",
				Version: "1.0.0",
				Assets: []model.Asset{
					{Filename: "somelib-1.0.0.jar", DownloadURL: "http://example.com/somelib.jar"},
				},
			},
			rule: config.FormatRule{
				IncludeAssetSuffixes: []string{},
				SBOMSuffix:           "-cyclonedx.json",
			},
			fetchContent:  map[string]string{},
			wantFilename:  "somerlib-1.0.0.zip",
			wantFileCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetch := func(ctx context.Context, downloadURL string) (io.ReadCloser, error) {
				if err, ok := tt.fetchErr[downloadURL]; ok {
					return nil, err
				}
				content, ok := tt.fetchContent[downloadURL]
				if !ok {
					content = "default-content"
				}
				return io.NopCloser(strings.NewReader(content)), nil
			}

			buf, filename, err := Assemble(context.Background(), tt.component, tt.rule, fetch)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.wantErrContent != "" && !strings.Contains(err.Error(), tt.wantErrContent) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErrContent)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if filename != tt.wantFilename {
				t.Fatalf("filename = %q, want %q", filename, tt.wantFilename)
			}
			if buf == nil {
				t.Fatal("buffer is nil")
			}

			reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			if err != nil {
				t.Fatalf("creating zip reader: %v", err)
			}
			if len(reader.File) != tt.wantFileCount {
				t.Fatalf("zip has %d files, want %d", len(reader.File), tt.wantFileCount)
			}

			for _, expected := range tt.wantFiles {
				found := false
				for _, f := range reader.File {
					if f.Name == expected {
						found = true
						if strings.Contains(f.Name, "/") {
							t.Fatalf("zip entry %q contains path separator /", f.Name)
						}
						if strings.Contains(f.Name, "\\") {
							t.Fatalf("zip entry %q contains path separator \\", f.Name)
						}
						break
					}
				}
				if !found {
					t.Fatalf("expected file %q not found in zip", expected)
				}
			}
		})
	}
}

func TestAssemble_ErrorOnFetchFailure(t *testing.T) {
	comp := model.Component{
		Name:    "failib",
		Version: "1.0.0",
		Assets: []model.Asset{
			{Filename: "failib-1.0.0.jar", DownloadURL: "http://example.com/failib.jar"},
		},
	}
	rule := config.FormatRule{
		IncludeAssetSuffixes: []string{".jar"},
		SBOMSuffix:           "-cyclonedx.json",
	}

	fetch := func(ctx context.Context, downloadURL string) (io.ReadCloser, error) {
		return nil, io.ErrUnexpectedEOF
	}

	_, _, err := Assemble(context.Background(), comp, rule, fetch)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "fetching asset") {
		t.Fatalf("error %q does not contain %q", err.Error(), "fetching asset")
	}
	if !strings.Contains(err.Error(), "failib-1.0.0.jar") {
		t.Fatalf("error %q does not contain %q", err.Error(), "failib-1.0.0.jar")
	}
}

func TestAssemble_ContextCancellation(t *testing.T) {
	comp := model.Component{
		Name:    "ctxlib",
		Version: "1.0.0",
		Assets: []model.Asset{
			{Filename: "ctxlib-1.0.0.jar", DownloadURL: "http://example.com/ctxlib.jar"},
		},
	}
	rule := config.FormatRule{
		IncludeAssetSuffixes: []string{".jar"},
		SBOMSuffix:           "-cyclonedx.json",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fetch := func(ctx context.Context, downloadURL string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("content")), nil
	}

	buf, filename, err := Assemble(ctx, comp, rule, fetch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf == nil {
		t.Fatal("buffer is nil")
	}
	if filename != "ctxlib-1.0.0.zip" {
		t.Fatalf("filename = %q, want %q", filename, "ctxlib-1.0.0.zip")
	}
}
