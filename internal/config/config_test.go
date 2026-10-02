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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return path
}

func TestLoad_valid(t *testing.T) {
	path := writeTempConfig(t, `
nxrm:
  url: https://nexus.example.com
  auth:
    username: admin
    password: secret
s3:
  bucket: sonatype-3p-catalog
  region: us-east-1
repositories:
  jackson-maven-releases:
    ecosystem: maven
    namespaceFromGroup: true
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.NXRM.URL != "https://nexus.example.com" {
		t.Errorf("NXRM.URL = %q", cfg.NXRM.URL)
	}
	if cfg.S3.Bucket != "sonatype-3p-catalog" {
		t.Errorf("S3.Bucket = %q", cfg.S3.Bucket)
	}
	repo, ok := cfg.RepositoryFor("jackson-maven-releases")
	if !ok {
		t.Fatal("expected jackson-maven-releases repository to be found")
	}
	if repo.Ecosystem != "maven" {
		t.Errorf("Ecosystem = %q", repo.Ecosystem)
	}
}

func TestLoad_missingNXRMURL(t *testing.T) {
	path := writeTempConfig(t, `
s3:
  bucket: sonatype-3p-catalog
repositories:
  repo1:
    ecosystem: maven
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing nxrm.url")
	}
}

func TestLoad_missingS3Bucket(t *testing.T) {
	path := writeTempConfig(t, `
nxrm:
  url: https://nexus.example.com
repositories:
  repo1:
    ecosystem: maven
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing s3.bucket")
	}
}

func TestLoad_noRepositories(t *testing.T) {
	path := writeTempConfig(t, `
nxrm:
  url: https://nexus.example.com
s3:
  bucket: sonatype-3p-catalog
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for empty repositories")
	}
}

func TestLoad_repositoryMissingEcosystem(t *testing.T) {
	path := writeTempConfig(t, `
nxrm:
  url: https://nexus.example.com
s3:
  bucket: sonatype-3p-catalog
repositories:
  repo1:
    namespaceFromGroup: true
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for repository with no ecosystem (no default allowed)")
	}
}

func TestLoad_fileNotFound(t *testing.T) {
	if _, err := Load("/nonexistent/path/config.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFormatRuleFor(t *testing.T) {
	cfg := &Config{
		Formats: map[string]FormatRule{
			"maven2": {IncludeAssetSuffixes: []string{".jar", ".pom"}, SBOMSuffix: "-cyclonedx.json"},
		},
	}

	rule, ok := cfg.FormatRuleFor("maven2")
	if !ok {
		t.Fatal("expected maven2 format rule to be found")
	}
	if len(rule.IncludeAssetSuffixes) != 2 {
		t.Errorf("IncludeAssetSuffixes = %v", rule.IncludeAssetSuffixes)
	}

	if _, ok := cfg.FormatRuleFor("unknown"); ok {
		t.Error("expected unknown format to not be found")
	}
}

func TestValidate_requiredAssetSuffixes(t *testing.T) {
	base := func() *Config {
		return &Config{
			NXRM:         NXRM{URL: "https://nexus.example.com"},
			S3:           S3{Bucket: "b"},
			Repositories: map[string]Repository{"r": {Ecosystem: "maven"}},
			Formats: map[string]FormatRule{
				"maven2": {
					IncludeAssetSuffixes:  []string{".jar", ".pom", "-sources.jar"},
					RequiredAssetSuffixes: []string{".jar", ".pom"},
					SBOMSuffix:            "-cyclonedx.json",
				},
			},
		}
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cfg := base()
	rule := cfg.Formats["maven2"]
	rule.RequiredAssetSuffixes = []string{".jar", ".war"}
	cfg.Formats["maven2"] = rule
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), ".war") {
		t.Errorf("a required suffix not in includeAssetSuffixes must be rejected, got: %v", err)
	}
}
