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

// Package config loads and validates this tool's YAML configuration: NXRM
// connection details, the webhook shared secret, the destination S3 bucket,
// per-NXRM-format bundle assembly rules, and the set of NXRM repositories
// this tool is allowed to act on (each with its required S3 ecosystem).
package config

import (
	"fmt"
	"os"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level YAML document loaded via Load.
type Config struct {
	NXRM         NXRM                  `yaml:"nxrm"`
	Webhook      Webhook               `yaml:"webhook"`
	S3           S3                    `yaml:"s3"`
	Formats      map[string]FormatRule `yaml:"formats"`
	Repositories map[string]Repository `yaml:"repositories"`
}

// NXRM holds connection details for the NXRM server this tool talks to.
type NXRM struct {
	URL  string   `yaml:"url"`
	Auth NXRMAuth `yaml:"auth"`
}

// NXRMAuth is basic-auth credentials for the NXRM REST API. Either both
// fields are set (basic auth) or both are empty (unauthenticated / relies on
// a pre-configured HTTP client — not currently supported by config, see
// internal/nxrm).
type NXRMAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Webhook holds settings for the `serve` subcommand's NXRM webhook receiver.
type Webhook struct {
	// Secret is the shared HMAC-SHA1 secret configured on the NXRM webhook
	// capability. Required for serve mode; unused otherwise.
	Secret string `yaml:"secret"`
	// ListenAddr is the address the webhook HTTP server binds to, e.g. ":8443".
	ListenAddr string `yaml:"listenAddr"`
	// SettleDelay is how long serve waits after the last webhook event for a
	// component before checking whether it is complete. NXRM sends many
	// events for one upload; this coalesces them. Written as a Go duration,
	// e.g. "10s". Zero means the default (10s).
	SettleDelay time.Duration `yaml:"settleDelay"`
	// MaxWait is how long serve keeps waiting for a component to gain its
	// required assets before giving up with an error. Zero means the default
	// (10m).
	MaxWait time.Duration `yaml:"maxWait"`
}

// S3 holds the destination bucket for the Sonatype Third-Party Component
// Catalog. Credentials are intentionally not part of this struct: they come
// from the standard AWS SDK v2 credential chain (env, shared config, IAM
// role/SSO profile), never from this tool's own config file.
type S3 struct {
	Bucket string `yaml:"bucket"`
	Region string `yaml:"region"`
}

// FormatRule describes, for one NXRM component "format" (e.g. "maven2",
// "npm"), which sibling assets belong in the flat component archive bundle
// and how to recognize the vendor's CycloneDX asset among a component's
// assets.
type FormatRule struct {
	// IncludeAssetSuffixes lists filename suffixes that should be pulled into
	// the bundle .zip, e.g. [".jar", ".pom", "-sources.jar", "-javadoc.jar"].
	IncludeAssetSuffixes []string `yaml:"includeAssetSuffixes"`
	// RequiredAssetSuffixes lists filename suffixes of which a component
	// must have at least one matching asset before it is published, e.g.
	// [".jar", ".pom"]. The vendor CycloneDX asset (SBOMSuffix) is always
	// required and need not be listed. Assets that are optional extras, such
	// as "-sources.jar", belong only in IncludeAssetSuffixes. Every entry
	// must also be covered by IncludeAssetSuffixes.
	RequiredAssetSuffixes []string `yaml:"requiredAssetSuffixes"`
	// SBOMSuffix is the filename suffix identifying the vendor's CycloneDX
	// asset, e.g. "-cyclonedx.json". This asset is never included in the
	// bundle zip itself; it is split into SBOM/VEX peer files (see
	// internal/cyclonedx) and uploaded separately.
	SBOMSuffix string `yaml:"sbomSuffix"`
}

// Repository maps one watched NXRM repository name to the S3 ecosystem
// segment used for its component uploads, plus how to derive the S3
// "namespace" path segment from the component's NXRM group coordinate.
//
// Ecosystem has no default: every repository this tool acts on must declare
// it explicitly, so a misclassified/unconfigured repository fails config
// validation rather than silently landing under a guessed ecosystem.
type Repository struct {
	// Ecosystem is the S3 path ecosystem segment, e.g. "maven", "npm". Required.
	Ecosystem string `yaml:"ecosystem"`
	// NamespaceFromGroup, when true, uses the component's NXRM group
	// coordinate (e.g. Maven groupId) as the S3 path namespace segment. When
	// false, no namespace segment is used (per the spec, for ecosystems
	// without a namespace concept).
	NamespaceFromGroup bool `yaml:"namespaceFromGroup"`
}

// Load reads and parses the YAML config file at path, then validates it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config file %q: %w", path, err)
	}

	return &cfg, nil
}

// Validate checks structural requirements that would otherwise surface as
// confusing failures deep in the pipeline: a missing NXRM URL, an S3 bucket
// left unset, or a watched repository with no explicit ecosystem.
func (c *Config) Validate() error {
	if c.NXRM.URL == "" {
		return fmt.Errorf("nxrm.url is required")
	}
	if c.S3.Bucket == "" {
		return fmt.Errorf("s3.bucket is required")
	}
	if len(c.Repositories) == 0 {
		return fmt.Errorf("at least one entry under repositories is required")
	}
	if c.Webhook.SettleDelay < 0 {
		return fmt.Errorf("webhook.settleDelay must not be negative")
	}
	if c.Webhook.MaxWait < 0 {
		return fmt.Errorf("webhook.maxWait must not be negative")
	}
	for name, repo := range c.Repositories {
		if repo.Ecosystem == "" {
			return fmt.Errorf("repositories.%s.ecosystem is required (no default ecosystem)", name)
		}
	}
	for format, rule := range c.Formats {
		for _, req := range rule.RequiredAssetSuffixes {
			if !slices.Contains(rule.IncludeAssetSuffixes, req) {
				return fmt.Errorf("formats.%s.requiredAssetSuffixes entry %q must also appear in includeAssetSuffixes", format, req)
			}
		}
	}
	return nil
}

// FormatRuleFor returns the configured FormatRule for the given NXRM
// component format, and whether one was found. Callers needing bundle
// assembly behavior for an unconfigured format should treat false as an
// error, not silently fall back to "include everything" (see ARCHITECTURE.md
// §5).
func (c *Config) FormatRuleFor(format string) (FormatRule, bool) {
	r, ok := c.Formats[format]
	return r, ok
}

// RepositoryFor returns the configured Repository entry for the given NXRM
// repository name, and whether one was found. An NXRM event/coordinate for a
// repository not present here must be ignored by callers, not defaulted.
func (c *Config) RepositoryFor(name string) (Repository, bool) {
	r, ok := c.Repositories[name]
	return r, ok
}
