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

// Package cli implements this tool's subcommands: publish (one-off manual
// submission by NXRM coordinates), backfill (bulk enumeration of an existing
// NXRM repository), and serve (long-running NXRM webhook receiver).
package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/config"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/nxrm"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/pipeline"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/s3upload"
)

// RunPublish implements the `publish` subcommand: resolve one component by
// NXRM coordinates and run it through the pipeline once.
func RunPublish(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config YAML file (required)")
	repository := fs.String("repository", "", "NXRM repository name (required)")
	group := fs.String("group", "", "component group/namespace coordinate (optional, ecosystem-dependent)")
	name := fs.String("name", "", "component name (required)")
	version := fs.String("version", "", "component version (required)")
	outputDir := fs.String("output-dir", "", "write bundle/SBOM/VEX to this local directory instead of uploading to S3 (for inspection/dry-run)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nxrm-3pc-publisher publish -config <path> -repository <name> -name <name> -version <version> [-group <group>] [-output-dir <path>]")
		fmt.Fprintln(os.Stderr, "\nResolves a single component in NXRM by coordinates and publishes its bundle/SBOM/VEX to S3.")
		fmt.Fprintln(os.Stderr, "With -output-dir, writes the same files to a local directory instead of S3 (s3: config is ignored).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *configPath == "" || *repository == "" || *name == "" || *version == "" {
		fs.Usage()
		return fmt.Errorf("missing required flag(s)")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	repoCfg, ok := cfg.RepositoryFor(*repository)
	if !ok {
		return fmt.Errorf("repository %q is not configured (see repositories: in config)", *repository)
	}

	client := nxrm.NewClient(nxrm.Options{
		BaseURL:  cfg.NXRM.URL,
		Username: cfg.NXRM.Auth.Username,
		Password: cfg.NXRM.Auth.Password,
	})

	comp, err := client.ResolveByCoordinates(ctx, *repository, *group, *name, *version)
	if err != nil {
		return fmt.Errorf("resolving component: %w", err)
	}

	formatRule, ok := cfg.FormatRuleFor(comp.Format)
	if !ok {
		return fmt.Errorf("no bundle assembly rule configured for NXRM format %q (see formats: in config)", comp.Format)
	}

	var uploader pipeline.Uploader
	if *outputDir != "" {
		if err := os.MkdirAll(*outputDir, 0o755); err != nil {
			return fmt.Errorf("creating output directory %q: %w", *outputDir, err)
		}
		uploader = &localUploader{dir: *outputDir}
		log.Printf("writing output to local directory %q instead of S3", *outputDir)
	} else {
		uploader, err = s3upload.NewUploader(ctx, cfg.S3.Bucket, cfg.S3.Region)
		if err != nil {
			return fmt.Errorf("initializing S3 uploader: %w", err)
		}
	}

	result, err := pipeline.Publish(ctx, client.FetchAssetContent, comp, repoCfg, formatRule, uploader)
	if err != nil {
		return fmt.Errorf("publishing %s@%s: %w", comp.Name, comp.Version, err)
	}

	logResult(comp.Name, comp.Version, result)
	return nil
}

func logResult(name, version string, result pipeline.Result) {
	log.Printf("published %s@%s: bundle=%s (skipped=%v, includes embedded SBOM)", name, version, result.BundleKey, result.BundleSkipped)
	if result.VEXKey != "" {
		log.Printf("published %s@%s: vex=%s (skipped=%v)", name, version, result.VEXKey, result.VEXSkipped)
	}
}
