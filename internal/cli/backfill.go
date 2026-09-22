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

// RunBackfill implements the `backfill` subcommand: page through every
// component in an NXRM repository via continuationToken and publish each
// one. Per-component failures are logged and skipped so one bad component
// doesn't abort the run (ARCHITECTURE.md §7); a summary is printed at the end.
func RunBackfill(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("backfill", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config YAML file (required)")
	repository := fs.String("repository", "", "NXRM repository name to backfill (required)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nxrm-3pc-publisher backfill -config <path> -repository <name>")
		fmt.Fprintln(os.Stderr, "\nEnumerates every component in the given NXRM repository and publishes each to S3.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *configPath == "" || *repository == "" {
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

	uploader, err := s3upload.NewUploader(ctx, cfg.S3.Bucket, cfg.S3.Region)
	if err != nil {
		return fmt.Errorf("initializing S3 uploader: %w", err)
	}

	var succeeded, failed int
	continuationToken := ""
	for {
		items, nextToken, err := client.ListComponentsPage(ctx, *repository, continuationToken)
		if err != nil {
			return fmt.Errorf("listing components in %q: %w", *repository, err)
		}

		for _, comp := range items {
			formatRule, ok := cfg.FormatRuleFor(comp.Format)
			if !ok {
				log.Printf("skipping %s@%s: no bundle assembly rule configured for NXRM format %q", comp.Name, comp.Version, comp.Format)
				failed++
				continue
			}

			result, err := pipeline.Publish(ctx, client.FetchAssetContent, comp, repoCfg, formatRule, uploader)
			if err != nil {
				log.Printf("skipping %s@%s: %v", comp.Name, comp.Version, err)
				failed++
				continue
			}

			logResult(comp.Name, comp.Version, result)
			succeeded++
		}

		if nextToken == "" {
			break
		}
		continuationToken = nextToken
	}

	log.Printf("backfill of %q complete: %d succeeded, %d failed/skipped", *repository, succeeded, failed)
	if failed > 0 {
		return fmt.Errorf("backfill completed with %d failed/skipped component(s)", failed)
	}
	return nil
}
