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

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/cli"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/logging"
)

// version and commit are set via -ldflags at build time (see .goreleaser.yml).
var (
	version = "dev"
	commit  = "none"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var err error
	switch os.Args[1] {
	case "publish":
		err = cli.RunPublish(ctx, os.Args[2:])
	case "backfill":
		err = cli.RunBackfill(ctx, os.Args[2:])
	case "serve":
		err = cli.RunServe(ctx, os.Args[2:])
	case "version":
		fmt.Printf("nxrm-3pc-publisher %s (%s)\n", version, commit)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}

	if err != nil {
		// Each subcommand builds its own -log-level/-log-format-configured
		// logger and threads it through everything it calls; by the time an
		// error reaches here, that logger has already gone out of scope. This
		// fallback (fixed at INFO/text) is only for errors a subcommand
		// returns before or without having logged them itself (e.g. a flag
		// parse failure) -- per this tool's "log once, at the handling point"
		// convention (internal/logging), this is that point for anything
		// that escapes all the way to main.
		fallback := logging.New(slog.LevelInfo, "text", os.Stderr)
		fallback.Error(err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `nxrm-3pc-publisher publishes third-party component bundles from
Nexus Repository Manager (NXRM) to Sonatype's Third-Party Component Catalog.

Usage: nxrm-3pc-publisher <command> [flags]

Commands:
  publish    Resolve one component by NXRM coordinates and publish it once
  backfill   Enumerate every component in an NXRM repository and publish each
  serve      Run an HTTP server that receives NXRM component webhooks
  version    Print version information

Run 'nxrm-3pc-publisher <command> -h' for flags on a specific command.`)
}
