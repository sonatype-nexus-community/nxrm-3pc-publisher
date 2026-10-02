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
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/config"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/logging"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/model"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/nxrm"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/pipeline"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/s3upload"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/settle"
)

// RunServe implements the `serve` subcommand: a long-running HTTP server
// that receives NXRM `rm:repository:component` webhooks and publishes each
// newly created component to S3 (ARCHITECTURE.md §4.2).
func RunServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config YAML file (required)")
	outputDir := fs.String("output-dir", "", "write bundle/SBOM/VEX to this local directory instead of uploading to S3 (for inspection/dry-run)")
	logLevel := fs.String("log-level", "info", "log level: error, warn, info, or trace")
	logFormat := fs.String("log-format", "text", "log format: text or json")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nxrm-3pc-publisher serve -config <path> [-output-dir <dir>] [-log-level <level>] [-log-format <format>]")
		fmt.Fprintln(os.Stderr, "\nRuns an HTTP server that receives NXRM component webhooks and publishes to S3.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	level, err := logging.ParseLevel(*logLevel)
	if err != nil {
		return err
	}
	logger := logging.New(level, *logFormat, os.Stderr)

	if *configPath == "" {
		fs.Usage()
		return fmt.Errorf("missing required flag(s)")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Webhook.Secret == "" {
		return fmt.Errorf("webhook.secret is required for serve mode")
	}
	listenAddr := cfg.Webhook.ListenAddr
	if listenAddr == "" {
		listenAddr = ":8443"
	}

	client := nxrm.NewClient(nxrm.Options{
		BaseURL:  cfg.NXRM.URL,
		Username: cfg.NXRM.Auth.Username,
		Password: cfg.NXRM.Auth.Password,
	}, logger)

	var uploader pipeline.Uploader
	if *outputDir != "" {
		if err := os.MkdirAll(*outputDir, 0o755); err != nil {
			return fmt.Errorf("creating output directory %q: %w", *outputDir, err)
		}
		uploader = &localUploader{dir: *outputDir, logger: logger}
		logger.Info("writing output to local directory instead of S3", "dir", *outputDir)
	} else {
		uploader, err = s3upload.NewUploader(ctx, cfg.S3.Bucket, cfg.S3.Region, logger)
		if err != nil {
			return fmt.Errorf("initializing S3 uploader: %w", err)
		}
	}

	h := newWebhookHandler(ctx, cfg, client, uploader, logger)
	defer h.stop()
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/nxrm", h.handle)

	logger.Info("listening for NXRM webhooks", "addr", listenAddr)
	srv := &http.Server{Addr: listenAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

const (
	// defaultSettleDelay is how long serve waits after the last webhook event
	// for a component before checking it. NXRM sends many events for a single
	// upload, so this coalesces them into one publish attempt.
	defaultSettleDelay = 10 * time.Second
	// defaultMaxWait bounds how long serve waits for a component to gain all
	// its required assets before giving up on it.
	defaultMaxWait = 10 * time.Minute
)

// componentSource is the slice of *nxrm.Client the webhook handler needs,
// kept narrow so tests can substitute a fake NXRM.
type componentSource interface {
	ResolveByID(ctx context.Context, componentID string) (model.Component, error)
	FetchAssetContent(ctx context.Context, downloadURL string) (io.ReadCloser, error)
}

type webhookHandler struct {
	cfg      *config.Config
	source   componentSource
	uploader pipeline.Uploader
	sched    *settle.Scheduler
	logger   *slog.Logger
}

func newWebhookHandler(ctx context.Context, cfg *config.Config, source componentSource, uploader pipeline.Uploader, logger *slog.Logger) *webhookHandler {
	settleDelay := cfg.Webhook.SettleDelay
	if settleDelay == 0 {
		settleDelay = defaultSettleDelay
	}
	maxWait := cfg.Webhook.MaxWait
	if maxWait == 0 {
		maxWait = defaultMaxWait
	}

	return &webhookHandler{
		cfg:      cfg,
		source:   source,
		uploader: uploader,
		logger:   logger,
		sched: settle.New(ctx, logger, settle.Options{
			Settle:    settleDelay,
			MaxWait:   maxWait,
			Retryable: func(err error) bool { return errors.Is(err, pipeline.ErrIncomplete) },
			OnError: func(key string, err error) {
				logger.Error("skipping component", "component", key, "maxWait", maxWait, "error", err)
			},
		}),
	}
}

// stop cancels pending publishes and waits for any in flight to return.
func (h *webhookHandler) stop() { h.sched.Stop() }

func (h *webhookHandler) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("reading webhook request body", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	signature := r.Header.Get("X-Nexus-Webhook-Signature")
	if !nxrm.VerifyHMAC(body, signature, h.cfg.Webhook.Secret) {
		h.logger.Warn("rejecting webhook: invalid signature", "remoteAddr", r.RemoteAddr)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	eventID := r.Header.Get("X-Nexus-Webhook-Id")
	if eventID != nxrm.ComponentWebhookEventID {
		h.logger.Warn("ignoring webhook: unrecognized event id", "eventId", eventID)
		w.WriteHeader(http.StatusOK)
		return
	}

	payload, err := nxrm.ParseWebhookPayload(bytes.NewReader(body))
	if err != nil {
		h.logger.Error("rejecting webhook: invalid payload", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	key := componentKey(payload)

	switch payload.Action {
	case nxrm.ActionUpdated:
		// NXRM sends an UPDATED each time a file is attached to a component.
		// It never starts a publish, but it tells us an upload is still in
		// progress, so it pushes back a wait that is already under way.
		h.logger.Log(r.Context(), logging.LevelTrace, "component updated, extending wait if pending", "component", key)
		h.sched.Touch(key)
		w.WriteHeader(http.StatusOK)
		return
	case nxrm.ActionCreated:
	default:
		h.logger.Warn("ignoring webhook: unhandled action", "action", payload.Action, "repository", payload.RepositoryName)
		w.WriteHeader(http.StatusOK)
		return
	}

	repoCfg, ok := h.cfg.RepositoryFor(payload.RepositoryName)
	if !ok {
		h.logger.Warn("ignoring webhook: repository not configured", "repository", payload.RepositoryName)
		w.WriteHeader(http.StatusOK)
		return
	}

	// One upload makes NXRM send several CREATED events for the same
	// component, in no reliable order relative to its files. They all share
	// this key, so the scheduler folds them into a single publish attempt
	// that runs once the burst has gone quiet.
	h.logger.Info("received webhook, waiting for component to settle", "component", key, "componentId", payload.Component.ComponentID)
	w.WriteHeader(http.StatusOK)
	h.sched.Trigger(key, func(ctx context.Context) error {
		return h.publish(ctx, payload, repoCfg)
	})
}

// componentKey identifies one component version across the events NXRM sends
// for it.
func componentKey(p nxrm.WebhookPayload) string {
	return fmt.Sprintf("%s/%s/%s@%s", p.RepositoryName, p.Component.Group, p.Component.Name, p.Component.Version)
}

// publish resolves the component as NXRM holds it now and runs the pipeline.
// A component that is still missing required assets returns an error
// wrapping pipeline.ErrIncomplete, which the scheduler treats as "try again
// later"; anything else is final.
func (h *webhookHandler) publish(ctx context.Context, payload nxrm.WebhookPayload, repoCfg config.Repository) error {
	comp, err := h.source.ResolveByID(ctx, payload.Component.ComponentID)
	if err != nil {
		return fmt.Errorf("resolving component: %w", err)
	}

	formatRule, ok := h.cfg.FormatRuleFor(comp.Format)
	if !ok {
		return fmt.Errorf("no bundle assembly rule configured for format %q", comp.Format)
	}

	if _, err := pipeline.Publish(ctx, h.logger, h.source.FetchAssetContent, comp, repoCfg, formatRule, h.uploader); err != nil {
		return err
	}
	return nil
}
