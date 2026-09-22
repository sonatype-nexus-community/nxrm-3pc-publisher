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
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/config"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/nxrm"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/pipeline"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/s3upload"
)

// RunServe implements the `serve` subcommand: a long-running HTTP server
// that receives NXRM `rm:repository:component` webhooks and publishes each
// newly created component to S3 (ARCHITECTURE.md §4.2).
func RunServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config YAML file (required)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nxrm-3pc-publisher serve -config <path>")
		fmt.Fprintln(os.Stderr, "\nRuns an HTTP server that receives NXRM component webhooks and publishes to S3.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

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
	})

	uploader, err := s3upload.NewUploader(ctx, cfg.S3.Bucket, cfg.S3.Region)
	if err != nil {
		return fmt.Errorf("initializing S3 uploader: %w", err)
	}

	h := &webhookHandler{cfg: cfg, client: client, uploader: uploader}
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/nxrm", h.handle)

	log.Printf("listening for NXRM webhooks on %s", listenAddr)
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

type webhookHandler struct {
	cfg      *config.Config
	client   *nxrm.Client
	uploader *s3upload.Uploader
}

func (h *webhookHandler) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	signature := r.Header.Get("X-Nexus-Webhook-Signature")
	if !nxrm.VerifyHMAC(body, signature, h.cfg.Webhook.Secret) {
		log.Printf("rejecting webhook: invalid signature")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if r.Header.Get("X-Nexus-Webhook-Id") != nxrm.ComponentWebhookEventID {
		w.WriteHeader(http.StatusOK)
		return
	}

	payload, err := nxrm.ParseWebhookPayload(bytes.NewReader(body))
	if err != nil {
		log.Printf("rejecting webhook: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if payload.Action != nxrm.ActionCreated {
		w.WriteHeader(http.StatusOK)
		return
	}

	repoCfg, ok := h.cfg.RepositoryFor(payload.RepositoryName)
	if !ok {
		// Unconfigured repository: ignore, not an error (ARCHITECTURE.md §4.2).
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
	go h.publish(payload, repoCfg)
}

func (h *webhookHandler) publish(payload nxrm.WebhookPayload, repoCfg config.Repository) {
	ctx := context.Background()

	comp, err := h.client.ResolveByID(ctx, payload.Component.ComponentID)
	if err != nil {
		log.Printf("skipping webhook for component %q: %v", payload.Component.ComponentID, err)
		return
	}

	formatRule, ok := h.cfg.FormatRuleFor(comp.Format)
	if !ok {
		log.Printf("skipping %s@%s: no bundle assembly rule configured for NXRM format %q", comp.Name, comp.Version, comp.Format)
		return
	}

	result, err := pipeline.Publish(ctx, h.client.FetchAssetContent, comp, repoCfg, formatRule, h.uploader)
	if err != nil {
		log.Printf("skipping %s@%s: %v", comp.Name, comp.Version, err)
		return
	}

	logResult(comp.Name, comp.Version, result)
}
