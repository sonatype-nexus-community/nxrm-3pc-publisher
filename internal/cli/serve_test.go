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
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/config"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/model"
)

const testSecret = "shared-secret"

// fakeNXRM serves components whose asset list can be grown over time, the way
// files arrive during a real multi-file upload.
type fakeNXRM struct {
	mu       sync.Mutex
	comp     model.Component
	content  map[string][]byte
	resolves int
}

func (f *fakeNXRM) addAsset(filename string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	url := "https://nexus.example.com/" + filename
	f.comp.Assets = append(f.comp.Assets, model.Asset{Filename: filename, DownloadURL: url})
	f.content[url] = data
}

func (f *fakeNXRM) resolveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resolves
}

func (f *fakeNXRM) ResolveByID(_ context.Context, _ string) (model.Component, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolves++
	c := f.comp
	c.Assets = append([]model.Asset(nil), f.comp.Assets...)
	return c, nil
}

func (f *fakeNXRM) FetchAssetContent(_ context.Context, url string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.content[url]
	if !ok {
		return nil, fmt.Errorf("no content for %s", url)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

type recordingUploader struct {
	mu   sync.Mutex
	keys []string
}

func (u *recordingUploader) Upload(_ context.Context, key string, data io.Reader, _ string) (bool, error) {
	_, _ = io.Copy(io.Discard, data)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.keys = append(u.keys, key)
	return false, nil
}

func (u *recordingUploader) uploaded() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.keys...)
}

func conformingSBOM(t *testing.T) []byte {
	t.Helper()
	bom := &cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_6,
		SerialNumber: "urn:uuid:0f2c9a6e-71c4-4d8b-9e3a-5b6d1f0a2c44",
		Version:      1,
		Components: &[]cdx.Component{{
			BOMRef: "pkg:maven/org.example/widget@1.0.0", Group: "org.example", Name: "widget", Version: "1.0.0",
			Type:     cdx.ComponentTypeLibrary,
			Licenses: &cdx.Licenses{{License: &cdx.License{ID: "Apache-2.0"}}},
			Pedigree: &cdx.Pedigree{Ancestors: &[]cdx.Component{{Name: "widget", Version: "0.9.0"}}},
		}},
	}
	var buf bytes.Buffer
	require.NoError(t, cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).Encode(bom))
	return buf.Bytes()
}

type harness struct {
	nxrm     *fakeNXRM
	uploader *recordingUploader
	handler  *webhookHandler
	logs     *syncBuffer
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newHarness(t *testing.T, settleDelay, maxWait time.Duration) *harness {
	t.Helper()
	cfg := &config.Config{
		Webhook: config.Webhook{Secret: testSecret, SettleDelay: settleDelay, MaxWait: maxWait},
		Formats: map[string]config.FormatRule{"maven2": {
			IncludeAssetSuffixes:  []string{".jar", ".pom", "-sources.jar", "-javadoc.jar"},
			RequiredAssetSuffixes: []string{".jar", ".pom"},
			SBOMSuffix:            "-cyclonedx.json",
		}},
		Repositories: map[string]config.Repository{"maven-releases": {Ecosystem: "maven", NamespaceFromGroup: true}},
	}
	fake := &fakeNXRM{
		comp:    model.Component{Repository: "maven-releases", Format: "maven2", Group: "org.example", Name: "widget", Version: "1.0.0"},
		content: map[string][]byte{},
	}
	uploader := &recordingUploader{}
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))

	h := newWebhookHandler(context.Background(), cfg, fake, uploader, logger)
	t.Cleanup(h.stop)
	return &harness{nxrm: fake, uploader: uploader, handler: h, logs: logs}
}

func (h *harness) send(t *testing.T, eventID, action, repo, componentID string) int {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"repositoryName": repo,
		"action":         action,
		"component":      map[string]string{"componentId": componentID, "format": "maven2", "group": "org.example", "name": "widget", "version": "1.0.0"},
	})
	require.NoError(t, err)

	mac := hmac.New(sha1.New, []byte(testSecret))
	mac.Write(body)

	req := httptest.NewRequest(http.MethodPost, "/webhook/nxrm", bytes.NewReader(body))
	req.Header.Set("X-Nexus-Webhook-Id", eventID)
	req.Header.Set("X-Nexus-Webhook-Signature", hex.EncodeToString(mac.Sum(nil)))
	rec := httptest.NewRecorder()
	h.handler.handle(rec, req)
	return rec.Code
}

func (h *harness) created(t *testing.T) int {
	return h.send(t, "rm:repository:component", "CREATED", "maven-releases", "cid-1")
}

func (h *harness) updated(t *testing.T) int {
	return h.send(t, "rm:repository:component", "UPDATED", "maven-releases", "cid-1")
}

func TestServe_webhookSettling(t *testing.T) {
	sbom := conformingSBOM(t)

	t.Run("a burst of CREATED events publishes once, after the files have arrived", func(t *testing.T) {
		h := newHarness(t, 60*time.Millisecond, 5*time.Second)
		h.nxrm.addAsset("widget-1.0.0-cyclonedx.json", sbom) // CycloneDX lands first, as observed in NXRM

		for range 5 {
			assert.Equal(t, http.StatusOK, h.created(t))
		}
		h.nxrm.addAsset("widget-1.0.0.pom", []byte("pom"))
		h.nxrm.addAsset("widget-1.0.0.jar", []byte("jar"))
		h.created(t)

		require.Eventually(t, func() bool { return len(h.uploader.uploaded()) == 1 }, 3*time.Second, 10*time.Millisecond)
		time.Sleep(200 * time.Millisecond)

		assert.Equal(t, []string{"packages/maven/org.example/widget/1.0.0/widget-1.0.0.zip"}, h.uploader.uploaded())
		assert.Equal(t, 1, h.nxrm.resolveCount(), "six events must collapse into one resolve and publish")
	})

	t.Run("UPDATED events alone never start a publish", func(t *testing.T) {
		h := newHarness(t, 40*time.Millisecond, 5*time.Second)
		h.nxrm.addAsset("widget-1.0.0-cyclonedx.json", sbom)
		h.nxrm.addAsset("widget-1.0.0.pom", []byte("pom"))
		h.nxrm.addAsset("widget-1.0.0.jar", []byte("jar"))

		for range 3 {
			assert.Equal(t, http.StatusOK, h.updated(t))
		}
		time.Sleep(200 * time.Millisecond)

		assert.Empty(t, h.uploader.uploaded())
		assert.Zero(t, h.nxrm.resolveCount())
	})

	t.Run("UPDATED events push back a wait in progress", func(t *testing.T) {
		h := newHarness(t, 150*time.Millisecond, 5*time.Second)
		h.nxrm.addAsset("widget-1.0.0-cyclonedx.json", sbom)
		h.nxrm.addAsset("widget-1.0.0.pom", []byte("pom"))
		h.nxrm.addAsset("widget-1.0.0.jar", []byte("jar"))

		h.created(t)
		time.Sleep(100 * time.Millisecond)
		h.updated(t) // another file is still arriving
		time.Sleep(100 * time.Millisecond)

		assert.Zero(t, h.nxrm.resolveCount(), "the publish must not start while updates keep arriving")
		require.Eventually(t, func() bool { return len(h.uploader.uploaded()) == 1 }, 3*time.Second, 10*time.Millisecond)
	})

	t.Run("an incomplete component is retried and published once it completes", func(t *testing.T) {
		h := newHarness(t, 40*time.Millisecond, 5*time.Second)
		h.nxrm.addAsset("widget-1.0.0-cyclonedx.json", sbom)
		h.created(t)

		require.Eventually(t, func() bool { return h.nxrm.resolveCount() >= 2 }, 3*time.Second, 10*time.Millisecond)
		assert.Empty(t, h.uploader.uploaded(), "nothing may be published while the jar and pom are missing")

		h.nxrm.addAsset("widget-1.0.0.pom", []byte("pom"))
		h.nxrm.addAsset("widget-1.0.0.jar", []byte("jar"))

		require.Eventually(t, func() bool { return len(h.uploader.uploaded()) == 1 }, 3*time.Second, 10*time.Millisecond)
		assert.NotContains(t, h.logs.String(), "level=ERROR")
	})

	t.Run("a component that never completes is reported once and uploads nothing", func(t *testing.T) {
		h := newHarness(t, 30*time.Millisecond, 250*time.Millisecond)
		h.nxrm.addAsset("widget-1.0.0-cyclonedx.json", sbom)
		h.created(t)

		require.Eventually(t, func() bool { return strings.Contains(h.logs.String(), "level=ERROR") }, 3*time.Second, 10*time.Millisecond)
		time.Sleep(150 * time.Millisecond)

		assert.Empty(t, h.uploader.uploaded())
		assert.Equal(t, 1, strings.Count(h.logs.String(), "level=ERROR"))
		assert.Contains(t, h.logs.String(), "required assets missing")
	})

	t.Run("a permanent failure is not retried", func(t *testing.T) {
		h := newHarness(t, 30*time.Millisecond, 5*time.Second)
		bad := bytes.ReplaceAll(sbom, []byte(`"specVersion":"1.6"`), []byte(`"specVersion":"1.5"`))
		h.nxrm.addAsset("widget-1.0.0-cyclonedx.json", bad)
		h.nxrm.addAsset("widget-1.0.0.pom", []byte("pom"))
		h.nxrm.addAsset("widget-1.0.0.jar", []byte("jar"))
		h.created(t)

		require.Eventually(t, func() bool { return strings.Contains(h.logs.String(), "level=ERROR") }, 3*time.Second, 10*time.Millisecond)
		time.Sleep(200 * time.Millisecond)

		assert.Equal(t, 1, h.nxrm.resolveCount(), "an invalid SBOM will not improve by waiting")
		assert.Empty(t, h.uploader.uploaded())
	})

	t.Run("events after a successful publish do not publish again", func(t *testing.T) {
		h := newHarness(t, 30*time.Millisecond, 5*time.Second)
		h.nxrm.addAsset("widget-1.0.0-cyclonedx.json", sbom)
		h.nxrm.addAsset("widget-1.0.0.pom", []byte("pom"))
		h.nxrm.addAsset("widget-1.0.0.jar", []byte("jar"))
		h.created(t)
		require.Eventually(t, func() bool { return len(h.uploader.uploaded()) == 1 }, 3*time.Second, 10*time.Millisecond)

		h.created(t)
		h.created(t)
		time.Sleep(200 * time.Millisecond)

		assert.Len(t, h.uploader.uploaded(), 1)
		assert.Equal(t, 1, h.nxrm.resolveCount())
	})

	t.Run("an unconfigured repository is ignored", func(t *testing.T) {
		h := newHarness(t, 30*time.Millisecond, time.Second)
		code := h.send(t, "rm:repository:component", "CREATED", "some-other-repo", "cid-1")
		time.Sleep(120 * time.Millisecond)

		assert.Equal(t, http.StatusOK, code)
		assert.Zero(t, h.nxrm.resolveCount())
	})

	t.Run("an invalid signature is rejected", func(t *testing.T) {
		h := newHarness(t, 30*time.Millisecond, time.Second)
		req := httptest.NewRequest(http.MethodPost, "/webhook/nxrm", strings.NewReader(`{"action":"CREATED"}`))
		req.Header.Set("X-Nexus-Webhook-Id", "rm:repository:component")
		req.Header.Set("X-Nexus-Webhook-Signature", "deadbeef")
		rec := httptest.NewRecorder()
		h.handler.handle(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Zero(t, h.nxrm.resolveCount())
	})
}
