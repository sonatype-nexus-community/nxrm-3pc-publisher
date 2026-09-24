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

package nxrm

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	v395 "github.com/sonatype-nexus-community/nexus-repo-api-client-go/v395"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestSplitScheme(t *testing.T) {
	cases := []struct {
		in         string
		wantScheme string
		wantHost   string
	}{
		{"https://nexus.example.com", "https", "nexus.example.com"},
		{"http://nexus.example.com", "http", "nexus.example.com"},
		{"nexus.example.com", "https", "nexus.example.com"},
	}
	for _, c := range cases {
		scheme, host := splitScheme(c.in)
		if scheme != c.wantScheme || host != c.wantHost {
			t.Errorf("splitScheme(%q) = (%q, %q), want (%q, %q)", c.in, scheme, host, c.wantScheme, c.wantHost)
		}
	}
}

func strPtr(s string) *string { return &s }

func TestToComponent(t *testing.T) {
	checksum := map[string]string{"sha1": "abc123"}
	xo := v395.ComponentXO{
		Repository: strPtr("maven-releases"),
		Format:     strPtr("maven2"),
		Group:      strPtr("com.fasterxml.jackson.core"),
		Name:       strPtr("jackson-core"),
		Version:    strPtr("2.13.5.1-osera-00001"),
		Assets: []v395.AssetXO{
			{
				Path:        strPtr("/com/fasterxml/jackson/core/jackson-core/2.13.5.1-osera-00001/jackson-core-2.13.5.1-osera-00001.jar"),
				DownloadUrl: strPtr("https://nexus.example.com/repository/maven-releases/com/fasterxml/jackson/core/jackson-core/2.13.5.1-osera-00001/jackson-core-2.13.5.1-osera-00001.jar"),
				Checksum:    &checksum,
			},
		},
	}

	comp := toComponent(xo)

	if comp.Repository != "maven-releases" {
		t.Errorf("Repository = %q", comp.Repository)
	}
	if comp.Format != "maven2" {
		t.Errorf("Format = %q", comp.Format)
	}
	if comp.Group != "com.fasterxml.jackson.core" {
		t.Errorf("Group = %q", comp.Group)
	}
	if comp.Name != "jackson-core" {
		t.Errorf("Name = %q", comp.Name)
	}
	if comp.Version != "2.13.5.1-osera-00001" {
		t.Errorf("Version = %q", comp.Version)
	}
	if len(comp.Assets) != 1 {
		t.Fatalf("len(Assets) = %d, want 1", len(comp.Assets))
	}
	if comp.Assets[0].Filename != "jackson-core-2.13.5.1-osera-00001.jar" {
		t.Errorf("Assets[0].Filename = %q", comp.Assets[0].Filename)
	}
	if comp.Assets[0].Checksums["sha1"] != "abc123" {
		t.Errorf("Assets[0].Checksums[sha1] = %q", comp.Assets[0].Checksums["sha1"])
	}
}

func TestToAsset_pathWithNoSlash(t *testing.T) {
	xo := v395.AssetXO{Path: strPtr("react-19.2.8-patched-1.tgz")}
	asset := toAsset(xo)
	if asset.Filename != "react-19.2.8-patched-1.tgz" {
		t.Errorf("Filename = %q", asset.Filename)
	}
}

func TestClient_FetchAssetContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("binary-content"))
	}))
	defer srv.Close()

	c := NewClient(Options{BaseURL: srv.URL}, discardLogger())
	rc, err := c.FetchAssetContent(context.Background(), srv.URL+"/asset.jar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading content: %v", err)
	}
	if string(data) != "binary-content" {
		t.Errorf("content = %q, want %q", string(data), "binary-content")
	}
}

func TestClient_FetchAssetContent_sendsBasicAuth(t *testing.T) {
	var gotUser, gotPass string
	var gotOK bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOK = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("binary-content"))
	}))
	defer srv.Close()

	c := NewClient(Options{BaseURL: srv.URL, Username: "alice", Password: "secret"}, discardLogger())
	rc, err := c.FetchAssetContent(context.Background(), srv.URL+"/asset.jar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = rc.Close() }()

	if !gotOK {
		t.Fatal("expected request to carry basic auth credentials")
	}
	if gotUser != "alice" || gotPass != "secret" {
		t.Errorf("BasicAuth() = (%q, %q), want (%q, %q)", gotUser, gotPass, "alice", "secret")
	}
}

func TestClient_FetchAssetContent_noAuthConfigured(t *testing.T) {
	var gotOK bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, gotOK = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("binary-content"))
	}))
	defer srv.Close()

	c := NewClient(Options{BaseURL: srv.URL}, discardLogger())
	rc, err := c.FetchAssetContent(context.Background(), srv.URL+"/asset.jar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = rc.Close() }()

	if gotOK {
		t.Error("expected no basic auth header when no credentials configured")
	}
}

func TestClient_FetchAssetContent_notFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	c := NewClient(Options{BaseURL: srv.URL}, discardLogger())
	_, err := c.FetchAssetContent(context.Background(), srv.URL+"/missing.jar")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}
