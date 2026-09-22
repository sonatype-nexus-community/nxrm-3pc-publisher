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

// Package nxrm wraps the official nexus-repo-api-client-go client
// (github.com/sonatype-nexus-community/nexus-repo-api-client-go) with the
// narrow surface this tool needs: resolving a single component by
// coordinates or by id, and paging every component in a repository for
// backfill. Per project convention, all NXRM REST calls go through that
// client rather than hand-rolled HTTP — if it's ever missing something this
// tool needs, fix it upstream there instead of working around it here (see
// ARCHITECTURE.md §4.1, §12).
//
// Fetching asset *content* (as opposed to metadata) is out of scope for the
// generated client, so Client also exposes FetchAssetContent using a plain
// net/http client.
package nxrm

import (
	"context"
	"fmt"
	"io"
	"net/http"

	v395 "github.com/sonatype-nexus-community/nexus-repo-api-client-go/v395"

	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/model"
)

// Client resolves NXRM components/assets into this tool's model types.
type Client struct {
	api        *v395.APIClient
	username   string
	password   string
	httpClient *http.Client
}

// Options configures a new Client.
type Options struct {
	// BaseURL is the NXRM server's base URL, e.g. "https://nexus.example.com".
	BaseURL string
	// Username/Password are basic-auth credentials for the NXRM REST API.
	Username string
	Password string
	// HTTPClient is used both by the generated API client and for asset
	// content downloads. Defaults to http.DefaultClient when nil.
	HTTPClient *http.Client
}

// NewClient builds a Client wrapping nexus-repo-api-client-go, configured
// against the given NXRM server.
func NewClient(opts Options) *Client {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	cfg := v395.NewConfiguration()
	cfg.Host = opts.BaseURL
	cfg.HTTPClient = httpClient
	// NewConfiguration seeds Servers[0].URL with the "/service/rest" base
	// path only; Host/Scheme must be derived from opts.BaseURL ourselves,
	// since the generated client expects Host to be just the authority.
	scheme, host := splitScheme(opts.BaseURL)
	cfg.Scheme = scheme
	cfg.Host = host

	return &Client{
		api:        v395.NewAPIClient(cfg),
		username:   opts.Username,
		password:   opts.Password,
		httpClient: httpClient,
	}
}

// withAuth attaches this Client's basic-auth credentials onto ctx for a
// single request, alongside whatever deadline/cancellation the caller
// already set. Returns ctx unchanged if no credentials were configured.
func (c *Client) withAuth(ctx context.Context) context.Context {
	if c.username == "" && c.password == "" {
		return ctx
	}
	return context.WithValue(ctx, v395.ContextBasicAuth, v395.BasicAuth{
		UserName: c.username,
		Password: c.password,
	})
}

// splitScheme divides a base URL like "https://nexus.example.com" into
// ("https", "nexus.example.com") as required by v395.Configuration, which
// wants Scheme and Host as separate fields rather than one URL.
func splitScheme(baseURL string) (scheme, host string) {
	const httpsPrefix = "https://"
	const httpPrefix = "http://"
	switch {
	case len(baseURL) >= len(httpsPrefix) && baseURL[:len(httpsPrefix)] == httpsPrefix:
		return "https", baseURL[len(httpsPrefix):]
	case len(baseURL) >= len(httpPrefix) && baseURL[:len(httpPrefix)] == httpPrefix:
		return "http", baseURL[len(httpPrefix):]
	default:
		return "https", baseURL
	}
}

// ResolveByCoordinates finds exactly one component in repo matching group,
// name and version via the search endpoint. group may be empty for
// ecosystems without a namespace concept. Returns an error if zero or more
// than one component matches (coordinates are expected to be unique for a
// single hosted component version).
func (c *Client) ResolveByCoordinates(ctx context.Context, repo, group, name, version string) (model.Component, error) {
	req := c.api.SearchAPI.ListSearch(c.withAuth(ctx)).
		Repository(repo).Name(name).Version(version)
	if group != "" {
		req = req.Group(group)
	}

	page, _, err := req.Execute()
	if err != nil {
		return model.Component{}, fmt.Errorf("searching NXRM for %s/%s/%s@%s: %w", repo, group, name, version, err)
	}

	items := page.GetItems()
	switch len(items) {
	case 0:
		return model.Component{}, fmt.Errorf("no component found in repository %q for %s/%s@%s", repo, group, name, version)
	case 1:
		return toComponent(items[0]), nil
	default:
		return model.Component{}, fmt.Errorf("ambiguous coordinates: %d components found in repository %q for %s/%s@%s", len(items), repo, group, name, version)
	}
}

// ResolveByID fetches a single component (with its full asset list) by its
// NXRM component id, as delivered in a webhook payload's componentId field.
//
// Note: despite the plural name, ComponentsAPI.GetComponents(ctx, id) is
// NXRM's "get a single component by id" endpoint in this client version.
func (c *Client) ResolveByID(ctx context.Context, id string) (model.Component, error) {
	comp, _, err := c.api.ComponentsAPI.GetComponents(c.withAuth(ctx), id).Execute()
	if err != nil {
		return model.Component{}, fmt.Errorf("fetching NXRM component %q: %w", id, err)
	}
	return toComponent(*comp), nil
}

// ListComponentsPage returns one page of every component in repo, using
// NXRM's continuationToken pagination. Pass an empty continuationToken to
// fetch the first page; the returned token (empty when there are no more
// pages) should be passed back in to fetch the next page. Used by the
// backfill subcommand to walk an entire repository.
//
// This deliberately calls SearchAPI.ListSearch rather than
// ComponentsAPI.ListComponents: in nexus-repo-api-client-go v395.96.2,
// ListComponents returns the untyped Page{Items []map[string]interface{}}
// model instead of a typed component list, while ListSearch (filtered only
// by repository, i.e. equivalent to "list everything in this repo") returns
// the typed PageComponentXO this tool needs. Per project convention, that
// typing gap belongs upstream in nexus-repo-api-client-go, not worked around
// here with ad-hoc map decoding (see ARCHITECTURE.md §4.1, §12).
func (c *Client) ListComponentsPage(ctx context.Context, repo, continuationToken string) (items []model.Component, nextToken string, err error) {
	req := c.api.SearchAPI.ListSearch(c.withAuth(ctx)).Repository(repo)
	if continuationToken != "" {
		req = req.ContinuationToken(continuationToken)
	}

	page, _, err := req.Execute()
	if err != nil {
		return nil, "", fmt.Errorf("listing components in repository %q: %w", repo, err)
	}

	for _, comp := range page.GetItems() {
		items = append(items, toComponent(comp))
	}
	return items, page.GetContinuationToken(), nil
}

// FetchAssetContent downloads the content at an asset's DownloadURL. The
// generated NXRM client only models metadata, not content, so this uses a
// plain HTTP GET against the URL NXRM itself returned.
func (c *Client) FetchAssetContent(ctx context.Context, downloadURL string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %q: %w", downloadURL, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %q: %w", downloadURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("fetching %q: unexpected status %s: %s", downloadURL, resp.Status, string(body))
	}
	return resp.Body, nil
}

// toComponent converts a generated v395.ComponentXO into this tool's
// model.Component, flattening pointer fields (the generated client models
// every optional field as a pointer; nil becomes the Go zero value here).
func toComponent(c v395.ComponentXO) model.Component {
	out := model.Component{
		Repository: c.GetRepository(),
		Format:     c.GetFormat(),
		Group:      c.GetGroup(),
		Name:       c.GetName(),
		Version:    c.GetVersion(),
	}
	for _, a := range c.GetAssets() {
		out.Assets = append(out.Assets, toAsset(a))
	}
	return out
}

// toAsset converts a generated v395.AssetXO into this tool's model.Asset.
func toAsset(a v395.AssetXO) model.Asset {
	path := a.GetPath()
	filename := path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			filename = path[i+1:]
			break
		}
	}
	return model.Asset{
		Path:        path,
		Filename:    filename,
		DownloadURL: a.GetDownloadUrl(),
		Checksums:   a.GetChecksum(),
	}
}
