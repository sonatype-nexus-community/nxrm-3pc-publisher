# Architecture: nxrm-3pc-publisher

## 1. Purpose

A single Go binary that watches one or more Nexus Repository Manager (NXRM)
hosted repositories, and for each qualifying component version:

1. Fetches the binary assets and vendor-authored CycloneDX document from NXRM.
2. Splits the single CycloneDX document into a conformant **SBOM** file and
   one or more conformant **VEX** file(s) (the catalog spec requires these as
   separate documents; embedded vulnerability data is otherwise silently
   ignored by Sonatype's ingestion).
3. Assembles the flat `.zip` component bundle required by Sonatype's
   Third-Party Component Catalog spec, **embedding the derived SBOM inside
   it** (one of the spec's two allowed SBOM placements — see §5).
4. Validates the bundle and VEX against the spec's structural requirements.
5. Uploads bundle (SBOM included) + VEX to the Sonatype-owned, immutable S3
   bucket using the path layout the spec defines.

Three trigger modes share one pipeline:

| Mode        | Trigger                                                | Use case                        |
|-------------|---------------------------------------------------------|----------------------------------|
| `serve`     | NXRM webhook (`rm:repository:component` CREATED)         | Ongoing/new artifact publish     |
| `publish`   | Operator-supplied NXRM coordinates (repo/group/name/version) | Manual retry / one-off submission |
| `backfill`  | NXRM REST API enumeration of a repository                | Historical bulk backfill        |

**Supported NXRM version**: 3.95.x and later (see §4.1).

## 2. Non-goals (v1)

- Generating/scaffolding CycloneDX documents — vendors author these themselves.
- Handling non-NXRM sources (local-file-only submission is not in scope; all
  modes resolve through NXRM coordinates).
- Overwrite/delete workflows against S3 (bucket is immutable by design;
  out-of-band exception handling is Sonatype's process, not this tool's).

## 3. Pipeline (shared by all three modes)

```
NXRM coordinates (repo, group?, name, version)
        │
        ▼
 [1] Resolve component  ── ComponentsAPI.ListComponents / SearchAPI.ListSearch
        │                  (or continuationToken-paged ListComponents, for backfill)
        ▼
 [2] Fetch assets        ── download binary assets + <name>-<version>-cyclonedx.json
        │                  via each AssetXO.DownloadUrl (plain net/http; client library
        │                  stops at metadata, not content)
        ▼
 [3] Split CycloneDX     ── components/licenses/pedigree → SBOM doc
        │                   vulnerabilities/affects       → VEX doc(s)
        ▼
 [4] Assemble bundle     ── apply per-format include rules + embed SBOM doc
        │                  → flat zip in memory/tmp
        ▼
 [5] Validate            ── structural checks against spec (§6)
        │
        ├─ fail → structured log entry, skip this component, continue
        ▼
 [6] Upload to S3        ── HEAD before each PUT; skip existing objects
```

Steps 1–2 differ slightly by mode:

- **`serve`**: webhook payload gives `componentId`/coordinates directly; tool
  calls `ComponentsAPI.GetComponents(ctx, id)` to get the full asset list.
- **`publish`**: operator gives coordinates on the CLI; same resolve step via
  `SearchAPI.ListSearch` (filtered by repository/group/name/version).
- **`backfill`**: tool pages `ComponentsAPI.ListComponents(ctx).Repository(X)`
  via `continuationToken` and feeds each component through steps 2–6.

## 4. NXRM Integration

### 4.1 REST client library

All NXRM REST calls (search, component/asset lookup, pagination) go through
the official generated client,
[`nexus-repo-api-client-go`](https://github.com/sonatype-nexus-community/nexus-repo-api-client-go)
— **no hand-rolled NXRM HTTP calls**. This is an OpenAPI-generated client,
versioned and released in lockstep with NXRM itself.

```go
import v395 "github.com/sonatype-nexus-community/nexus-repo-api-client-go/v395"

cfg := v395.NewConfiguration()
cfg.Host = nxrmHost
cfg.Scheme = "https"
client := v395.NewAPIClient(cfg)

auth := context.WithValue(ctx, v395.ContextBasicAuth, v395.BasicAuth{
    UserName: user, Password: pass,
})

page, _, err := client.ComponentsAPI.ListComponents(auth).
    Repository(repo).ContinuationToken(token).Execute()
for _, c := range page.GetItems() {
    // c.GetName(), c.GetVersion(), c.GetAssets() → []AssetXO, each with GetDownloadUrl()
}
```

Relevant surface used by this tool:

| Need                                  | Library call                                              |
|----------------------------------------|-------------------------------------------------------------|
| Resolve one component by coordinates   | `SearchAPI.ListSearch(ctx).Repository().Group().Name().Version().Execute()` |
| Resolve one component by id (webhook)  | `ComponentsAPI.GetComponents(ctx, id).Execute()`             |
| Page all components in a repo (backfill) | `ComponentsAPI.ListComponents(ctx).Repository().ContinuationToken().Execute()` → `PageComponentXO{ContinuationToken, Items []ComponentXO}` |
| Asset metadata (paths, checksums, download URL) | `ComponentXO.GetAssets() []AssetXO`, or `AssetsAPI.ListAssets`/`GetAssets` directly |

The library models NXRM's REST resources (search/components/assets) but not
asset *content* or webhooks — both remain the tool's own responsibility:

- **Asset content**: fetched via plain `net/http` GET against each
  `AssetXO.GetDownloadUrl()` — the client library stops at metadata.
- **Webhooks**: the library has no webhook types/verification helpers at all
  (it's a REST client, not a webhook toolkit), so `internal/nxrm/webhook.go`
  still owns signature verification and payload parsing (§4.2). Once the
  webhook payload yields a `componentId`, resolution switches back to the
  library via `GetComponents`.
- **Auth**: `v395.BasicAuth` via context, or a custom `*http.Client` injected
  into `Configuration.HTTPClient` for bearer-token/mTLS setups — either way,
  configured from this tool's own config file (§9), not the library's
  defaults.

**Supported NXRM version**: 3.95.x+, pinned to the `nexus-repo-api-client-go`
`/v395` module major-version line. If NXRM adds a field/endpoint this tool
needs and the installed client version lacks it, **fix it upstream in
`nexus-repo-api-client-go`** (Sonatype owns and controls that repo) rather
than working around the gap locally (e.g. raw HTTP calls bypassing the
client, or duplicating types in this repo). Bump the `/v395` import and
`go.mod` requirement when adopting a newer NXRM target.

### 4.2 Webhook receiver (`serve`)

- HTTP server, one route (e.g. `POST /webhook/nxrm`).
- Verifies `X-Nexus-Webhook-Signature` (HMAC-SHA1 over the raw, whitespace-free
  JSON body) using the shared secret from config before processing — this
  verification and the payload struct are hand-rolled in `internal/nxrm`,
  since the client library doesn't cover webhooks (§4.1).
- Filters on `X-Nexus-Webhook-Id: rm:repository:component` and
  `action: CREATED`; ignores everything else (200 OK, no-op).
- Filters further on `repositoryName` against the set of repositories present
  in config — unconfigured repositories are ignored, not errored.
- On a matching event, hands `componentId` to the shared pipeline (§3), which
  resolves the rest via `nexus-repo-api-client-go`.
- Processing happens synchronously per request today (v1); a queue is future
  work if webhook volume/latency demands it.

## 5. Bundle Assembly

Per-NXRM-`format` default include rules, e.g.:

```yaml
formats:
  maven2:
    includeAssetSuffixes: [".jar", ".pom", "-sources.jar", "-javadoc.jar"]
    sbomSuffix: "-cyclonedx.json"
  npm:
    includeAssetSuffixes: [".tgz"]
    sbomSuffix: "-cyclonedx.json"
```

- Config can override or extend `includeAssetSuffixes`/`sbomSuffix` per
  repository, but ships with sensible maven2/npm defaults.
- The vendor's raw CycloneDX asset (matched by `sbomSuffix`) is *never*
  included as-is inside the zip. Instead, the **derived SBOM document** (the
  output of the CycloneDX split in §6, named per `SBOMFilename`) is embedded
  in the bundle as `<name>-<version>.bom.json`. This is one of the two SBOM
  placements the spec allows ("include the SBOM in the component archive
  bundle **or** in the s3 directory as a peer to the component archive
  bundle") — this tool embeds rather than uploading a separate peer object.
- Bundle member filenames are taken as-is from NXRM asset paths (already
  matching `<name>-<version>[-classifier].<ext>` by construction), except for
  the embedded SBOM, which uses the derived filename above rather than the
  vendor asset's own name.

## 6. CycloneDX Handling

Uses `github.com/CycloneDX/cyclonedx-go` for parsing and generation.

**Split logic**, from one source document (`<name>-<version>-cyclonedx.json`
in NXRM) into:

- **SBOM** (`<name>-<version>.bom.json`): `bomFormat`, `specVersion`,
  `serialNumber`, `metadata`, `components`, `dependencies` carried through
  unchanged; `vulnerabilities` stripped. If `components` is empty/nil but
  `metadata.component` is set, that component is folded into `components[]`
  as the sole entry — real vendor CycloneDX documents commonly describe
  their single subject library only via `metadata.component` (a standard,
  valid CycloneDX pattern), and without this fold SBOM validation would
  reject them for having zero components.
- **VEX** (`<CVE>-<timestamp>.bom.json` for single-CVE, or
  `<timestamp>.bom.json` for multi-CVE): `bomFormat`, `specVersion`, a
  **new** `serialNumber` (VEX is a distinct BOM), `vulnerabilities` carried
  through; `affects[].ref` rewritten to a BOM-Link
  (`urn:cdx:<sbom-serialNumber>/<version>#<url-encoded-bom-ref>`) pointing at
  the corresponding component in the SBOM just produced.
- Timestamp for VEX filenames is the vendor CycloneDX doc's
  `metadata.timestamp` if present, else time of processing.
- If the source document has no `vulnerabilities`, no VEX file is produced or
  uploaded — this is expected and not an error.

## 7. Validation (before any S3 write)

Applied to the assembled bundle, SBOM, and VEX independently; any failure
logs the NXRM coordinates + reason and skips the component (§8), it does not
abort the run.

- Bundle: is a flat zip (no directories); filename matches
  `<name>-<version>.zip`.
- SBOM: has `bomFormat`, `specVersion`, `serialNumber`; every `components[]`
  entry has `name`, `version`, `type`, `bom-ref`; `licenses` present.
- VEX: has `bomFormat`, `specVersion`, `serialNumber`; every
  `vulnerabilities[]` entry has `id`, `analysis.state`, and at least one
  `affects[].ref`.
- Filenames match the spec's naming patterns exactly (including required
  `.bom.json`/`.cdx.json` suffix).

## 8. S3 Upload

- Path construction directly from config's per-repository `ecosystem`
  (required, no default) + optional `namespace` extraction rule + NXRM
  `name`/`version`:
  - `/packages/<ecosystem>/<namespace>/<name>/<version>/<name>-<version>.zip`
    (SBOM embedded inside this bundle — see §5 — not uploaded separately)
  - VEX under `/vex/<vex-filename>`
- Idempotency: `HeadObject` before every `PutObject`; if present, log
  "already exists, skipping" and move on — no local state store needed.
- Auth via default AWS SDK v2 credential chain (env, shared config, IAM
  role/SSO profile).

## 9. Configuration

Single YAML file (`--config`), no CLI-flag-driven coordinates for `serve`;
`publish`/`backfill` take coordinates as flags plus `--config` for
destination/credentials:

```yaml
nxrm:
  url: https://nexus.example.com
  auth:
    username: ...
    password: ...   # or token
webhook:
  secret: ...        # HMAC shared secret; serve mode only

s3:
  bucket: sonatype-3p-catalog
  region: us-east-1
  # credentials via standard AWS SDK chain, not stored here

repositories:
  jackson-maven-releases:
    ecosystem: maven          # required, no default
    namespaceFromGroup: true  # group "com.fasterxml.jackson.core" → namespace segment
  patched-npm-releases:
    ecosystem: npm
    namespaceFromGroup: false
```

## 10. Project Layout & Tooling

Aligned with `iq-pv-reporter` / `nxfw-policy-tester` and
contribute.sonatype.com conventions:

```
/main.go                      # entry point, Apache-2.0 header, subcommand dispatch
/internal/
  cli/                         # flag parsing for publish/backfill/serve
  config/                      # YAML config load + validation
  nxrm/                        # nexus-repo-api-client-go wiring, webhook handler, HMAC verification
  bundle/                      # per-format assembly rules
  cyclonedx/                   # split logic, spec validation
  s3upload/                    # path construction, HEAD/PUT, AWS SDK v2 wiring
  pipeline/                    # orchestrates steps 1–6, shared by all modes
/LICENSE                       # Apache-2.0
/README.md
/CONTRIBUTING.md
/.goreleaser.yml                # v2, linux/darwin/windows, amd64/arm64
/.github/workflows/build.yml    # checkout, setup-go, build, vet, golangci-lint
/.github/workflows/release.yml  # goreleaser + sonatype/actions/evaluate
```

- Module: `github.com/sonatype-nexus-community/nxrm-3pc-publisher`
- Go stdlib `flag` for CLI (no cobra), matching sibling repos.
- `github.com/sonatype-nexus-community/nexus-repo-api-client-go/v395` for all
  NXRM REST calls (search/components/assets) — required per project
  convention; no hand-rolled NXRM HTTP client (§4.1). Module major-version
  segment (`/v395`) tracks the NXRM server version the client was generated
  against; bump on upgrade.
- `github.com/CycloneDX/cyclonedx-go` for CycloneDX parsing/generation.
- AWS SDK v2 (`github.com/aws/aws-sdk-go-v2`) for S3.

## 11. Testing

Unlike the two sibling repos, this build includes table-driven unit tests
(stdlib `testing`, `testify` where useful) for the highest-risk logic, since
output feeds an immutable, no-delete bucket:

- `internal/cyclonedx`: split correctness (SBOM/VEX field partitioning,
  BOM-Link rewriting, timestamp/filename derivation).
- `internal/bundle`: per-format include-rule application, override merging.
- `internal/s3upload`: path construction per ecosystem/namespace rules.
- `internal/nxrm`: webhook HMAC verification, payload parsing, and the
  pagination loop driving `nexus-repo-api-client-go`'s `continuationToken`.

NXRM/S3 network calls are mocked via interfaces at the package boundary —
for NXRM, that means wrapping the pieces of `nexus-repo-api-client-go` this
tool calls behind a small internal interface, so tests don't hit a live
server.

## 12. Open Items / Future Work

- **Upstream-first policy**: `nexus-repo-api-client-go` is a sibling
  Sonatype Nexus Community repo, not a third-party dependency — any missing
  endpoint, field, or bug encountered while using it should be fixed there
  (PR upstream) rather than worked around in this repo. This tool tracks
  released versions of that client, it does not fork or patch around it.
- Webhook processing is synchronous; revisit with a queue if needed.
- `publish`/`backfill` local-file-input mode (bypassing NXRM) was explicitly
  deferred — could be added as a fourth subcommand later.
- No local state/checkpoint store for backfill resumability; relies on S3
  HEAD checks, which is simple but re-verifies already-known-good items on
  re-runs of large backfills. Acceptable for v1; reconsider if backfill scale
  makes S3 HEAD calls the bottleneck.
