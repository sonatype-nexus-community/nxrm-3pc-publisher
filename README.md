# nxrm-3pc-publisher

<!-- Badges Section -->
[![shield_gh-workflow-test]][link_gh-workflow-test]
[![shield_license]][license_file]
<!-- Add other badges or shields as appropriate -->

---

A Go CLI that publishes third-party component bundles from Nexus Repository
Manager (NXRM) into Sonatype's Third-Party Component Catalog: it assembles
the flat archive bundle, splits the vendor's CycloneDX document into
conformant SBOM and VEX files, validates both, and uploads everything to
Sonatype's S3 bucket — triggered by an NXRM webhook, a one-off manual publish
by coordinates, or a bulk backfill over an existing repository.

- [How it works](#how-it-works)
- [Supported ecosystems](#supported-ecosystems)
- [Publishing to NXRM: what the tool expects](#publishing-to-nxrm-what-the-tool-expects)
- [Usage](#usage)
- [Output](#output)
- [Development](#development)
- [The Fine Print](#the-fine-print)

## How it works

For each component version, the tool:

1. Reads the component and its assets from NXRM (3.95.x or later).
2. Downloads the vendor-authored CycloneDX document
   (`<name>-<version>-cyclonedx.json`).
3. Splits it into an **SBOM** (components, licenses, dependencies) and
   **VEX** document(s) (vulnerabilities), as the catalog requires them as
   separate documents.
4. Zips the binary assets plus the derived SBOM into one flat bundle.
5. Validates the bundle, SBOM and VEX. A component that fails is logged and
   skipped; the run carries on.
6. Uploads the bundle and VEX to the catalog's S3 bucket. The bucket is
   immutable, so objects that already exist are skipped, never overwritten.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design.

## Supported ecosystems

| Ecosystem | NXRM format | Default bundle contents | Status |
|---|---|---|---|
| `maven` | `maven2` | `.jar`, `.pom`, `-sources.jar`, `-javadoc.jar` (`.jar` and `.pom` required) | Supported. Namespace is the Maven `groupId`. |
| `npm` | `npm` | `.tgz` (required) | Default rules only; not yet verified end to end. Scoped packages (`@scope/name`) are untested, so the scope may be missing from the S3 path. |

Only **hosted** repositories are intended as sources. Each watched repository
must declare its `ecosystem` explicitly in the config; there is no default, so
a misconfigured repository fails validation rather than being published under
a guessed ecosystem.

Other NXRM formats can be enabled by adding a `formats:` entry (which assets
go in the bundle) and a repository with an `ecosystem` value in the config.
That path is not tested, so check the output with `-output-dir` first and
confirm the ecosystem value and S3 layout with the catalog's maintainers.

## Publishing to NXRM: what the tool expects

Every component version to be published must be a single NXRM component that
holds:

1. **The binary assets** for its format (for example the `.jar` and `.pom`).
2. **A vendor-authored CycloneDX JSON document** named
   `<name>-<version>-cyclonedx.json`, attached to the same component. The
   suffix is configurable per format with `sbomSuffix`.

For Maven this looks like the following in NXRM, where the CycloneDX file is an
extra asset with classifier `cyclonedx` and extension `json`:

```
com/fasterxml/jackson/core/jackson-core/2.13.5.1-osera-00001/
├── jackson-core-2.13.5.1-osera-00001.jar
├── jackson-core-2.13.5.1-osera-00001.pom
└── jackson-core-2.13.5.1-osera-00001-cyclonedx.json
```

Notes on the CycloneDX document:

- It can describe its subject either in `components[]` or only in
  `metadata.component`; in the latter case the tool folds it into
  `components[]`.
- `specVersion` must be CycloneDX **1.6 or 1.7**; other versions are rejected.
- Every component needs `name`, `version`, `type`, `bom-ref` and at least one
  entry under `licenses`. Maven components also need a `group`.
- Components derived from an open source project should declare it under
  `pedigree.ancestors`, so newly disclosed upstream vulnerabilities can be
  matched to your build. A component without ancestors is published, with a
  warning in the log.
- Put vulnerability data in the document's `vulnerabilities[]`, each with an
  `id`, `analysis.state` and `affects[].ref`. The tool moves these into VEX
  files. A document with no vulnerabilities simply produces no VEX file.
- The VEX file name includes `metadata.timestamp` from your document. The
  bucket never overwrites, so to publish a revised set of vulnerabilities for
  the same component, bump `metadata.timestamp`; otherwise the new file has the
  same name and is skipped.
- The raw CycloneDX document is never placed in the bundle as is. The derived
  SBOM, named `<name>-<version>.bom.json`, is embedded instead.

A component is published only when its CycloneDX document and the format's
required assets (see `requiredAssetSuffixes` in
[`config.example.yaml`](./config.example.yaml); for Maven, the `.jar` and
`.pom`) are all present. Extras such as `-sources.jar` and `-javadoc.jar` are
optional and are bundled when present.

[docs/QUICKSTART.md](./docs/QUICKSTART.md) walks through uploading a Maven
component, including the `mvn deploy:deploy-file` command.

## Usage

New here? Follow the [Quickstart](./docs/QUICKSTART.md).

### Installation

```
go install github.com/sonatype-nexus-community/nxrm-3pc-publisher@latest
```

Or download a prebuilt binary from the [releases page](https://github.com/sonatype-nexus-community/nxrm-3pc-publisher/releases).
Release checksums (`*_SHA256SUMS`) are GPG-signed.

### Configuration

All three commands read a YAML config file (`-config`). See
[`config.example.yaml`](./config.example.yaml) for a documented example
covering NXRM connection details, the S3 destination, per-NXRM-format bundle
assembly rules, and the watched repositories (each with a required
`ecosystem` — there is no default). AWS credentials are never read from this
file; they come from the standard AWS SDK credential chain (environment
variables, shared config, IAM role, or SSO profile).

A minimal config for a single Maven repository:

```yaml
nxrm:
  url: https://<your-nxrm-host>
  auth:
    username: <nxrm-username>
    password: <nxrm-password-or-user-token>
s3:
  bucket: <catalog-bucket-name>
  region: <bucket-region>
formats:
  maven2:
    includeAssetSuffixes: [".jar", ".pom", "-sources.jar", "-javadoc.jar"]
    requiredAssetSuffixes: [".jar", ".pom"]
    sbomSuffix: "-cyclonedx.json"
repositories:
  <your-maven-hosted-repository>:
    ecosystem: maven
    namespaceFromGroup: true
```

### Commands

| Command | Purpose | Flags |
|---|---|---|
| `publish` | Publish one component by NXRM coordinates | `-config`, `-repository`, `-group` (optional), `-name`, `-version`, `-output-dir` (optional) |
| `backfill` | Publish every component in a repository | `-config`, `-repository` |
| `serve` | Receive NXRM component webhooks and publish each new component | `-config` |
| `version` | Print version information | |

Every publishing command also takes `-log-level` (`error`, `warn`, `info` —
the default — or `trace`) and `-log-format` (`text` — the default — or
`json`). Run `nxrm-3pc-publisher <command> -h` for the full flag list.

### Examples

```
# One-off: resolve a component by NXRM coordinates and publish it
nxrm-3pc-publisher publish -config config.yaml \
  -repository maven-releases \
  -group com.fasterxml.jackson.core -name jackson-core -version 2.13.5.1-osera-00001

# Dry run: write what would be uploaded to ./out instead of S3
nxrm-3pc-publisher publish -config config.yaml \
  -repository maven-releases \
  -group com.fasterxml.jackson.core -name jackson-core -version 2.13.5.1-osera-00001 \
  -output-dir ./out

# Backfill: publish every component currently in a repository
nxrm-3pc-publisher backfill -config config.yaml -repository maven-releases

# Serve: run an HTTP server that receives NXRM component webhooks, with
# verbose logging and JSON output suited to a log aggregator
nxrm-3pc-publisher serve -config config.yaml -log-level trace -log-format json
```

### Serve mode

`serve` listens on `webhook.listenAddr` and accepts `POST /webhook/nxrm`. It
verifies the `X-Nexus-Webhook-Signature` HMAC-SHA1 header against
`webhook.secret`, and acts only on `component` `CREATED` events for
repositories listed in the config; everything else is acknowledged and
ignored. It speaks plain HTTP, so run it behind a TLS-terminating proxy.

The webhook fires when NXRM creates the component, so the CycloneDX asset must
already be attached by then. If a component is created before its CycloneDX
file arrives it is skipped; re-run it with `publish` once it is complete. See
the [Quickstart](./docs/QUICKSTART.md#6-automate-with-a-webhook).

## Output

The S3 layout, which `-output-dir` mirrors on disk:

```
packages/<ecosystem>/<namespace>/<name>/<version>/<name>-<version>.zip
vex/<CVE-ID>-<timestamp>.bom.json      # a VEX with exactly one vulnerability
vex/<timestamp>.bom.json               # a VEX with several
```

The `<namespace>` segment is omitted when the repository has
`namespaceFromGroup: false` or the component has no group. Logging levels and
conventions are described in
[ARCHITECTURE.md §12](./ARCHITECTURE.md#12-logging).

## Development

See [CONTRIBUTING.md](./CONTRIBUTING.md) for details, and
[ARCHITECTURE.md](./ARCHITECTURE.md) for the design of this tool. Release
history is in [CHANGELOG.md](./CHANGELOG.md).

## The Fine Print

Remember:

This project is part of the [Sonatype Nexus Community](https://github.com/sonatype-nexus-community) organization, which is not officially supported by Sonatype. Please review the latest pull requests, issues, and commits to understand this project's readiness for contribution and use.

* File suggestions and requests on this repo through GitHub Issues, so that the community can pitch in
* Use or contribute to this project according to your organization's policies and your own risk tolerance
* Don't file Sonatype support tickets related to this project— it won't reach the right people that way

Last but not least of all - have fun!

<!-- Links Section -->
[shield_gh-workflow-test]: https://img.shields.io/github/actions/workflow/status/sonatype-nexus-community/nxrm-3pc-publisher/build.yml?branch=main&logo=GitHub&logoColor=white "build"
[shield_license]: https://img.shields.io/github/license/sonatype-nexus-community/nxrm-3pc-publisher?logo=open%20source%20initiative&logoColor=white "license"

[link_gh-workflow-test]: https://github.com/sonatype-nexus-community/nxrm-3pc-publisher/actions/workflows/build.yml?query=branch%3Amain
[license_file]: https://github.com/sonatype-nexus-community/nxrm-3pc-publisher/blob/main/LICENSE
