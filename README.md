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

- [Usage](#usage)
- [Development](#development)
- [The Fine Print](#the-fine-print)

## Usage

### Installation

```
go install github.com/sonatype-nexus-community/nxrm-3pc-publisher@latest
```

Or download a prebuilt binary from the [releases page](https://github.com/sonatype-nexus-community/nxrm-3pc-publisher/releases).

### Configuration

All three commands read a YAML config file (`-config`). See
[`config.example.yaml`](./config.example.yaml) for a documented example
covering NXRM connection details, the S3 destination, per-NXRM-format bundle
assembly rules, and the watched repositories (each with a required
`ecosystem` — there is no default). AWS credentials are never read from this
file; they come from the standard AWS SDK credential chain (environment
variables, shared config, IAM role, or SSO profile).

### Execution

```
# One-off: resolve a component by NXRM coordinates and publish it
nxrm-3pc-publisher publish -config config.yaml -repository maven-releases -name jackson-core -version 2.13.5.1-osera-00001

# Backfill: publish every component currently in a repository
nxrm-3pc-publisher backfill -config config.yaml -repository maven-releases

# Serve: run an HTTP server that receives NXRM component webhooks
nxrm-3pc-publisher serve -config config.yaml
```

Run `nxrm-3pc-publisher <command> -h` for the full flag list on any
subcommand. See [ARCHITECTURE.md](./ARCHITECTURE.md) for how the three modes
share one pipeline.

## Development

See [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the design of this tool.

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
