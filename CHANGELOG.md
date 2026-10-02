# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-02

First public release.

### Added

- `publish` subcommand: resolve a single component by NXRM coordinates
  (repository, optional group, name, version) and publish it.
- `backfill` subcommand: page through every component in an NXRM repository
  and publish each one.
- `serve` subcommand: HTTP receiver for NXRM `rm:repository:component`
  `CREATED` webhooks, verified with an HMAC-SHA1 shared secret.
- CycloneDX split: a vendor's single CycloneDX document is divided into a
  conformant SBOM and one or more VEX documents, with VEX `affects` references
  rewritten to BOM-Links into the SBOM. A document that only describes its
  subject via `metadata.component` has that component folded into
  `components[]`.
- Flat zip bundle assembly driven by per-NXRM-format include rules, with the
  derived SBOM embedded in the bundle as `<name>-<version>.bom.json`.
- Structural validation of bundle, SBOM and VEX before any upload; a component
  that fails validation is logged and skipped.
- Idempotent uploads to the Sonatype Third-Party Component Catalog S3 bucket
  (`HeadObject` before every `PutObject`), using the standard AWS SDK
  credential chain.
- `publish -output-dir`: write the bundle, SBOM and VEX to a local directory
  instead of S3, for inspection or dry runs.
- Structured logging via `-log-level` (`error`, `warn`, `info`, `trace`) and
  `-log-format` (`text`, `json`).
- Prebuilt, GPG-signed release binaries for Linux, macOS, Windows and FreeBSD
  (amd64 and arm64).

[Unreleased]: https://github.com/sonatype-nexus-community/nxrm-3pc-publisher/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sonatype-nexus-community/nxrm-3pc-publisher/releases/tag/v0.1.0
