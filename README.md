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

Use this section (and any additional sub-sections) to explain how to use this project.

Include:
- Installation
- Configuration
- Execution

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
