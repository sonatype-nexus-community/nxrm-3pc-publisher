# How to contribute

It's great you're here and reading this guide, because we need volunteers to help keep this project active and alive for the greater benefit of everyone!

- [Engaging with this project](#engaging-with-this-project)
- [Develpoment Guidelines](#develpoment-guidelines)
  - [Coding Conventions](#coding-conventions)
- [Testing](#testing)
- [Submitting Contributions](#submitting-contributions)

## Engaging with this project

Here are some important resources:
- [GitHub Issues](https://github.com/sonatype-nexus-community/nxrm-3pc-publisher/issues) - a place for bugs to be raised and feature requests made
- [GitHub Discussions](https://github.com/sonatype-nexus-community/nxrm-3pc-publisher/discussions) - a place to discuss ideas or real-world usage

## Development Guidelines

This is a Go project. See [ARCHITECTURE.md](./ARCHITECTURE.md) for the
overall design before making non-trivial changes.

- All NXRM REST calls go through
  [`nexus-repo-api-client-go`](https://github.com/sonatype-nexus-community/nexus-repo-api-client-go).
  If that client is missing an endpoint or field this project needs, please
  raise a fix or feature request in that repo rather than working around the
  gap here (e.g. raw HTTP calls that bypass the client, or duplicated types).
- PRs are checked by CI (`go build`, `go vet`, `golangci-lint`) on every push
  and pull request; a release is cut via GoReleaser on tagged pushes.

### Coding Conventions

- In order to help verify the authenticity of contributed code, we ask that your [commits be signed](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits). 
  All commits must be signed off to show that you agree to publish your changes under the current terms and licenses of the project.
  
  Here are some notes we found helpful in configuring a local environment to automatically sign git commits:
    - [GPG commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#gpg-commit-signature-verification)
    - [Telling Git about your GPG key](https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key#telling-git-about-your-gpg-key)

- Code is formatted with `gofmt` and linted with
  [`golangci-lint`](https://golangci-lint.run/); run both locally before
  opening a PR. Follow existing package conventions (flat `internal/`
  packages, no `cmd/`/`pkg/`) rather than introducing new structure.

## Testing

Run `go test ./...` before submitting a PR. Unit tests use the standard
library `testing` package (and `testify` where it improves clarity), and
mock NXRM/S3 network calls via interfaces at the package boundary rather than
hitting live servers. New logic that touches CycloneDX SBOM/VEX generation,
bundle assembly, or S3 path construction should come with table-driven test
coverage, since output from this tool is written to an immutable, no-delete
S3 bucket.


## Submitting Contributions

Please send Pull Requests that:
1. Have a singluar purpose, and that is backed by one or more GitHub Issues in this project
2. Are clear
3. Have appropriate test coverage for the Pull Requests purpose
4. Meet our Code Style Convention (see [above](#develpoment-guidelines))
5. Sign off your commits to show that you agree to publish your changes under the current terms and licenses of the project, and to indicate agreement with [Developer Certificate of Origin (DCO)](https://developercertificate.org/).
