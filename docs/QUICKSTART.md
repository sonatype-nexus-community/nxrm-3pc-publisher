# Quickstart

This guide takes you from nothing to a first published component. It uses a
Maven component, which is the best-documented path; see
[Supported ecosystems](../README.md#supported-ecosystems) for the rest.

- [Before you start](#before-you-start)
- [1. Install](#1-install)
- [2. Publish your component to NXRM](#2-publish-your-component-to-nxrm)
- [3. Write a config file](#3-write-a-config-file)
- [4. Dry run locally](#4-dry-run-locally)
- [5. Publish to the catalog](#5-publish-to-the-catalog)
- [6. Automate with a webhook](#6-automate-with-a-webhook)
- [7. Backfill existing components](#7-backfill-existing-components)
- [Troubleshooting](#troubleshooting)

## Before you start

You need:

- A **hosted** NXRM repository (NXRM 3.95.x or later) containing your
  third-party components.
- An NXRM account that can read that repository and call the REST API.
- The name of the catalog S3 bucket, plus AWS credentials with permission to
  `HeadObject` and `PutObject` on it, both supplied by Sonatype as part of
  onboarding to the Third-Party Component Catalog.

AWS credentials are never put in the config file. They are read from the
standard AWS SDK credential chain: environment variables, a shared
config/profile (`AWS_PROFILE`), SSO, or an IAM role.

## 1. Install

Download the archive for your platform from the
[releases page](https://github.com/sonatype-nexus-community/nxrm-3pc-publisher/releases),
or:

```
go install github.com/sonatype-nexus-community/nxrm-3pc-publisher@latest
```

Check it runs:

```
nxrm-3pc-publisher version
```

## 2. Publish your component to NXRM

Each component version you want in the catalog must have, in the **same NXRM
component**, its binary assets and a vendor-authored CycloneDX document named
`<name>-<version>-cyclonedx.json`.

For Maven, that means uploading the CycloneDX file as an extra asset with
classifier `cyclonedx` and extension `json`:

```
mvn deploy:deploy-file \
  -DgroupId=com.fasterxml.jackson.core \
  -DartifactId=jackson-core \
  -Dversion=2.13.5.1-osera-00001 \
  -Dpackaging=jar \
  -Dfile=jackson-core-2.13.5.1-osera-00001.jar \
  -DpomFile=jackson-core-2.13.5.1-osera-00001.pom \
  -Dfiles=jackson-core-2.13.5.1-osera-00001-cyclonedx.json \
  -Dclassifiers=cyclonedx \
  -Dtypes=json \
  -DrepositoryId=nxrm \
  -Durl=https://<your-nxrm-host>/repository/<your-maven-hosted-repository>/
```

Or upload the extra asset through the NXRM UI (Browse → the repository →
Upload component). The resulting component should list these assets:

```
jackson-core-2.13.5.1-osera-00001.jar
jackson-core-2.13.5.1-osera-00001.pom
jackson-core-2.13.5.1-osera-00001-cyclonedx.json
```

The CycloneDX document must be CycloneDX 1.6 or 1.7, and each component needs
`group` (Maven), `licenses`, and ideally `pedigree.ancestors`; see the
[README](../README.md#publishing-to-nxrm-what-the-tool-expects). It may
contain `vulnerabilities`. These become VEX files during publishing. If it has
none, no VEX file is produced, which is normal. To revise a component's
vulnerabilities later, change the document's `metadata.timestamp` so the VEX
file gets a new name.

## 3. Write a config file

Copy [`config.example.yaml`](../config.example.yaml) and fill in the
placeholders. The minimum for `publish` and `backfill` is:

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

`ecosystem` is required for every repository, with no default.
Keep this file out of version control, because it holds credentials.

## 4. Dry run locally

`-output-dir` writes exactly what would be uploaded to a local directory,
without touching S3. The catalog bucket is immutable, so look at the output
first.

```
nxrm-3pc-publisher publish \
  -config config.yaml \
  -repository <your-maven-hosted-repository> \
  -group com.fasterxml.jackson.core \
  -name jackson-core \
  -version 2.13.5.1-osera-00001 \
  -output-dir ./out
```

The directory mirrors the S3 key layout:

```
out/
├── packages/maven/com.fasterxml.jackson.core/jackson-core/2.13.5.1-osera-00001/
│   └── jackson-core-2.13.5.1-osera-00001.zip     # jar, pom, and the derived SBOM
└── vex/
    └── CVE-2024-0001-2026-10-02T09:30:00Z.bom.json   # only if vulnerabilities exist
```

Unzip the bundle and check it. It should hold your binaries and a
`<name>-<version>.bom.json` SBOM, and it should not hold your original
`-cyclonedx.json` file.

Add `-log-level trace` to see each asset included or excluded.

## 5. Publish to the catalog

Drop `-output-dir`:

```
nxrm-3pc-publisher publish \
  -config config.yaml \
  -repository <your-maven-hosted-repository> \
  -group com.fasterxml.jackson.core \
  -name jackson-core \
  -version 2.13.5.1-osera-00001
```

Uploads are idempotent: an object that already exists in the bucket is skipped
and logged, never overwritten. Running the same command twice is safe.

## 6. Automate with a webhook

`serve` publishes each new component as it lands in NXRM.

1. Add a `webhook` section to the config with a `secret` and a `listenAddr`.
2. Optionally tune the wait in the `webhook` section (`settleDelay` and
   `maxWait` are Go durations such as `30s` or `15m`), then start the server:

   ```
   nxrm-3pc-publisher serve -config config.yaml -log-format json
   ```

3. In NXRM, open Settings → Capabilities and create a **Webhook: Repository**
   capability with:
   - Repository: your hosted repository
   - Event types: **component**
   - URL: `https://<your-publisher-host>/webhook/nxrm`
   - Secret key: the same value as `webhook.secret`. NXRM treats the secret as
     optional, but `serve` rejects every delivery that is not signed with it.

   NXRM blocks webhook URLs that resolve to private addresses by default. If
   your publisher runs on an internal address, allow it in NXRM's SSRF
   protection settings.

The server only acts on `component` `CREATED` events for repositories listed
in the config. Everything else is acknowledged and ignored. It serves plain
HTTP, so put it behind a TLS-terminating reverse proxy or load balancer.

**How `serve` handles timing.** A single Maven deploy makes NXRM send many
`component` events for the same component while its files are still
arriving, in no reliable order. `serve` folds them together:

1. The first `CREATED` event starts a wait. Further events for the same
   component extend it, so nothing happens mid-upload.
2. When the component has been quiet for `webhook.settleDelay` (default
   `10s`), `serve` reads it from NXRM and publishes if the CycloneDX asset and
   every required asset are present.
3. If something is still missing it checks again, until `webhook.maxWait`
   (default `10m`) has passed since the first event. Then the component is
   logged as an error and dropped. Run `publish` for it once it is complete.
4. A component that fails validation is reported straight away and not
   retried, since waiting will not fix it.

Optional files such as `-sources.jar` are not waited for, so if they arrive
more than `settleDelay` after the required files they will be missing from the
bundle. The bucket never overwrites, so raise `settleDelay` if your upload
tooling is slow between files. To preview what `serve` would publish, start
it with `-output-dir ./out`.

## 7. Backfill existing components

To publish everything already in a repository:

```
nxrm-3pc-publisher backfill -config config.yaml -repository <your-maven-hosted-repository>
```

A component that fails validation is logged as an error and skipped, and the
run continues. Re-running is safe, since existing objects are skipped.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `repositories.<name>.ecosystem is required` | Every watched repository needs an explicit `ecosystem`. |
| Component skipped, required assets missing | The component lacks an asset ending in one of the format's `requiredAssetSuffixes` (for Maven, `.jar` and `.pom`). |
| Component skipped, no CycloneDX asset found | No asset in the component ends with the format's `sbomSuffix`. Check the asset names in NXRM. |
| Component skipped, SBOM validation failed | The CycloneDX document is not version 1.6 or 1.7, or a component lacks `name`, `version`, `type`, `bom-ref`, `licenses` or (Maven) `group`. The log names the field. |
| Warning: no `pedigree.ancestors` | The component declares no upstream ancestor. It is still published. |
| Webhook ignored, signature did not verify | `webhook.secret` differs from the NXRM capability's secret key. |
| Webhook ignored, repository not configured | The repository is missing from `repositories:` in the config. |
| Component logged as an error after `maxWait`, required assets missing | The upload never finished, or took longer than `webhook.maxWait`. Complete it, then run `publish`. |
| Bundle missing `-sources.jar` or `-javadoc.jar` | They arrived after `settleDelay` had passed. Raise `webhook.settleDelay`. The existing bundle cannot be replaced. |
| Everything is `already exists, skipping` | Expected on re-runs. Objects in the bucket are never overwritten. |
