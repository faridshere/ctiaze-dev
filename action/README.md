# skopnix/stack-check

A GitHub Action that checks an SBOM against [skopnix.com](https://skopnix.com)
threat intelligence: CVEs per component, CISA KEV, EPSS, and the threat actors
skopnix cites for each CVE. It writes a markdown table to the job summary and
fails the step on the rules you pick.

It runs the [skopnix CLI](../cli/README.md) (`dist/` is the compiled CLI, so
there is no install step and nothing is downloaded from npm) on the runner's
Node 24. The only network call is to the skopnix API.

> **Status:** the action calls `POST https://skopnix.com/api/v1/stack`, which
> may not be live yet. Until it is, the step fails with "the stack endpoint may
> not be deployed yet". Until publication as `skopnix/stack-check`, use it from
> this repository as `faridshere/ctiaze-dev/action@<commit-sha>`.

## Example: generate an SBOM with Syft and check it

```yaml
name: stack check
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "17 6 * * *" # daily: new KEV entries and actor citations appear without a code change

permissions:
  contents: read

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          path: .
          format: cyclonedx-json # spdx-json works too
          output-file: sbom.cdx.json
          upload-artifact: false

      - name: Check against skopnix
        id: skopnix
        uses: skopnix/stack-check@v1 # or faridshere/ctiaze-dev/action@<sha> for now
        with:
          sbom: sbom.cdx.json
          fail-on: kev,epss>=0.5

      - name: Keep the full report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: skopnix-report
          path: ${{ steps.skopnix.outputs.report }}
```

To scan a container image instead, use `image: ghcr.io/org/app:tag` in place
of `path: .`.

## Inputs

| Input | Default | |
|---|---|---|
| `sbom` | *(required)* | Path to a CycloneDX JSON, SPDX 2.x JSON, or a plain `vendor product version` list. |
| `fail-on` | `""` | Comma-separated rules. The step fails if any CVE matches any rule: `kev`, `actor` (skopnix cites a threat actor), `any`, `epss>=0.5`, `epss>0.9`. Empty means report only. |
| `api-base` | `https://skopnix.com/api/v1` | Override the API root (staging, a mirror, or the mock server). |
| `summary` | `"true"` | Set `"false"` to skip the job summary. |

## Outputs

| Output | |
|---|---|
| `components` | Components sent for checking. |
| `findings` | (component, CVE) findings. |
| `kev` | Findings in CISA KEV. |
| `with-actors` | Findings with at least one cited threat actor. |
| `failed` | `"true"` if a rule matched or the check errored. |
| `report` | Path to the JSON report (same as `skopnix check --json`). |

## Behaviour

- **Fails the step** (exit 1) when a `fail-on` rule matches, with an `::error::`
  annotation listing the first matches.
- **Errors** (unreadable SBOM, bad rule, API down after retries) also fail
  the step (exit 2), and the job summary shows the message.
- Rate limits (`429`) and `5xx` responses are retried with backoff, and
  `Retry-After` is honoured. See the [CLI README](../cli/README.md#reliability).
- Components go to the API in chunks of 500.

To report without ever failing the build, leave `fail-on` empty and set
`continue-on-error: true` on the step, so API outages are ignored too.

## Developing

The action's code lives in `../cli/src/action.ts`. `cd ../cli && npm run build`
recompiles and refreshes `dist/` here. Commit `dist/` with your change; CI
checks that it is current and runs this action against a local mock of
`/stack` (`.github/workflows/cli.yml`).

To publish as `skopnix/stack-check`, copy this directory to the root of that
repository and tag `v1`.
