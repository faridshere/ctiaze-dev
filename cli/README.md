# skopnix CLI

Check a software bill of materials against [skopnix.com](https://skopnix.com)
threat intelligence: which components have known CVEs, which of those are in
CISA KEV, their EPSS scores, and which threat actors skopnix cites for them
(with the quote and source that ties them together). Also reads recent
hacktivist/leak-site claims and actor dossiers.

Uses the public, no-key JSON API at `https://skopnix.com/api/v1/`. Node.js 20
or newer, no runtime dependencies.

> **Status:** `skopnix check` calls `POST /api/v1/stack`, which may not be live
> yet. Until it is, `check` exits 2 with "the stack endpoint may not be deployed
> yet". `skopnix claims` and `skopnix actor` work today.

## Install

```bash
npm install -g skopnix        # once published
npx skopnix check sbom.json   # or without installing
```

From this repo:

```bash
cd cli && npm ci && npm run build
node dist/bin.js --help       # or: npm link, then `skopnix --help`
```

## `skopnix check <sbom|->`

```bash
skopnix check sbom.cdx.json
skopnix check sbom.spdx.json --fail-on kev,epss>=0.5
syft . -o cyclonedx-json | skopnix check - --json > report.json
```

```
COMPONENT          CVE             KEV  EPSS   CITED ACTORS
-----------------  --------------  ---  -----  --------------------
log4j-core@2.14.1  CVE-2021-44228  yes  0.976  APT41, Lazarus Group
log4j-core@2.14.1  CVE-2021-45046       0.900
openssl@3.0.1      CVE-2022-3602        -      Unnamed cluster

5 components checked, 2 with known CVEs: 3 CVE findings, 1 in KEV, 2 with cited threat actors.
fail-on kev,epss>=0.5: FAILED (1 × kev, 1 × epss>=0.5).
```

(Example output from the test fixtures and a mock server, not live data.)

**Inputs** (detected automatically):

| Format | What is read |
|---|---|
| CycloneDX JSON (any 1.x) | `components[]`, recursively; `name`, `version`, `purl`, `cpe`. `metadata.component` and `type: file` entries are skipped. |
| SPDX 2.x JSON | `packages[]`: `name`, `versionInfo`, `externalRefs` of type `purl` and `cpe23Type`/`cpe22Type`. The package the document DESCRIBES is skipped when it has no purl/cpe (it is the scanned directory or image). |
| `{"components":[...]}` or a JSON array | entries with `name`, `version`, optional `purl`, `cpe` — the API's own body shape. |
| Plain text | one per line: `vendor product version` (turned into a CPE 2.3), `product version`, a `pkg:` purl, or a `cpe:` string. `#` starts a comment. |

Entries without a version, purl or CPE are skipped, and duplicates are
collapsed; the count is printed. `-` reads from stdin.

Components go to the API in chunks of 500.

**Options**

| | |
|---|---|
| `--fail-on <rules>` | Exit 1 if any CVE matches any rule. Comma-separated or repeated: `kev`, `actor` (at least one cited actor), `any`, `epss>=0.5` / `epss>0.9`. |
| `--json` | Print the full report as JSON (see below). |
| `--markdown` | Print the markdown report the GitHub Action posts. |
| `--summary <file>` | Also append the markdown report to a file (e.g. `$GITHUB_STEP_SUMMARY`). |
| `--api-base <url>` | API root; default `https://skopnix.com/api/v1`, or `$SKOPNIX_API_BASE`. |

**Exit codes:** `0` ok · `1` a `--fail-on` rule matched · `2` error (bad
arguments, unreadable SBOM, API error after retries).

**JSON report** (`--json`):

```jsonc
{
  "source": "sbom.cdx.json", "format": "cyclonedx", "apiBase": "https://skopnix.com/api/v1",
  "generatedAt": "2026-10-17T12:00:00.000Z",
  "stats": { "components": 5, "skipped": 3, "vulnerableComponents": 3, "findings": 4, "kev": 1, "withActors": 2 },
  "failOn": ["kev"], "failed": true,
  "hits": [{ "rule": "kev", "component": "log4j-core@2.14.1", "cve": "CVE-2021-44228" }],
  "results": [   // only components with at least one CVE
    { "name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/...",
      "cves": [{ "cve": "CVE-2021-44228", "kev": true, "epss": 0.97565,
                 "actors": [{ "actor": "APT41", "quote": "…", "url": "https://skopnix.com/actors/apt41" }] }] }
  ]
}
```

## `skopnix claims [--days 7]`

Recent third-party claims (hacktivist channels, trackers, leak sites) from
`/api/v1/claims`. These are claims, not verified incidents. `--limit 50` caps
the table, `--json` prints everything. The CLI filters by `--days` itself, so
the window holds even if the server ignores the parameter.

## `skopnix actor <name>`

An actor dossier from `/api/v1/actors/{id}`: aliases, origin, MITRE id, CVEs
with KEV/EPSS and evidence, recent reports. `<name>` can be an id (`apt28`), a
name, or an alias (`"Fancy Bear"`). If the name is not an id, the CLI searches
the roster. `--json` prints the raw dossier.

## Reliability

- `429` and `5xx` responses, timeouts and network errors are retried up to 4
  times. The CLI waits for the server's `Retry-After` (seconds or HTTP date,
  capped at 2 min) when one is sent, and otherwise backs off exponentially
  with jitter (≈1s, 2s, 4s, 8s). Retries are logged to stderr, so `--json`
  output stays clean.
- Other `4xx` errors fail at once, with the API's `error` message.
- The `/stack` response is parsed defensively. The documented shape is
  `{components:[{name, version, purl?, cpe?, cves:[{cve, kev, epss, actors:[{actor, quote, url}]}]}]}`,
  and `results`, `id`, `vulnerabilities`, `cited_actors` and `epss: {score}`
  are accepted as aliases.

## Try `check` before `/stack` is live

```bash
node scripts/mock-stack-server.mjs 4555 &
node dist/bin.js check test/fixtures/cyclonedx.json --api-base http://127.0.0.1:4555/api/v1
```

The mock answers from `test/fixtures/stack-response.json`, which is made-up
test data.

## Development

```bash
npm ci
npm run typecheck
npm test            # node:test, HTTP mocked, no network
npm run build       # dist/ + refreshes ../action/dist (commit it)
npm run check:action
```

`npm run build` also copies the compiled code into `../action/dist`, which the
GitHub Action runs without an install step. Commit it with your change; CI
fails if it is stale. To release, bump `version` in `package.json` and
`src/version.ts` (a test checks they match), then `npm publish`.
