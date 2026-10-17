# ctiaze-dev — developer portal + read-only MCP server

Status (19 Sep 2026): **deployed at https://www.ctiaze.dev but not functional** —
the Vercel project has no `MONGO_URI_READONLY`, so every MCP tool call returns an
error. The code also predates the skopnix rebrand (Azerbaijani copy, ctiaze.tech
links, sorting on `published_at` instead of `effective_at`). The plan of record
(`ctiaze-web/docs/SKOPNIX-PLAN-2026-09-16.md`, story 4) is to serve the MCP
server from the main site instead, so treat this repo as a candidate for
retirement rather than a place to build.

## What it is

- `app/api/[transport]/route.ts` — Streamable-HTTP MCP server (`mcp-handler`)
  with four read-only tools over the `items` collection of the `ctiaze` Atlas
  database: `get_recent_threats`, `get_recent_kev`, `search_threats`, `lookup_cve`.
- `app/page.tsx` — a one-page landing describing the tools and feeds.
- `lib/db.ts` — Mongo client (deferred to first call so the site builds without
  the env var); `lib/data.ts` — the queries; `lib/types.ts` — the `FeedItem`
  contract, a copy of what `ctiaze-web/lib/types.ts` looked like in July 2026.

## Distribution tools

These are standalone packages with their own tooling. The Next.js app ignores
them, and they do not depend on it or on Mongo.

- [`cli/`](cli/README.md): the `skopnix` command-line tool (npm package
  `skopnix`, Node 20+, no runtime deps). `skopnix check <sbom>` checks a
  CycloneDX/SPDX/plain-list SBOM via `POST /api/v1/stack` and gates CI with
  `--fail-on kev|actor|epss>=0.5`. `skopnix claims` and `skopnix actor` read
  the live API.
- [`action/`](action/README.md): the `skopnix/stack-check` GitHub Action,
  which runs the CLI on an SBOM, writes a job-summary table and fails per
  `fail-on`. Its README has an example with `anchore/sbom-action`.

`POST /api/v1/stack` is being built on the main site and may not be live yet.
Until then, `check` and the action stop with a clear error.

## Run locally

```bash
nvm use            # Node 22 (.nvmrc)
npm ci
cp .env.example .env.local   # then paste a read-only Atlas URI
npm run dev        # http://localhost:3000, MCP at /api/mcp
node scripts/test-mcp.mjs    # handshake + one tool call against a running server
```

## Deploy

Vercel, git-integrated on `main`. The custom domain is `ctiaze.dev` (apex 308s
to `www`). Set `MONGO_URI_READONLY` in the project settings and redeploy.
