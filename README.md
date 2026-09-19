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
