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
  database: `get_recent_threats`, `get_recent_kev`, `search_threats`, `lookup_cve`,
  plus three claim / attribution tools (below) registered from `lib/intel-tools.ts`.
- `app/page.tsx` — a one-page landing describing the tools and feeds.
- `lib/db.ts` — Mongo client (deferred to first call so the site builds without
  the env var); `lib/data.ts` — the queries; `lib/types.ts` — the `FeedItem`
  contract, a copy of what `ctiaze-web/lib/types.ts` looked like in July 2026.

## Claim and attribution tools

Read-only, input-validated, and capped (row limits per tool, long text fields
cut at 1000 chars, whole result ≤ 60k chars with `truncated: true` when trimmed).
Queries live in `lib/intel.ts`.

| Tool | Input | Reads | Returns |
| --- | --- | --- | --- |
| `get_az_claims` | `days` 1–90 (default 7), `kind?` `telegram` \| `bluesky` \| `ransomware` | `hacktivist_posts` where `az` and `claim_like` | ≤50 claims: `group`, `kind`, `claimed_at` (`published` else `first_seen`), `summary` (`summary.summary_en`, else first 300 chars of `text`), `targets`, `checks`, `url` |
| `get_cve_actors` | `cve` (e.g. `CVE-2024-3400`, case-insensitive) | `cve_actor_citations` | ≤100 citations: `actor_id`, `actor_text`, `statement` ("… cited as exploiting CVE-…"), `relation`, `quote`, `url`, `host`, `kev` |
| `get_actor_cves` | `actor` (id, name or alias; 2–100 chars) | `threat_actors` | the actor's `cves` rows (≤200, newest first): `cve`, `kev`, `epss`, `evidence`, `url` (when present), `source`, `date` |

`darkweb` rows are never returned by `get_az_claims` (not queried, and dropped
again if one slips through), and `.onion` URLs are stripped from every field of
all three tools.

Examples (MCP `tools/call` arguments → abridged result):

```jsonc
// get_az_claims
{ "days": 3, "kind": "telegram" }
→ { "days": 3, "kind": "telegram", "count": 1, "claims": [
    { "group": "CyberArmy", "kind": "telegram", "claimed_at": "2026-10-16T08:00:00.000Z",
      "summary": "Claims DDoS on gov.az", "targets": ["gov.az"],
      "checks": { "http_down": false }, "url": "https://t.me/cyberarmy/123" } ] }

// get_cve_actors
{ "cve": "CVE-2024-3400" }
→ { "cve": "CVE-2024-3400", "count": 1, "citations": [
    { "actor_id": "uta0218", "actor_text": "UTA0218",
      "statement": "UTA0218 cited as exploiting CVE-2024-3400", "relation": "exploited",
      "quote": "UTA0218 exploited CVE-2024-3400 to gain access.",
      "url": "https://www.volexity.com/blog/…", "host": "www.volexity.com", "kev": true } ] }

// get_actor_cves
{ "actor": "Fancy Bear" }
→ { "actor_id": "apt28", "name": "APT28", "aliases": ["Fancy Bear", "Sofacy"], "total": 1,
    "count": 1, "cves": [
    { "cve": "CVE-2023-23397", "kev": true, "epss": 0.93, "evidence": "Used against EU targets",
      "url": "https://example.com/apt28", "source": "vendor", "date": "2023-03-15T00:00:00.000Z" } ] }
```

## Run locally

```bash
nvm use            # Node 22 (.nvmrc)
npm ci
cp .env.example .env.local   # then paste a read-only Atlas URI
npm run dev        # http://localhost:3000, MCP at /api/mcp
node scripts/test-mcp.mjs    # handshake + one tool call against a running server
```

Checks (no database needed — the tests mock `lib/db.ts` with fixtures):

```bash
npm test           # vitest: test/**/*.test.ts
npm run lint
npm run typecheck
npm run build
```

## Deploy

Vercel, git-integrated on `main`. The custom domain is `ctiaze.dev` (apex 308s
to `www`). Set `MONGO_URI_READONLY` in the project settings and redeploy.
