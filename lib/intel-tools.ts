import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  CLAIM_KINDS,
  CVE_RE,
  getActorCves,
  getAzClaims,
  getCveActors,
} from "./intel";

// Hard ceiling on one tool result. Lists are trimmed from the end (oldest /
// lowest-ranked first) until the JSON fits, and `truncated` says so.
export const MAX_RESULT_CHARS = 60_000;

type TextResult = { content: { type: "text"; text: string }[] };

function text(t: string): TextResult {
  return { content: [{ type: "text" as const, text: t }] };
}

export function cappedJson<T>(
  meta: Record<string, unknown>,
  key: string,
  rows: T[],
  emptyMsg: string,
  maxChars = MAX_RESULT_CHARS
): TextResult {
  if (rows.length === 0) return text(emptyMsg);
  let n = rows.length;
  let body = "";
  for (;;) {
    const truncated = n < rows.length;
    body = JSON.stringify(
      { ...meta, count: n, ...(truncated && { truncated: true }), [key]: rows.slice(0, n) },
      null,
      2
    );
    if (body.length <= maxChars || n <= 1) break;
    n = Math.max(1, Math.floor(n * 0.8));
  }
  return text(body.length <= maxChars ? body : body.slice(0, maxChars));
}

// The three claim / attribution tools. Registered from the route next to the
// story tools; kept here so they can be exercised without Next.
export function registerIntelTools(server: McpServer) {
  server.tool(
    "get_az_claims",
    "Azərbaycanı hədəf aldığını iddia edən hacktivist / ransomware postları (Telegram, Bluesky, ransomware leak saytları; darkweb heç vaxt). Returns Azerbaijan-targeted hacktivist and ransomware claims from the last N days: group, kind, claim time, English summary, claimed targets, our verification checks and the source URL. These are claims, not confirmed incidents. .onion links are removed.",
    {
      days: z.number().int().min(1).max(90).optional().describe("Look-back window in days (default 7, max 90)"),
      kind: z.enum(CLAIM_KINDS).optional().describe("Restrict to one source kind"),
    },
    async ({ days, kind }) =>
      cappedJson(
        { days: days ?? 7, ...(kind && { kind }) },
        "claims",
        await getAzClaims(days ?? 7, kind),
        `No Azerbaijan-targeted claims in the last ${days ?? 7} days.`
      ),
  );

  server.tool(
    "get_cve_actors",
    "Verilmiş CVE-ni istismar etdiyi bildirilən təhdid aktorları (mənbə sitatı ilə). Returns every threat actor cited as exploiting a given CVE, each with the verbatim quote and the URL of the source that cites it.",
    {
      cve: z
        .string()
        .trim()
        .toUpperCase()
        .regex(CVE_RE, "Expected a CVE id like CVE-2024-3400")
        .describe("A CVE identifier, e.g. CVE-2024-3400"),
    },
    async ({ cve }) =>
      cappedJson(
        { cve },
        "citations",
        await getCveActors(cve),
        `No actor is cited as exploiting ${cve} in ctiaze's archive.`
      ),
  );

  server.tool(
    "get_actor_cves",
    "Təhdid aktorunun (id, ad və ya alias) istismar etdiyi CVE-lər. Resolves a threat actor by id, name or alias and returns the CVEs it is cited as exploiting, with KEV status, EPSS, evidence, source and date.",
    {
      actor: z
        .string()
        .trim()
        .min(2)
        .max(100)
        .describe("Actor id, name or alias, e.g. 'APT28' or 'Fancy Bear'"),
    },
    async ({ actor }) => {
      const res = await getActorCves(actor);
      if (!res) return text(`No threat actor matching "${actor}".`);
      const { cves, ...meta } = res;
      return cappedJson(meta, "cves", cves, `${res.name ?? res.actor_id} has no cited CVEs.`);
    },
  );
}
