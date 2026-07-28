import { createMcpHandler } from "mcp-handler";
import { z } from "zod";
import {
  getRecent,
  getRecentKev,
  searchThreats,
  lookupCve,
} from "@/lib/data";
import type { FeedItem } from "@/lib/types";

// A read-only MCP server over ctiaze's Azerbaijani CTI archive. AI agents / SOC
// copilots connect at https://ctiaze.dev/api/mcp (Streamable HTTP) and query the
// same published-story data that powers ctiaze.tech. No writes, no auth needed —
// it exposes only already-public threat intelligence.
function asText(items: FeedItem[], emptyMsg: string) {
  if (items.length === 0) {
    return { content: [{ type: "text" as const, text: emptyMsg }] };
  }
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify({ count: items.length, items }, null, 2),
      },
    ],
  };
}

const handler = createMcpHandler(
  (server) => {
    server.tool(
      "get_recent_threats",
      "ctiaze-in Azərbaycan dilli CTI arxivindən ən son dərc olunmuş kibertəhlükəsizlik xəbərlərini qaytarır. Returns the most recently published Azerbaijani cyber threat intelligence items.",
      { limit: z.number().int().min(1).max(50).optional() },
      async ({ limit }) => asText(await getRecent(limit), "No recent threats found."),
    );

    server.tool(
      "get_recent_kev",
      "CISA-nın Known Exploited Vulnerabilities (KEV) siyahısına aid, ctiaze-də əhatə olunan ən son aktiv istismar edilən zəiflikləri qaytarır. Returns recent actively-exploited (CISA KEV) vulnerabilities covered by ctiaze.",
      { limit: z.number().int().min(1).max(50).optional() },
      async ({ limit }) => asText(await getRecentKev(limit), "No recent KEV items found."),
    );

    server.tool(
      "search_threats",
      "ctiaze arxivində açar sözlə axtarış (başlıq, kateqoriya, CVE). Keyword-search ctiaze's CTI archive across Azerbaijani/English titles, category, and CVE ids.",
      {
        query: z.string().min(2).describe("Search keyword, e.g. 'ransomware', 'phishing', 'Fortinet'"),
        limit: z.number().int().min(1).max(50).optional(),
      },
      async ({ query, limit }) =>
        asText(await searchThreats(query, limit), `No results for "${query}".`),
    );

    server.tool(
      "lookup_cve",
      "Verilmiş CVE-nin ctiaze-in Azərbaycan dilli əhatəsində görünüb-görünmədiyini yoxlayır və aid xəbərləri qaytarır. Checks whether a given CVE appears in ctiaze's coverage and returns the matching items.",
      { cve_id: z.string().describe("A CVE identifier, e.g. CVE-2024-3400") },
      async ({ cve_id }) =>
        asText(
          await lookupCve(cve_id),
          `${cve_id} not found in ctiaze's archive (or invalid CVE id format).`,
        ),
    );
  },
  {},
  { basePath: "/api", maxDuration: 30, verboseLogs: false },
);

export { handler as GET, handler as POST };
