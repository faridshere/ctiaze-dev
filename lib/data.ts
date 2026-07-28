import type { Filter } from "mongodb";
import { getDb } from "./db";
import { toFeedItem, type FeedItem, type StoryDoc } from "./types";

// Same gate ctiaze.tech uses: only fully-published, non-retracted, safe, real
// stories are ever exposed. The MCP server is a second read surface over the
// exact same trusted output.
const PUBLISHED_FILTER: Filter<StoryDoc> = {
  published: true,
  retracted: { $ne: true },
  blocked_unsafe: { $ne: true },
  az_stub: { $ne: true },
};

async function items() {
  const db = await getDb();
  return db.collection<StoryDoc>("items");
}

function clampLimit(n: number | undefined, def: number, max: number): number {
  if (!n || n < 1) return def;
  return Math.min(Math.floor(n), max);
}

export async function getRecent(limit?: number): Promise<FeedItem[]> {
  const col = await items();
  const docs = await col
    .find(PUBLISHED_FILTER)
    .sort({ published_at: -1 })
    .limit(clampLimit(limit, 15, 50))
    .toArray();
  return docs.map(toFeedItem);
}

export async function getRecentKev(limit?: number): Promise<FeedItem[]> {
  const col = await items();
  const docs = await col
    .find({ ...PUBLISHED_FILTER, kev: true })
    .sort({ published_at: -1 })
    .limit(clampLimit(limit, 15, 50))
    .toArray();
  return docs.map(toFeedItem);
}

// Keyword search across the Azerbaijani title, English title, category and CVE
// ids. Case-insensitive regex — the archive is small enough (low thousands)
// that this stays cheap and needs no text index.
export async function searchThreats(
  query: string,
  limit?: number
): Promise<FeedItem[]> {
  const q = query.trim();
  if (!q) return [];
  const rx = new RegExp(escapeRegex(q), "i");
  const col = await items();
  const filter: Filter<StoryDoc> = {
    ...PUBLISHED_FILTER,
    $or: [
      { az_title: rx },
      { title: rx },
      { ai_category: rx },
      { cve_ids: rx },
    ],
  };
  const docs = await col
    .find(filter)
    .sort({ published_at: -1 })
    .limit(clampLimit(limit, 15, 50))
    .toArray();
  return docs.map(toFeedItem);
}

// Has this CVE appeared in ctiaze's AZ-relevant coverage? Returns every story
// that references it (normalised to upper-case, CVE-id match).
export async function lookupCve(cveId: string): Promise<FeedItem[]> {
  const id = cveId.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return [];
  const col = await items();
  const docs = await col
    .find({ ...PUBLISHED_FILTER, cve_ids: id })
    .sort({ published_at: -1 })
    .limit(25)
    .toArray();
  return docs.map(toFeedItem);
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
