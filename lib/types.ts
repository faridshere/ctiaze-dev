// Mirrors a published document in ctiaze-engine's MongoDB "items" collection.
// Read-only here. Kept in sync with ctiaze-web/lib/types.ts.
export type StoryDoc = {
  _id: string;
  title: string;
  url: string;
  source: string;
  cve_ids?: string[];
  severity?: "critical" | "high" | "medium" | "low" | null;
  kev?: boolean;
  ai_category?: string;
  ai_score?: number;
  ai_region?: boolean;
  az_title?: string;
  az_body?: string;
  published_at?: Date | string;
};

// Public, machine-readable shape returned by the MCP tools. snake_case: this is
// an external data contract for AI agents, matching ctiaze.tech's feed.json.
export type FeedItem = {
  id: string;
  slug: string;
  title_az: string;
  title_en: string;
  url: string; // permalink on ctiaze.tech
  source_url: string;
  category: string;
  severity: string | null;
  kev: boolean;
  cve_ids: string[];
  region_relevant: boolean;
  published_at: string; // ISO 8601
};

const SITE = "https://ctiaze.tech";

function slugify(id: string, titleAz: string): string {
  const base = titleAz
    .toLowerCase()
    .replace(/[^a-z0-9əıöüğşç\s-]/gi, "")
    .trim()
    .replace(/\s+/g, "-")
    .slice(0, 60);
  const shortId = id.replace(/^(cve:|url:)/, "").slice(0, 12);
  return `${shortId}-${base}`.replace(/-+$/, "");
}

export function toFeedItem(doc: StoryDoc): FeedItem {
  const slug = slugify(doc._id, doc.az_title || doc.title || "xəbər");
  const publishedAt = doc.published_at
    ? new Date(doc.published_at).toISOString()
    : new Date().toISOString();
  return {
    id: doc._id,
    slug,
    title_az: doc.az_title || doc.title,
    title_en: doc.title,
    url: `${SITE}/xeber/${slug}`,
    source_url: doc.url,
    category: doc.ai_category || "other",
    severity: doc.severity ?? null,
    kev: Boolean(doc.kev),
    cve_ids: doc.cve_ids ?? [],
    region_relevant: Boolean(doc.ai_region),
    published_at: publishedAt,
  };
}
