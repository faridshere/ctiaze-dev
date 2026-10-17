import type { Filter } from "mongodb";
import { getDb } from "./db";

// Read-only queries over the claim / attribution collections that sit next to
// `items` in the ctiaze database: hacktivist_posts, cve_actor_citations and
// threat_actors. Every function here only ever calls find/findOne.

// Darkweb rows are never exposed, not even as metadata: only these kinds are
// queried, and rows of any other kind are dropped again after the query.
export const CLAIM_KINDS = ["telegram", "bluesky", "ransomware"] as const;
export type ClaimKind = (typeof CLAIM_KINDS)[number];

export const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

const MAX_CLAIMS = 50;
const MAX_CITATIONS = 100;
const MAX_ACTOR_CVES = 200;
const MAX_FIELD_CHARS = 1000;
const TEXT_FALLBACK_CHARS = 300;

export type HacktivistPostDoc = {
  _id: unknown;
  az?: boolean;
  claim_like?: boolean;
  kind?: string;
  group?: string;
  published?: Date | string | null;
  first_seen?: Date | string | null;
  summary?: { summary_en?: string | null } | null;
  text?: string | null;
  targets?: unknown;
  checks?: unknown;
  url?: string | null;
};

export type CveActorCitationDoc = {
  _id?: unknown;
  cve: string;
  actor_id?: string | null;
  actor_text?: string | null;
  relation?: string | null;
  quote?: string | null;
  url?: string | null;
  host?: string | null;
  kev?: boolean | null;
};

export type ActorCveRow = {
  cve: string;
  kev?: boolean | null;
  epss?: number | null;
  evidence?: string | null;
  url?: string | null;
  source?: string | null;
  date?: Date | string | null;
};

export type ThreatActorDoc = {
  _id: string;
  name?: string;
  aliases?: string[];
  cves?: ActorCveRow[];
};

export type AzClaim = {
  group: string | null;
  kind: ClaimKind;
  claimed_at: string | null; // ISO 8601: published, else first_seen
  summary: string | null;
  targets: unknown;
  checks: unknown;
  url: string | null;
};

export type CveActorCitation = {
  cve: string;
  actor_id: string | null;
  actor_text: string | null;
  statement: string;
  relation: string | null;
  quote: string | null;
  url: string | null;
  host: string | null;
  kev: boolean;
};

export type ActorCves = {
  actor_id: string;
  name: string | null;
  aliases: string[];
  total: number;
  cves: Array<{
    cve: string;
    kev: boolean;
    epss: number | null;
    evidence: string | null;
    url?: string;
    source: string | null;
    date: string | null;
  }>;
};

// --- sanitising -------------------------------------------------------------

const ONION_URL_RE =
  /(?:[a-z][a-z0-9+.-]*:\/\/)?[a-z0-9.-]*\.onion(?::\d+)?(?:[/?#][^\s"'<>)\]]*)?/gi;

export function isOnionUrl(u: string): boolean {
  try {
    return new URL(u).hostname.toLowerCase().endsWith(".onion");
  } catch {
    return /\.onion(?:[:/?#]|$)/i.test(u);
  }
}

// Removes every .onion URL from a string and recursively from arrays / plain
// objects (targets and checks have no fixed shape).
export function stripOnion<T>(value: T): T {
  if (typeof value === "string") {
    return value.replace(ONION_URL_RE, "[onion link removed]") as T;
  }
  if (Array.isArray(value)) return value.map(stripOnion) as T;
  if (value && typeof value === "object" && !(value instanceof Date)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = stripOnion(v);
    return out as T;
  }
  return value;
}

function safeUrl(u: string | null | undefined): string | null {
  if (!u || isOnionUrl(u)) return null;
  return u;
}

function cap(s: string | null | undefined, n = MAX_FIELD_CHARS): string | null {
  if (!s) return null;
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function toIso(d: Date | string | null | undefined): string | null {
  if (!d) return null;
  const t = new Date(d);
  return Number.isNaN(t.getTime()) ? null : t.toISOString();
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// --- get_az_claims ----------------------------------------------------------

// Claim time is `published`, falling back to `first_seen`. Both Date and ISO
// string storage are matched, since Mongo never compares a Date to a string.
export function azClaimsFilter(
  days: number,
  kind: ClaimKind | undefined,
  now = new Date()
): Filter<HacktivistPostDoc> {
  const since = new Date(now.getTime() - days * 86_400_000);
  const gte = (v: Date | string) => ({ $gte: v });
  return {
    az: true,
    claim_like: true,
    kind: kind ? kind : { $in: [...CLAIM_KINDS] },
    $or: [
      { published: gte(since) },
      { published: gte(since.toISOString()) },
      { published: { $in: [null] }, first_seen: gte(since) },
      { published: { $in: [null] }, first_seen: gte(since.toISOString()) },
    ],
  } as Filter<HacktivistPostDoc>;
}

export function toAzClaim(doc: HacktivistPostDoc): AzClaim | null {
  if (!doc.kind || !(CLAIM_KINDS as readonly string[]).includes(doc.kind)) {
    return null;
  }
  const summary =
    doc.summary?.summary_en?.trim() ||
    (doc.text ? doc.text.slice(0, TEXT_FALLBACK_CHARS) : null);
  return {
    group: doc.group ?? null,
    kind: doc.kind as ClaimKind,
    claimed_at: toIso(doc.published) ?? toIso(doc.first_seen),
    summary: stripOnion(cap(summary)),
    targets: stripOnion(doc.targets ?? null),
    checks: stripOnion(doc.checks ?? null),
    url: safeUrl(doc.url),
  };
}

export async function getAzClaims(
  days = 7,
  kind?: ClaimKind
): Promise<AzClaim[]> {
  const db = await getDb();
  const docs = await db
    .collection<HacktivistPostDoc>("hacktivist_posts")
    .find(azClaimsFilter(days, kind), {
      projection: {
        group: 1,
        kind: 1,
        published: 1,
        first_seen: 1,
        "summary.summary_en": 1,
        text: 1,
        targets: 1,
        checks: 1,
        url: 1,
      },
    })
    .sort({ published: -1, first_seen: -1 })
    .limit(MAX_CLAIMS)
    .toArray();
  return docs
    .map(toAzClaim)
    .filter((c): c is AzClaim => c !== null)
    .sort((a, b) => (b.claimed_at ?? "").localeCompare(a.claimed_at ?? ""));
}

// --- get_cve_actors ---------------------------------------------------------

export function toCitation(doc: CveActorCitationDoc): CveActorCitation {
  const who = doc.actor_text || doc.actor_id || "An unnamed actor";
  return {
    cve: doc.cve,
    actor_id: doc.actor_id ?? null,
    actor_text: doc.actor_text ?? null,
    statement: `${who} cited as exploiting ${doc.cve}`,
    relation: doc.relation ?? null,
    quote: stripOnion(cap(doc.quote)),
    url: safeUrl(doc.url),
    host: doc.host && !doc.host.toLowerCase().endsWith(".onion") ? doc.host : null,
    kev: Boolean(doc.kev),
  };
}

export async function getCveActors(cve: string): Promise<CveActorCitation[]> {
  const id = cve.trim().toUpperCase();
  if (!CVE_RE.test(id)) return [];
  const db = await getDb();
  const docs = await db
    .collection<CveActorCitationDoc>("cve_actor_citations")
    .find({ cve: id })
    .limit(MAX_CITATIONS)
    .toArray();
  return docs.map(toCitation);
}

// --- get_actor_cves ---------------------------------------------------------

export function toActorCves(doc: ThreatActorDoc): ActorCves {
  const rows = Array.isArray(doc.cves) ? doc.cves : [];
  const sorted = [...rows].sort((a, b) =>
    (toIso(b.date) ?? "").localeCompare(toIso(a.date) ?? "")
  );
  return {
    actor_id: doc._id,
    name: doc.name ?? null,
    aliases: doc.aliases ?? [],
    total: rows.length,
    cves: sorted.slice(0, MAX_ACTOR_CVES).map((r) => {
      const url = safeUrl(r.url);
      return {
        cve: r.cve,
        kev: Boolean(r.kev),
        epss: typeof r.epss === "number" ? r.epss : null,
        evidence: stripOnion(cap(r.evidence)),
        ...(url ? { url } : {}),
        source: r.source ?? null,
        date: toIso(r.date),
      };
    }),
  };
}

// Resolves an actor by exact id first, then by case-insensitive exact match on
// name or any alias.
export async function getActorCves(actor: string): Promise<ActorCves | null> {
  const q = actor.trim();
  if (!q) return null;
  const db = await getDb();
  const col = db.collection<ThreatActorDoc>("threat_actors");
  const projection = { name: 1, aliases: 1, cves: 1 };
  let doc = await col.findOne({ _id: q }, { projection });
  if (!doc) {
    const rx = new RegExp(`^${escapeRegex(q)}$`, "i");
    doc = await col.findOne({ $or: [{ name: rx }, { aliases: rx }] }, { projection });
  }
  return doc ? toActorCves(doc) : null;
}
