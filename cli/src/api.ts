import type { ActorCitation, Component, ComponentResult, CveFinding } from "./types.js";
import { VERSION } from "./version.js";

export const DEFAULT_API_BASE = "https://skopnix.com/api/v1";
export const STACK_CHUNK_SIZE = 500;

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export type RetryInfo = { attempt: number; delayMs: number; reason: string; url: string };

export type ClientOptions = {
  apiBase?: string;
  fetch?: FetchLike;
  maxRetries?: number; // retries after the first attempt
  baseDelayMs?: number;
  maxDelayMs?: number; // cap for computed backoff
  maxRetryAfterMs?: number; // cap for a server-sent Retry-After
  timeoutMs?: number;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
  now?: () => number;
  onRetry?: (info: RetryInfo) => void;
};

export class ApiError extends Error {
  override name = "ApiError";
  constructor(
    message: string,
    readonly status?: number,
    readonly url?: string,
  ) {
    super(message);
  }
}

export type Client = ReturnType<typeof createClient>;

export function createClient(opts: ClientOptions = {}) {
  const apiBase = (opts.apiBase || DEFAULT_API_BASE).replace(/\/+$/, "");
  const doFetch: FetchLike = opts.fetch ?? ((url, init) => fetch(url, init));
  const maxRetries = opts.maxRetries ?? 4;
  const baseDelayMs = opts.baseDelayMs ?? 1000;
  const maxDelayMs = opts.maxDelayMs ?? 30_000;
  const maxRetryAfterMs = opts.maxRetryAfterMs ?? 120_000;
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const random = opts.random ?? Math.random;
  const now = opts.now ?? Date.now;

  // Exponential backoff with jitter: half fixed, half random.
  const backoff = (attempt: number) => {
    const full = Math.min(maxDelayMs, baseDelayMs * 2 ** attempt);
    return Math.round(full / 2 + (random() * full) / 2);
  };

  const retryAfter = (res: Response): number | undefined => {
    const h = res.headers.get("retry-after");
    if (!h) return undefined;
    const secs = Number(h);
    const ms = Number.isFinite(secs) ? secs * 1000 : Date.parse(h) - now();
    if (!Number.isFinite(ms)) return undefined;
    return Math.min(maxRetryAfterMs, Math.max(0, ms));
  };

  async function request<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
    const url = `${apiBase}${path}`;
    for (let attempt = 0; ; attempt++) {
      let res: Response;
      try {
        res = await doFetch(url, {
          method,
          headers: {
            accept: "application/json",
            "user-agent": `skopnix-cli/${VERSION}`,
            ...(body !== undefined ? { "content-type": "application/json" } : {}),
          },
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch (e) {
        const reason = (e as Error).message || String(e);
        if (attempt < maxRetries) {
          const delayMs = backoff(attempt);
          opts.onRetry?.({ attempt: attempt + 1, delayMs, reason: `network error: ${reason}`, url });
          await sleep(delayMs);
          continue;
        }
        throw new ApiError(`${method} ${url} failed: ${reason}`, undefined, url);
      }

      if (res.ok) {
        const text = await res.text();
        try {
          return JSON.parse(text) as T;
        } catch {
          throw new ApiError(`${method} ${url} returned non-JSON (${text.slice(0, 80)}…)`, res.status, url);
        }
      }

      const retryable = res.status === 429 || res.status === 408 || res.status >= 500;
      if (retryable && attempt < maxRetries) {
        const delayMs = retryAfter(res) ?? backoff(attempt);
        await res.body?.cancel().catch(() => {});
        opts.onRetry?.({
          attempt: attempt + 1,
          delayMs,
          reason: res.status === 429 ? "rate limited (429)" : `HTTP ${res.status}`,
          url,
        });
        await sleep(delayMs);
        continue;
      }

      throw new ApiError(
        `${method} ${url} → HTTP ${res.status}${await errorDetail(res)}` +
          (retryable ? ` (gave up after ${maxRetries + 1} attempts)` : ""),
        res.status,
        url,
      );
    }
  }

  return {
    apiBase,
    request,

    /** POST /stack in chunks of STACK_CHUNK_SIZE, results in input order. */
    async stack(
      components: Component[],
      onChunk?: (done: number, total: number) => void,
    ): Promise<ComponentResult[]> {
      const out: ComponentResult[] = [];
      for (let i = 0; i < components.length; i += STACK_CHUNK_SIZE) {
        const chunk = components.slice(i, i + STACK_CHUNK_SIZE);
        let json: unknown;
        try {
          json = await request("POST", "/stack", { components: chunk });
        } catch (e) {
          if (e instanceof ApiError && (e.status === 404 || e.status === 405)) {
            throw new ApiError(
              `${e.message}\nPOST ${apiBase}/stack is not available — the stack endpoint may not be deployed yet. ` +
                `Use --api-base to point at a server that has it.`,
              e.status,
              e.url,
            );
          }
          throw e;
        }
        out.push(...normalizeStackResponse(json, chunk));
        onChunk?.(Math.min(i + STACK_CHUNK_SIZE, components.length), components.length);
      }
      return out;
    },

    /** GET /claims. The server may ignore `days`, so filter here as well. */
    async claims(days: number): Promise<{ claims: Claim[]; raw: Obj }> {
      const raw = await request<Obj>("GET", `/claims?days=${encodeURIComponent(days)}`);
      const since = now() - days * 86_400_000;
      const list = Array.isArray(raw.claims) ? (raw.claims as Claim[]) : [];
      const claims = list.filter((c) => {
        const t = Date.parse(String(c.at ?? c.seenAt ?? ""));
        return Number.isFinite(t) && t >= since;
      });
      return { claims, raw };
    },

    /**
     * GET /actors/{id}; if `name` is not an id, search the roster (by name
     * and alias) and fetch the single best match.
     */
    async actor(name: string): Promise<Obj> {
      const id = slugify(name);
      if (id) {
        try {
          return await request<Obj>("GET", `/actors/${encodeURIComponent(id)}`);
        } catch (e) {
          if (!(e instanceof ApiError && e.status === 404)) throw e;
        }
      }
      const roster = await request<Obj>("GET", `/actors?q=${encodeURIComponent(name)}`);
      const actors = (Array.isArray(roster.actors) ? roster.actors : []) as Obj[];
      const needle = name.trim().toLowerCase();
      const exact = actors.filter(
        (a) =>
          String(a.name ?? "").toLowerCase() === needle ||
          String(a.id ?? "").toLowerCase() === needle ||
          (Array.isArray(a.aliases) && a.aliases.some((x) => String(x).toLowerCase() === needle)),
      );
      const pick = exact.length === 1 ? exact[0] : actors.length === 1 ? actors[0] : undefined;
      if (pick && typeof pick.id === "string") {
        return request<Obj>("GET", `/actors/${encodeURIComponent(pick.id)}`);
      }
      const names = actors.slice(0, 10).map((a) => `${a.name} (${a.id})`);
      throw new ApiError(
        actors.length === 0
          ? `No actor matches "${name}".`
          : `"${name}" matches ${actors.length} actors; be more specific:\n  ${names.join("\n  ")}`,
        404,
      );
    },
  };
}

type Obj = Record<string, unknown>;

export type Claim = {
  id?: string;
  kind?: string;
  group?: string;
  url?: string;
  at?: string;
  seenAt?: string;
  summaryEn?: string;
  text?: string;
  claimType?: string;
  targets?: string[];
  [k: string]: unknown;
};

export function slugify(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

async function errorDetail(res: Response): Promise<string> {
  try {
    const text = await res.text();
    try {
      const j = JSON.parse(text) as Obj;
      const msg = j.error ?? j.message;
      if (typeof msg === "string") return `: ${msg}`;
      if (isObj(msg) && typeof msg.message === "string") return `: ${msg.message}`;
    } catch {
      // HTML error pages are not worth echoing.
    }
  } catch {
    // body unreadable
  }
  return "";
}

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

const num = (v: unknown): number | null => {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() && Number.isFinite(Number(v))) return Number(v);
  if (isObj(v)) return num(v.score ?? v.epss);
  return null;
};

/**
 * Map a /stack response onto the components that were sent. The documented
 * shape is `{components:[{name,version,purl?,cpe?,cves:[{cve,kev,epss,
 * actors:[{actor,quote,url}]}]}]}`; a few obvious aliases (`results`, `id`,
 * `vulnerabilities`) are accepted so a small server-side rename does not
 * break every pipeline using this tool.
 */
export function normalizeStackResponse(json: unknown, sent: Component[]): ComponentResult[] {
  const list: unknown[] | null = Array.isArray(json)
    ? json
    : !isObj(json)
      ? null
      : Array.isArray(json.components)
        ? json.components
        : Array.isArray(json.results)
          ? json.results
          : null;
  if (!list) throw new ApiError("POST /stack response has no `components` array");
  return list.map((entry, i) => {
    const e = isObj(entry) ? entry : {};
    const base = sent[i];
    const result: ComponentResult = {
      name: typeof e.name === "string" ? e.name : (base?.name ?? "?"),
      version: typeof e.version === "string" ? e.version : (base?.version ?? ""),
      cves: [],
    };
    const purl = typeof e.purl === "string" ? e.purl : base?.purl;
    const cpe = typeof e.cpe === "string" ? e.cpe : base?.cpe;
    if (purl) result.purl = purl;
    if (cpe) result.cpe = cpe;
    const cves = Array.isArray(e.cves) ? e.cves : Array.isArray(e.vulnerabilities) ? e.vulnerabilities : [];
    result.cves = cves.filter(isObj).map(normalizeCve).filter((c): c is CveFinding => c !== null);
    return result;
  });
}

function normalizeCve(v: Obj): CveFinding | null {
  const cve = v.cve ?? v.id;
  if (typeof cve !== "string") return null;
  const rawActors = Array.isArray(v.actors) ? v.actors : Array.isArray(v.cited_actors) ? v.cited_actors : [];
  const actors: ActorCitation[] = [];
  for (const a of rawActors) {
    if (typeof a === "string") actors.push({ actor: a });
    else if (isObj(a)) {
      const actor = a.actor ?? a.name;
      if (typeof actor !== "string") continue;
      const c: ActorCitation = { actor };
      if (typeof a.quote === "string") c.quote = a.quote;
      if (typeof a.url === "string") c.url = a.url;
      actors.push(c);
    }
  }
  return { cve, kev: v.kev === true || v.in_kev === true, epss: num(v.epss), actors };
}
