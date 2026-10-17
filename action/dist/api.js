import { VERSION } from "./version.js";
export const DEFAULT_API_BASE = "https://skopnix.com/api/v1";
export const STACK_CHUNK_SIZE = 500;
export class ApiError extends Error {
    status;
    url;
    name = "ApiError";
    constructor(message, status, url) {
        super(message);
        this.status = status;
        this.url = url;
    }
}
export function createClient(opts = {}) {
    const apiBase = (opts.apiBase || DEFAULT_API_BASE).replace(/\/+$/, "");
    const doFetch = opts.fetch ?? ((url, init) => fetch(url, init));
    const maxRetries = opts.maxRetries ?? 4;
    const baseDelayMs = opts.baseDelayMs ?? 1000;
    const maxDelayMs = opts.maxDelayMs ?? 30_000;
    const maxRetryAfterMs = opts.maxRetryAfterMs ?? 120_000;
    const timeoutMs = opts.timeoutMs ?? 60_000;
    const sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    const random = opts.random ?? Math.random;
    const now = opts.now ?? Date.now;
    // Exponential backoff with jitter: half fixed, half random.
    const backoff = (attempt) => {
        const full = Math.min(maxDelayMs, baseDelayMs * 2 ** attempt);
        return Math.round(full / 2 + (random() * full) / 2);
    };
    const retryAfter = (res) => {
        const h = res.headers.get("retry-after");
        if (!h)
            return undefined;
        const secs = Number(h);
        const ms = Number.isFinite(secs) ? secs * 1000 : Date.parse(h) - now();
        if (!Number.isFinite(ms))
            return undefined;
        return Math.min(maxRetryAfterMs, Math.max(0, ms));
    };
    async function request(method, path, body) {
        const url = `${apiBase}${path}`;
        for (let attempt = 0;; attempt++) {
            let res;
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
            }
            catch (e) {
                const reason = e.message || String(e);
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
                    return JSON.parse(text);
                }
                catch {
                    throw new ApiError(`${method} ${url} returned non-JSON (${text.slice(0, 80)}…)`, res.status, url);
                }
            }
            const retryable = res.status === 429 || res.status === 408 || res.status >= 500;
            if (retryable && attempt < maxRetries) {
                const delayMs = retryAfter(res) ?? backoff(attempt);
                await res.body?.cancel().catch(() => { });
                opts.onRetry?.({
                    attempt: attempt + 1,
                    delayMs,
                    reason: res.status === 429 ? "rate limited (429)" : `HTTP ${res.status}`,
                    url,
                });
                await sleep(delayMs);
                continue;
            }
            throw new ApiError(`${method} ${url} → HTTP ${res.status}${await errorDetail(res)}` +
                (retryable ? ` (gave up after ${maxRetries + 1} attempts)` : ""), res.status, url);
        }
    }
    return {
        apiBase,
        request,
        /** POST /stack in chunks of STACK_CHUNK_SIZE, results in input order. */
        async stack(components, onChunk) {
            const out = [];
            for (let i = 0; i < components.length; i += STACK_CHUNK_SIZE) {
                const chunk = components.slice(i, i + STACK_CHUNK_SIZE);
                let json;
                try {
                    json = await request("POST", "/stack", { components: chunk });
                }
                catch (e) {
                    if (e instanceof ApiError && (e.status === 404 || e.status === 405)) {
                        throw new ApiError(`${e.message}\nPOST ${apiBase}/stack is not available — the stack endpoint may not be deployed yet. ` +
                            `Use --api-base to point at a server that has it.`, e.status, e.url);
                    }
                    throw e;
                }
                out.push(...normalizeStackResponse(json, chunk));
                onChunk?.(Math.min(i + STACK_CHUNK_SIZE, components.length), components.length);
            }
            return out;
        },
        /** GET /claims. The server may ignore `days`, so filter here as well. */
        async claims(days) {
            const raw = await request("GET", `/claims?days=${encodeURIComponent(days)}`);
            const since = now() - days * 86_400_000;
            const list = Array.isArray(raw.claims) ? raw.claims : [];
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
        async actor(name) {
            const id = slugify(name);
            if (id) {
                try {
                    return await request("GET", `/actors/${encodeURIComponent(id)}`);
                }
                catch (e) {
                    if (!(e instanceof ApiError && e.status === 404))
                        throw e;
                }
            }
            const roster = await request("GET", `/actors?q=${encodeURIComponent(name)}`);
            const actors = (Array.isArray(roster.actors) ? roster.actors : []);
            const needle = name.trim().toLowerCase();
            const exact = actors.filter((a) => String(a.name ?? "").toLowerCase() === needle ||
                String(a.id ?? "").toLowerCase() === needle ||
                (Array.isArray(a.aliases) && a.aliases.some((x) => String(x).toLowerCase() === needle)));
            const pick = exact.length === 1 ? exact[0] : actors.length === 1 ? actors[0] : undefined;
            if (pick && typeof pick.id === "string") {
                return request("GET", `/actors/${encodeURIComponent(pick.id)}`);
            }
            const names = actors.slice(0, 10).map((a) => `${a.name} (${a.id})`);
            throw new ApiError(actors.length === 0
                ? `No actor matches "${name}".`
                : `"${name}" matches ${actors.length} actors; be more specific:\n  ${names.join("\n  ")}`, 404);
        },
    };
}
export function slugify(name) {
    return name
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "");
}
async function errorDetail(res) {
    try {
        const text = await res.text();
        try {
            const j = JSON.parse(text);
            const msg = j.error ?? j.message;
            if (typeof msg === "string")
                return `: ${msg}`;
            if (isObj(msg) && typeof msg.message === "string")
                return `: ${msg.message}`;
        }
        catch {
            // HTML error pages are not worth echoing.
        }
    }
    catch {
        // body unreadable
    }
    return "";
}
const isObj = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const num = (v) => {
    if (typeof v === "number" && Number.isFinite(v))
        return v;
    if (typeof v === "string" && v.trim() && Number.isFinite(Number(v)))
        return Number(v);
    if (isObj(v))
        return num(v.score ?? v.epss);
    return null;
};
/**
 * Map a /stack response onto the components that were sent. The documented
 * shape is `{components:[{name,version,purl?,cpe?,cves:[{cve,kev,epss,
 * actors:[{actor,quote,url}]}]}]}`; a few obvious aliases (`results`, `id`,
 * `vulnerabilities`) are accepted so a small server-side rename does not
 * break every pipeline using this tool.
 */
export function normalizeStackResponse(json, sent) {
    const list = Array.isArray(json)
        ? json
        : !isObj(json)
            ? null
            : Array.isArray(json.components)
                ? json.components
                : Array.isArray(json.results)
                    ? json.results
                    : null;
    if (!list)
        throw new ApiError("POST /stack response has no `components` array");
    return list.map((entry, i) => {
        const e = isObj(entry) ? entry : {};
        const base = sent[i];
        const result = {
            name: typeof e.name === "string" ? e.name : (base?.name ?? "?"),
            version: typeof e.version === "string" ? e.version : (base?.version ?? ""),
            cves: [],
        };
        const purl = typeof e.purl === "string" ? e.purl : base?.purl;
        const cpe = typeof e.cpe === "string" ? e.cpe : base?.cpe;
        if (purl)
            result.purl = purl;
        if (cpe)
            result.cpe = cpe;
        const cves = Array.isArray(e.cves) ? e.cves : Array.isArray(e.vulnerabilities) ? e.vulnerabilities : [];
        result.cves = cves.filter(isObj).map(normalizeCve).filter((c) => c !== null);
        return result;
    });
}
function normalizeCve(v) {
    const cve = v.cve ?? v.id;
    if (typeof cve !== "string")
        return null;
    const rawActors = Array.isArray(v.actors) ? v.actors : Array.isArray(v.cited_actors) ? v.cited_actors : [];
    const actors = [];
    for (const a of rawActors) {
        if (typeof a === "string")
            actors.push({ actor: a });
        else if (isObj(a)) {
            const actor = a.actor ?? a.name;
            if (typeof actor !== "string")
                continue;
            const c = { actor };
            if (typeof a.quote === "string")
                c.quote = a.quote;
            if (typeof a.url === "string")
                c.url = a.url;
            actors.push(c);
        }
    }
    return { cve, kev: v.kev === true || v.in_kev === true, epss: num(v.epss), actors };
}
