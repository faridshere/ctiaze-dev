import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, createClient, normalizeStackResponse, STACK_CHUNK_SIZE } from "../src/api.js";
import type { Component } from "../src/types.js";
import { mockFetch } from "./helpers.js";

const noSleep = () => {
  const sleeps: number[] = [];
  return { sleeps, sleep: async (ms: number) => void sleeps.push(ms) };
};

const many = (n: number): Component[] => Array.from({ length: n }, (_, i) => ({ name: `pkg${i}`, version: "1.0.0" }));

test("stack() posts in chunks of 500 and keeps input order", async () => {
  const { fetch, calls } = mockFetch((call) => ({
    json: { components: (call.body as { components: Component[] }).components.map((c) => ({ ...c, cves: [] })) },
  }));
  const client = createClient({ fetch, apiBase: "https://example.test/api/v1/" });
  const results = await client.stack(many(1201));
  assert.equal(STACK_CHUNK_SIZE, 500);
  assert.deepEqual(
    calls.map((c) => [c.method, c.url, (c.body as { components: unknown[] }).components.length]),
    [
      ["POST", "https://example.test/api/v1/stack", 500],
      ["POST", "https://example.test/api/v1/stack", 500],
      ["POST", "https://example.test/api/v1/stack", 201],
    ],
  );
  assert.equal(results.length, 1201);
  assert.equal(results[0]!.name, "pkg0");
  assert.equal(results[1200]!.name, "pkg1200");
});

test("429 honours Retry-After seconds, then succeeds", async () => {
  const { sleeps, sleep } = noSleep();
  const retries: string[] = [];
  const { fetch, calls } = mockFetch((_, n) =>
    n < 3 ? { status: 429, json: { error: "slow down" }, headers: { "retry-after": "7" } } : { json: { components: [] } },
  );
  const client = createClient({ fetch, sleep, onRetry: (r) => retries.push(r.reason) });
  await client.stack([{ name: "a", version: "1" }]);
  assert.equal(calls.length, 3);
  assert.deepEqual(sleeps, [7000, 7000]);
  assert.deepEqual(retries, ["rate limited (429)", "rate limited (429)"]);
});

test("429 with an HTTP-date Retry-After waits until that time, capped", async () => {
  const { sleeps, sleep } = noSleep();
  const now = Date.parse("2026-10-17T12:00:00Z");
  const { fetch } = mockFetch((_, n) =>
    n === 1
      ? { status: 429, headers: { "retry-after": "Sat, 17 Oct 2026 12:00:30 GMT" } }
      : n === 2
        ? { status: 429, headers: { "retry-after": "86400" } }
        : { json: { components: [] } },
  );
  await createClient({ fetch, sleep, now: () => now, maxRetryAfterMs: 60_000 }).stack([{ name: "a", version: "1" }]);
  assert.deepEqual(sleeps, [30_000, 60_000]);
});

test("5xx and network errors back off exponentially with jitter", async () => {
  const { sleeps, sleep } = noSleep();
  const { fetch, calls } = mockFetch((_, n) =>
    n === 1 ? new TypeError("fetch failed") : n <= 3 ? { status: 503, text: "<html>busy</html>" } : { json: { components: [] } },
  );
  await createClient({ fetch, sleep, random: () => 1, baseDelayMs: 100 }).stack([{ name: "a", version: "1" }]);
  assert.equal(calls.length, 4);
  assert.deepEqual(sleeps, [100, 200, 400]);
});

test("gives up after maxRetries and says so", async () => {
  const { sleep } = noSleep();
  const { fetch, calls } = mockFetch(() => ({ status: 429, json: { error: "rate limit exceeded" } }));
  await assert.rejects(createClient({ fetch, sleep, maxRetries: 2 }).stack([{ name: "a", version: "1" }]), (e) => {
    assert.ok(e instanceof ApiError);
    assert.equal(e.status, 429);
    assert.match(e.message, /rate limit exceeded/);
    assert.match(e.message, /gave up after 3 attempts/);
    return true;
  });
  assert.equal(calls.length, 3);
});

test("4xx is not retried and surfaces the API's error message", async () => {
  const { sleeps, sleep } = noSleep();
  const { fetch, calls } = mockFetch(() => ({ status: 400, json: { error: "components[0].version is required" } }));
  await assert.rejects(createClient({ fetch, sleep }).stack([{ name: "a", version: "" }]), /HTTP 400: components\[0\]\.version is required/);
  assert.equal(calls.length, 1);
  assert.deepEqual(sleeps, []);
});

test("404 on /stack explains the endpoint may not be live yet", async () => {
  const { fetch } = mockFetch(() => ({ status: 404, text: "<!DOCTYPE html><html>404</html>" }));
  await assert.rejects(createClient({ fetch }).stack([{ name: "a", version: "1" }]), /may not be deployed yet/);
});

test("a 200 that is not JSON is an ApiError, not a crash", async () => {
  const { fetch } = mockFetch(() => ({ text: "<html>maintenance</html>" }));
  await assert.rejects(createClient({ fetch }).stack([{ name: "a", version: "1" }]), /non-JSON/);
});

test("normalizeStackResponse: documented shape plus aliases, fills gaps from what was sent", () => {
  const sent: Component[] = [
    { name: "a", version: "1", purl: "pkg:npm/a@1" },
    { name: "b", version: "2" },
  ];
  const out = normalizeStackResponse(
    {
      results: [
        { cves: [{ id: "CVE-1", in_kev: true, epss: { score: "0.42" }, cited_actors: ["X", { name: "Y", url: "u" }] }] },
        { name: "b", version: "2", vulnerabilities: [{ cve: "CVE-2", epss: null }, { nonsense: true }] },
      ],
    },
    sent,
  );
  assert.deepEqual(out, [
    {
      name: "a",
      version: "1",
      purl: "pkg:npm/a@1",
      cves: [{ cve: "CVE-1", kev: true, epss: 0.42, actors: [{ actor: "X" }, { actor: "Y", url: "u" }] }],
    },
    { name: "b", version: "2", cves: [{ cve: "CVE-2", kev: false, epss: null, actors: [] }] },
  ]);
  assert.throws(() => normalizeStackResponse({ ok: true }, sent), /no `components` array/);
});

test("claims(): passes days and filters client-side by timestamp", async () => {
  const { fetch, calls } = mockFetch(() => ({
    json: {
      claims: [
        { group: "new", at: "2026-10-16T00:00:00Z" },
        { group: "seen-only", seenAt: "2026-10-12T00:00:00Z" },
        { group: "old", at: "2026-09-01T00:00:00Z" },
        { group: "undated" },
      ],
    },
  }));
  const now = () => Date.parse("2026-10-17T12:00:00Z");
  const { claims } = await createClient({ fetch, now }).claims(7);
  assert.equal(calls[0]!.url, "https://skopnix.com/api/v1/claims?days=7");
  assert.deepEqual(claims.map((c) => c.group), ["new", "seen-only"]);
});

test("actor(): direct id hit", async () => {
  const { fetch, calls } = mockFetch(() => ({ json: { id: "apt28", name: "APT28" } }));
  const a = await createClient({ fetch }).actor("APT 28");
  assert.equal(a.id, "apt28");
  assert.equal(calls[0]!.url, "https://skopnix.com/api/v1/actors/apt-28");
});

test("actor(): falls back to roster search and matches an alias exactly", async () => {
  const { fetch, calls } = mockFetch((call) => {
    if (call.url.endsWith("/actors/fancy-bear")) return { status: 404, json: { error: "No dossier" } };
    if (call.url.includes("/actors?q=")) {
      return {
        json: {
          actors: [
            { id: "apt28", name: "APT28", aliases: ["Fancy Bear", "Sofacy"] },
            { id: "fancy-bear-wannabe", name: "Fancy Bear Wannabe", aliases: [] },
          ],
        },
      };
    }
    return { json: { id: "apt28", name: "APT28" } };
  });
  const a = await createClient({ fetch }).actor("Fancy Bear");
  assert.equal(a.id, "apt28");
  assert.deepEqual(
    calls.map((c) => c.url.replace("https://skopnix.com/api/v1", "")),
    ["/actors/fancy-bear", "/actors?q=Fancy%20Bear", "/actors/apt28"],
  );
});

test("actor(): ambiguous search lists candidates", async () => {
  const { fetch } = mockFetch((call) =>
    call.url.includes("?q=")
      ? { json: { actors: [{ id: "a1", name: "Bear One" }, { id: "a2", name: "Bear Two" }] } }
      : { status: 404, json: {} },
  );
  await assert.rejects(createClient({ fetch }).actor("bear"), /matches 2 actors[\s\S]*Bear One \(a1\)/);
});
