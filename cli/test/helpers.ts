import { readFileSync } from "node:fs";
import type { FetchLike } from "../src/api.js";
import type { Io } from "../src/io.js";

// Compiled tests live in .test-build/test; fixtures stay in test/fixtures.
const FIXTURES = new URL("../../test/fixtures/", import.meta.url);

export const fixturePath = (name: string) => new URL(name, FIXTURES).pathname;
export const fixture = (name: string) => readFileSync(new URL(name, FIXTURES), "utf8");
export const fixtureJson = <T = unknown>(name: string): T => JSON.parse(fixture(name)) as T;

export type Call = { url: string; method: string; body?: unknown };

export type Reply = { status?: number; json?: unknown; text?: string; headers?: Record<string, string> } | Error;

/** A fetch stand-in: `handler` decides each reply; every call is recorded. */
export function mockFetch(handler: (call: Call, n: number) => Reply) {
  const calls: Call[] = [];
  const fetch: FetchLike = async (url, init) => {
    const call: Call = {
      url,
      method: init?.method ?? "GET",
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    };
    calls.push(call);
    const reply = handler(call, calls.length);
    if (reply instanceof Error) throw reply;
    const body = reply.text ?? JSON.stringify(reply.json ?? {});
    return new Response(body, {
      status: reply.status ?? 200,
      headers: { "content-type": reply.text ? "text/html" : "application/json", ...reply.headers },
    });
  };
  return { fetch, calls };
}

export function memoryIo(opts: { fetch?: FetchLike; stdin?: string; env?: Record<string, string>; now?: number } = {}) {
  const out = { stdout: "", stderr: "", files: new Map<string, string>(), sleeps: [] as number[] };
  const io: Io & { writeFile: (p: string, d: string) => Promise<void> } = {
    stdout: (s) => void (out.stdout += s),
    stderr: (s) => void (out.stderr += s),
    readFile: async (p) => readFileSync(p, "utf8"),
    readStdin: async () => opts.stdin ?? "",
    appendFile: async (p, d) => void out.files.set(p, (out.files.get(p) ?? "") + d),
    writeFile: async (p, d) => void out.files.set(p, d),
    env: opts.env ?? {},
    fetch: opts.fetch ?? (async () => {
      throw new Error("network disabled in tests");
    }),
    sleep: async (ms) => void out.sleeps.push(ms),
    now: () => opts.now ?? Date.parse("2026-10-17T12:00:00Z"),
  };
  return { io, out };
}

/** A fake /stack that answers every chunk from the canned response by name. */
export function fakeStack() {
  const canned = fixtureJson<{ components: { name: string; cves: unknown[] }[] }>("stack-response.json");
  const byName = new Map(canned.components.map((c) => [c.name, c]));
  return mockFetch((call) => {
    if (!call.url.endsWith("/stack")) return { status: 404, json: { error: "not found" } };
    const sent = (call.body as { components: { name: string; version: string }[] }).components;
    return {
      json: { components: sent.map((c) => ({ ...c, cves: byName.get(c.name)?.cves ?? [] })) },
    };
  });
}
