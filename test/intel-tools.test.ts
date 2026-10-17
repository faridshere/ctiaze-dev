import { beforeEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { citations, hacktivistPosts, threatActors } from "./fixtures/intel";
import { fakeDb, type FakeDb } from "./fake-db";

let db: FakeDb;
vi.mock("@/lib/db", () => ({ getDb: async () => db }));

const { registerIntelTools, cappedJson } = await import("@/lib/intel-tools");

async function connect() {
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerIntelTools(server);
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

async function call(name: string, args: Record<string, unknown>) {
  const client = await connect();
  const res = (await client.callTool({ name, arguments: args })) as {
    isError?: boolean;
    content: { text: string }[];
  };
  return { isError: Boolean(res.isError), text: res.content[0].text };
}

beforeEach(() => {
  db = fakeDb({
    hacktivist_posts: hacktivistPosts,
    cve_actor_citations: citations,
    threat_actors: threatActors,
  });
});

describe("tool registration", () => {
  it("lists the three tools", async () => {
    const { tools } = await (await connect()).listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      "get_actor_cves",
      "get_az_claims",
      "get_cve_actors",
    ]);
  });
});

describe("get_az_claims", () => {
  it("defaults to 7 days", async () => {
    const res = await call("get_az_claims", {});
    const body = JSON.parse(res.text);
    expect(body).toMatchObject({ days: 7, count: 3 });
    expect(res.text).not.toMatch(/darkweb|\.onion/);
  });

  it.each([
    [{ kind: "darkweb" }],
    [{ days: 0 }],
    [{ days: 91 }],
    [{ days: 1.5 }],
  ])("rejects %j", async (args) => {
    const res = await call("get_az_claims", args);
    expect(res.isError).toBe(true);
    expect(db.calls).toHaveLength(0);
  });
});

describe("get_cve_actors", () => {
  it("normalises the id and returns citations", async () => {
    const body = JSON.parse((await call("get_cve_actors", { cve: "cve-2024-3400" })).text);
    expect(body.cve).toBe("CVE-2024-3400");
    expect(body.citations[0].statement).toContain("cited as exploiting");
  });

  it("rejects malformed ids", async () => {
    expect((await call("get_cve_actors", { cve: "not-a-cve" })).isError).toBe(true);
    expect(db.calls).toHaveLength(0);
  });
});

describe("get_actor_cves", () => {
  it("returns the actor's CVEs", async () => {
    const body = JSON.parse((await call("get_actor_cves", { actor: "Sofacy" })).text);
    expect(body).toMatchObject({ actor_id: "apt28", count: 2, total: 2 });
  });

  it("says so for an unknown actor", async () => {
    expect((await call("get_actor_cves", { actor: "Nobody" })).text).toBe(
      'No threat actor matching "Nobody".'
    );
  });

  it("rejects too-short and too-long input", async () => {
    expect((await call("get_actor_cves", { actor: "a" })).isError).toBe(true);
    expect((await call("get_actor_cves", { actor: "a".repeat(101) })).isError).toBe(true);
  });
});

describe("cappedJson", () => {
  it("trims rows to fit and flags truncation", () => {
    const rows = Array.from({ length: 100 }, (_, i) => ({ i, pad: "x".repeat(100) }));
    const res = cappedJson({}, "rows", rows, "empty", 2_000);
    const body = JSON.parse(res.content[0].text);
    expect(res.content[0].text.length).toBeLessThanOrEqual(2_000);
    expect(body.truncated).toBe(true);
    expect(body.rows.length).toBe(body.count);
    expect(body.rows[0].i).toBe(0);
  });

  it("returns the empty message for no rows", () => {
    expect(cappedJson({}, "rows", [], "nothing").content[0].text).toBe("nothing");
  });
});
