import { beforeEach, describe, expect, it, vi } from "vitest";
import { citations, hacktivistPosts, NOW, threatActors } from "./fixtures/intel";
import { fakeDb, type FakeDb } from "./fake-db";

let db: FakeDb;
vi.mock("@/lib/db", () => ({ getDb: async () => db }));

const intel = await import("@/lib/intel");

beforeEach(() => {
  db = fakeDb({
    hacktivist_posts: hacktivistPosts,
    cve_actor_citations: citations,
    threat_actors: threatActors,
  });
});

describe("stripOnion", () => {
  it("removes onion URLs from strings, arrays and objects", () => {
    const out = intel.stripOnion({
      a: "see http://abcdefghijklmnop.onion/x?y=1 now",
      b: ["abc.onion", "https://ok.az"],
      d: 3,
    });
    expect(out).toEqual({
      a: "see [onion link removed] now",
      b: ["[onion link removed]", "https://ok.az"],
      d: 3,
    });
  });

  it("leaves clearnet text alone", () => {
    expect(intel.stripOnion("onion soup at https://gov.az")).toBe("onion soup at https://gov.az");
  });
});

describe("azClaimsFilter", () => {
  it("requires az + claim_like and never includes darkweb", () => {
    const f = intel.azClaimsFilter(7, undefined, NOW) as Record<string, unknown>;
    expect(f.az).toBe(true);
    expect(f.claim_like).toBe(true);
    expect(f.kind).toEqual({ $in: ["telegram", "bluesky", "ransomware"] });
    expect(JSON.stringify(f)).not.toContain("darkweb");
  });

  it("narrows to one kind and windows on published, then first_seen", () => {
    const f = intel.azClaimsFilter(3, "bluesky", NOW) as Record<string, unknown>;
    expect(f.kind).toBe("bluesky");
    const since = new Date("2026-10-14T12:00:00Z");
    expect(f.$or).toEqual([
      { published: { $gte: since } },
      { published: { $gte: since.toISOString() } },
      { published: { $in: [null] }, first_seen: { $gte: since } },
      { published: { $in: [null] }, first_seen: { $gte: since.toISOString() } },
    ]);
  });
});

describe("getAzClaims", () => {
  it("shapes rows, drops darkweb and strips onion links", async () => {
    const claims = await intel.getAzClaims(7);
    expect(claims.map((c) => c.kind)).toEqual(["telegram", "bluesky", "ransomware"]);
    expect(JSON.stringify(claims)).not.toMatch(/\.onion/);
    expect(JSON.stringify(claims)).not.toContain("darkweb");

    const [tg, bs, rw] = claims;
    expect(tg).toMatchObject({
      group: "CyberArmy",
      claimed_at: "2026-10-16T08:00:00.000Z",
      url: "https://t.me/cyberarmy/123",
      checks: { http_down: false },
    });
    expect(tg.summary).toBe("Claims DDoS on gov.az; mirror at [onion link removed]");
    // no published -> first_seen; no summary_en -> first 300 chars of text
    expect(bs.claimed_at).toBe("2026-10-15T10:00:00.000Z");
    expect(bs.summary).toHaveLength(300);
    // onion source URL is removed entirely
    expect(rw.url).toBeNull();
  });

  it("queries hacktivist_posts with the claim filter", async () => {
    await intel.getAzClaims(7, "ransomware");
    expect(db.calls[0]).toMatchObject({
      collection: "hacktivist_posts",
      filter: { az: true, claim_like: true, kind: "ransomware" },
    });
  });
});

describe("getCveActors", () => {
  it("returns every citation with quote, url and 'cited as exploiting' wording", async () => {
    const rows = await intel.getCveActors(" cve-2024-3400 ");
    expect(db.calls[0]).toMatchObject({
      collection: "cve_actor_citations",
      filter: { cve: "CVE-2024-3400" },
    });
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      statement: "UTA0218 cited as exploiting CVE-2024-3400",
      quote: "UTA0218 exploited CVE-2024-3400 to gain access.",
      url: "https://www.volexity.com/blog/x",
      kev: true,
    });
    expect(rows[1]).toMatchObject({ url: null, host: null, kev: false });
    expect(JSON.stringify(rows)).not.toMatch(/\.onion/);
  });

  it("does not query for an invalid CVE id", async () => {
    expect(await intel.getCveActors("CVE-24-1")).toEqual([]);
    expect(db.calls).toHaveLength(0);
  });
});

describe("getActorCves", () => {
  it("resolves by id", async () => {
    const res = await intel.getActorCves("apt28");
    expect(res?.actor_id).toBe("apt28");
    expect(db.calls).toHaveLength(1);
  });

  it("resolves by alias, case-insensitively, newest CVE first", async () => {
    const res = await intel.getActorCves("fancy bear");
    expect(res).toMatchObject({ actor_id: "apt28", name: "APT28", total: 2 });
    expect(res!.cves).toEqual([
      {
        cve: "CVE-2023-38831",
        kev: true,
        epss: null,
        evidence: "WinRAR exploitation",
        source: "cert",
        date: "2023-10-01T00:00:00.000Z",
      },
      {
        cve: "CVE-2023-23397",
        kev: true,
        epss: 0.93,
        evidence: "Used against EU targets",
        url: "https://example.com/apt28",
        source: "vendor",
        date: "2023-03-15T00:00:00.000Z",
      },
    ]);
  });

  it("treats regex metacharacters literally", async () => {
    expect(await intel.getActorCves(".*")).toBeNull();
  });

  it("returns null for unknown actors", async () => {
    expect(await intel.getActorCves("Nobody")).toBeNull();
  });
});
