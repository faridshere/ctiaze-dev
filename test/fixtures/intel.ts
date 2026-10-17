import type {
  CveActorCitationDoc,
  HacktivistPostDoc,
  ThreatActorDoc,
} from "@/lib/intel";

export const NOW = new Date("2026-10-17T12:00:00Z");

export const hacktivistPosts: HacktivistPostDoc[] = [
  {
    _id: "tg-1",
    az: true,
    claim_like: true,
    kind: "telegram",
    group: "CyberArmy",
    published: new Date("2026-10-16T08:00:00Z"),
    first_seen: new Date("2026-10-16T09:00:00Z"),
    summary: { summary_en: "Claims DDoS on gov.az; mirror at http://abcdefghijklmnop.onion/leak" },
    text: "ignored because summary_en exists",
    targets: ["gov.az", { host: "mirror.onion", note: "see abcdefghijklmnop.onion" }],
    checks: { http_down: false },
    url: "https://t.me/cyberarmy/123",
  },
  {
    _id: "bs-1",
    az: true,
    claim_like: true,
    kind: "bluesky",
    group: "NoName",
    published: null,
    first_seen: "2026-10-15T10:00:00.000Z",
    summary: null,
    text: "x".repeat(500),
    targets: [],
    checks: null,
    url: "https://bsky.app/profile/noname/post/1",
  },
  {
    _id: "rw-1",
    az: true,
    claim_like: true,
    kind: "ransomware",
    group: "LockBit",
    published: "2026-10-14T00:00:00.000Z",
    summary: { summary_en: "Listed an Azerbaijani logistics firm" },
    targets: ["example.az"],
    checks: [],
    url: "http://lockbitxyzxyzxyz.onion/post/9",
  },
  // Must never come back, even if the query lets it through.
  {
    _id: "dw-1",
    az: true,
    claim_like: true,
    kind: "darkweb",
    group: "Forum seller",
    published: new Date("2026-10-16T00:00:00Z"),
    summary: { summary_en: "Selling access" },
    url: "http://forumforumforum.onion/t/1",
  },
];

export const citations: CveActorCitationDoc[] = [
  {
    cve: "CVE-2024-3400",
    actor_id: "uta0218",
    actor_text: "UTA0218",
    relation: "exploited",
    quote: "UTA0218 exploited CVE-2024-3400 to gain access.",
    url: "https://www.volexity.com/blog/x",
    host: "www.volexity.com",
    kev: true,
  },
  {
    cve: "CVE-2024-3400",
    actor_id: null,
    actor_text: "an unnamed group",
    relation: "exploited",
    quote: "Seen exploited; payloads at http://qqqqqqqqqqqqqqqq.onion/p",
    url: "http://qqqqqqqqqqqqqqqq.onion/report",
    host: "qqqqqqqqqqqqqqqq.onion",
    kev: null,
  },
];

export const threatActors: ThreatActorDoc[] = [
  {
    _id: "apt28",
    name: "APT28",
    aliases: ["Fancy Bear", "Sofacy"],
    cves: [
      {
        cve: "CVE-2023-23397",
        kev: true,
        epss: 0.93,
        evidence: "Used against EU targets",
        url: "https://example.com/apt28",
        source: "vendor",
        date: "2023-03-15T00:00:00.000Z",
      },
      {
        cve: "CVE-2023-38831",
        kev: true,
        epss: null,
        evidence: "WinRAR exploitation",
        source: "cert",
        date: new Date("2023-10-01T00:00:00Z"),
      },
    ],
  },
];
