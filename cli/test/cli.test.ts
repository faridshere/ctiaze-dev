import assert from "node:assert/strict";
import { test } from "node:test";
import type { CheckReport } from "../src/check.js";
import { main } from "../src/cli.js";
import { fakeStack, fixturePath, memoryIo, mockFetch } from "./helpers.js";

test("check: prints a table sorted KEV-first with a summary line, exit 0", async () => {
  const { fetch, calls } = fakeStack();
  const { io, out } = memoryIo({ fetch });
  const code = await main(["check", fixturePath("cyclonedx.json")], io);
  assert.equal(code, 0);
  assert.equal(calls.length, 1);
  const lines = out.stdout.split("\n");
  assert.match(lines[0]!, /^COMPONENT\s+CVE\s+KEV\s+EPSS\s+CITED ACTORS$/);
  assert.match(lines[2]!, /^log4j-core@2\.14\.1\s+CVE-2021-44228\s+yes\s+0\.976\s+APT41, Lazarus Group$/);
  assert.match(lines[3]!, /CVE-2021-45046\s+0\.900/);
  assert.match(out.stdout, /openssl@3\.0\.1\s+CVE-2022-3602\s+-\s+Unnamed cluster/);
  assert.match(out.stdout, /5 components checked, 3 with known CVEs: 4 CVE findings, 1 in KEV, 2 with cited threat actors\./);
  assert.match(out.stdout, /3 SBOM entries skipped/);
});

test("check --fail-on kev exits 1 and names the rule", async () => {
  const { io, out } = memoryIo({ fetch: fakeStack().fetch });
  const code = await main(["check", fixturePath("cyclonedx.json"), "--fail-on", "kev"], io);
  assert.equal(code, 1);
  assert.match(out.stdout, /fail-on kev: FAILED \(1 × kev\)/);
});

test("check --fail-on passes (exit 0) when nothing matches", async () => {
  const { io, out } = memoryIo({ fetch: fakeStack().fetch });
  // spdx.json's openssl has one CVE: not KEV, no EPSS score.
  const code = await main(["check", fixturePath("spdx.json"), "--fail-on", "kev,epss>=0.5"], io);
  assert.equal(code, 0);
  assert.match(out.stdout, /3 components checked, 1 with known CVEs/);
  assert.match(out.stdout, /fail-on kev,epss>=0.5: passed\./);
});

test("check --json emits a machine-readable report", async () => {
  const { io, out } = memoryIo({ fetch: fakeStack().fetch });
  const code = await main(["check", fixturePath("cyclonedx.json"), "--json", "--fail-on", "epss>=0.5"], io);
  assert.equal(code, 1);
  const report = JSON.parse(out.stdout) as CheckReport;
  assert.equal(report.format, "cyclonedx");
  assert.deepEqual(report.stats, { components: 5, skipped: 3, vulnerableComponents: 3, findings: 4, kev: 1, withActors: 2 });
  assert.deepEqual(report.failOn, ["epss>=0.5"]);
  assert.equal(report.failed, true);
  assert.equal(report.hits.length, 2);
  assert.deepEqual(report.results.map((r) => r.name), ["log4j-core", "lodash", "openssl"]);
  assert.equal(report.results[0]!.cves[0]!.actors[0]!.quote, "APT41 exploited Log4Shell within hours of disclosure.");
});

test("check --summary appends markdown with a table, escaped pipes and actor quotes", async () => {
  const { io, out } = memoryIo({ fetch: fakeStack().fetch });
  await main(["check", fixturePath("cyclonedx.json"), "--summary", "/tmp/summary.md", "--fail-on", "actor"], io);
  const md = out.files.get("/tmp/summary.md")!;
  assert.match(md, /^### skopnix stack check — ❌ failed/);
  assert.match(md, /\| Component \| CVE \| KEV \| EPSS \| Cited actors \|/);
  assert.match(
    md,
    /\| `log4j-core@2\.14\.1` \| \[CVE-2021-44228\]\(https:\/\/skopnix\.com\/cve\/CVE-2021-44228\) \| 🔴 KEV \| 0\.976 \| \[APT41\]\(https:\/\/skopnix\.com\/actors\/apt41\), \[Lazarus Group\]/,
  );
  assert.match(md, /Lazarus \\\| used Log4j/);
  assert.match(md, /<details><summary>Why these actors are cited<\/summary>/);
});

test("check reads stdin with -, and --api-base / $SKOPNIX_API_BASE override the URL", async () => {
  const a = fakeStack();
  const run1 = memoryIo({ fetch: a.fetch, stdin: "nginx 1.25.3\n" });
  assert.equal(await main(["check", "-", "--api-base", "http://localhost:3000/api/v1"], run1.io), 0);
  assert.equal(a.calls[0]!.url, "http://localhost:3000/api/v1/stack");
  assert.deepEqual(a.calls[0]!.body, { components: [{ name: "nginx", version: "1.25.3" }] });

  const b = fakeStack();
  const run2 = memoryIo({ fetch: b.fetch, stdin: "nginx 1.25.3\n", env: { SKOPNIX_API_BASE: "https://staging.test/api/v1" } });
  await main(["check", "-"], run2.io);
  assert.equal(b.calls[0]!.url, "https://staging.test/api/v1/stack");
});

test("check: a bad --fail-on fails with exit 2 before any HTTP call", async () => {
  const { fetch, calls } = fakeStack();
  const { io, out } = memoryIo({ fetch });
  assert.equal(await main(["check", fixturePath("cyclonedx.json"), "--fail-on", "critical"], io), 2);
  assert.equal(calls.length, 0);
  assert.match(out.stderr, /unknown rule "critical"/);
});

test("check: API errors and unreadable files exit 2 with a message", async () => {
  const notLive = mockFetch(() => ({ status: 404, text: "<html>not found</html>" }));
  const r1 = memoryIo({ fetch: notLive.fetch });
  assert.equal(await main(["check", fixturePath("components.json")], r1.io), 2);
  assert.match(r1.out.stderr, /stack endpoint may not be deployed yet/);

  const r2 = memoryIo();
  assert.equal(await main(["check", fixturePath("does-not-exist.json")], r2.io), 2);
  assert.match(r2.out.stderr, /ENOENT/);

  const r3 = memoryIo();
  assert.equal(await main(["check", fixturePath("unknown.json")], r3.io), 2);
  assert.match(r3.out.stderr, /Unrecognised SBOM JSON/);
});

test("check: retries are reported on stderr, stdout stays clean JSON", async () => {
  let n = 0;
  const { fetch } = mockFetch((call) => {
    n++;
    if (n === 1) return { status: 429, headers: { "retry-after": "1" } };
    return { json: { components: (call.body as { components: unknown[] }).components.map((c) => ({ ...(c as object), cves: [] })) } };
  });
  const { io, out } = memoryIo({ fetch });
  assert.equal(await main(["check", fixturePath("components.json"), "--json"], io), 0);
  assert.match(out.stderr, /rate limited \(429\); retry 1 in 1\.0s/);
  assert.deepEqual(out.sleeps, [1000]);
  JSON.parse(out.stdout);
});

test("check: an SBOM with no usable components makes no API call", async () => {
  const { fetch, calls } = fakeStack();
  const { io, out } = memoryIo({ fetch });
  assert.equal(await main(["check", "-", "--fail-on", "any"], { ...io, readStdin: async () => '{"components":[]}' }), 0);
  assert.equal(calls.length, 0);
  assert.match(out.stdout, /0 components checked/);
});

test("usage: help, version, unknown command, missing argument", async () => {
  const r = memoryIo();
  assert.equal(await main(["--help"], r.io), 0);
  assert.match(r.out.stdout, /skopnix check <sbom/);
  assert.equal(await main(["--version"], r.io), 0);
  assert.equal(await main(["frobnicate"], r.io), 2);
  assert.equal(await main(["check"], r.io), 2);
  assert.equal(await main(["check", "a.json", "--nope"], r.io), 2);
  assert.match(r.out.stderr, /Unknown option '--nope'/);
});

test("claims: table of recent claims, --json", async () => {
  const { fetch, calls } = mockFetch(() => ({
    json: {
      claims: [
        { group: "313 Team", claimType: "ddos", at: "2026-10-16T02:43:31.000Z", targets: ["bravosupermarket.az"], url: "https://t.me/x/1" },
        { group: "Old Crew", claimType: "leak", at: "2026-01-01T00:00:00.000Z", url: "https://t.me/x/0" },
      ],
    },
  }));
  const { io, out } = memoryIo({ fetch });
  assert.equal(await main(["claims", "--days", "3"], io), 0);
  assert.equal(calls[0]!.url, "https://skopnix.com/api/v1/claims?days=3");
  assert.match(out.stdout, /2026-10-16 02:43\s+ddos\s+313 Team\s+bravosupermarket\.az\s+https:\/\/t\.me\/x\/1/);
  assert.doesNotMatch(out.stdout, /Old Crew/);
  assert.match(out.stdout, /1 claim\(s\) in the last 3 day\(s\)/);

  const j = memoryIo({ fetch });
  await main(["claims", "--json"], j.io);
  assert.equal((JSON.parse(j.out.stdout) as { count: number }).count, 1);

  assert.equal(await main(["claims", "--days", "0"], j.io), 2);
});

test("actor: renders a dossier", async () => {
  const { fetch } = mockFetch(() => ({
    json: {
      id: "apt28",
      name: "APT28",
      type: "nation-state",
      origin_country: "RU",
      mitre: "G0007",
      aliases: ["Fancy Bear", "Sofacy"],
      description: "A cyber espionage group.",
      cves: [{ cve: "CVE-2026-21509", kev: true, epss: 0.72554, evidence: "APT28 leverages CVE-2026-21509" }],
      reports: [{ title: "Report", source: "CERT-UA", date: "2023-12-28T00:00:00.000Z", url: "https://example.test/r" }],
      url: "https://skopnix.com/actors/apt28",
    },
  }));
  const { io, out } = memoryIo({ fetch });
  assert.equal(await main(["actor", "apt28"], io), 0);
  assert.match(out.stdout, /^APT28 \(apt28\)\ntype: nation-state · origin: RU · MITRE: G0007\naka Fancy Bear, Sofacy/);
  assert.match(out.stdout, /CVE-2026-21509\s+yes\s+0\.726\s+APT28 leverages/);
  assert.match(out.stdout, /2023-12-28 {2}CERT-UA: Report/);

  const roster = mockFetch((call) =>
    call.url.includes("?q=") ? { json: { actors: [] } } : { status: 404, json: { error: "No dossier" } },
  );
  const missing = memoryIo({ fetch: roster.fetch });
  assert.equal(await main(["actor", "nobody"], missing.io), 2);
  assert.match(missing.out.stderr, /No actor matches "nobody"/);
});
