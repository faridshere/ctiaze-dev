import assert from "node:assert/strict";
import { test } from "node:test";
import { runAction } from "../src/action.js";
import { fakeStack, fixturePath, memoryIo, mockFetch } from "./helpers.js";

const env = (inputs: Record<string, string>) => ({
  GITHUB_STEP_SUMMARY: "/gh/summary.md",
  GITHUB_OUTPUT: "/gh/output",
  RUNNER_TEMP: "/gh/tmp",
  ...Object.fromEntries(Object.entries(inputs).map(([k, v]) => [`INPUT_${k.toUpperCase()}`, v])),
});

test("action: writes the job summary, outputs and report, fails per fail-on", async () => {
  const { io, out } = memoryIo({ fetch: fakeStack().fetch, env: env({ sbom: fixturePath("cyclonedx.json"), "fail-on": "kev" }) });
  const code = await runAction(io);
  assert.equal(code, 1);
  assert.match(out.files.get("/gh/summary.md")!, /### skopnix stack check — ❌ failed/);
  assert.equal(
    out.files.get("/gh/output"),
    "components=5\nfindings=4\nkev=1\nwith-actors=2\nfailed=true\nreport=/gh/tmp/skopnix-report.json\n",
  );
  assert.equal((JSON.parse(out.files.get("/gh/tmp/skopnix-report.json")!) as { failed: boolean }).failed, true);
  assert.match(out.stdout, /::error title=skopnix fail-on kev::1 finding\(s\) matched:%0Alog4j-core@2\.14\.1 CVE-2021-44228 \(kev\)/);
});

test("action: passes without fail-on, and summary can be turned off", async () => {
  const { io, out } = memoryIo({ fetch: fakeStack().fetch, env: env({ sbom: fixturePath("spdx.json"), summary: "false" }) });
  assert.equal(await runAction(io), 0);
  assert.equal(out.files.has("/gh/summary.md"), false);
  assert.match(out.files.get("/gh/output")!, /failed=false/);
});

test("action: API error fails the step with an annotation and a summary note", async () => {
  const { io, out } = memoryIo({
    fetch: mockFetch(() => ({ status: 404, text: "<html></html>" })).fetch,
    env: env({ sbom: fixturePath("components.json"), "api-base": "https://example.test/api/v1" }),
  });
  assert.equal(await runAction(io), 2);
  assert.match(out.stdout, /::error title=skopnix stack check::POST https:\/\/example\.test\/api\/v1\/stack → HTTP 404/);
  assert.match(out.files.get("/gh/summary.md")!, /⚠️ error/);
  assert.equal(out.files.get("/gh/output"), "failed=true\n");
});

test("action: missing sbom input", async () => {
  const { io, out } = memoryIo({ env: env({}) });
  assert.equal(await runAction(io), 2);
  assert.match(out.stdout, /input `sbom` is required/);
});
