import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSbom, SbomError } from "../src/sbom.js";
import { fixture } from "./helpers.js";

test("CycloneDX: walks nested components, keeps purl/cpe, skips files, dupes and empties", () => {
  const sbom = parseSbom(fixture("cyclonedx.json"));
  assert.equal(sbom.format, "cyclonedx");
  assert.deepEqual(sbom.components, [
    {
      name: "log4j-core",
      version: "2.14.1",
      purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      cpe: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
    },
    { name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20" },
    { name: "lodash.merge", version: "4.6.1", purl: "pkg:npm/lodash.merge@4.6.1" },
    { name: "openssl", version: "3.0.1", cpe: "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*" },
    { name: "net", version: "", purl: "pkg:golang/golang.org/x/net" },
  ]);
  // duplicate lodash, versionless "no-version-no-ids", the file entry
  assert.equal(sbom.skipped, 3);
});

test("CycloneDX: metadata.component is not treated as a dependency", () => {
  const sbom = parseSbom(fixture("cyclonedx.json"));
  assert.ok(!sbom.components.some((c) => c.name === "/github/workspace"));
});

test("SPDX: reads versionInfo + purl/cpe refs, drops the described root and NOASSERTION", () => {
  const sbom = parseSbom(fixture("spdx.json"));
  assert.equal(sbom.format, "spdx");
  assert.deepEqual(sbom.components, [
    {
      name: "requests",
      version: "2.25.0",
      purl: "pkg:pypi/requests@2.25.0",
      cpe: "cpe:2.3:a:python:requests:2.25.0:*:*:*:*:*:*:*",
    },
    { name: "urllib3", version: "1.26.4", purl: "pkg:pypi/urllib3@1.26.4" },
    { name: "openssl", version: "3.0.11-1~deb12u2", cpe: "cpe:/a:openssl:openssl:3.0.11" },
  ]);
  assert.equal(sbom.skipped, 2);
});

test("plain list: vendor product version → CPE; product version; purl; cpe; comments", () => {
  const sbom = parseSbom(fixture("list.txt"));
  assert.equal(sbom.format, "list");
  assert.deepEqual(sbom.components, [
    { name: "http server", version: "2.4.49", cpe: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" },
    { name: "fortios", version: "7.2.0", cpe: "cpe:2.3:a:fortinet:fortios:7.2.0:*:*:*:*:*:*:*" },
    { name: "nginx", version: "1.25.3" },
    { name: "core", version: "7.22.0", purl: "pkg:npm/%40babel/core@7.22.0" },
    { name: "connect secure", version: "22.7", cpe: "cpe:2.3:a:ivanti:connect_secure:22.7:r2.3:*:*:*:*:*:*" },
  ]);
  assert.equal(sbom.skipped, 1); // the repeated nginx line
});

test("plain list: a line with one token is an error naming the line", () => {
  assert.throws(() => parseSbom(fixture("bad-list.txt")), (e: unknown) => {
    assert.ok(e instanceof SbomError);
    assert.match((e as Error).message, /line 1/);
    return true;
  });
});

test("JSON {components:[...]} (the API body shape) and a bare array are accepted", () => {
  const a = parseSbom(fixture("components.json"));
  assert.equal(a.format, "components");
  assert.equal(a.components.length, 2);
  const b = parseSbom(JSON.stringify([{ name: "x", version: "1" }, { nope: true }]));
  assert.deepEqual(b.components, [{ name: "x", version: "1" }]);
  assert.equal(b.skipped, 1);
});

test("unrecognised or broken input fails with SbomError", () => {
  assert.throws(() => parseSbom(fixture("unknown.json")), SbomError);
  assert.throws(() => parseSbom("{ not json"), /does not parse/);
  assert.throws(() => parseSbom("   \n"), /empty/);
  assert.throws(() => parseSbom('{"@context":"https://spdx.org/rdf/3.0.0/spdx-context.jsonld","@graph":[]}'), /SPDX 3/);
});

test("a UTF-8 BOM in front of the JSON is tolerated", () => {
  const sbom = parseSbom("﻿" + fixture("components.json"));
  assert.equal(sbom.components.length, 2);
});
