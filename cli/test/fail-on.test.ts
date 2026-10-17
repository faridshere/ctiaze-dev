import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeStackResponse } from "../src/api.js";
import { evaluateFailOn, FailOnError, parseFailOn } from "../src/fail-on.js";
import { fixtureJson } from "./helpers.js";

const results = normalizeStackResponse(fixtureJson("stack-response.json"), []);

test("parseFailOn: commas, spaces, repeats, case and spaced operators", () => {
  assert.deepEqual(parseFailOn(undefined), []);
  assert.deepEqual(parseFailOn(""), []);
  assert.deepEqual(parseFailOn(["KEV, actor", "epss >= 0.5"]), [
    { kind: "kev" },
    { kind: "actor" },
    { kind: "epss", op: ">=", threshold: 0.5 },
  ]);
  assert.deepEqual(parseFailOn("epss>.9 any"), [{ kind: "epss", op: ">", threshold: 0.9 }, { kind: "any" }]);
});

test("parseFailOn: rejects unknown rules and out-of-range thresholds", () => {
  assert.throws(() => parseFailOn("critical"), FailOnError);
  assert.throws(() => parseFailOn("epss>=1.5"), /between 0 and 1/);
  assert.throws(() => parseFailOn("epss=0.5"), FailOnError);
});

test("no rules never fails", () => {
  assert.deepEqual(evaluateFailOn([], results), []);
});

test("kev matches only KEV-listed CVEs", () => {
  const hits = evaluateFailOn(parseFailOn("kev"), results);
  assert.deepEqual(hits, [{ rule: "kev", component: "log4j-core@2.14.1", cve: "CVE-2021-44228" }]);
});

test("epss>=0.5 compares the raw score and ignores missing scores", () => {
  const hits = evaluateFailOn(parseFailOn("epss>=0.5"), results).map((h) => h.cve);
  assert.deepEqual(hits, ["CVE-2021-44228", "CVE-2021-45046"]);
  assert.deepEqual(
    evaluateFailOn(parseFailOn("epss>=0.9"), results).map((h) => h.cve),
    ["CVE-2021-44228", "CVE-2021-45046"],
  );
  assert.deepEqual(evaluateFailOn(parseFailOn("epss>0.9"), results).map((h) => h.cve), ["CVE-2021-44228"]);
});

test("actor matches CVEs with at least one cited actor", () => {
  const hits = evaluateFailOn(parseFailOn("actor"), results).map((h) => h.cve);
  assert.deepEqual(hits, ["CVE-2021-44228", "CVE-2022-3602"]);
});

test("rules combine with OR, each CVE reported once under the first rule it trips", () => {
  const hits = evaluateFailOn(parseFailOn("kev,actor,epss>=0.5"), results);
  assert.deepEqual(
    hits.map((h) => `${h.cve}:${h.rule}`),
    ["CVE-2021-44228:kev", "CVE-2021-45046:epss>=0.5", "CVE-2022-3602:actor"],
  );
  assert.equal(evaluateFailOn(parseFailOn("any"), results).length, 4);
});
