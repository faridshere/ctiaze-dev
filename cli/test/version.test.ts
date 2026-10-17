import assert from "node:assert/strict";
import { test } from "node:test";
import { VERSION } from "../src/version.js";
import { fixture } from "./helpers.js";

test("VERSION matches package.json", () => {
  const pkg = JSON.parse(fixture("../../package.json")) as { version: string };
  assert.equal(VERSION, pkg.version);
});
