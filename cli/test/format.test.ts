import assert from "node:assert/strict";
import { test } from "node:test";
import { mdCell } from "../src/format.js";

test("mdCell: pipes, backslashes and newlines cannot break out of a table cell", () => {
  assert.equal(mdCell("a|b"), "a\\|b");
  assert.equal(mdCell("a\\|b"), "a\\\\\\|b"); // backslash escaped, then the pipe: still one cell
  assert.equal(mdCell("C:\\path"), "C:\\\\path");
  assert.equal(mdCell("one\r\ntwo\nthree"), "one two three");
  // Every pipe left in the output is preceded by an odd number of backslashes (escaped).
  for (const s of ["|", "\\|", "\\\\|", "x\\\\\\|y|z"]) {
    for (const m of mdCell(s).matchAll(/(\\*)\|/g)) assert.equal((m[1] ?? "").length % 2, 1, `${JSON.stringify(s)} -> ${mdCell(s)}`);
  }
});
