#!/usr/bin/env node
import { main } from "./cli.js";
import { processIo } from "./io.js";

const [major] = process.versions.node.split(".").map(Number);
if ((major ?? 0) < 20) {
  process.stderr.write(`skopnix needs Node.js 20 or newer (this is ${process.version})\n`);
  process.exit(2);
}

main(process.argv.slice(2), processIo()).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    process.stderr.write(`skopnix: unexpected error: ${(e as Error)?.stack ?? e}\n`);
    process.exitCode = 2;
  },
);
