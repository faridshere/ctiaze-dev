import { appendFile, readFile } from "node:fs/promises";
import type { FetchLike } from "./api.js";

// Everything the commands touch outside the process, so tests can swap it.
export type Io = {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  readFile: (path: string) => Promise<string>;
  readStdin: () => Promise<string>;
  appendFile: (path: string, data: string) => Promise<void>;
  env: Record<string, string | undefined>;
  fetch?: FetchLike;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
};

export function processIo(): Io {
  return {
    stdout: (s) => void process.stdout.write(s),
    stderr: (s) => void process.stderr.write(s),
    readFile: (p) => readFile(p, "utf8"),
    readStdin: async () => {
      const chunks: Buffer[] = [];
      for await (const c of process.stdin) chunks.push(c as Buffer);
      return Buffer.concat(chunks).toString("utf8");
    },
    appendFile: (p, d) => appendFile(p, d, "utf8"),
    env: process.env,
  };
}
