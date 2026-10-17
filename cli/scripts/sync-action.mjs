// Copies the compiled CLI into ../action/dist so the GitHub Action runs with
// no install step. `--check` exits 1 if the committed copy is stale.
import { readdir, readFile, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const src = join(root, "dist");
const dest = join(root, "..", "action", "dist");
const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));

async function expected() {
  const files = new Map();
  for (const name of (await readdir(src)).sort()) {
    if (!name.endsWith(".js") || name === "bin.js") continue;
    files.set(name, await readFile(join(src, name), "utf8"));
  }
  // dist/ is ESM; the action directory has no package.json of its own.
  files.set("package.json", JSON.stringify({ type: "module", private: true, version: pkg.version }, null, 2) + "\n");
  return files;
}

const want = await expected();

if (process.argv.includes("--check")) {
  const have = new Map();
  try {
    for (const name of await readdir(dest)) have.set(name, await readFile(join(dest, name), "utf8"));
  } catch {
    // missing dir: everything is stale
  }
  const stale = [...new Set([...want.keys(), ...have.keys()])].filter((n) => want.get(n) !== have.get(n));
  if (stale.length) {
    console.error(`action/dist is out of date (${stale.join(", ")}). Run: cd cli && npm run build`);
    process.exit(1);
  }
  console.log("action/dist is up to date");
} else {
  await rm(dest, { recursive: true, force: true });
  await mkdir(dest, { recursive: true });
  for (const [name, body] of want) await writeFile(join(dest, name), body);
  console.log(`synced ${want.size} files to action/dist`);
}
