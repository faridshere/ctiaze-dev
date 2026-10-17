import { createClient, type ClientOptions } from "./api.js";
import { evaluateFailOn, parseFailOn, ruleLabel, type FailHit } from "./fail-on.js";
import { parseSbom, type SbomFormat } from "./sbom.js";
import type { ComponentResult } from "./types.js";
import type { Io } from "./io.js";

export type CheckOptions = {
  input: string; // a path, or "-" for stdin
  failOn?: string[];
  apiBase?: string;
};

export type CheckReport = {
  source: string;
  format: SbomFormat;
  apiBase: string;
  generatedAt: string;
  stats: {
    components: number;
    skipped: number;
    vulnerableComponents: number;
    findings: number;
    kev: number;
    withActors: number;
  };
  failOn: string[];
  failed: boolean;
  hits: FailHit[];
  // Only components with at least one CVE.
  results: ComponentResult[];
};

export async function runCheck(opts: CheckOptions, io: Io): Promise<CheckReport> {
  // Validate the gate before spending any API calls.
  const rules = parseFailOn(opts.failOn);
  const text = opts.input === "-" ? await io.readStdin() : await io.readFile(opts.input);
  const sbom = parseSbom(text);

  const clientOpts: ClientOptions = {
    apiBase: opts.apiBase,
    fetch: io.fetch,
    sleep: io.sleep,
    onRetry: (r) =>
      io.stderr(`skopnix: ${r.reason}; retry ${r.attempt} in ${(r.delayMs / 1000).toFixed(1)}s\n`),
  };
  const client = createClient(clientOpts);
  const all =
    sbom.components.length === 0
      ? []
      : await client.stack(sbom.components, (done, total) => {
          if (total > 500) io.stderr(`skopnix: checked ${done}/${total} components\n`);
        });

  const results = all.filter((r) => r.cves.length > 0);
  const findings = results.flatMap((r) => r.cves);
  const hits = evaluateFailOn(rules, results);
  return {
    source: opts.input === "-" ? "stdin" : opts.input,
    format: sbom.format,
    apiBase: client.apiBase,
    generatedAt: new Date(io.now?.() ?? Date.now()).toISOString(),
    stats: {
      components: sbom.components.length,
      skipped: sbom.skipped,
      vulnerableComponents: results.length,
      findings: findings.length,
      kev: findings.filter((f) => f.kev).length,
      withActors: findings.filter((f) => f.actors.length > 0).length,
    },
    failOn: rules.map(ruleLabel),
    failed: hits.length > 0,
    hits,
    results,
  };
}
