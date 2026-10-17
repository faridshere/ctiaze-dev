import type { ComponentResult } from "./types.js";

export type FailRule =
  | { kind: "any" }
  | { kind: "kev" }
  | { kind: "actor" }
  | { kind: "epss"; op: ">=" | ">"; threshold: number };

export type FailHit = {
  rule: string;
  component: string;
  cve: string;
};

export class FailOnError extends Error {
  override name = "FailOnError";
}

/**
 * Parse `--fail-on` values. Each value may hold several rules separated by
 * commas or spaces; a CVE trips the gate if it matches ANY rule.
 *   any        - any CVE at all
 *   kev        - CVE is in CISA KEV
 *   actor      - skopnix cites at least one threat actor for the CVE
 *   epss>=0.5  - EPSS score at or above the threshold (also `>`)
 */
export function parseFailOn(values: string | string[] | undefined): FailRule[] {
  const list = (Array.isArray(values) ? values : values ? [values] : [])
    .flatMap((v) => v.replace(/\s*(>=|>)\s*/g, "$1").split(/[\s,]+/))
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
  return list.map((token) => {
    if (token === "any" || token === "kev" || token === "actor") return { kind: token };
    if (token === "actors") return { kind: "actor" };
    const m = /^epss(>=|>)(\d*\.?\d+)$/.exec(token);
    if (m) {
      const threshold = Number(m[2]);
      if (!(threshold >= 0 && threshold <= 1)) {
        throw new FailOnError(`--fail-on ${token}: EPSS threshold must be between 0 and 1`);
      }
      return { kind: "epss", op: m[1] as ">=" | ">", threshold };
    }
    throw new FailOnError(
      `--fail-on: unknown rule "${token}" (use kev, actor, any, or epss>=0.5)`,
    );
  });
}

export function ruleLabel(rule: FailRule): string {
  return rule.kind === "epss" ? `epss${rule.op}${rule.threshold}` : rule.kind;
}

export function evaluateFailOn(rules: FailRule[], results: ComponentResult[]): FailHit[] {
  const hits: FailHit[] = [];
  if (rules.length === 0) return hits;
  for (const r of results) {
    const component = r.version ? `${r.name}@${r.version}` : r.name;
    for (const cve of r.cves) {
      const matched = rules.find((rule) => {
        switch (rule.kind) {
          case "any":
            return true;
          case "kev":
            return cve.kev;
          case "actor":
            return cve.actors.length > 0;
          case "epss":
            if (cve.epss === null) return false;
            return rule.op === ">=" ? cve.epss >= rule.threshold : cve.epss > rule.threshold;
        }
      });
      if (matched) hits.push({ rule: ruleLabel(matched), component, cve: cve.cve });
    }
  }
  return hits;
}
