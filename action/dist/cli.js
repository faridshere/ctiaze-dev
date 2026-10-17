import { parseArgs } from "node:util";
import { ApiError, createClient } from "./api.js";
import { runCheck } from "./check.js";
import { FailOnError } from "./fail-on.js";
import { markdownReport, table, textReport } from "./format.js";
import { SbomError } from "./sbom.js";
import { VERSION } from "./version.js";
export const EXIT_OK = 0;
export const EXIT_FAIL_ON = 1; // --fail-on matched
export const EXIT_ERROR = 2; // bad usage, unreadable SBOM, API error
const HELP = `skopnix ${VERSION} — check your stack against skopnix.com threat intelligence

Usage:
  skopnix check <sbom.json|list.txt|-> [options]
  skopnix claims [--days 7] [--limit 50] [--json]
  skopnix actor <name> [--json]

check options:
  --fail-on <rules>   exit 1 if any CVE matches: kev, actor, any, epss>=0.5
                      (comma-separated or repeated; any rule matching fails)
  --json              print the full report as JSON
  --markdown          print a markdown report (what the GitHub Action posts)
  --summary <file>    also append the markdown report to <file>

common options:
  --api-base <url>    API root (default https://skopnix.com/api/v1,
                      or $SKOPNIX_API_BASE)
  -h, --help          show this help
  -v, --version       print the version

Input formats: CycloneDX JSON, SPDX 2.x JSON, {"components":[...]}, or a text
list with one "vendor product version", "product version", purl or CPE per
line. Use - to read from stdin.

Exit codes: 0 ok, 1 --fail-on matched, 2 error.
`;
export async function main(argv, io) {
    const [command, ...rest] = argv;
    try {
        switch (command) {
            case undefined:
            case "help":
            case "-h":
            case "--help":
                io.stdout(HELP);
                return command === undefined ? EXIT_ERROR : EXIT_OK;
            case "-v":
            case "--version":
            case "version":
                io.stdout(`${VERSION}\n`);
                return EXIT_OK;
            case "check":
                return await checkCommand(rest, io);
            case "claims":
                return await claimsCommand(rest, io);
            case "actor":
                return await actorCommand(rest, io);
            default:
                io.stderr(`skopnix: unknown command "${command}"\n\n${HELP}`);
                return EXIT_ERROR;
        }
    }
    catch (e) {
        if (e instanceof ApiError ||
            e instanceof SbomError ||
            e instanceof FailOnError ||
            e instanceof UsageError ||
            isNodeError(e)) {
            io.stderr(`skopnix: ${e.message}\n`);
            return EXIT_ERROR;
        }
        throw e;
    }
}
class UsageError extends Error {
}
const isNodeError = (e) => e instanceof Error &&
    typeof e.code === "string" &&
    /^(E[A-Z]+|ERR_PARSE_ARGS_\w+)$/.test(e.code);
const apiBase = (flag, io) => flag || io.env.SKOPNIX_API_BASE || undefined;
async function checkCommand(args, io) {
    const { values, positionals } = parseArgs({
        args,
        allowPositionals: true,
        options: {
            "fail-on": { type: "string", multiple: true },
            json: { type: "boolean" },
            markdown: { type: "boolean" },
            summary: { type: "string" },
            "api-base": { type: "string" },
            help: { type: "boolean", short: "h" },
        },
    });
    if (values.help) {
        io.stdout(HELP);
        return EXIT_OK;
    }
    if (positionals.length !== 1)
        throw new UsageError("check takes exactly one SBOM path (or - for stdin)");
    const report = await runCheck({ input: positionals[0], failOn: values["fail-on"], apiBase: apiBase(values["api-base"], io) }, io);
    if (values.json)
        io.stdout(JSON.stringify(report, null, 2) + "\n");
    else if (values.markdown)
        io.stdout(markdownReport(report));
    else
        io.stdout(textReport(report));
    if (values.summary)
        await io.appendFile(values.summary, markdownReport(report));
    return report.failed ? EXIT_FAIL_ON : EXIT_OK;
}
async function claimsCommand(args, io) {
    const { values } = parseArgs({
        args,
        options: {
            days: { type: "string", default: "7" },
            limit: { type: "string", default: "50" },
            json: { type: "boolean" },
            "api-base": { type: "string" },
        },
    });
    const days = Number(values.days);
    const limit = Number(values.limit);
    if (!(days > 0))
        throw new UsageError("--days must be a positive number");
    if (!(Number.isInteger(limit) && limit > 0))
        throw new UsageError("--limit must be a positive integer");
    const client = createClient({ apiBase: apiBase(values["api-base"], io), fetch: io.fetch, sleep: io.sleep, now: io.now });
    const { claims } = await client.claims(days);
    if (values.json) {
        io.stdout(JSON.stringify({ days, count: claims.length, claims }, null, 2) + "\n");
        return EXIT_OK;
    }
    if (claims.length === 0) {
        io.stdout(`No claims in the last ${days} day(s).\n`);
        return EXIT_OK;
    }
    const rows = claims.slice(0, limit).map((c) => [
        String(c.at ?? c.seenAt ?? "").replace("T", " ").slice(0, 16),
        String(c.claimType ?? ""),
        String(c.group ?? ""),
        (Array.isArray(c.targets) && c.targets.length ? c.targets.join(", ") : String(c.summaryEn ?? c.text ?? "")),
        String(c.url ?? ""),
    ]);
    io.stdout(table(["WHEN (UTC)", "TYPE", "GROUP", "TARGETS", "SOURCE"], rows, [16, 12, 36, 48, 90]) + "\n");
    const more = claims.length > limit ? ` (showing ${limit}; --limit to see more)` : "";
    io.stdout(`\n${claims.length} claim(s) in the last ${days} day(s)${more}. These are third-party claims, not verified incidents.\n`);
    return EXIT_OK;
}
async function actorCommand(args, io) {
    const { values, positionals } = parseArgs({
        args,
        allowPositionals: true,
        options: { json: { type: "boolean" }, "api-base": { type: "string" } },
    });
    const name = positionals.join(" ").trim();
    if (!name)
        throw new UsageError("actor takes a name, e.g. skopnix actor apt28");
    const client = createClient({ apiBase: apiBase(values["api-base"], io), fetch: io.fetch, sleep: io.sleep });
    const a = await client.actor(name);
    if (values.json) {
        io.stdout(JSON.stringify(a, null, 2) + "\n");
        return EXIT_OK;
    }
    io.stdout(renderActor(a));
    return EXIT_OK;
}
function renderActor(a) {
    const out = [];
    const s = (v) => (v === null || v === undefined ? "" : String(v));
    const aliases = Array.isArray(a.aliases) ? a.aliases.map(String) : [];
    out.push(`${s(a.name)} (${s(a.id)})`);
    const facts = [
        ["type", s(a.type)],
        ["origin", s(a.origin_country ?? a.origin)],
        ["sponsor", s(a.state_sponsor)],
        ["MITRE", s(a.mitre)],
        ["last active", s(a.last_active).slice(0, 10)],
    ].filter(([, v]) => v);
    if (facts.length)
        out.push(facts.map(([k, v]) => `${k}: ${v}`).join(" · "));
    if (aliases.length) {
        out.push(`aka ${aliases.slice(0, 12).join(", ")}${aliases.length > 12 ? `, +${aliases.length - 12} more` : ""}`);
    }
    if (a.description)
        out.push("", wrap(s(a.description), 88));
    const cves = (Array.isArray(a.cves) ? a.cves : []);
    if (cves.length) {
        out.push("", `CVEs (${cves.length}):`);
        const rows = cves
            .slice(0, 15)
            .map((c) => [s(c.cve), c.kev ? "yes" : "", typeof c.epss === "number" ? c.epss.toFixed(3) : "-", s(c.evidence)]);
        out.push(table(["CVE", "KEV", "EPSS", "EVIDENCE"], rows, [20, 3, 5, 70]));
        if (cves.length > 15)
            out.push(`…${cves.length - 15} more (--json for all)`);
    }
    const reports = (Array.isArray(a.reports) ? a.reports : []);
    if (reports.length) {
        out.push("", "Recent reports:");
        for (const r of reports.slice(0, 5)) {
            out.push(`  ${s(r.date).slice(0, 10)}  ${s(r.source)}: ${s(r.title)}`, `              ${s(r.url)}`);
        }
    }
    if (a.url)
        out.push("", s(a.url));
    return out.join("\n") + "\n";
}
function wrap(text, width) {
    const lines = [];
    let line = "";
    for (const word of text.split(/\s+/)) {
        if (line && line.length + word.length + 1 > width) {
            lines.push(line);
            line = word;
        }
        else
            line = line ? `${line} ${word}` : word;
    }
    if (line)
        lines.push(line);
    return lines.join("\n");
}
