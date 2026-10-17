/** One row per (component, CVE): KEV first, then highest EPSS. */
export function findingRows(results) {
    const rows = [];
    for (const r of results) {
        const component = r.version ? `${r.name}@${r.version}` : r.name;
        for (const finding of r.cves)
            rows.push({ component, finding });
    }
    return rows.sort((a, b) => Number(b.finding.kev) - Number(a.finding.kev) ||
        (b.finding.epss ?? -1) - (a.finding.epss ?? -1) ||
        a.component.localeCompare(b.component) ||
        a.finding.cve.localeCompare(b.finding.cve));
}
export const fmtEpss = (e) => (e === null ? "-" : e.toFixed(3));
const actorNames = (f) => [...new Set(f.actors.map((a) => a.actor))].join(", ");
export function table(headers, rows, maxWidths = []) {
    const clip = (s, w) => w !== undefined && s.length > w ? `${s.slice(0, Math.max(1, w - 1))}…` : s;
    const cells = [headers, ...rows].map((r) => r.map((c, i) => clip(c.replace(/\s+/g, " "), maxWidths[i])));
    const widths = headers.map((_, i) => Math.max(...cells.map((r) => (r[i] ?? "").length)));
    const line = (r) => r
        .map((c, i) => (i === r.length - 1 ? c : c.padEnd(widths[i] ?? 0)))
        .join("  ")
        .trimEnd();
    return [line(cells[0]), widths.map((w) => "-".repeat(w)).join("  "), ...cells.slice(1).map(line)].join("\n");
}
export function summaryLine(report) {
    const s = report.stats;
    return (`${s.components} components checked, ${s.vulnerableComponents} with known CVEs: ` +
        `${s.findings} CVE findings, ${s.kev} in KEV, ${s.withActors} with cited threat actors.`);
}
export function textReport(report) {
    const rows = findingRows(report.results);
    const out = [];
    if (rows.length) {
        out.push(table(["COMPONENT", "CVE", "KEV", "EPSS", "CITED ACTORS"], rows.map(({ component, finding: f }) => [
            component,
            f.cve,
            f.kev ? "yes" : "",
            fmtEpss(f.epss),
            actorNames(f),
        ]), [48, 20, 3, 5, 60]), "");
    }
    out.push(summaryLine(report));
    if (report.stats.skipped) {
        out.push(`(${report.stats.skipped} SBOM entries skipped: duplicates, files, or no version/purl/cpe)`);
    }
    out.push(...failLines(report));
    return out.join("\n") + "\n";
}
function failLines(report) {
    if (report.failOn.length === 0)
        return [];
    if (!report.failed)
        return [`fail-on ${report.failOn.join(",")}: passed.`];
    const byRule = new Map();
    for (const h of report.hits)
        byRule.set(h.rule, (byRule.get(h.rule) ?? 0) + 1);
    const parts = [...byRule].map(([rule, n]) => `${n} × ${rule}`);
    return [`fail-on ${report.failOn.join(",")}: FAILED (${parts.join(", ")}).`];
}
const mdCell = (s) => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const MD_ROW_LIMIT = 300;
/** GitHub-flavoured markdown, sized for $GITHUB_STEP_SUMMARY (1 MiB cap). */
export function markdownReport(report) {
    const rows = findingRows(report.results);
    const status = report.failOn.length === 0 ? "" : report.failed ? " — ❌ failed" : " — ✅ passed";
    const out = [`### skopnix stack check${status}`, ""];
    out.push(`\`${mdCell(report.source)}\` (${report.format}) · ${summaryLine(report)}`, "");
    if (report.failOn.length) {
        out.push(...failLines(report).map((l) => `**${l}**`), "");
    }
    if (rows.length === 0) {
        out.push("No known CVEs for these components.", "");
        return out.join("\n");
    }
    out.push("| Component | CVE | KEV | EPSS | Cited actors |", "|---|---|:-:|--:|---|");
    for (const { component, finding: f } of rows.slice(0, MD_ROW_LIMIT)) {
        const actors = f.actors
            .map((a) => (a.url ? `[${mdCell(a.actor)}](${a.url})` : mdCell(a.actor)))
            .filter((v, i, arr) => arr.indexOf(v) === i)
            .join(", ");
        out.push(`| \`${mdCell(component)}\` | [${f.cve}](https://skopnix.com/cve/${encodeURIComponent(f.cve)}) | ${f.kev ? "🔴 KEV" : ""} | ${fmtEpss(f.epss)} | ${actors} |`);
    }
    if (rows.length > MD_ROW_LIMIT) {
        out.push("", `_…and ${rows.length - MD_ROW_LIMIT} more rows; run \`skopnix check --json\` for all of them._`);
    }
    const quoted = rows.filter((r) => r.finding.actors.some((a) => a.quote));
    if (quoted.length) {
        out.push("", "<details><summary>Why these actors are cited</summary>", "");
        for (const { finding: f } of quoted.slice(0, MD_ROW_LIMIT)) {
            for (const a of f.actors) {
                if (!a.quote)
                    continue;
                const src = a.url ? ` ([source](${a.url}))` : "";
                out.push(`- **${mdCell(a.actor)}** · ${f.cve}: “${mdCell(a.quote)}”${src}`);
            }
        }
        out.push("", "</details>");
    }
    out.push("");
    return out.join("\n");
}
