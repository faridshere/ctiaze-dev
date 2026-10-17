// Entry point of the skopnix/stack-check GitHub Action (action/action.yml).
// It talks to the runner through the documented env/file protocol (INPUT_*,
// GITHUB_OUTPUT, GITHUB_STEP_SUMMARY, ::error:: commands) so it needs no
// @actions/* packages.
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runCheck } from "./check.js";
import { EXIT_ERROR, EXIT_FAIL_ON, EXIT_OK } from "./cli.js";
import { markdownReport, textReport } from "./format.js";
import { processIo } from "./io.js";
// The runner upper-cases input names and keeps hyphens: fail-on → INPUT_FAIL-ON.
const input = (io, name) => (io.env[`INPUT_${name.toUpperCase()}`] ?? "").trim();
// Workflow commands need %, CR and LF escaped.
const escapeData = (s) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
export async function runAction(io) {
    const sbom = input(io, "sbom");
    const failOn = input(io, "fail-on");
    const apiBase = input(io, "api-base") || undefined;
    const writeSummary = input(io, "summary").toLowerCase() !== "false";
    const summaryFile = io.env.GITHUB_STEP_SUMMARY;
    const outputFile = io.env.GITHUB_OUTPUT;
    const setOutputs = async (outputs) => {
        if (!outputFile)
            return;
        const lines = Object.entries(outputs).map(([k, v]) => `${k}=${String(v).replace(/\r?\n/g, " ")}\n`);
        await io.appendFile(outputFile, lines.join(""));
    };
    if (!sbom) {
        io.stdout("::error title=skopnix::input `sbom` is required\n");
        return EXIT_ERROR;
    }
    try {
        const report = await runCheck({ input: sbom, failOn: failOn ? [failOn] : [], apiBase }, io);
        io.stdout(textReport(report));
        if (writeSummary && summaryFile)
            await io.appendFile(summaryFile, markdownReport(report));
        const reportPath = join(io.env.RUNNER_TEMP || ".", "skopnix-report.json");
        await io.writeFile(reportPath, JSON.stringify(report, null, 2) + "\n");
        await setOutputs({
            components: report.stats.components,
            findings: report.stats.findings,
            kev: report.stats.kev,
            "with-actors": report.stats.withActors,
            failed: report.failed,
            report: reportPath,
        });
        if (report.failed) {
            const sample = report.hits
                .slice(0, 10)
                .map((h) => `${h.component} ${h.cve} (${h.rule})`)
                .join("\n");
            const more = report.hits.length > 10 ? `\n…and ${report.hits.length - 10} more` : "";
            io.stdout(`::error title=skopnix fail-on ${report.failOn.join(",")}::${escapeData(`${report.hits.length} finding(s) matched:\n${sample}${more}`)}\n`);
            return EXIT_FAIL_ON;
        }
        return EXIT_OK;
    }
    catch (e) {
        const message = e.message ?? String(e);
        io.stdout(`::error title=skopnix stack check::${escapeData(message)}\n`);
        if (writeSummary && summaryFile) {
            await io.appendFile(summaryFile, `### skopnix stack check — ⚠️ error\n\n\`\`\`\n${message}\n\`\`\`\n`);
        }
        await setOutputs({ failed: true });
        return EXIT_ERROR;
    }
}
// Run when executed by the runner (node dist/action.js), not when imported.
if (process.env.GITHUB_ACTIONS === "true" && process.argv[1] && /(^|[\\/])action\.js$/.test(process.argv[1])) {
    runAction({ ...processIo(), writeFile: (p, d) => writeFile(p, d, "utf8") }).then((code) => {
        process.exitCode = code;
    }, (e) => {
        process.stdout.write(`::error title=skopnix::${escapeData(String(e?.stack ?? e))}\n`);
        process.exitCode = 2;
    });
}
