import { appendFile, readFile } from "node:fs/promises";
export function processIo() {
    return {
        stdout: (s) => void process.stdout.write(s),
        stderr: (s) => void process.stderr.write(s),
        readFile: (p) => readFile(p, "utf8"),
        readStdin: async () => {
            const chunks = [];
            for await (const c of process.stdin)
                chunks.push(c);
            return Buffer.concat(chunks).toString("utf8");
        },
        appendFile: (p, d) => appendFile(p, d, "utf8"),
        env: process.env,
    };
}
