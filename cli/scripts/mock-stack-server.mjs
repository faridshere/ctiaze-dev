// A stand-in for POST /api/v1/stack, answering from test/fixtures/stack-response.json
// by component name. For trying the CLI or the Action before the real endpoint
// is live:  node scripts/mock-stack-server.mjs [port]  then
//           skopnix check sbom.json --api-base http://127.0.0.1:4555/api/v1
import http from "node:http";
import { readFileSync } from "node:fs";

const port = Number(process.argv[2] ?? process.env.PORT ?? 4555);
const canned = JSON.parse(readFileSync(new URL("../test/fixtures/stack-response.json", import.meta.url), "utf8"));
const byName = new Map(canned.components.map((c) => [c.name, c]));

http
  .createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      const send = (status, json) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(json));
      };
      if (req.method !== "POST" || !req.url?.endsWith("/stack")) return send(404, { error: "mock only serves POST /stack" });
      let sent;
      try {
        sent = JSON.parse(body).components;
      } catch {
        return send(400, { error: "body must be JSON {components:[...]}" });
      }
      if (!Array.isArray(sent) || sent.length > 500) return send(400, { error: "components must be an array of at most 500" });
      send(200, { components: sent.map((c) => ({ ...c, cves: byName.get(c.name)?.cves ?? [] })) });
    });
  })
  .listen(port, "127.0.0.1", () => console.log(`mock /stack on http://127.0.0.1:${port}/api/v1`));
