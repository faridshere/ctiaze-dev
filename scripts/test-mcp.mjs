// Local smoke test: connect to the MCP server like a real agent would and
// exercise every tool against live Mongo data. Not committed as a test suite —
// just a verification harness.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const url = process.argv[2] || "http://localhost:3006/api/mcp";
const transport = new StreamableHTTPClientTransport(new URL(url));
const client = new Client({ name: "ctiaze-smoke-test", version: "1.0.0" });

await client.connect(transport);
console.log("connected to", url);

const { tools } = await client.listTools();
console.log("\nTOOLS:", tools.map((t) => t.name).join(", "));

async function call(name, args) {
  const res = await client.callTool({ name, arguments: args });
  const text = res.content?.[0]?.text ?? "(no text)";
  console.log(`\n== ${name}(${JSON.stringify(args)}) ==`);
  console.log(text.slice(0, 420));
}

await call("get_recent_threats", { limit: 2 });
await call("get_recent_kev", { limit: 2 });
await call("search_threats", { query: "ransomware", limit: 2 });
await call("lookup_cve", { cve_id: "CVE-2024-3400" });

await client.close();
console.log("\nOK — all tools responded.");
process.exit(0);
