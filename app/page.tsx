const TOOLS = [
  ["get_recent_threats", "Ən son dərc olunmuş CTI xəbərləri"],
  ["get_recent_kev", "Ən son aktiv istismar edilən (CISA KEV) zəifliklər"],
  ["search_threats", "Arxivdə açar sözlə axtarış (başlıq / kateqoriya / CVE)"],
  ["lookup_cve", "Bir CVE-nin ctiaze əhatəsində görünüb-görünmədiyini yoxla"],
];

const FEEDS = [
  ["feed.json", "https://ctiaze.tech/feed.json", "Machine-readable JSON feed"],
  ["rss.xml", "https://ctiaze.tech/rss.xml", "RSS 2.0"],
  ["llms.txt", "https://ctiaze.tech/llms.txt", "AI answer-engine map"],
];

export default function Home() {
  return (
    <main className="mx-auto min-h-screen max-w-3xl bg-[#0b0b0d] px-6 py-16 text-zinc-300">
      <div className="mb-14 flex items-center gap-3">
        <svg viewBox="0 0 40 40" width="30" height="30" fill="none" aria-hidden="true" className="opacity-90">
          <circle cx="20" cy="20" r="15" stroke="#e0514f" strokeWidth="1.4" />
          <circle cx="20" cy="20" r="3.4" fill="#e0514f" />
          <path d="M20 1.5v9M20 29.5v9M1.5 20h9M29.5 20h9" stroke="#e0514f" strokeWidth="1.4" />
        </svg>
        <span className="font-mono text-xs uppercase tracking-[0.2em] text-zinc-500">
          ctiaze / developer
        </span>
      </div>

      <h1 className="mb-4 text-4xl font-normal italic text-zinc-100" style={{ fontFamily: "Georgia, serif" }}>
        Machine-readable Azərbaycan CTI
      </h1>
      <p className="mb-14 max-w-xl leading-relaxed text-zinc-400">
        <a href="https://ctiaze.tech" className="text-[#e0514f] hover:underline">ctiaze.tech</a>-in
        agent-consumable tərəfi: AI agent-ləri və SOC copilot-ları üçün structured feed və read-only MCP server.
      </p>

      <section className="mb-14">
        <h2 className="mb-1 font-mono text-xs uppercase tracking-widest text-[#e0514f]">MCP server</h2>
        <p className="mb-4 text-sm text-zinc-400">
          Read-only Model Context Protocol server (Streamable HTTP). Endpoint:
        </p>
        <code className="mb-5 block rounded border border-zinc-800 bg-[#131317] px-4 py-3 font-mono text-sm text-zinc-200">
          https://ctiaze.dev/api/mcp
        </code>
        <div className="mb-6 divide-y divide-zinc-800 rounded border border-zinc-800">
          {TOOLS.map(([name, desc]) => (
            <div key={name} className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-baseline sm:gap-4">
              <code className="font-mono text-sm text-zinc-100 sm:w-52 sm:shrink-0">{name}</code>
              <span className="text-sm text-zinc-400">{desc}</span>
            </div>
          ))}
        </div>
        <p className="mb-2 text-sm text-zinc-500">Claude Code ilə qoşulmaq:</p>
        <pre className="overflow-x-auto rounded border border-zinc-800 bg-[#131317] px-4 py-3 font-mono text-xs text-zinc-300">
          claude mcp add --transport http ctiaze https://ctiaze.dev/api/mcp
        </pre>
      </section>

      <section className="mb-14">
        <h2 className="mb-4 font-mono text-xs uppercase tracking-widest text-[#e0514f]">Feeds</h2>
        <div className="divide-y divide-zinc-800 rounded border border-zinc-800">
          {FEEDS.map(([name, url, desc]) => (
            <a key={name} href={url} className="flex flex-col gap-1 px-4 py-3 hover:bg-[#131317] sm:flex-row sm:items-baseline sm:gap-4">
              <code className="font-mono text-sm text-[#e0514f] sm:w-40 sm:shrink-0">{name}</code>
              <span className="text-sm text-zinc-400">{desc}</span>
            </a>
          ))}
        </div>
      </section>

      <footer className="border-t border-zinc-800 pt-6 font-mono text-xs text-zinc-600">
        ctiaze.dev · read-only · <a href="https://ctiaze.tech" className="text-zinc-500 hover:text-[#e0514f]">ctiaze.tech →</a>
      </footer>
    </main>
  );
}
