export default function Home() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-[#0b0b0d] px-6 text-center">
      <svg viewBox="0 0 40 40" width="36" height="36" fill="none" aria-hidden="true" className="mb-6 opacity-90">
        <circle cx="20" cy="20" r="15" stroke="#e0514f" strokeWidth="1.4" />
        <circle cx="20" cy="20" r="3.4" fill="#e0514f" />
        <path d="M20 1.5v9M20 29.5v9M1.5 20h9M29.5 20h9" stroke="#e0514f" strokeWidth="1.4" />
      </svg>
      <p className="mb-2 font-mono text-xs uppercase tracking-[0.2em] text-zinc-500">ctiaze / developer</p>
      <h1 className="mb-4 max-w-xl text-3xl font-normal italic text-zinc-100" style={{ fontFamily: "Georgia, serif" }}>
        API &amp; MCP portal — tikilir
      </h1>
      <p className="max-w-md text-sm leading-relaxed text-zinc-400">
        Azərbaycan-dilli CTI feed-inin machine-readable tərəfi burada olacaq: feed.json, RSS,
        IOC/CVE lookup API və read-only MCP server. Hazırda tikinti mərhələsindədir.
      </p>
      <a
        href="https://ctiaze.tech"
        className="mt-8 font-mono text-xs uppercase tracking-widest text-[#e0514f] hover:underline"
      >
        ctiaze.tech →
      </a>
    </div>
  );
}
