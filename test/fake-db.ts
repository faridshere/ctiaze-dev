// Minimal in-memory stand-in for the parts of the Mongo driver lib/intel.ts
// touches. It records every filter it is given and returns fixture rows; only
// the simple equality lookups get_actor_cves relies on are actually evaluated.
type Doc = Record<string, unknown>;

export type FakeDb = {
  calls: { collection: string; op: "find" | "findOne"; filter: Doc }[];
  collection: (name: string) => unknown;
};

function matches(doc: Doc, filter: Doc): boolean {
  return Object.entries(filter).every(([k, v]) => {
    if (k === "$or") return (v as Doc[]).some((f) => matches(doc, f));
    const field = doc[k];
    if (v instanceof RegExp) {
      return Array.isArray(field)
        ? field.some((x) => typeof x === "string" && v.test(x))
        : typeof field === "string" && v.test(field);
    }
    return field === v;
  });
}

export function fakeDb(data: Record<string, Doc[]>): FakeDb {
  const db: FakeDb = {
    calls: [],
    collection(name: string) {
      const rows = data[name] ?? [];
      return {
        find(filter: Doc) {
          db.calls.push({ collection: name, op: "find", filter });
          const cursor = {
            sort: () => cursor,
            limit: (n: number) => ({ toArray: async () => rows.slice(0, n) }),
          };
          return cursor;
        },
        async findOne(filter: Doc) {
          db.calls.push({ collection: name, op: "findOne", filter });
          return rows.find((r) => matches(r, filter)) ?? null;
        },
      };
    },
  };
  return db;
}
