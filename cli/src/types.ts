// What POST /api/v1/stack takes, one entry per component.
export type Component = {
  name: string;
  version: string;
  purl?: string;
  cpe?: string;
};

// A threat actor the site cites for a CVE, with the sentence that ties them.
export type ActorCitation = {
  actor: string;
  quote?: string;
  url?: string;
};

export type CveFinding = {
  cve: string;
  kev: boolean;
  epss: number | null; // 0..1, null when FIRST has no score yet
  actors: ActorCitation[];
};

export type ComponentResult = Component & { cves: CveFinding[] };
