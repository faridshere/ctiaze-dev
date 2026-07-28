import { MongoClient } from "mongodb";

// Server-only. Same READ-ONLY MongoDB user that ctiaze.tech uses — this portal
// only ever reads the published-story archive, never writes.
//
// The env check + connection are deferred to first call (not module load) on
// purpose: that way the site still builds and deploys even before
// MONGO_URI_READONLY is set in the Vercel project, and only the data-backed
// routes (the MCP endpoint) fail — at request time — until it is.
declare global {
  var _mongoClientPromise: Promise<MongoClient> | undefined;
}

function clientPromise(): Promise<MongoClient> {
  if (global._mongoClientPromise) return global._mongoClientPromise;
  const uri = process.env.MONGO_URI_READONLY;
  if (!uri) {
    throw new Error(
      "MONGO_URI_READONLY is not set. Add it (the same read-only credential as ctiaze-web) to the ctiaze-dev Vercel project environment variables."
    );
  }
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 8000 });
  const promise = client.connect();
  global._mongoClientPromise = promise;
  return promise;
}

export async function getDb() {
  const c = await clientPromise();
  return c.db("ctiaze");
}
