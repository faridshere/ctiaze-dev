import { MongoClient } from "mongodb";

// Server-only. Same READ-ONLY MongoDB user that ctiaze.tech uses — this portal
// only ever reads the published-story archive, never writes.
const uri = process.env.MONGO_URI_READONLY;

if (!uri) {
  throw new Error(
    "MONGO_URI_READONLY is not set. Use the same read-only credential as ctiaze-web — never a read-write cred."
  );
}

declare global {
  var _mongoClientPromise: Promise<MongoClient> | undefined;
}

const client = new MongoClient(uri, { serverSelectionTimeoutMS: 8000 });

const clientPromise: Promise<MongoClient> =
  global._mongoClientPromise ?? client.connect();

if (process.env.NODE_ENV !== "production") {
  global._mongoClientPromise = clientPromise;
}

export async function getDb() {
  const c = await clientPromise;
  return c.db("ctiaze");
}
