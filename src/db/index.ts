import "server-only";

import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";

import * as schema from "./schema";

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error(
    "Critical Configuration Error: DATABASE_URL is missing from the server environment.",
  );
}

// The Neon HTTP driver is appropriate for one-shot queries in Next.js serverless routes.
const sql = neon(connectionString);

export const db = drizzle({ client: sql, schema });
