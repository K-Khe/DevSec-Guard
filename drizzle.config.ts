import { existsSync } from "node:fs";
import { loadEnvFile } from "node:process";

import { defineConfig } from "drizzle-kit";

// Drizzle Kit runs outside Next.js, so load local development variables explicitly.
// Existing process environment variables retain precedence.
if (existsSync(".env.local")) {
  loadEnvFile(".env.local");
}

const connectionString =
  process.env.DATABASE_URL_UNPOOLED ?? process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error(
    "DATABASE_URL_UNPOOLED (preferred for migrations) or DATABASE_URL is required.",
  );
}

export default defineConfig({
  dialect: "postgresql",
  schema: "./src/db/schema.ts",
  out: "./drizzle",
  dbCredentials: {
    // Neon’s direct URL is used when present; application traffic continues via DATABASE_URL.
    url: connectionString,
  },
});
