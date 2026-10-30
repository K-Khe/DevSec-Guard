import { sql } from "drizzle-orm";
import {
  char,
  check,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";

/**
 * A server-owned, expiring record of a passive external scan.
 * The raw capability token never enters this table; only its SHA-256 hex digest does.
 */
export const scanRecords = pgTable(
  "scan_records",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    // Normalized by the application to lower-case ASCII/punycode before insertion.
    targetHostname: varchar("target_hostname", { length: 253 }).notNull(),
    score: integer("score").notNull(),
    grade: varchar("grade", { length: 2 }).notNull(),
    detectedStack: text("detected_stack").array().notNull(),
    deterministicFindings: jsonb("deterministic_findings").notNull(),
    tokenDigest: char("token_digest", { length: 64 }).notNull().unique(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (table) => [
    // `unique()` above already creates an index for token_digest.
    index("scan_records_expires_at_idx").on(table.expiresAt),
    check("scan_records_score_range", sql`${table.score} between 0 and 100`),
    check(
      "scan_records_grade_valid",
      sql`${table.grade} in ('A+', 'A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D', 'F')`,
    ),
    check(
      "scan_records_expiry_timeline",
      sql`${table.expiresAt} > ${table.createdAt}`,
    ),
  ],
);

export type ScanRecord = typeof scanRecords.$inferSelect;
export type NewScanRecord = typeof scanRecords.$inferInsert;
