import { and, eq, gt } from "drizzle-orm";
import { z } from "zod";

import { digestCapabilityToken, getMemoryScanStore } from "@/lib/scanRecord";
import type { HeaderKey, HeaderState, ScanResult } from "@/lib/types";

const headerKey = z.enum(["csp", "xfo", "hsts", "xcto", "rp", "pp"]);
const headerState = z.enum(["strong", "weak", "missing"]);

const storedFactsSchema = z
  .object({
    scannedAt: z.string(),
    finalProtocol: z.enum(["http", "https", "unknown"]),
    tests: z.object({ passed: z.number().int().nullable(), total: z.number().int().nullable() }),
    robots: z.object({
      found: z.boolean(),
      status: z.number().int().nullable(),
      bots: z.array(z.object({ name: z.string().max(40), blocked: z.boolean() })).max(10),
    }),
    headers: z.object({
      status: z.number().int().nullable(),
      items: z.array(z.object({ key: headerKey, label: z.string().max(100), state: headerState })).max(10),
    }),
    cookies: z.array(z.object({
      // `name` is accepted only to read older records; new records never persist it.
      name: z.string().max(80).optional(), state: headerState, secure: z.boolean(), httpOnly: z.boolean(),
      sameSite: z.enum(["Strict", "Lax", "None"]).nullable(),
    })).max(20),
    htmlFindings: z.array(z.object({
      key: z.enum(["mixed-content", "insecure-form", "source-map", "possible-secret", "unsafe-blank-link", "missing-sri", "wordpress-surface", "php-version-exposure"]),
      severity: z.enum(["high", "medium", "low"]),
    })).max(10),
    leaks: z.array(z.object({
      path: z.string().max(60), status: z.number().int().nullable(), state: z.enum(["exposed", "soft-200", "safe", "unreachable"]),
    })).max(10),
    redirects: z.object({
      status: z.enum(["no_redirect", "http_upgraded", "clean_secure", "insecure_start", "invalid_first_upgrade", "downgrade_detected", "max_hops_exceeded", "invalid_redirect"]),
      secure: z.boolean(),
      hops: z.array(z.object({
        hopIndex: z.number().int().min(1).max(5),
        statusCode: z.number().int().min(100).max(599),
        protocol: z.enum(["http", "https"]),
        hostChangedFromPrevious: z.boolean(),
      })).max(5),
    }).optional(),
  })
  .strict();

export type TrustedEvidence = z.infer<typeof storedFactsSchema> & {
  score: number;
  grade: string;
  detectedStack: string[];
};

export class TrustedEvidenceError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = "TrustedEvidenceError";
  }
}

/** Loads an unexpired scan record by digest. The raw token never enters a SQL query. */
export async function loadTrustedEvidence(capabilityToken: string): Promise<{ evidence: TrustedEvidence; tokenDigest: string }> {
  const tokenDigest = digestCapabilityToken(capabilityToken);

  let record: {
    score: number;
    grade: string;
    detectedStack: string[];
    deterministicFindings: unknown;
  } | undefined;

  if (process.env.DATABASE_URL) {
    try {
      const [{ db }, { scanRecords }] = await Promise.all([import("@/src/db"), import("@/src/db/schema")]);
      const [dbRecord] = await db
        .select({
          score: scanRecords.score,
          grade: scanRecords.grade,
          detectedStack: scanRecords.detectedStack,
          deterministicFindings: scanRecords.deterministicFindings,
        })
        .from(scanRecords)
        .where(and(eq(scanRecords.tokenDigest, tokenDigest), gt(scanRecords.expiresAt, new Date())))
        .limit(1);
      record = dbRecord;
    } catch {
      /* fall back to memory store if DB connection fails */
    }
  }

  if (!record) {
    const mem = getMemoryScanStore().get(tokenDigest);
    if (mem && mem.expiresAt.getTime() > Date.now()) {
      record = {
        score: mem.score,
        grade: mem.grade,
        detectedStack: mem.detectedStack,
        deterministicFindings: mem.deterministicFindings,
      };
    }
  }

  if (!record) {
    throw new TrustedEvidenceError("This scan ticket is invalid or has expired. Run a new scan.", 404);
  }

  const facts = storedFactsSchema.safeParse(record.deterministicFindings);
  if (!facts.success) {
    throw new TrustedEvidenceError("The stored scan evidence is invalid. Run a new scan.", 422);
  }

  return {
    tokenDigest,
    evidence: { ...facts.data, score: record.score, grade: record.grade, detectedStack: record.detectedStack },
  };
}

/** Reconstructs a deliberately redacted, presentation-safe result for local rules and external AI. */
export function toRedactedScan(evidence: TrustedEvidence): ScanResult {
  return {
    url: "https://redacted-target.invalid/",
    finalUrl: "https://redacted-target.invalid/",
    scannedAt: evidence.scannedAt,
    score: evidence.score,
    grade: evidence.grade,
    testsPassed: evidence.tests.passed ?? undefined,
    testsTotal: evidence.tests.total ?? undefined,
    detectedStack: evidence.detectedStack,
    robots: evidence.robots,
    headers: {
      status: evidence.headers.status,
      items: evidence.headers.items.map((header) => ({
        ...header,
        key: header.key as HeaderKey,
        present: header.state !== "missing",
        state: header.state as HeaderState,
        value: null,
      })),
      isolation: [],
      exposures: [],
    },
    cookies: evidence.cookies.map((cookie, index) => ({
      name: cookie.name ?? `Observed cookie ${index + 1}`,
      state: cookie.state,
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite,
      path: "/",
      expires: "Session",
      prefix: null,
    })),
    htmlFindings: evidence.htmlFindings.map((finding) => ({
      ...finding,
      title: finding.key,
      note: "Observed in the public response; validate in the application before remediation.",
    })),
    leaks: evidence.leaks.map((leak) => ({
      ...leak,
      note: leak.state === "exposed" ? "Publicly served." : "Not publicly served.",
    })),
    redirects: evidence.redirects,
  };
}
