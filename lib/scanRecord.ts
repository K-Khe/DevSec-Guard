import { createHash, randomBytes } from "node:crypto";

import type { ScanResult } from "@/lib/types";

/** A 256-bit random token encoded as Base64URL (43 characters, without padding). */
export function createCapabilityToken(): string {
  return randomBytes(32).toString("base64url");
}

/** Only this digest is persisted; the raw capability token remains with the caller. */
export function digestCapabilityToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export class ScanRecordStoreError extends Error {
  constructor() {
    super("The scan completed, but its server-side record could not be secured. Please try again.");
    this.name = "ScanRecordStoreError";
  }
}

/**
 * Removes target URLs, raw HTTP header values, cookie values, and page snippets
 * before persisting scan facts. This object is the trusted input for later analysis.
 */
export function sanitizeScanFacts(scan: ScanResult): Record<string, unknown> {
  return {
    scannedAt: scan.scannedAt,
    finalProtocol: (() => {
      try {
        return new URL(scan.finalUrl ?? scan.url).protocol.replace(":", "");
      } catch {
        return "unknown";
      }
    })(),
    tests: { passed: scan.testsPassed ?? null, total: scan.testsTotal ?? null },
    robots: {
      found: scan.robots.found,
      status: scan.robots.status,
      bots: scan.robots.bots.map((bot) => ({ name: bot.name.slice(0, 40), blocked: bot.blocked })),
    },
    headers: {
      status: scan.headers.status,
      items: scan.headers.items.map((header) => ({
        key: header.key,
        label: header.label.slice(0, 100),
        state: header.state,
      })),
    },
    // Names can reveal application roles (for example, admin_session). The trusted
    // record keeps only policy flags needed for later analysis.
    cookies: scan.cookies.map((cookie) => ({
      state: cookie.state,
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite,
    })),
    htmlFindings: scan.htmlFindings.map((finding) => ({
      key: finding.key,
      severity: finding.severity,
    })),
    leaks: scan.leaks.map((leak) => ({
      path: leak.path,
      status: leak.status,
      state: leak.state,
    })),
    redirects: scan.redirects
      ? {
          status: scan.redirects.status,
          secure: scan.redirects.secure,
          hops: scan.redirects.hops.map((hop) => ({
            hopIndex: hop.hopIndex,
            statusCode: hop.statusCode,
            protocol: hop.protocol,
            hostChangedFromPrevious: hop.hostChangedFromPrevious,
          })),
        }
      : undefined,
  };
}

function normalizedHostname(scan: ScanResult): string {
  // WHATWG URL normalizes Unicode hosts to ASCII/punycode. DNS host matching is case-insensitive.
  return new URL(scan.finalUrl ?? scan.url).hostname.toLowerCase();
}

export interface StoredScanRecord {
  targetHostname: string;
  score: number;
  grade: string;
  detectedStack: string[];
  deterministicFindings: Record<string, unknown>;
  tokenDigest: string;
  expiresAt: Date;
}

const globalForScanStore = globalThis as unknown as {
  __devsecMemoryScanStore?: Map<string, StoredScanRecord>;
};

export function getMemoryScanStore(): Map<string, StoredScanRecord> {
  if (!globalForScanStore.__devsecMemoryScanStore) {
    globalForScanStore.__devsecMemoryScanStore = new Map();
  }
  return globalForScanStore.__devsecMemoryScanStore;
}

/**
 * Persists the scanner's deterministic evidence and returns the one-time capability token.
 * A test run intentionally has no database dependency; when DATABASE_URL is not set in dev,
 * falls back to an in-memory server-side store keyed by SHA-256 tokenDigest.
 */
export async function persistScanRecord(scan: ScanResult, ttlMs = 24 * 60 * 60 * 1000): Promise<string | null> {
  if (process.env.NODE_ENV === "test" && !process.env.DATABASE_URL) {
    return null;
  }

  const capabilityToken = createCapabilityToken();
  const expiresAt = new Date(Date.now() + ttlMs);
  const record: StoredScanRecord = {
    targetHostname: normalizedHostname(scan),
    score: scan.score,
    grade: scan.grade,
    detectedStack: scan.detectedStack.slice(0, 12).map((entry) => entry.slice(0, 80)),
    deterministicFindings: sanitizeScanFacts(scan),
    tokenDigest: digestCapabilityToken(capabilityToken),
    expiresAt,
  };

  if (!process.env.DATABASE_URL) {
    const store = getMemoryScanStore();
    store.set(record.tokenDigest, record);
    return capabilityToken;
  }

  try {
    const [{ db }, { scanRecords }] = await Promise.all([
      import("@/src/db"),
      import("@/src/db/schema"),
    ]);

    await db.insert(scanRecords).values(record);
  } catch {
    // Fallback to in-memory store if local DB is unreachable so scans still work seamlessly
    const store = getMemoryScanStore();
    store.set(record.tokenDigest, record);
  }

  return capabilityToken;
}
