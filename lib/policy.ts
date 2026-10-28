import { createHash, timingSafeEqual } from "node:crypto";
import { ScanError } from "./validate";

export const USAGE_POLICY_SUMMARY =
  "Passive, non-intrusive security check only. You must own the target domain or have explicit authorization from its owner.";

const DEFAULT_BLOCKED_SUFFIXES = [".gov", ".mil"];

function parseHostList(envVar: string | undefined): string[] {
  if (!envVar) return [];
  return envVar
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

/** Matches exact host (`example.com`), wildcard (`*.example.com`), or suffix (`.gov`). */
export function matchesHostPattern(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase();
  if (p.startsWith("*.")) {
    const base = p.slice(2);
    return h === base || h.endsWith(`.${base}`);
  }
  if (p.startsWith(".")) {
    return h.endsWith(p);
  }
  return h === p;
}

/** Constant-time token comparison using SHA-256 digests so lengths do not leak. */
function safeTokenEquals(provided: string, expected: string): boolean {
  const a = createHash("sha256").update(provided).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

/**
 * Enforces optional API token authentication (`SCANNER_ACCESS_TOKEN`).
 * When set, clients must supply `x-scanner-token` or `Authorization: Bearer <token>`.
 */
export function assertRequestAuthorized(req: Request): void {
  const expectedToken = process.env.SCANNER_ACCESS_TOKEN?.trim();
  if (!expectedToken) return;

  const headerToken = req.headers.get("x-scanner-token")?.trim();
  const bearerMatch = req.headers.get("authorization")?.match(/^Bearer\s+(.+)$/i);
  const provided = headerToken || bearerMatch?.[1]?.trim() || "";

  if (!provided || !safeTokenEquals(provided, expectedToken)) {
    throw new ScanError("Unauthorized: valid scanner access token required.", 401);
  }
}

/**
 * Enforces usage policy:
 * 1. Explicit user attestation (`authorized: true`) when `REQUIRE_SCAN_ATTESTATION` is not `"false"`.
 * 2. Blocked host suffixes (`SCAN_BLOCKED_HOSTS` + `.gov` / `.mil` default).
 * 3. Optional allowed host scope (`SCAN_ALLOWED_HOSTS`) for restricted production deployments.
 */
export function assertTargetPolicy(url: URL, authorizedAttestation?: unknown): void {
  const requireAttestation = process.env.REQUIRE_SCAN_ATTESTATION?.toLowerCase() !== "false";
  if (requireAttestation && authorizedAttestation !== true) {
    throw new ScanError(
      "Please confirm that you own this site or have explicit permission to scan it.",
      403,
    );
  }

  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const allowedPatterns = parseHostList(process.env.SCAN_ALLOWED_HOSTS);
  const blockedPatterns = [
    ...DEFAULT_BLOCKED_SUFFIXES,
    ...parseHostList(process.env.SCAN_BLOCKED_HOSTS),
  ];

  // If an explicit allowlist is configured, only listed hosts are permitted.
  if (allowedPatterns.length > 0) {
    const isAllowed = allowedPatterns.some((pattern) => matchesHostPattern(host, pattern));
    if (!isAllowed) {
      throw new ScanError(
        "Target domain is outside the configured SCAN_ALLOWED_HOSTS scope for this deployment.",
        403,
      );
    }
    return;
  }

  if (blockedPatterns.some((pattern) => matchesHostPattern(host, pattern))) {
    throw new ScanError(
      "Scanning restricted government/military or policy-blocked domains is not permitted.",
      403,
    );
  }
}

