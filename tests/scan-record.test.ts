import { describe, expect, it } from "vitest";

import { createCapabilityToken, digestCapabilityToken, sanitizeScanFacts } from "@/lib/scanRecord";
import type { ScanResult } from "@/lib/types";

describe("capability tokens", () => {
  it("creates a 256-bit Base64URL token without padding", () => {
    const token = createCapabilityToken();
    expect(token).toHaveLength(43);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("persists a SHA-256 hex digest rather than the raw token", () => {
    const token = createCapabilityToken();
    const digest = digestCapabilityToken(token);
    expect(digest).toHaveLength(64);
    expect(digest).toMatch(/^[a-f0-9]{64}$/);
    expect(digest).not.toBe(token);
  });

  it("does not persist observed cookie names", () => {
    const scan = {
      url: "https://example.com/", finalUrl: "https://example.com/", scannedAt: "2026-10-30T00:00:00.000Z", score: 0, grade: "F", detectedStack: [],
      robots: { found: false, status: 404, bots: [] }, headers: { status: 200, items: [] }, htmlFindings: [], leaks: [],
      cookies: [{ name: "admin_session", path: "/", expires: null, prefix: null, secure: true, httpOnly: true, sameSite: "Lax", state: "strong" }],
    } satisfies ScanResult;
    const facts = sanitizeScanFacts(scan);
    expect(JSON.stringify(facts)).not.toContain("admin_session");
  });
});
