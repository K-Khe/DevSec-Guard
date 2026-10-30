import { describe, expect, it } from "vitest";

import { POST } from "../app/api/analyze/route";
import { toRedactedScan, type TrustedEvidence } from "@/lib/trustedEvidence";

const evidence: TrustedEvidence = {
  score: 55,
  grade: "C+",
  detectedStack: ["nginx"],
  scannedAt: "2026-10-29T00:00:00.000Z",
  finalProtocol: "https",
  tests: { passed: 5, total: 10 },
  robots: { found: true, status: 200, bots: [{ name: "GPTBot", blocked: false }] },
  headers: { status: 200, items: [{ key: "csp", label: "Content-Security-Policy", state: "missing" }] },
  cookies: [],
  htmlFindings: [],
  leaks: [{ path: "/.env", status: 404, state: "safe" }],
};

describe("trusted analysis boundary", () => {
  it("reconstructs a redacted analysis view without a real hostname or header value", () => {
    const scan = toRedactedScan(evidence);
    expect(scan.url).toBe("https://redacted-target.invalid/");
    expect(scan.headers.items[0].value).toBeNull();
    expect(scan.headers.items[0].state).toBe("missing");
  });

  it("rejects the former browser ScanResult payload instead of accepting it", async () => {
    const response = await POST(
      new Request("https://app.test/api/analyze", {
        method: "POST",
        body: JSON.stringify({ ...toRedactedScan(evidence), mode: "local" }),
      }),
    );
    expect(response.status).toBe(400);
  });
});
