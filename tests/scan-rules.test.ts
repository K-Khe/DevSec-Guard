import { beforeEach, describe, expect, it, vi } from "vitest";

const { normalizeUrl, safeFetch } = vi.hoisted(() => ({
  normalizeUrl: vi.fn(),
  safeFetch: vi.fn(),
}));

vi.mock("@/lib/validate", () => ({
  ScanError: class ScanError extends Error {
    status: number;
    constructor(message: string, status = 400) {
      super(message);
      this.status = status;
    }
  },
  normalizeUrl,
  safeFetch,
  readText: async (response: Response) => response.text(),
}));

import { POST } from "../app/api/scan/route";

function scannedResponse(url: string, headers: HeadersInit = {}, body = ""): Response & { finalUrl: URL } {
  return Object.assign(new Response(body, { status: 200, headers }), { finalUrl: new URL(url) });
}

beforeEach(() => {
  normalizeUrl.mockResolvedValue(new URL("https://example.test/"));
  safeFetch.mockImplementation(async (url: string) => {
    if (url.endsWith("/robots.txt")) return scannedResponse(url, { "content-type": "text/plain" }, "User-agent: *\nDisallow: /");
    if (url.endsWith("/.env")) return scannedResponse(url, {}, "DB_PASSWORD=not-a-real-secret");
    if (url.endsWith("/.git/HEAD")) return scannedResponse(url, {}, "ref: refs/heads/main");
    return scannedResponse(url);
  });
});

async function runScan() {
  const response = await POST(
    new Request("https://app.test/api/scan", { method: "POST", body: JSON.stringify({ url: "example.test", authorized: true }) }),
  );
  return response.json();
}

describe("robots.txt evaluation", () => {
  it("uses a bot-specific group instead of the wildcard group", async () => {
    safeFetch.mockImplementation(async (url: string) => {
      if (url.endsWith("/robots.txt")) {
        return scannedResponse(url, { "content-type": "text/plain" }, "User-agent: *\nDisallow: /\n\nUser-agent: GPTBot\nAllow: /");
      }
      if (url.endsWith("/.env") || url.endsWith("/.git/HEAD")) return scannedResponse(url, {}, "not a sensitive file");
      return scannedResponse(url);
    });

    const result = await runScan();
    expect(result.robots.bots.find((bot: { name: string }) => bot.name === "GPTBot").blocked).toBe(false);
    expect(result.robots.bots.find((bot: { name: string }) => bot.name === "ClaudeBot").blocked).toBe(true);
  });
});

describe("security-header evaluation", () => {
  it("marks a restrictive six-header configuration as strong", async () => {
    safeFetch.mockImplementation(async (url: string) => {
      if (url.endsWith("/robots.txt")) return scannedResponse(url, { "content-type": "text/plain" }, "User-agent: *\nDisallow: /");
      if (url.endsWith("/.env") || url.endsWith("/.git/HEAD")) return scannedResponse(url, {}, "not a sensitive file");
      return scannedResponse(url, {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=()",
      });
    });

    const result = await runScan();
    expect(result.headers.items.every((header: { state: string }) => header.state === "strong")).toBe(true);
  });

  it("identifies unsafe CSP, short HSTS, and unsafe referrer policy as weak", async () => {
    safeFetch.mockImplementation(async (url: string) => {
      if (url.endsWith("/robots.txt")) return scannedResponse(url, { "content-type": "text/plain" }, "");
      if (url.endsWith("/.env") || url.endsWith("/.git/HEAD")) return scannedResponse(url, {}, "not a sensitive file");
      return scannedResponse(url, {
        "content-security-policy": "script-src 'unsafe-inline' *",
        "strict-transport-security": "max-age=100",
        "referrer-policy": "unsafe-url",
      });
    });

    const result = await runScan();
    expect(result.headers.items.find((header: { key: string }) => header.key === "csp").state).toBe("weak");
    expect(result.headers.items.find((header: { key: string }) => header.key === "hsts").state).toBe("weak");
    expect(result.headers.items.find((header: { key: string }) => header.key === "rp").state).toBe("weak");
    expect(result.headers.items.find((header: { key: string }) => header.key === "xfo").state).toBe("missing");
  });
});

describe("cookie security evaluation", () => {
  it("returns security metadata without returning a cookie value", async () => {
    safeFetch.mockImplementation(async (url: string) => {
      if (url.endsWith("/robots.txt")) return scannedResponse(url, { "content-type": "text/plain" }, "");
      if (url.endsWith("/.env") || url.endsWith("/.git/HEAD")) return scannedResponse(url, {}, "not a sensitive file");
      return scannedResponse(url, { "set-cookie": "session=secret-value; Path=/; Secure; HttpOnly; SameSite=Lax" });
    });

    const result = await runScan();
    expect(result.cookies).toEqual([
      expect.objectContaining({ name: "session", secure: true, httpOnly: true, sameSite: "Lax", state: "strong" }),
    ]);
    expect(JSON.stringify(result.cookies)).not.toContain("secret-value");
  });

  it("marks missing cookie protections as weak", async () => {
    safeFetch.mockImplementation(async (url: string) => {
      if (url.endsWith("/robots.txt")) return scannedResponse(url, { "content-type": "text/plain" }, "");
      if (url.endsWith("/.env") || url.endsWith("/.git/HEAD")) return scannedResponse(url, {}, "not a sensitive file");
      return scannedResponse(url, { "set-cookie": "session=value; Path=/" });
    });

    const result = await runScan();
    expect(result.cookies[0]).toMatchObject({ name: "session", secure: false, httpOnly: false, sameSite: null, state: "weak" });
    expect(result.cookies[0].note).toContain("missing Secure");
  });
});

describe("HTML inspection", () => {
  it("reports high-signal patterns without returning page content", async () => {
    safeFetch.mockImplementation(async (url: string) => {
      if (url.endsWith("/robots.txt")) return scannedResponse(url, { "content-type": "text/plain" }, "");
      if (url.endsWith("/.env") || url.endsWith("/.git/HEAD")) return scannedResponse(url, {}, "not a sensitive file");
      return scannedResponse(
        url,
        { "content-type": "text/html" },
        `<form action="http://example.test/login"></form><script>const api_key="not-returned-secret";//# sourceMappingURL=app.js.map</script><a href="https://external.test" target="_blank">link</a>`,
      );
    });

    const result = await runScan();
    expect(result.htmlFindings.map((finding: { key: string }) => finding.key)).toEqual(
      expect.arrayContaining(["insecure-form", "possible-secret", "source-map", "unsafe-blank-link"]),
    );
    expect(JSON.stringify(result.htmlFindings)).not.toContain("not-returned-secret");
  });
});

describe("deterministic scoring", () => {
  it("forces an F when a sensitive file is exposed", async () => {
    const result = await runScan();
    expect(result).toMatchObject({ score: 15, grade: "F" });
  });

  it("does not award leak-check points when paths are unreachable", async () => {
    safeFetch.mockImplementation(async (url: string) => {
      if (url.endsWith("/robots.txt")) return scannedResponse(url, { "content-type": "text/plain" }, "User-agent: *\nDisallow: /");
      if (url.endsWith("/.env") || url.endsWith("/.git/HEAD")) throw new Error("network timeout");
      return scannedResponse(url, {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=()",
      });
    });

    const result = await runScan();
    expect(result.leaks.every((leak: { state: string }) => leak.state === "unreachable")).toBe(true);
    expect(result).toMatchObject({ score: 90, grade: "A" });
  });
});
