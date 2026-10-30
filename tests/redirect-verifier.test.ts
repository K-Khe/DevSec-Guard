import { describe, expect, it } from "vitest";

import { MAX_REDIRECT_HOPS, verifyRedirectChain } from "../lib/redirectVerifier";

function response(status: number, location?: string): Response {
  return new Response(null, { status, headers: location ? { location } : undefined });
}

function scripted(responses: Response[]) {
  let cursor = 0;
  return async () => {
    const next = responses[cursor++];
    if (!next) throw new Error("unexpected network request");
    return next;
  };
}

const allowAll = async () => {};

describe("redirect verifier", () => {
  it("accepts an immediate same-host HTTP to HTTPS upgrade", async () => {
    const result = await verifyRedirectChain(new URL("http://example.com/"), {
      fetcher: scripted([response(301, "https://example.com/"), response(200)]), validateTarget: allowAll,
    });
    expect(result.evidence).toMatchObject({ status: "http_upgraded", secure: true });
    expect(result.response.finalUrl.protocol).toBe("https:");
  });

  it("flags a first redirect that changes host before HTTPS is established", async () => {
    const result = await verifyRedirectChain(new URL("http://example.com/"), {
      fetcher: scripted([response(301, "https://www.example.com/"), response(200)]), validateTarget: allowAll,
    });
    expect(result.evidence.status).toBe("invalid_first_upgrade");
    expect(result.evidence.secure).toBe(false);
  });

  it("detects an HTTPS downgrade anywhere in the chain", async () => {
    const result = await verifyRedirectChain(new URL("https://example.com/"), {
      fetcher: scripted([response(302, "http://example.com/login"), response(301, "https://example.com/login"), response(200)]), validateTarget: allowAll,
    });
    expect(result.evidence.status).toBe("downgrade_detected");
    expect(result.evidence.secure).toBe(false);
  });

  it("allows a terminal response at the fifth hop", async () => {
    const chain = Array.from({ length: MAX_REDIRECT_HOPS - 1 }, () => response(302, "/next"));
    const result = await verifyRedirectChain(new URL("https://example.com/"), {
      fetcher: scripted([...chain, response(200)]), validateTarget: allowAll,
    });
    expect(result.evidence.hops).toHaveLength(MAX_REDIRECT_HOPS);
    expect(result.evidence.status).toBe("clean_secure");
  });

  it("stops when hop five still asks for another redirect", async () => {
    const chain = Array.from({ length: MAX_REDIRECT_HOPS }, () => response(302, "/next"));
    await expect(verifyRedirectChain(new URL("https://example.com/"), {
      fetcher: scripted(chain), validateTarget: allowAll,
    })).rejects.toMatchObject({ message: "Too many redirects." });
  });

  it("validates every redirect target before requesting it", async () => {
    const checked: string[] = [];
    await expect(verifyRedirectChain(new URL("https://example.com/"), {
      fetcher: scripted([response(302, "http://127.0.0.1/admin")]),
      validateTarget: async (url) => {
        checked.push(url.hostname);
        if (url.hostname === "127.0.0.1") throw new Error("blocked target");
      },
    })).rejects.toThrow("blocked target");
    expect(checked).toEqual(["example.com", "127.0.0.1"]);
  });
});
