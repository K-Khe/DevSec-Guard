import { describe, expect, it } from "vitest";
import { isPrivateIP, normalizeUrl } from "../lib/validate";

describe("SSRF address guard", () => {
  it.each([
    "127.0.0.1",
    "10.0.0.1",
    "169.254.169.254",
    "192.168.1.1",
    "::1",
    "fc00::1",
    "::ffff:127.0.0.1",
    "64:ff9b::7f00:1",
    "2002:7f00:0001::",
  ])("blocks private or special address %s", (ip) => {
    expect(isPrivateIP(ip)).toBe(true);
  });

  it.each(["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])("allows public address %s", (ip) => {
    expect(isPrivateIP(ip)).toBe(false);
  });

  it("rejects a localhost target before DNS lookup", async () => {
    await expect(normalizeUrl("http://localhost:3000")).rejects.toThrow("Private and local addresses");
  });
});
