import { describe, expect, it } from "vitest";
import { hit, type RateLimitRule } from "../lib/rateLimit";

const rule: RateLimitRule = { name: `test-${Date.now()}`, limit: 2, windowMs: 1_000 };

describe("local rate-limit fallback", () => {
  it("limits within the window and permits requests after it expires", async () => {
    const start = 1_000_000;
    await expect(hit(rule, "test-client", start)).resolves.toMatchObject({ ok: true, remaining: 1 });
    await expect(hit(rule, "test-client", start + 1)).resolves.toMatchObject({ ok: true, remaining: 0 });
    await expect(hit(rule, "test-client", start + 2)).resolves.toMatchObject({ ok: false, retryAfterSec: 1 });
    await expect(hit(rule, "test-client", start + 1_001)).resolves.toMatchObject({ ok: true, remaining: 1 });
  });
});
