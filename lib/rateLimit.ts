/**
 * Simple in-memory sliding-window rate limiter.
 *
 * Limitations (by design, to stay dependency-free):
 * - State is per server instance. On serverless / multi-instance deployments each
 *   instance has its own counters, so use Redis/Upstash or similar for strict limits.
 * - The client IP comes from proxy headers. Those are trustworthy only behind a proxy
 *   that overwrites them (Vercel, nginx with `proxy_set_header`, etc.). A global
 *   bucket is provided as a backstop that can't be bypassed by spoofing IPs.
 */

interface Bucket {
  hits: number[];
}

interface Store {
  buckets: Map<string, Bucket>;
  lastSweep: number;
}

// Keep state on globalThis so it survives dev-mode hot reloads.
const g = globalThis as typeof globalThis & { __devsecRateLimit?: Store };
const store: Store = (g.__devsecRateLimit ??= { buckets: new Map(), lastSweep: Date.now() });

const MAX_BUCKETS = 10_000;
const SWEEP_INTERVAL_MS = 60_000;

export interface RateLimitRule {
  /** Bucket namespace, e.g. "scan" or "analyze:global". */
  name: string;
  /** Max requests allowed within the window. */
  limit: number;
  windowMs: number;
}

export interface RateLimitResult {
  ok: boolean;
  remaining: number;
  retryAfterSec: number;
}

function sweep(now: number, maxWindowMs: number) {
  if (now - store.lastSweep < SWEEP_INTERVAL_MS && store.buckets.size < MAX_BUCKETS) return;
  store.lastSweep = now;
  store.buckets.forEach((bucket, key) => {
    if (!bucket.hits.length || now - bucket.hits[bucket.hits.length - 1] > maxWindowMs) {
      store.buckets.delete(key);
    }
  });
  // Hard cap: if still too large (e.g. IP-spray attack), drop the oldest entries.
  if (store.buckets.size >= MAX_BUCKETS) {
    const excess = store.buckets.size - MAX_BUCKETS / 2;
    let i = 0;
    for (const key of Array.from(store.buckets.keys())) {
      if (i++ >= excess) break;
      store.buckets.delete(key);
    }
  }
}

/** Records a hit for `key` under `rule` and reports whether it is allowed. */
export function hit(rule: RateLimitRule, key: string, now = Date.now()): RateLimitResult {
  sweep(now, rule.windowMs);
  const id = `${rule.name}:${key}`;
  const bucket = store.buckets.get(id) ?? { hits: [] };
  const cutoff = now - rule.windowMs;
  bucket.hits = bucket.hits.filter((t) => t > cutoff);

  if (bucket.hits.length >= rule.limit) {
    store.buckets.set(id, bucket);
    const retryAfterMs = bucket.hits[0] + rule.windowMs - now;
    return { ok: false, remaining: 0, retryAfterSec: Math.max(1, Math.ceil(retryAfterMs / 1000)) };
  }

  bucket.hits.push(now);
  store.buckets.set(id, bucket);
  return { ok: true, remaining: rule.limit - bucket.hits.length, retryAfterSec: 0 };
}

/** Best-effort client IP from common proxy headers. */
export function clientIp(req: Request): string {
  const h = req.headers;
  const forwarded = h.get("x-forwarded-for")?.split(",")[0]?.trim();
  return h.get("x-real-ip")?.trim() || forwarded || "unknown";
}

/**
 * Applies a per-IP rule and optional global rule. Returns a 429 response when
 * limited, or null when the request may proceed.
 */
export function enforceRateLimit(
  req: Request,
  perIp: RateLimitRule,
  global?: RateLimitRule,
): Response | null {
  const ipResult = hit(perIp, clientIp(req));
  const globalResult = ipResult.ok && global ? hit(global, "all") : null;
  const blocked = !ipResult.ok ? ipResult : globalResult && !globalResult.ok ? globalResult : null;
  if (!blocked) return null;

  return new Response(
    JSON.stringify({ error: `Too many requests. Please wait ${blocked.retryAfterSec}s and try again.` }),
    {
      status: 429,
      headers: { "Content-Type": "application/json", "Retry-After": String(blocked.retryAfterSec) },
    },
  );
}

const MINUTE = 60_000;

function envInt(name: string, fallback: number): number {
  const n = Number.parseInt(process.env[name] ?? "", 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export const RATE_LIMITS = {
  scan: { name: "scan", limit: envInt("RATE_LIMIT_SCAN_PER_MIN", 10), windowMs: MINUTE },
  analyze: { name: "analyze", limit: envInt("RATE_LIMIT_ANALYZE_PER_MIN", 5), windowMs: MINUTE },
  analyzeGlobal: {
    name: "analyze:global",
    limit: envInt("RATE_LIMIT_ANALYZE_GLOBAL_PER_MIN", 30),
    windowMs: MINUTE,
  },
} satisfies Record<string, RateLimitRule>;
