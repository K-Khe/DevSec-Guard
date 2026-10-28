/**
 * Sliding-window rate limiter with an Upstash Redis production backend.
 *
 * - Development without Redis credentials uses a per-instance in-memory fallback.
 * - With Upstash credentials, the Redis window is shared atomically by all instances.
 * - The client IP comes from proxy headers. Those are trustworthy only behind a proxy
 *   that overwrites them (Vercel, nginx with `proxy_set_header`, etc.). A global
 *   bucket is provided as a backstop that can't be bypassed by spoofing IPs.
 */

import { createHash, randomUUID } from "node:crypto";

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
  backend: "upstash" | "memory";
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

/** Records a development-only local hit for `key` under `rule`. */
function hitLocal(rule: RateLimitRule, key: string, now = Date.now()): RateLimitResult {
  sweep(now, rule.windowMs);
  const id = `${rule.name}:${key}`;
  const bucket = store.buckets.get(id) ?? { hits: [] };
  const cutoff = now - rule.windowMs;
  bucket.hits = bucket.hits.filter((t) => t > cutoff);

  if (bucket.hits.length >= rule.limit) {
    store.buckets.set(id, bucket);
    const retryAfterMs = bucket.hits[0] + rule.windowMs - now;
    return {
      ok: false,
      remaining: 0,
      retryAfterSec: Math.max(1, Math.ceil(retryAfterMs / 1000)),
      backend: "memory",
    };
  }

  bucket.hits.push(now);
  store.buckets.set(id, bucket);
  return {
    ok: true,
    remaining: rule.limit - bucket.hits.length,
    retryAfterSec: 0,
    backend: "memory",
  };
}

export class RateLimitStoreError extends Error {}

const UPSTASH_WINDOW_SCRIPT = `
local cutoff = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local member = ARGV[4]
local window = tonumber(ARGV[5])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
local count = redis.call('ZCARD', KEYS[1])
if count >= limit then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  return {0, count, tonumber(oldest[2])}
end
redis.call('ZADD', KEYS[1], now, member)
redis.call('PEXPIRE', KEYS[1], window)
return {1, count + 1, 0}
`;

function opaqueKey(value: string) {
  const salt = process.env.RATE_LIMIT_KEY_SALT ?? "";
  return createHash("sha256").update(`${salt}:${value}`).digest("hex");
}

function upstashConfig() {
  const url = process.env.UPSTASH_REDIS_REST_URL?.trim().replace(/\/$/, "");
  const token = process.env.UPSTASH_REDIS_REST_TOKEN?.trim();
  const namespace = process.env.RATE_LIMIT_NAMESPACE?.trim() || "devsec-guard";
  return { url, token, namespace };
}

async function hitUpstash(
  url: string,
  token: string,
  namespace: string,
  rule: RateLimitRule,
  key: string,
  now: number,
): Promise<RateLimitResult> {
  const redisKey = `${namespace}:rate-limit:${rule.name}:${opaqueKey(key)}`;
  const command = [
    "EVAL",
    UPSTASH_WINDOW_SCRIPT,
    "1",
    redisKey,
    String(now - rule.windowMs),
    String(rule.limit),
    String(now),
    `${now}:${randomUUID()}`,
    String(rule.windowMs),
  ];
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(command),
      signal: AbortSignal.timeout(2_000),
      cache: "no-store",
    });
  } catch {
    throw new RateLimitStoreError("Rate-limit store is unavailable.");
  }
  const payload = (await response.json().catch(() => null)) as { result?: unknown; error?: string } | null;
  if (!response.ok || payload?.error || !Array.isArray(payload?.result)) {
    throw new RateLimitStoreError("Rate-limit store is unavailable.");
  }
  const [allowed, count, oldest] = payload.result.map(Number);
  if (allowed === 1) {
    return {
      ok: true,
      remaining: Math.max(0, rule.limit - count),
      retryAfterSec: 0,
      backend: "upstash",
    };
  }
  return {
    ok: false,
    remaining: 0,
    retryAfterSec: Math.max(1, Math.ceil((oldest + rule.windowMs - now) / 1000)),
    backend: "upstash",
  };
}

/** Uses a shared Upstash window when configured; otherwise uses the local development fallback. */
export async function hit(rule: RateLimitRule, key: string, now = Date.now()): Promise<RateLimitResult> {
  const { url, token, namespace } = upstashConfig();
  if (url && token) return hitUpstash(url, token, namespace, rule, key, now);
  return hitLocal(rule, opaqueKey(key), now);
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
export async function enforceRateLimit(
  req: Request,
  perIp: RateLimitRule,
  global?: RateLimitRule,
): Promise<Response | null> {
  let ipResult: RateLimitResult;
  let globalResult: RateLimitResult | null;
  try {
    ipResult = await hit(perIp, clientIp(req));
    globalResult = ipResult.ok && global ? await hit(global, "all") : null;
  } catch (error) {
    if (error instanceof RateLimitStoreError) {
      return new Response(
        JSON.stringify({ error: "Rate limit service is temporarily unavailable. Please retry." }),
        {
          status: 503,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
    throw error;
  }
  const blocked = !ipResult.ok ? ipResult : globalResult && !globalResult.ok ? globalResult : null;
  if (!blocked) return null;

  const triggeredRule = !ipResult.ok ? perIp.name : global!.name;
  console.info(
    JSON.stringify({
      ts: new Date().toISOString(),
      type: "security_audit",
      action: "rate_limit.exceeded",
      actor: opaqueKey(clientIp(req)).slice(0, 16),
      status: 429,
      meta: { rule: triggeredRule, backend: blocked.backend, retryAfterSec: blocked.retryAfterSec },
    }),
  );

  return new Response(
    JSON.stringify({ error: `Too many requests. Please wait ${blocked.retryAfterSec}s and try again.` }),
    {
      status: 429,
      headers: {
        "Content-Type": "application/json",
        "Retry-After": String(blocked.retryAfterSec),
        "X-RateLimit-Backend": blocked.backend,
      },
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
