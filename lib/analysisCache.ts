import { randomBytes } from "node:crypto";

import { Redis } from "@upstash/redis";

let client: Redis | null | undefined;

function redis(): Redis | null {
  if (client !== undefined) return client;
  const url = process.env.UPSTASH_REDIS_REST_URL?.trim();
  const token = process.env.UPSTASH_REDIS_REST_TOKEN?.trim();
  client = url && token ? new Redis({ url, token }) : null;
  return client;
}

const LOCK_TTL_MS = 30_000;
const CACHE_TTL_SECONDS = 60 * 60;

const RELEASE_IF_OWNER = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end";
const CACHE_IF_OWNER = "if redis.call('GET', KEYS[2]) == ARGV[1] then return redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3]) else return nil end";

const cacheKey = (digest: string, mode: string) => `devsec:analysis:v1:${digest}:${mode}`;
const lockKey = (digest: string, mode: string) => `devsec:analysis:v1:lock:${digest}:${mode}`;

export function cacheEnabled(): boolean {
  return redis() !== null;
}

export async function readAnalysisCache<T>(digest: string, mode: string): Promise<T | null> {
  const instance = redis();
  if (!instance) return null;
  const raw = await instance.get<string>(cacheKey(digest, mode));
  if (!raw) return null;
  try {
    return typeof raw === "string" ? (JSON.parse(raw) as T) : (raw as T);
  } catch {
    return null;
  }
}

export async function acquireAnalysisLock(digest: string, mode: string): Promise<string | null> {
  const instance = redis();
  if (!instance) return "cache-disabled";
  const owner = randomBytes(18).toString("base64url");
  const acquired = await instance.set(lockKey(digest, mode), owner, { nx: true, px: LOCK_TTL_MS });
  return acquired ? owner : null;
}

export async function cacheWhileLockOwner<T>(digest: string, mode: string, owner: string, value: T): Promise<boolean> {
  const instance = redis();
  if (!instance || owner === "cache-disabled") return false;
  const result = await instance.eval(CACHE_IF_OWNER, [cacheKey(digest, mode), lockKey(digest, mode)], [owner, JSON.stringify(value), String(CACHE_TTL_SECONDS)]);
  return result === "OK";
}

export async function releaseAnalysisLock(digest: string, mode: string, owner: string): Promise<void> {
  const instance = redis();
  if (!instance || owner === "cache-disabled") return;
  await instance.eval(RELEASE_IF_OWNER, [lockKey(digest, mode)], [owner]);
}

export async function waitForCachedAnalysis<T>(digest: string, mode: string): Promise<T | null> {
  for (let attempt = 0; attempt < 6; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 200));
    const cached = await readAnalysisCache<T>(digest, mode);
    if (cached) return cached;
  }
  return null;
}
