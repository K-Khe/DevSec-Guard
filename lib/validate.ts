import { lookup } from "node:dns/promises";
import net from "node:net";

export class ScanError extends Error {
  status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}

function isPrivateIPv4(ip: string) {
  const [a, b] = ip.split(".").map(Number);
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

function isPrivateIP(ip: string) {
  const version = net.isIP(ip);
  if (version === 4) return isPrivateIPv4(ip);
  if (version === 6) {
    const l = ip.toLowerCase();
    if (l === "::" || l === "::1") return true;
    if (l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80")) return true;
    const mapped = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return mapped ? isPrivateIPv4(mapped[1]) : false;
  }
  return true;
}

/** Blocks localhost, private ranges and hosts that resolve to them (basic SSRF guard). */
export async function assertPublicHost(u: URL) {
  if (!["http:", "https:"].includes(u.protocol)) {
    throw new ScanError("Only http and https URLs can be scanned.");
  }
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const privateMsg = "Private and local addresses can't be scanned.";

  if (/(^localhost$|\.localhost$|\.local$|\.internal$)/.test(host)) throw new ScanError(privateMsg);
  if (net.isIP(host)) {
    if (isPrivateIP(host)) throw new ScanError(privateMsg);
    return;
  }
  if (!host.includes(".")) throw new ScanError("Enter a full domain, like example.com.");

  try {
    const addrs = await lookup(host, { all: true });
    if (addrs.some((a) => isPrivateIP(a.address))) throw new ScanError(privateMsg);
  } catch (e) {
    if (e instanceof ScanError) throw e;
    throw new ScanError("Couldn't resolve that domain. Check the spelling and try again.");
  }
}

export async function normalizeUrl(input: unknown): Promise<URL> {
  if (typeof input !== "string" || !input.trim()) throw new ScanError("Enter a URL to scan.");
  let raw = input.trim();
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ScanError("That doesn't look like a valid URL.");
  }
  await assertPublicHost(url);
  return url;
}

/** fetch with timeout, no-store, and per-hop SSRF validation on redirects. */
export async function safeFetch(
  url: string,
  init: { method?: "GET" | "HEAD" } = {},
  timeoutMs = 6000,
  maxRedirects = 3
) {
  let current = new URL(url);
  for (let hop = 0; hop <= maxRedirects; hop++) {
    await assertPublicHost(current);
    const res = await fetch(current, {
      method: init.method ?? "GET",
      redirect: "manual",
      cache: "no-store",
      signal: AbortSignal.timeout(timeoutMs),
      headers: { "User-Agent": "DevSecGuard/1.0 (security audit)" },
    });
    const location = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && location && hop < maxRedirects) {
      await res.body?.cancel();
      current = new URL(location, current);
      continue;
    }
    return res;
  }
  throw new ScanError("Too many redirects.", 502);
}

/** Reads at most maxBytes of a response body, then cancels the stream. */
export async function readText(res: Response, maxBytes = 2048) {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (total < maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }
  await reader.cancel().catch(() => {});
  return new TextDecoder().decode(Buffer.concat(chunks)).slice(0, maxBytes);
}
