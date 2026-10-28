import { lookup } from "node:dns/promises";
import net from "node:net";

export class ScanError extends Error {
  status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}

/* ---------- private / special-purpose address detection ---------- */

/** IANA special-purpose IPv4 ranges that must never be fetched. */
const BLOCKED_V4: [string, number][] = [
  ["0.0.0.0", 8], // "this network"
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local (cloud metadata lives here)
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // TEST-NET-1
  ["192.88.99.0", 24], // 6to4 relay anycast (deprecated)
  ["192.168.0.0", 16], // private
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // TEST-NET-2
  ["203.0.113.0", 24], // TEST-NET-3
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved + broadcast
];

/** IANA special-purpose IPv6 ranges (embedded-IPv4 forms are handled separately). */
const BLOCKED_V6: [string, number][] = [
  ["::", 128], // unspecified
  ["::1", 128], // loopback
  ["64:ff9b:1::", 48], // local-use NAT64
  ["100::", 64], // discard-only
  ["2001::", 23], // IETF protocol assignments (incl. Teredo 2001::/32)
  ["2001:db8::", 32], // documentation
  ["fc00::", 7], // unique local
  ["fe80::", 10], // link-local
  ["fec0::", 10], // site-local (deprecated)
  ["ff00::", 8], // multicast
];

const blockList = new net.BlockList();
for (const [addr, prefix] of BLOCKED_V4) blockList.addSubnet(addr, prefix, "ipv4");
for (const [addr, prefix] of BLOCKED_V6) blockList.addSubnet(addr, prefix, "ipv6");

/** Expands an IPv6 string (incl. `::` and a dotted-quad tail) to 8 numeric hextets. */
function ipv6ToHextets(ip: string): number[] | null {
  let s = ip.toLowerCase().split("%")[0];
  const v4Tail = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Tail) {
    const o = v4Tail[1].split(".").map(Number);
    s = s.slice(0, -v4Tail[1].length) + `${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const [head, tail, ...rest] = s.split("::");
  if (rest.length) return null;
  const h = head ? head.split(":") : [];
  const t = tail !== undefined ? (tail ? tail.split(":") : []) : null;
  const parts = t ? [...h, ...Array(8 - h.length - t.length).fill("0"), ...t] : h;
  if (parts.length !== 8) return null;
  const nums = parts.map((p) => Number.parseInt(p, 16));
  return nums.every((n) => Number.isInteger(n) && n >= 0 && n <= 0xffff) ? nums : null;
}

const hextetsToV4 = (hi: number, lo: number) => `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;

/**
 * Returns the IPv4 address embedded in an IPv6 address, for the transition
 * formats an attacker could use to smuggle a private IPv4 past a naive check.
 */
function embeddedIPv4(h: number[]): string | null {
  const zero = (from: number, to: number) => h.slice(from, to).every((x) => x === 0);
  // ::ffff:a.b.c.d (IPv4-mapped) — also matches the hex form ::ffff:7f00:1
  if (zero(0, 5) && h[5] === 0xffff) return hextetsToV4(h[6], h[7]);
  // ::ffff:0:a.b.c.d (IPv4-translated, SIIT)
  if (zero(0, 4) && h[4] === 0xffff && h[5] === 0) return hextetsToV4(h[6], h[7]);
  // ::a.b.c.d (deprecated IPv4-compatible); also covers :: and ::1
  if (zero(0, 6)) return hextetsToV4(h[6], h[7]);
  // 64:ff9b::a.b.c.d (well-known NAT64 prefix)
  if (h[0] === 0x64 && h[1] === 0xff9b && zero(2, 6)) return hextetsToV4(h[6], h[7]);
  // 2002:AABB:CCDD::/48 (6to4)
  if (h[0] === 0x2002) return hextetsToV4(h[1], h[2]);
  return null;
}

export function isPrivateIP(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) return blockList.check(ip, "ipv4");
  if (version === 6) {
    const h = ipv6ToHextets(ip);
    if (!h) return true; // unparseable: fail closed
    const v4 = embeddedIPv4(h);
    if (v4 && blockList.check(v4, "ipv4")) return true;
    const normalized = h.map((x) => x.toString(16)).join(":");
    return blockList.check(normalized, "ipv6");
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

/**
 * fetch with timeout, no-store, and per-hop SSRF validation on redirects.
 * The returned Response carries `finalUrl`, the URL actually fetched after redirects.
 */
export async function safeFetch(
  url: string,
  init: { method?: "GET" | "HEAD" } = {},
  timeoutMs = 6000,
  maxRedirects = 3
): Promise<Response & { finalUrl: URL }> {
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
    return Object.assign(res, { finalUrl: current });
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
