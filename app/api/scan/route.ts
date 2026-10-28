import { NextResponse } from "next/server";
import { ScanError, normalizeUrl, readText, safeFetch } from "@/lib/validate";
import type { BotRule, HeaderCheck, LeakCheck, ScanResult } from "@/lib/types";
import { RATE_LIMITS, enforceRateLimit } from "@/lib/rateLimit";

export const runtime = "nodejs";
export const maxDuration = 30;

const AI_BOTS = ["GPTBot", "ClaudeBot", "CCBot"];

const LEAK_PATHS = [
  { path: "/.env", signature: /^\s*[A-Z][A-Z0-9_]*\s*=/m },
  { path: "/.git/HEAD", signature: /^ref:\s*refs\//m },
];

interface RobotsRule {
  allow: boolean;
  pattern: string;
}

/** Converts a robots.txt path pattern (supports `*` and a trailing `$`) to a RegExp. */
function patternToRegex(pattern: string): RegExp {
  const anchored = pattern.endsWith("$");
  const body = (anchored ? pattern.slice(0, -1) : pattern)
    .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*");
  return new RegExp(`^${body}${anchored ? "$" : ""}`);
}

/**
 * RFC 9309 evaluation of whether `path` is disallowed: the most specific (longest)
 * matching rule wins, and on a tie `Allow` wins. Empty `Disallow:` lines are no-ops.
 */
function isDisallowed(rules: RobotsRule[], path: string): boolean {
  let best: RobotsRule | null = null;
  for (const rule of rules) {
    if (!rule.pattern) continue;
    if (!patternToRegex(rule.pattern).test(path)) continue;
    if (
      !best ||
      rule.pattern.length > best.pattern.length ||
      (rule.pattern.length === best.pattern.length && rule.allow)
    ) {
      best = rule;
    }
  }
  return !!best && !best.allow;
}

/**
 * Returns, for each bot, whether the site root is disallowed for it.
 * Bot-specific groups take precedence; if none match, the `User-agent: *` group applies.
 */
function parseRobots(text: string): BotRule[] {
  const groups: { agents: string[]; rules: RobotsRule[] }[] = [];
  let current: (typeof groups)[number] | null = null;
  let lastWasAgent = false;

  for (const line of text.split(/\r?\n/)) {
    const clean = line.replace(/#.*/, "").trim();
    const m = clean.match(/^([a-z-]+)\s*:\s*(.*)$/i);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const value = m[2].trim();
    if (key === "user-agent") {
      if (!current || !lastWasAgent) {
        current = { agents: [], rules: [] };
        groups.push(current);
      }
      current.agents.push(value.toLowerCase());
      lastWasAgent = true;
    } else {
      lastWasAgent = false;
      if ((key === "disallow" || key === "allow") && current) {
        current.rules.push({ allow: key === "allow", pattern: value });
      }
    }
  }

  const rulesFor = (agent: string) =>
    groups.filter((g) => g.agents.includes(agent)).flatMap((g) => g.rules);
  const wildcardRules = rulesFor("*");

  return AI_BOTS.map((name) => {
    const specific = groups.some((g) => g.agents.includes(name.toLowerCase()));
    const rules = specific ? rulesFor(name.toLowerCase()) : wildcardRules;
    return { name, blocked: isDisallowed(rules, "/") };
  });
}

async function checkRobots(origin: string): Promise<ScanResult["robots"]> {
  const open = AI_BOTS.map((name) => ({ name, blocked: false }));
  try {
    const res = await safeFetch(`${origin}/robots.txt`, {}, 5000);
    const isHtml = (res.headers.get("content-type") ?? "").includes("html");
    if (res.status !== 200 || isHtml) {
      await res.body?.cancel();
      return { found: false, status: res.status, bots: open };
    }
    const text = await readText(res, 200_000);
    return { found: true, status: 200, bots: parseRobots(text) };
  } catch {
    return { found: false, status: null, bots: open };
  }
}

async function checkLeak(origin: string, target: (typeof LEAK_PATHS)[number]): Promise<LeakCheck> {
  try {
    // maxRedirects = 0: a redirect (e.g. to a login page) is not an exposed file.
    const res = await safeFetch(`${origin}${target.path}`, { method: "GET" }, 4000, 0);
    if (res.status !== 200) {
      await res.body?.cancel();
      return { path: target.path, status: res.status, state: "safe", note: "Not publicly served." };
    }
    const body = await readText(res, 1024);
    if (target.signature.test(body)) {
      return {
        path: target.path,
        status: 200,
        state: "exposed",
        note: "Real file contents are public. Block it and rotate any secrets.",
      };
    }
    return {
      path: target.path,
      status: 200,
      state: "soft-200",
      note: "Returns 200 but the content isn't the file (likely a catch-all page).",
    };
  } catch {
    return { path: target.path, status: null, state: "unreachable", note: "Request timed out or failed." };
  }
}

export async function POST(req: Request) {
  try {
    const limited = enforceRateLimit(req, RATE_LIMITS.scan);
    if (limited) return limited;

    const body = await req.json().catch(() => null);
    const url = await normalizeUrl(body?.url);
    const origin = url.origin;

    const [mainRes, robots, leaks] = await Promise.all([
      safeFetch(url.toString(), { method: "GET" }, 8000).catch(() => {
        throw new ScanError("Couldn't reach that site. It may be offline or blocking scanners.", 502);
      }),
      checkRobots(origin),
      Promise.all(LEAK_PATHS.map((t) => checkLeak(origin, t))),
    ]);
    await mainRes.body?.cancel();

    const h = mainRes.headers;
    const csp = h.get("content-security-policy");
    const xfo = h.get("x-frame-options");
    const hsts = h.get("strict-transport-security");
    const frameAncestors = csp?.match(/frame-ancestors[^;]*/i)?.[0] ?? null;

    const items: HeaderCheck[] = [
      { key: "csp", label: "Content-Security-Policy", present: !!csp, value: csp },
      {
        key: "xfo",
        label: "X-Frame-Options",
        present: !!xfo || !!frameAncestors,
        value: xfo ?? frameAncestors,
      },
      {
        key: "hsts",
        label: "Strict-Transport-Security",
        present: !!hsts && mainRes.finalUrl.protocol === "https:",
        value: hsts,
      },
    ];

    const result: ScanResult = {
      url: url.toString(),
      scannedAt: new Date().toISOString(),
      robots,
      headers: { status: mainRes.status, items },
      leaks,
    };
    return NextResponse.json(result);
  } catch (e) {
    if (e instanceof ScanError) return NextResponse.json({ error: e.message }, { status: e.status });
    return NextResponse.json({ error: "Scan failed unexpectedly. Try again." }, { status: 500 });
  }
}
