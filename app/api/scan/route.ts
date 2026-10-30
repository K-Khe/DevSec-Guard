import { NextResponse } from "next/server";
import { ScanError, normalizeUrl, readText, safeFetch } from "@/lib/validate";
import type {
  BotRule,
  CookieCheck,
  CrawledPage,
  CspCheckItem,
  HeaderCheck,
  HeaderExposure,
  HtmlFinding,
  IsolationHeaderCheck,
  LeakCheck,
  RawHeaderEntry,
  ScanResult,
} from "@/lib/types";
import { RATE_LIMITS, enforceRateLimit } from "@/lib/rateLimit";
import { auditLog } from "@/lib/audit";
import { assertRequestAuthorized, assertTargetPolicy } from "@/lib/policy";
import { persistScanRecord, ScanRecordStoreError } from "@/lib/scanRecord";
import { verifyRedirectChain } from "@/lib/redirectVerifier";

export const runtime = "nodejs";
export const maxDuration = 30;

const AI_BOTS = ["GPTBot", "ClaudeBot", "CCBot", "Google-Extended", "PerplexityBot"];

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

/** Parses a CSP string into a lowercase directive -> tokens map. */
function parseCspDirectives(csp: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const part of csp.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    if (!map.has(name)) {
      map.set(name, tokens.slice(1).map((t) => t.toLowerCase()));
    }
  }
  return map;
}

/** MDN Observatory-style granular CSP analysis. */
function analyzeCspDirectives(csp: string | null): {
  check: HeaderCheck;
  breakdown: CspCheckItem[];
} {
  if (!csp) {
    return {
      check: { key: "csp", label: "Content-Security-Policy", present: false, state: "missing", value: null },
      breakdown: [],
    };
  }

  const dirs = parseCspDirectives(csp);
  const defaultSrc = dirs.get("default-src");
  const scriptSrc = dirs.get("script-src") ?? defaultSrc ?? [];
  const styleSrc = dirs.get("style-src") ?? defaultSrc ?? [];
  const objectSrc = dirs.get("object-src") ?? defaultSrc ?? [];
  const baseUri = dirs.get("base-uri") ?? [];
  const formAction = dirs.get("form-action") ?? [];
  const frameAncestors = dirs.get("frame-ancestors");

  const hasNonceOrHashOrStrictDynamic = scriptSrc.some(
    (t) => t.startsWith("'nonce-") || t.startsWith("'sha256-") || t.startsWith("'sha384-") || t.startsWith("'sha512-") || t === "'strict-dynamic'",
  );
  // In CSP2/3, 'unsafe-inline' is ignored by browsers if a nonce or hash is present in script-src.
  const blocksInlineScript =
    (dirs.has("script-src") || dirs.has("default-src")) &&
    (!scriptSrc.includes("'unsafe-inline'") || hasNonceOrHashOrStrictDynamic) &&
    !scriptSrc.includes("*") &&
    !scriptSrc.includes("data:");

  const blocksEval =
    (dirs.has("script-src") || dirs.has("default-src")) && !scriptSrc.includes("'unsafe-eval'");

  const blocksPlugins =
    objectSrc.includes("'none'") || (objectSrc.length > 0 && !objectSrc.includes("*"));

  const blocksInlineStyles =
    (dirs.has("style-src") || dirs.has("default-src")) && !styleSrc.includes("'unsafe-inline'");

  const hasFrameAncestors =
    !!frameAncestors && !frameAncestors.includes("*") && frameAncestors.length > 0;

  const restrictsBaseUri =
    baseUri.includes("'none'") || baseUri.includes("'self'");

  const restrictsFormAction =
    formAction.includes("'none'") || formAction.includes("'self'") || formAction.length > 0;

  const breakdown: CspCheckItem[] = [
    {
      id: "no-unsafe-inline-script",
      label: "Blocks inline JavaScript ('unsafe-inline' in script-src)",
      passed: blocksInlineScript,
      info: blocksInlineScript
        ? "Inline scripts are blocked or guarded by hashes/nonces."
        : "script-src allows 'unsafe-inline' or wildcard sources.",
    },
    {
      id: "no-unsafe-eval",
      label: "Blocks JavaScript eval() ('unsafe-eval' in script-src)",
      passed: blocksEval,
      info: blocksEval ? "eval() is not permitted in script-src." : "script-src allows 'unsafe-eval'.",
    },
    {
      id: "object-src",
      label: "Restricts plug-ins (object-src)",
      passed: blocksPlugins,
      info: blocksPlugins ? "object-src is restricted." : "Set object-src 'none' to block legacy plug-ins.",
    },
    {
      id: "style-src",
      label: "Blocks inline styles ('unsafe-inline' in style-src)",
      passed: blocksInlineStyles,
      info: blocksInlineStyles
        ? "Inline styles are blocked."
        : "style-src allows 'unsafe-inline' (minor risk if script-src is locked down).",
    },
    {
      id: "frame-ancestors",
      label: "Clickjacking protection (frame-ancestors)",
      passed: hasFrameAncestors,
      info: hasFrameAncestors
        ? `frame-ancestors set to ${frameAncestors!.join(" ")}.`
        : "Not set in CSP (may still be covered by X-Frame-Options).",
    },
    {
      id: "base-uri",
      label: "Restricts <base> tag (base-uri 'self' or 'none')",
      passed: restrictsBaseUri,
      info: restrictsBaseUri ? "base-uri is restricted." : "Add base-uri 'self' or 'none'.",
    },
    {
      id: "form-action",
      label: "Restricts <form> submission targets (form-action)",
      passed: restrictsFormAction,
      info: restrictsFormAction ? "form-action is restricted." : "Add form-action 'self' to restrict form targets.",
    },
  ];

  // Critical issues that make CSP weak for XSS defense (matching MDN Observatory):
  const criticalIssues: string[] = [];
  if (!dirs.has("default-src") && !dirs.has("script-src")) {
    criticalIssues.push("missing default-src / script-src");
  }
  if (!blocksInlineScript) criticalIssues.push("script-src allows 'unsafe-inline' or *");
  if (!blocksEval) criticalIssues.push("script-src allows 'unsafe-eval'");

  const minorNotes: string[] = [];
  if (!blocksInlineStyles) minorNotes.push("style-src includes 'unsafe-inline'");

  const isWeak = criticalIssues.length > 0;
  const note = isWeak
    ? `Weak: ${criticalIssues.join(", ")}.`
    : minorNotes.length
      ? `Strong script protection (${minorNotes.join(", ")}).`
      : undefined;

  return {
    check: {
      key: "csp",
      label: "Content-Security-Policy",
      present: true,
      state: isWeak ? "weak" : "strong",
      value: csp,
      note,
    },
    breakdown,
  };
}

/** Evaluates all 6 security headers and flags weak configurations. */
function evaluateHeaders(h: Headers, isHttps: boolean): {
  items: HeaderCheck[];
  cspAnalysis: CspCheckItem[];
} {
  const csp = h.get("content-security-policy");
  const xfo = h.get("x-frame-options");
  const hsts = h.get("strict-transport-security");
  const xcto = h.get("x-content-type-options");
  const rp = h.get("referrer-policy");
  const pp = h.get("permissions-policy");
  const frameAncestors = csp?.match(/frame-ancestors[^;]*/i)?.[0]?.trim() ?? null;

  const { check: cspCheck, breakdown: cspAnalysis } = analyzeCspDirectives(csp);

  const evalXfo = (): HeaderCheck => {
    const val = xfo ?? frameAncestors;
    if (!val) return { key: "xfo", label: "X-Frame-Options", present: false, state: "missing", value: null };
    const validXfo = xfo ? /^\s*(DENY|SAMEORIGIN)\s*$/i.test(xfo) : true;
    const weakFa = !xfo && frameAncestors && /\*/.test(frameAncestors);
    const isWeak = !validXfo || !!weakFa;
    return {
      key: "xfo",
      label: "X-Frame-Options",
      present: true,
      state: isWeak ? "weak" : "strong",
      value: val,
      note: isWeak ? "Weak: prefer DENY, SAMEORIGIN, or restrictive frame-ancestors." : undefined,
    };
  };

  const evalHsts = (): HeaderCheck => {
    if (!hsts || !isHttps) {
      return {
        key: "hsts",
        label: "Strict-Transport-Security",
        present: false,
        state: "missing",
        value: hsts,
        note: hsts && !isHttps ? "Ignored because final URL is not HTTPS." : undefined,
      };
    }
    const m = hsts.match(/max-age\s*=\s*(\d+)/i);
    const maxAge = m ? Number.parseInt(m[1], 10) : 0;
    const isWeak = !m || maxAge < 15_552_000;
    return {
      key: "hsts",
      label: "Strict-Transport-Security",
      present: true,
      state: isWeak ? "weak" : "strong",
      value: hsts,
      note: isWeak ? `Weak: max-age=${maxAge} is under 6 months (15552000).` : undefined,
    };
  };

  const evalXcto = (): HeaderCheck => {
    if (!xcto) return { key: "xcto", label: "X-Content-Type-Options", present: false, state: "missing", value: null };
    const ok = /^\s*nosniff\s*$/i.test(xcto);
    return {
      key: "xcto",
      label: "X-Content-Type-Options",
      present: true,
      state: ok ? "strong" : "weak",
      value: xcto,
      note: ok ? undefined : "Weak: value should be 'nosniff'.",
    };
  };

  const evalRp = (): HeaderCheck => {
    if (!rp) return { key: "rp", label: "Referrer-Policy", present: false, state: "missing", value: null };
    const unsafe = /\b(unsafe-url|no-referrer-when-downgrade)\b/i.test(rp);
    return {
      key: "rp",
      label: "Referrer-Policy",
      present: true,
      state: unsafe ? "weak" : "strong",
      value: rp,
      note: unsafe ? "Weak: leaks full referrer URL across origins." : undefined,
    };
  };

  const evalPp = (): HeaderCheck => {
    if (!pp) return { key: "pp", label: "Permissions-Policy", present: false, state: "missing", value: null };
    const wildcard = /=\s*\*/.test(pp);
    return {
      key: "pp",
      label: "Permissions-Policy",
      present: true,
      state: wildcard ? "weak" : "strong",
      value: pp,
      note: wildcard ? "Weak: allows wildcard (*) feature access." : undefined,
    };
  };

  return {
    items: [cspCheck, evalXfo(), evalHsts(), evalXcto(), evalRp(), evalPp()],
    cspAnalysis,
  };
}

/** Checks Cross-Origin Isolation (COOP, COEP, CORP including Report-Only) and CORS. */
function evaluateIsolationHeaders(h: Headers): IsolationHeaderCheck[] {
  const coop = h.get("cross-origin-opener-policy");
  const coopRo = h.get("cross-origin-opener-policy-report-only");
  const coep = h.get("cross-origin-embedder-policy");
  const coepRo = h.get("cross-origin-embedder-policy-report-only");
  const corp = h.get("cross-origin-resource-policy");
  const cors = h.get("access-control-allow-origin");
  return [
    {
      key: "coop",
      label: "Cross-Origin-Opener-Policy",
      present: !!coop || !!coopRo,
      reportOnly: !coop && !!coopRo,
      value: coop ?? (coopRo ? `${coopRo} (Report-Only)` : null),
    },
    {
      key: "coep",
      label: "Cross-Origin-Embedder-Policy",
      present: !!coep || !!coepRo,
      reportOnly: !coep && !!coepRo,
      value: coep ?? (coepRo ? `${coepRo} (Report-Only)` : null),
    },
    { key: "corp", label: "Cross-Origin-Resource-Policy", present: !!corp, value: corp },
    { key: "cors", label: "Access-Control-Allow-Origin", present: !!cors, value: cors },
  ];
}

/** Detects headers that disclose server versions or framework fingerprints. */
function evaluateHeaderExposures(h: Headers): HeaderExposure[] {
  const exposures: HeaderExposure[] = [];
  const poweredBy = h.get("x-powered-by");
  if (poweredBy) {
    exposures.push({
      header: "x-powered-by",
      value: poweredBy,
      note: "Reveals framework/runtime fingerprint. Remove it (e.g. poweredByHeader: false in Next.js or expose_php = Off).",
    });
  }
  const server = h.get("server");
  if (server && /\d+\.\d+/.test(server)) {
    exposures.push({
      header: "server",
      value: server,
      note: "Exposes exact server version number. Hide version tokens (e.g. server_tokens off in nginx).",
    });
  }
  for (const name of ["x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime"]) {
    const val = h.get(name);
    if (val) {
      exposures.push({
        header: name,
        value: val,
        note: "Discloses runtime or generator details to scanners.",
      });
    }
  }
  return exposures;
}

/** Collects raw response headers for inspection while redacting Set-Cookie values. */
function collectRawHeaders(h: Headers): RawHeaderEntry[] {
  const entries: RawHeaderEntry[] = [];
  h.forEach((value, name) => {
    const lower = name.toLowerCase();
    if (lower === "set-cookie") {
      // Mask the secret cookie value while showing attribute metadata like MDN
      const masked = value.replace(/^([^=;]+)=[^;]*/, "$1=[REDACTED]");
      entries.push({ name: lower, value: masked.slice(0, 500) });
      return;
    }
    entries.push({ name: lower, value: value.slice(0, 500) });
  });
  return entries.slice(0, 45);
}

/** Detects server/platform clues from response headers and HTML surface. */
function detectStack(h: Headers, html = ""): string[] {
  const found = new Set<string>();
  const server = (h.get("server") ?? "").toLowerCase();
  const powered = (h.get("x-powered-by") ?? "").toLowerCase();
  const link = (h.get("link") ?? "").toLowerCase();

  if (h.get("x-vercel-id") || server.includes("vercel")) found.add("Vercel");
  if (powered.includes("next.js") || h.get("x-nextjs-cache") || h.get("x-nextjs-matched-path")) found.add("Next.js");
  if (h.get("cf-ray") || server.includes("cloudflare")) found.add("Cloudflare");
  if (h.get("x-nf-request-id") || server.includes("netlify")) found.add("Netlify");
  if (server.includes("nginx")) found.add("nginx");
  if (server.includes("apache")) found.add("Apache");
  if (server.includes("iis") || powered.includes("asp.net")) found.add("IIS");
  if (powered.includes("express")) found.add("Express");
  if (powered.includes("php") || server.includes("php")) found.add("PHP");
  if (
    h.get("x-pingback") ||
    link.includes("wp-json") ||
    /\/(?:wp-content|wp-includes)\//i.test(html) ||
    /<meta\b[^>]*name\s*=\s*["']generator["'][^>]*content\s*=\s*["'][^"']*wordpress/i.test(html)
  ) {
    found.add("WordPress");
    found.add("PHP");
  }
  if (h.get("x-amz-cf-id") || server.includes("cloudfront") || server.includes("amazons3")) found.add("AWS CloudFront");
  if (server.includes("github.com")) found.add("GitHub Pages");

  return Array.from(found);
}

/** Extracts cookie security metadata (including Path, Expires/Max-Age, Prefix) without retaining cookie values. */
function evaluateCookies(headers: Headers, isHttps: boolean): CookieCheck[] {
  const extendedHeaders = headers as Headers & { getSetCookie?: () => string[] };
  const rawCookies = extendedHeaders.getSetCookie?.() ?? (() => {
    const combined = headers.get("set-cookie");
    return combined ? [combined] : [];
  })();

  return rawCookies.slice(0, 20).flatMap((raw) => {
    const [pair, ...attributes] = raw.split(";");
    const equals = pair.indexOf("=");
    const name = (equals >= 0 ? pair.slice(0, equals) : pair).trim();
    if (!name) return [];

    const trimmedAttrs = attributes.map((a) => a.trim());
    const lowerAttributes = trimmedAttrs.map((a) => a.toLowerCase());
    const secure = lowerAttributes.includes("secure");
    const httpOnly = lowerAttributes.includes("httponly");

    const sameSiteValue = lowerAttributes
      .find((a) => a.startsWith("samesite="))
      ?.split("=")[1]
      ?.trim();
    const sameSite =
      sameSiteValue === "strict"
        ? "Strict"
        : sameSiteValue === "lax"
          ? "Lax"
          : sameSiteValue === "none"
            ? "None"
            : null;

    const pathAttr = trimmedAttrs.find((a) => /^path\s*=/i.test(a))?.split("=")[1]?.trim() ?? "/";
    const maxAgeAttr = trimmedAttrs.find((a) => /^max-age\s*=/i.test(a))?.split("=")[1]?.trim();
    const expiresAttr = trimmedAttrs.find((a) => /^expires\s*=/i.test(a))?.slice(8)?.trim();
    const expires = maxAgeAttr ? `Max-Age=${maxAgeAttr}s` : expiresAttr ?? "Session";

    const prefix: CookieCheck["prefix"] = name.startsWith("__Host-")
      ? "__Host-"
      : name.startsWith("__Secure-")
        ? "__Secure-"
        : null;

    const issues: string[] = [];
    if (isHttps && !secure) issues.push("missing Secure");
    if (!httpOnly) issues.push("missing HttpOnly");
    if (!sameSite) issues.push("missing SameSite");
    if (sameSite === "None" && !secure) issues.push("SameSite=None requires Secure");
    if (prefix === "__Host-" && (!secure || pathAttr !== "/")) {
      issues.push("__Host- prefix requires Secure and Path=/");
    }

    return [
      {
        name,
        path: pathAttr,
        expires,
        prefix,
        secure,
        httpOnly,
        sameSite,
        state: issues.length ? "weak" : "strong",
        note: issues.length ? `Weak: ${issues.join(", ")}.` : undefined,
      },
    ];
  });
}

/**
 * Finds high-signal client-side risks in HTML (including missing Subresource Integrity on external scripts
 * and PHP / WordPress attack surface indicators) without executing scripts or retaining page content.
 */
function inspectHtml(html: string, isHttps: boolean, originHost: string, headers?: Headers): HtmlFinding[] {
  const findings: HtmlFinding[] = [];
  const add = (finding: HtmlFinding) => {
    if (!findings.some((item) => item.key === finding.key)) findings.push(finding);
  };

  // PHP version exposure check (X-Powered-By: PHP/x.y.z or Server: ... PHP/x.y.z)
  const poweredBy = headers?.get("x-powered-by") ?? "";
  const serverHdr = headers?.get("server") ?? "";
  const phpMatch = `${poweredBy} ${serverHdr}`.match(/\bPHP\/(\d+\.\d+(?:\.\d+)?)/i);
  if (phpMatch) {
    add({
      key: "php-version-exposure",
      severity: "medium",
      title: `PHP version exposed (${phpMatch[0]})`,
      note: "Exposing the exact PHP runtime version allows automated scanners to target known PHP CGI/FPM and in-memory RCE vulnerabilities. Set expose_php = Off in php.ini.",
    });
  }

  // WordPress surface & plugin/xmlrpc fingerprint check
  const wpGenMatch = html.match(/<meta\b[^>]*name\s*=\s*["']generator["'][^>]*content\s*=\s*["'](WordPress[^"']*)["']/i);
  const wpPluginMatches = Array.from(
    new Set(
      (html.match(/\/wp-content\/plugins\/([a-z0-9_-]+)\//gi) ?? []).map((m) =>
        m.replace(/^\/wp-content\/plugins\//i, "").replace(/\/$/, ""),
      ),
    ),
  ).slice(0, 5);
  const hasXmlRpc =
    Boolean(headers?.get("x-pingback")) || /xmlrpc\.php/i.test(html);
  const hasWpSurface =
    Boolean(wpGenMatch) ||
    wpPluginMatches.length > 0 ||
    hasXmlRpc ||
    /\/(?:wp-content|wp-includes|wp-json)\//i.test(html);

  if (hasWpSurface) {
    const details: string[] = [];
    if (wpGenMatch?.[1]) details.push(`generator "${wpGenMatch[1]}"`);
    if (wpPluginMatches.length > 0) details.push(`plugins (${wpPluginMatches.join(", ")})`);
    if (hasXmlRpc) details.push("xmlrpc.php / X-Pingback active");
    add({
      key: "wordpress-surface",
      severity: wpGenMatch || hasXmlRpc || wpPluginMatches.length > 0 ? "medium" : "low",
      title: `WordPress attack surface detected${details.length ? `: ${details.join(" · ")}` : ""}`,
      note: "WordPress plugins and xmlrpc.php are frequent targets for automated RCE and in-memory web shell injection. Keep plugins updated, block xmlrpc.php if unused, and hide generator version tags.",
    });
  }

  if (isHttps && /(?:src|href)\s*=\s*["']http:\/\//i.test(html)) {
    add({
      key: "mixed-content",
      severity: "medium",
      title: "Possible mixed content",
      note: "The HTTPS page references an HTTP resource. Browsers may block it or expose users to content tampering.",
    });
  }
  if (/<form\b[^>]*\baction\s*=\s*["']http:\/\//i.test(html)) {
    add({
      key: "insecure-form",
      severity: "high",
      title: "Form submits over HTTP",
      note: "A form action uses HTTP, which can expose submitted data in transit.",
    });
  }

  // Subresource Integrity (SRI) check on external <script src="https://..."> tags
  const scriptTags = html.match(/<script\b[^>]*\bsrc\s*=\s*["']https?:\/\/[^"']+["'][^>]*>/gi) ?? [];
  let externalScriptsMissingSri = 0;
  for (const tag of scriptTags) {
    const srcMatch = tag.match(/\bsrc\s*=\s*["'](https?:\/\/[^"']+)["']/i);
    if (!srcMatch) continue;
    try {
      const scriptUrl = new URL(srcMatch[1]);
      if (scriptUrl.hostname.toLowerCase() !== originHost.toLowerCase() && !/\bintegrity\s*=\s*["']sha(?:256|384|512)-/i.test(tag)) {
        externalScriptsMissingSri++;
      }
    } catch {
      /* ignore malformed script URL */
    }
  }
  if (externalScriptsMissingSri > 0) {
    add({
      key: "missing-sri",
      severity: "low",
      title: `Subresource Integrity (SRI) missing on ${externalScriptsMissingSri} external script(s)`,
      note: "External scripts loaded from third-party CDNs lack an integrity='sha384-...' hash.",
    });
  }

  if (/sourceMappingURL\s*=\s*[^\s]+|\bsrc\s*=\s*["'][^"']+\.map(?:[?#][^"']*)?["']/i.test(html)) {
    add({
      key: "source-map",
      severity: "low",
      title: "Source-map reference exposed",
      note: "A source-map reference was found. Verify that production source maps do not reveal sensitive source code.",
    });
  }
  if (/(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\s*[:=]\s*["'][^"'\s]{8,}["']/i.test(html)) {
    add({
      key: "possible-secret",
      severity: "high",
      title: "Possible client-side secret pattern",
      note: "A credential-like assignment was found in page source. No value was retained; validate and rotate any real secret.",
    });
  }
  if (/<a\b[^>]*\btarget\s*=\s*["']_blank["'](?![^>]*\brel\s*=\s*["'][^"']*\bnoopener\b)/i.test(html)) {
    add({
      key: "unsafe-blank-link",
      severity: "low",
      title: "New-tab link may lack noopener",
      note: "A target=_blank link appears to lack rel=noopener, which can allow tabnabbing in older browser contexts.",
    });
  }
  return findings;
}

const MAX_CRAWL_SUBPAGES = 5;
const SKIP_EXT_RE = /\.(?:png|jpe?g|gif|webp|svg|ico|css|m?js|map|pdf|zip|gz|tar|xml|json|woff2?|ttf|eot|mp4|webm|mp3|wav)(?:$|[?#])/i;
const PRIORITY_PATH_RE = /\/(?:login|signin|sign-in|auth|register|signup|admin|account|profile|contact|dashboard|portal|user|checkout)\b/i;

/** Extracts up to MAX_CRAWL_SUBPAGES unique same-origin HTML links from page source, prioritizing high-value routes. */
function extractSameOriginSubpages(html: string, baseUrl: URL): URL[] {
  if (!html) return [];
  const seen = new Set<string>();
  const homeKey = `${baseUrl.pathname.replace(/\/+$/, "") || "/"}${baseUrl.search}`;
  seen.add(homeKey);
  seen.add("/robots.txt");
  seen.add("/.env");
  seen.add("/.git/head");

  const candidates: URL[] = [];
  const hrefMatches = html.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)["']/gi);

  for (const match of hrefMatches) {
    const rawHref = match[1]?.trim();
    if (!rawHref || /^(?:mailto:|tel:|javascript:|data:)/i.test(rawHref)) continue;
    try {
      const resolved = new URL(rawHref, baseUrl);
      if (resolved.origin !== baseUrl.origin) continue;
      if (SKIP_EXT_RE.test(resolved.pathname)) continue;
      resolved.hash = "";
      const normPath = `${resolved.pathname.replace(/\/+$/, "") || "/"}${resolved.search}`;
      const lowerKey = normPath.toLowerCase();
      if (seen.has(lowerKey)) continue;
      seen.add(lowerKey);
      candidates.push(resolved);
      if (candidates.length >= 25) break;
    } catch {
      /* ignore malformed href */
    }
  }

  candidates.sort((a, b) => {
    const aPri = PRIORITY_PATH_RE.test(a.pathname) ? 0 : 1;
    const bPri = PRIORITY_PATH_RE.test(b.pathname) ? 0 : 1;
    if (aPri !== bPri) return aPri - bPri;
    return a.pathname.length - b.pathname.length;
  });

  return candidates.slice(0, MAX_CRAWL_SUBPAGES);
}

async function crawlSameOriginSubpages(
  subpageUrls: URL[],
  originHost: string,
): Promise<{
  pages: CrawledPage[];
  extraCookies: CookieCheck[];
  extraFindings: HtmlFinding[];
}> {
  if (subpageUrls.length === 0) {
    return { pages: [], extraCookies: [], extraFindings: [] };
  }

  const results = await Promise.all(
    subpageUrls.map(async (target): Promise<{
      page: CrawledPage;
      cookies: CookieCheck[];
      findings: HtmlFinding[];
    }> => {
      const pathLabel = `${target.pathname}${target.search}` || "/";
      try {
        const res = await safeFetch(target.toString(), { method: "GET" }, 3000, 2);
        const ct = (res.headers.get("content-type") ?? "").toLowerCase();
        const isSubHttps = target.protocol === "https:";
        const subCookies = evaluateCookies(res.headers, isSubHttps);

        if (!ct.includes("text/html")) {
          await res.body?.cancel();
          return {
            page: {
              path: pathLabel,
              url: target.toString(),
              status: res.status,
              findingsCount: 0,
              cookiesCount: subCookies.length,
              findings: [],
            },
            cookies: subCookies,
            findings: [],
          };
        }

        const subHtml = await readText(res, 150_000);
        const subFindings = inspectHtml(subHtml, isSubHttps, originHost, res.headers).map((f) => ({
          ...f,
          title: `${f.title} (${pathLabel})`,
        }));

        return {
          page: {
            path: pathLabel,
            url: target.toString(),
            status: res.status,
            findingsCount: subFindings.length,
            cookiesCount: subCookies.length,
            findings: subFindings.map((f) => f.title),
          },
          cookies: subCookies,
          findings: subFindings,
        };
      } catch {
        return {
          page: {
            path: pathLabel,
            url: target.toString(),
            status: null,
            findingsCount: 0,
            cookiesCount: 0,
            findings: [],
          },
          cookies: [],
          findings: [],
        };
      }
    }),
  );

  return {
    pages: results.map((r) => r.page),
    extraCookies: results.flatMap((r) => r.cookies),
    extraFindings: results.flatMap((r) => r.findings),
  };
}

/**
 * International-standard (MDN Observatory / OWASP aligned) 0–100 score and letter grade.
 * - Security Headers: 90 pts total (CSP 25, HSTS 20, XFO 15, XCTO 12, RP 10, PP 8)
 * - Verified Leak Protection (/.env, /.git/HEAD): 10 pts total
 * - Modifiers: +5 bonus for HSTS preload+includeSubDomains, -5 for insecure cookies, -5 for high/medium HTML risk.
 * - AI crawler policy (robots.txt) is purely informational and never penalizes or inflates the security score.
 */
function computeScoreAndGrade(
  headers: HeaderCheck[],
  leaks: LeakCheck[],
  cookies: CookieCheck[],
  htmlFindings: HtmlFinding[],
): { score: number; grade: string; testsPassed: number; testsTotal: number } {
  const weights: Record<HeaderCheck["key"], { strong: number; weak: number }> = {
    csp: { strong: 25, weak: 14 },
    hsts: { strong: 20, weak: 10 },
    xfo: { strong: 15, weak: 8 },
    xcto: { strong: 12, weak: 6 },
    rp: { strong: 10, weak: 5 },
    pp: { strong: 8, weak: 4 },
  };

  let score = 0;
  let testsPassed = 0;
  const testsTotal = 10; // 6 headers + 2 leak checks + cookies check + SRI/HTML check

  for (const item of headers) {
    const w = weights[item.key];
    if (item.state === "strong") {
      score += w.strong;
      testsPassed++;
    } else if (item.state === "weak") {
      score += w.weak;
    }
  }

  // Award leak-check points only for paths that were positively verified as safe (10 pts max).
  const verifiedSafeLeaks = leaks.filter((l) => l.state === "safe").length;
  score += Math.min(10, verifiedSafeLeaks * 5);
  testsPassed += verifiedSafeLeaks;

  // +5 bonus for HSTS preload (matching MDN Observatory bonus)
  const hstsHeader = headers.find((h) => h.key === "hsts");
  if (hstsHeader?.state === "strong" && /\bpreload\b/i.test(hstsHeader.value ?? "")) {
    score += 5;
  }

  // Cookie check: deduct 5 points if any cookie is missing Secure/HttpOnly (matching MDN Observatory)
  const hasWeakCookies = cookies.some((c) => c.state === "weak");
  if (hasWeakCookies) {
    score -= 5;
  } else {
    testsPassed++;
  }

  // HTML / SRI check
  const hasHighOrMedHtmlRisk = htmlFindings.some((f) => f.severity === "high" || f.severity === "medium");
  if (!hasHighOrMedHtmlRisk) {
    testsPassed++;
  } else {
    score -= 5;
  }

  const hasExposedLeak = leaks.some((l) => l.state === "exposed");
  if (hasExposedLeak) {
    return { score: 15, grade: "F", testsPassed, testsTotal };
  }

  score = Math.max(0, Math.min(100, score));

  // Standard grade thresholds aligned with MDN Observatory / SecurityHeaders
  let grade = "F";
  if (score >= 95) grade = "A+";
  else if (score >= 85) grade = "A";
  else if (score >= 80) grade = "A-";
  else if (score >= 75) grade = "B+";
  else if (score >= 65) grade = "B";
  else if (score >= 60) grade = "B-";
  else if (score >= 55) grade = "C+";
  else if (score >= 45) grade = "C";
  else if (score >= 40) grade = "C-";
  else if (score >= 25) grade = "D";

  return { score, grade, testsPassed, testsTotal };
}

export async function POST(req: Request) {
  const startedAt = Date.now();
  let rawTarget = "";
  try {
    const limited = await enforceRateLimit(req, RATE_LIMITS.scan);
    if (limited) return limited;

    assertRequestAuthorized(req);

    const body = await req.json().catch(() => null);
    rawTarget = typeof body?.url === "string" ? body.url : "";
    const url = await normalizeUrl(body?.url);
    assertTargetPolicy(url, body?.authorized);
    const origin = url.origin;

    const [redirectResult, robots, leaks] = await Promise.all([
      verifyRedirectChain(url).catch((error) => {
        if (error instanceof ScanError) throw error;
        throw new ScanError("Couldn't reach that site. It may be offline or blocking scanners.", 502);
      }),
      checkRobots(origin),
      Promise.all(LEAK_PATHS.map((t) => checkLeak(origin, t))),
    ]);
    const mainRes = redirectResult.response;
    const isHttps = mainRes.finalUrl.protocol === "https:";
    const contentType = mainRes.headers.get("content-type") ?? "";
    const html = contentType.includes("text/html") ? await readText(mainRes, 250_000) : "";
    const { items, cspAnalysis } = evaluateHeaders(mainRes.headers, isHttps);
    const isolation = evaluateIsolationHeaders(mainRes.headers);
    const exposures = evaluateHeaderExposures(mainRes.headers);
    const raw = collectRawHeaders(mainRes.headers);
    const cookies = evaluateCookies(mainRes.headers, isHttps);
    const htmlFindings = inspectHtml(html, isHttps, mainRes.finalUrl.hostname, mainRes.headers);
    const homeFindingsTitles = htmlFindings.map((f) => f.title);
    const homeCookiesCount = cookies.length;

    // Bounded same-origin subpage crawl (up to 5 subpages discovered on the entry page)
    const subpageTargets = extractSameOriginSubpages(html, mainRes.finalUrl);
    const crawled = await crawlSameOriginSubpages(subpageTargets, mainRes.finalUrl.hostname);

    for (const extraCookie of crawled.extraCookies) {
      if (!cookies.some((c) => c.name === extraCookie.name)) {
        cookies.push(extraCookie);
      }
    }
    for (const extraFinding of crawled.extraFindings) {
      if (!htmlFindings.some((f) => f.key === extraFinding.key)) {
        htmlFindings.push(extraFinding);
      }
    }

    const entryPath = `${mainRes.finalUrl.pathname}${mainRes.finalUrl.search}` || "/";
    const crawledPages: CrawledPage[] = [
      {
        path: entryPath,
        url: mainRes.finalUrl.toString(),
        status: mainRes.status,
        findingsCount: homeFindingsTitles.length,
        cookiesCount: homeCookiesCount,
        findings: homeFindingsTitles,
      },
      ...crawled.pages,
    ];

    const detectedStack = detectStack(mainRes.headers, html);
    const { score, grade, testsPassed, testsTotal } = computeScoreAndGrade(
      items,
      leaks,
      cookies,
      htmlFindings,
    );

    const result: ScanResult = {
      url: url.toString(),
      finalUrl: mainRes.finalUrl.toString(),
      scannedAt: new Date().toISOString(),
      score,
      grade,
      testsPassed,
      testsTotal,
      detectedStack,
      robots,
      headers: { status: mainRes.status, items, cspAnalysis, isolation, exposures, raw },
      cookies,
      htmlFindings,
      leaks,
      redirects: redirectResult.evidence,
      crawledPages,
    };

    const capabilityToken = await persistScanRecord(result);
    if (capabilityToken) result.capabilityToken = capabilityToken;

    auditLog({
      action: "scan.completed",
      req,
      targetUrl: url.toString(),
      status: 200,
      durationMs: Date.now() - startedAt,
      meta: {
        score,
        grade,
        testsPassed,
        testsTotal,
        detectedStack,
        exposedLeaks: leaks.filter((l) => l.state === "exposed").map((l) => l.path),
      },
    });

    return NextResponse.json(result);
  } catch (e) {
    if (e instanceof ScanRecordStoreError) {
      auditLog({
        action: "scan.failed",
        req,
        targetUrl: rawTarget || undefined,
        status: 503,
        durationMs: Date.now() - startedAt,
        meta: { reason: e.name },
      });
      return NextResponse.json({ error: e.message }, { status: 503 });
    }
    if (e instanceof ScanError) {
      auditLog({
        action: e.status === 401 || e.status === 403 ? "policy.denied" : "scan.blocked",
        req,
        targetUrl: rawTarget || undefined,
        status: e.status,
        durationMs: Date.now() - startedAt,
        meta: { reason: e.message },
      });
      return NextResponse.json({ error: e.message }, { status: e.status });
    }
    auditLog({
      action: "scan.failed",
      req,
      targetUrl: rawTarget || undefined,
      status: 500,
      durationMs: Date.now() - startedAt,
      meta: { reason: e instanceof Error ? e.name : "UnknownError" },
    });
    return NextResponse.json({ error: "Scan failed unexpectedly. Try again." }, { status: 500 });
  }
}
