import type { ScanResult } from "@/lib/types";

type Platform = "nginx" | "apache" | "next";

const registry: Record<string, Record<Platform, string>> = {
  csp: {
    nginx: "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests\" always;",
    apache: "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests\"",
    next: '{ key: "Content-Security-Policy", value: "default-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\'; upgrade-insecure-requests" },',
  },
  xfo: {
    nginx: 'add_header X-Frame-Options "DENY" always;', apache: 'Header always set X-Frame-Options "DENY"', next: '{ key: "X-Frame-Options", value: "DENY" },',
  },
  hsts: {
    nginx: 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;', apache: 'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"', next: '{ key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },',
  },
  xcto: {
    nginx: 'add_header X-Content-Type-Options "nosniff" always;', apache: 'Header always set X-Content-Type-Options "nosniff"', next: '{ key: "X-Content-Type-Options", value: "nosniff" },',
  },
  rp: {
    nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;', apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"', next: '{ key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },',
  },
  pp: {
    nginx: 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;', apache: 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"', next: '{ key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },',
  },
};

function platformFor(stack: string[]): Platform {
  const lower = stack.map((item) => item.toLowerCase());
  if (lower.includes("next.js") || lower.includes("vercel")) return "next";
  if (lower.includes("apache")) return "apache";
  return "nginx";
}

/** Deterministic config snippets; external AI is never allowed to generate or modify these. */
export function compileStaticRemediation(scan: ScanResult): { language: string; code: string } {
  const platform = platformFor(scan.detectedStack);
  const needed = scan.headers.items.filter((header) => header.state !== "strong").map((header) => header.key);
  const snippets = [...new Set(needed)].flatMap((rule) => (registry[rule]?.[platform] ? [registry[rule][platform]] : []));
  const leakExposed = scan.leaks.some((leak) => leak.state === "exposed");

  if (platform === "next") {
    return {
      language: "javascript",
      code: `// next.config.mjs — deterministic server-side remediation\nconst nextConfig = {\n  poweredByHeader: false,\n  async headers() {\n    return [{ source: "/:path*", headers: [\n      ${snippets.length ? snippets.join("\n      ") : '{ key: "X-Content-Type-Options", value: "nosniff" },'}\n    ] }];\n  },\n};\n\nexport default nextConfig;`,
    };
  }

  if (platform === "apache") {
    const deny = leakExposed ? '\n\n<FilesMatch "^\\\\.(env|git)">\n  Require all denied\n</FilesMatch>' : "";
    return { language: "apache", code: `# .htaccess — deterministic server-side remediation\n<IfModule mod_headers.c>\n  ${snippets.length ? snippets.join("\n  ") : 'Header always set X-Content-Type-Options "nosniff"'}\n</IfModule>${deny}` };
  }

  const deny = leakExposed ? "\n\nlocation ~ /\\.(env|git) { deny all; return 404; }" : "";
  return { language: "nginx", code: `# nginx.conf — deterministic server-side remediation\nserver {\n  server_tokens off;\n  ${snippets.length ? snippets.join("\n  ") : 'add_header X-Content-Type-Options "nosniff" always;'}${deny}\n}` };
}
