import { createHash } from "node:crypto";

function extractIp(req: Request): string {
  const h = req.headers;
  const forwarded = h.get("x-forwarded-for")?.split(",")[0]?.trim();
  return h.get("x-real-ip")?.trim() || forwarded || "unknown";
}

export type AuditAction =
  | "scan.completed"
  | "scan.blocked"
  | "scan.failed"
  | "analyze.completed"
  | "analyze.failed"
  | "rate_limit.exceeded"
  | "policy.denied";

export interface AuditEvent {
  action: AuditAction;
  req?: Request;
  targetUrl?: string;
  status: number;
  durationMs?: number;
  meta?: Record<string, unknown>;
}

const SENSITIVE_PARAM_RE = /^(key|api[_-]?key|token|access[_-]?token|secret|password|passwd|auth|signature|sig|jwt|session)$/i;

const SECRET_VALUE_RE =
  /\b(AIza[0-9A-Za-z_-]{20,}|sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|Bearer\s+[A-Za-z0-9._~+/=-]+)\b/g;

/** Strips credentials and redacts sensitive query parameters from a URL before logging. */
export function sanitizeUrlForLog(rawUrl: string): string {
  try {
    const u = new URL(rawUrl);
    u.username = "";
    u.password = "";
    u.hash = "";
    for (const key of Array.from(u.searchParams.keys())) {
      if (SENSITIVE_PARAM_RE.test(key)) {
        u.searchParams.set(key, "[REDACTED]");
      }
    }
    return u.toString().slice(0, 300);
  } catch {
    return redactSecrets(rawUrl).slice(0, 200);
  }
}

/** Redacts API keys, bearer tokens, and secret assignments from arbitrary strings. */
export function redactSecrets(input: string): string {
  return input
    .replace(SECRET_VALUE_RE, "[REDACTED]")
    .replace(
      /((?:api[_-]?key|secret|token|password|authorization)\s*[:=]\s*["']?)[^\s"',;]+/gi,
      "$1[REDACTED]",
    );
}

function sanitizeMeta(value: unknown, depth = 0): unknown {
  if (depth > 3 || value == null) return value ?? null;
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "string") return redactSecrets(value).slice(0, 300);
  if (Array.isArray(value)) return value.slice(0, 15).map((item) => sanitizeMeta(item, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_PARAM_RE.test(k)) {
        out[k] = "[REDACTED]";
      } else {
        out[k] = sanitizeMeta(v, depth + 1);
      }
    }
    return out;
  }
  return String(value).slice(0, 100);
}

/** Anonymizes client IP into a stable correlation hash without storing raw IP addresses. */
export function hashActorIp(req?: Request): string {
  if (!req) return "system";
  const ip = extractIp(req);
  if (ip === "unknown") return "unknown";
  const salt = process.env.RATE_LIMIT_KEY_SALT ?? "devsec-guard-audit";
  return createHash("sha256").update(`${salt}:${ip}`).digest("hex").slice(0, 16);
}

/**
 * Emits a structured JSON audit record to stdout without ever logging secrets,
 * raw client IPs, cookie values, or `.env` file contents.
 */
export function auditLog(event: AuditEvent): void {
  if (process.env.AUDIT_LOG_ENABLED?.toLowerCase() === "false") return;

  const record: Record<string, unknown> = {
    ts: new Date().toISOString(),
    type: "security_audit",
    action: event.action,
    actor: hashActorIp(event.req),
    status: event.status,
  };

  if (event.targetUrl) {
    record.target = sanitizeUrlForLog(event.targetUrl);
  }
  if (typeof event.durationMs === "number") {
    record.durationMs = Math.round(event.durationMs);
  }
  if (event.meta) {
    record.meta = sanitizeMeta(event.meta);
  }

  console.info(JSON.stringify(record));
}
