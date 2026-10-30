export interface BotRule {
  name: string;
  blocked: boolean;
}

export type HeaderKey = "csp" | "xfo" | "hsts" | "xcto" | "rp" | "pp";

export type HeaderState = "strong" | "weak" | "missing";

export interface CspCheckItem {
  id: string;
  label: string;
  passed: boolean;
  info: string;
}

export interface HeaderCheck {
  key: HeaderKey;
  label: string;
  present: boolean;
  state: HeaderState;
  value: string | null;
  note?: string;
}

export type IsolationHeaderKey = "coop" | "coep" | "corp" | "cors";

export interface IsolationHeaderCheck {
  key: IsolationHeaderKey;
  label: string;
  present: boolean;
  reportOnly?: boolean;
  value: string | null;
}

export interface HeaderExposure {
  header: string;
  value: string;
  note: string;
}

export interface RawHeaderEntry {
  name: string;
  value: string;
}

export type LeakState = "exposed" | "soft-200" | "safe" | "unreachable";

export interface LeakCheck {
  path: string;
  status: number | null;
  state: LeakState;
  note: string;
}

export interface CookieCheck {
  /** Cookie name only. Values are deliberately never retained or returned. */
  name: string;
  path: string | null;
  expires: string | null;
  prefix: "__Host-" | "__Secure-" | null;
  secure: boolean;
  httpOnly: boolean;
  sameSite: "Strict" | "Lax" | "None" | null;
  state: HeaderState;
  note?: string;
}

export type HtmlFindingSeverity = "high" | "medium" | "low";

export interface HtmlFinding {
  key:
    | "mixed-content"
    | "insecure-form"
    | "source-map"
    | "possible-secret"
    | "unsafe-blank-link"
    | "missing-sri"
    | "wordpress-surface"
    | "php-version-exposure";
  severity: HtmlFindingSeverity;
  title: string;
  note: string;
}

export type RedirectChainStatus =
  | "no_redirect"
  | "http_upgraded"
  | "clean_secure"
  | "insecure_start"
  | "invalid_first_upgrade"
  | "downgrade_detected"
  | "max_hops_exceeded"
  | "invalid_redirect";

export interface RedirectHop {
  hopIndex: number;
  statusCode: number;
  protocol: "http" | "https";
  hostChangedFromPrevious: boolean;
}

export interface CrawledPage {
  path: string;
  url: string;
  status: number | null;
  findingsCount: number;
  cookiesCount: number;
  findings: string[];
}

export interface ScanResult {
  url: string;
  finalUrl?: string;
  scannedAt: string;
  score: number;
  grade: string;
  testsPassed?: number;
  testsTotal?: number;
  detectedStack: string[];
  robots: { found: boolean; status: number | null; bots: BotRule[] };
  headers: {
    status: number | null;
    items: HeaderCheck[];
    cspAnalysis?: CspCheckItem[];
    isolation?: IsolationHeaderCheck[];
    exposures?: HeaderExposure[];
    raw?: RawHeaderEntry[];
  };
  cookies: CookieCheck[];
  htmlFindings: HtmlFinding[];
  leaks: LeakCheck[];
  redirects?: { status: RedirectChainStatus; secure: boolean; hops: RedirectHop[] };
  crawledPages?: CrawledPage[];
  /** Present only when a server-side, expiring scan record was secured successfully. */
  capabilityToken?: string;
}

export type AnalysisMode = "local" | "ai-anonymized";

export interface AnalysisResult {
  grade: string;
  score: number;
  summary: string;
  laymanSummary?: string;
  findings: string[];
  language: string;
  code: string;
  mode?: AnalysisMode;
  anonymized?: boolean;
}
