export interface BotRule {
  name: string;
  blocked: boolean;
}

export interface HeaderCheck {
  key: "csp" | "xfo" | "hsts";
  label: string;
  present: boolean;
  value: string | null;
}

export type LeakState = "exposed" | "soft-200" | "safe" | "unreachable";

export interface LeakCheck {
  path: string;
  status: number | null;
  state: LeakState;
  note: string;
}

export interface ScanResult {
  url: string;
  scannedAt: string;
  robots: { found: boolean; status: number | null; bots: BotRule[] };
  headers: { status: number | null; items: HeaderCheck[] };
  leaks: LeakCheck[];
}

export interface AnalysisResult {
  grade: string;
  summary: string;
  language: string;
  code: string;
}
