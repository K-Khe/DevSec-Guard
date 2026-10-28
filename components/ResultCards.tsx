import { Bot, FileWarning, ShieldHalf } from "lucide-react";
import type { LeakState, ScanResult } from "@/lib/types";
import { Card, Pill, type Tone } from "./ui";

export function ScraperDefenseCard({ data }: { data: ScanResult["robots"] }) {
  return (
    <Card title="AI Scraper Defense" icon={<Bot className="h-5 w-5" />} accent="purple">
      <p className="mb-4 text-sm text-slate-400">
        {data.found
          ? "robots.txt found. Checking whether each AI crawler is disallowed."
          : `No robots.txt (HTTP ${data.status ?? "error"}). Crawlers are allowed by default.`}
      </p>
      <ul className="space-y-2">
        {data.bots.map((b) => (
          <li key={b.name} className="flex items-center justify-between rounded-lg bg-ink-800 px-3 py-2">
            <span className="font-mono text-sm">{b.name}</span>
            <Pill tone={b.blocked ? "ok" : "bad"}>{b.blocked ? "Blocked" : "Allowed"}</Pill>
          </li>
        ))}
      </ul>
    </Card>
  );
}

export function SecurityHeadersCard({ data }: { data: ScanResult["headers"] }) {
  return (
    <Card title="Security Headers" icon={<ShieldHalf className="h-5 w-5" />} accent="cyan">
      <p className="mb-4 text-sm text-slate-400">Response headers from the page (HTTP {data.status}).</p>
      <ul className="space-y-2">
        {data.items.map((h) => (
          <li key={h.key} className="rounded-lg bg-ink-800 px-3 py-2">
            <div className="flex items-center justify-between gap-3">
              <span className="font-mono text-sm">{h.label}</span>
              <Pill tone={h.present ? "ok" : "bad"}>{h.present ? "Present" : "Missing"}</Pill>
            </div>
            {h.value && (
              <p className="mt-1 truncate font-mono text-xs text-slate-500" title={h.value}>
                {h.value}
              </p>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
}

const LEAK_UI: Record<LeakState, { tone: Tone; label: string }> = {
  exposed: { tone: "bad", label: "Exposed" },
  "soft-200": { tone: "warn", label: "200, no file" },
  safe: { tone: "ok", label: "Safe" },
  unreachable: { tone: "muted", label: "No response" },
};

export function DevLeaksCard({ data }: { data: ScanResult["leaks"] }) {
  return (
    <Card title="Dev Leaks" icon={<FileWarning className="h-5 w-5" />} accent="green">
      <p className="mb-4 text-sm text-slate-400">Sensitive paths that should never return a file.</p>
      <ul className="space-y-2">
        {data.map((l) => (
          <li key={l.path} className="rounded-lg bg-ink-800 px-3 py-2">
            <div className="flex items-center justify-between gap-3">
              <span className="font-mono text-sm">
                {l.path} <span className="text-slate-500">{l.status ?? "-"}</span>
              </span>
              <Pill tone={LEAK_UI[l.state].tone}>{LEAK_UI[l.state].label}</Pill>
            </div>
            <p className="mt-1 text-xs text-slate-500">{l.note}</p>
          </li>
        ))}
      </ul>
    </Card>
  );
}
