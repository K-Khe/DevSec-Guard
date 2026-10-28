"use client";

import { useState } from "react";
import { Bot, ChevronDown, Code2, Cookie, EyeOff, FileWarning, Info, Lightbulb, ShieldAlert, ShieldHalf, Wrench, X } from "lucide-react";
import type { HeaderState, HtmlFindingSeverity, LeakState, ScanResult } from "@/lib/types";
import { getSecurityDictionaryEntry, type FixDifficulty, type SecurityDictionaryEntry } from "@/lib/security-dictionary";
import { Card, Pill, type Tone } from "./ui";

const DIFFICULTY_TONE: Record<FixDifficulty, { tone: Tone; label: string }> = {
  Easy: { tone: "ok", label: "Easy (แก้ได้ง่าย)" },
  Medium: { tone: "warn", label: "Medium (ปานกลาง)" },
  Hard: { tone: "bad", label: "Hard (ซับซ้อน)" },
};

function DictionaryModal({
  entry,
  onClose,
}: {
  entry: SecurityDictionaryEntry;
  onClose: () => void;
}) {
  const diff = DIFFICULTY_TONE[entry.fixDifficulty];
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="dict-modal-title"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-xl border border-neon-cyan/40 bg-ink-900 p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3 border-b border-white/10 pb-3">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-wider text-neon-cyan">
              Security Dictionary · คำอธิบายสำหรับคนทั่วไป
            </p>
            <h3 id="dict-modal-title" className="mt-1 font-mono text-base font-bold text-white">
              {entry.title}
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dictionary modal"
            className="rounded-lg p-1 text-slate-400 hover:bg-white/10 hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-4 space-y-3.5 text-sm">
          <div className="rounded-lg border border-neon-purple/30 bg-neon-purple/10 p-3.5">
            <p className="mb-1 flex items-center gap-1.5 font-mono text-xs font-semibold text-neon-purple">
              <Lightbulb className="h-3.5 w-3.5" />
              เปรียบเทียบให้เห็นภาพ (Simple Analogy)
            </p>
            <p className="leading-relaxed text-slate-200">{entry.simpleAnalogy}</p>
          </div>

          <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3.5">
            <p className="mb-1 flex items-center gap-1.5 font-mono text-xs font-semibold text-red-300">
              <ShieldAlert className="h-3.5 w-3.5" />
              ความเสี่ยงหากไม่มีหรือปล่อยรั่วไหล (Risk if Missing)
            </p>
            <p className="leading-relaxed text-slate-200">{entry.riskIfMissing}</p>
          </div>

          <div className="flex items-center justify-between rounded-lg bg-ink-800 px-3.5 py-2.5 text-xs">
            <span className="inline-flex items-center gap-1.5 font-mono text-slate-400">
              <Wrench className="h-3.5 w-3.5 text-neon-cyan" />
              ความยากในการแก้ไข (Fix Difficulty):
            </span>
            <Pill tone={diff.tone}>{diff.label}</Pill>
          </div>
        </div>
      </div>
    </div>
  );
}

function InfoButton({
  lookupKey,
  onSelect,
}: {
  lookupKey: string;
  onSelect: (entry: SecurityDictionaryEntry) => void;
}) {
  const entry = getSecurityDictionaryEntry(lookupKey);
  if (!entry) return null;
  return (
    <button
      type="button"
      onClick={() => onSelect(entry)}
      title={`ดูคำอธิบาย ${entry.title} แบบเข้าใจง่าย`}
      aria-label={`ดูคำอธิบาย ${entry.title}`}
      className="inline-flex items-center justify-center rounded-full p-1 text-slate-400 transition hover:bg-neon-cyan/15 hover:text-neon-cyan focus:outline-none focus-visible:ring-2 focus-visible:ring-neon-cyan"
    >
      <Info className="h-3.5 w-3.5" />
    </button>
  );
}

export function ScraperDefenseCard({ data }: { data: ScanResult["robots"] }) {
  return (
    <Card title="AI Crawler Policy" icon={<Bot className="h-5 w-5" />} accent="purple">
      <p className="mb-4 text-sm text-slate-400">
        {data.found
          ? "robots.txt found. Optional content-licensing policy (does not affect security score)."
          : `No robots.txt (HTTP ${data.status ?? "error"}). AI crawlers are allowed by default (informational).`}
      </p>
      <ul className="space-y-2">
        {data.bots.map((b) => (
          <li key={b.name} className="flex items-center justify-between rounded-lg bg-ink-800 px-3 py-2">
            <span className="font-mono text-sm">{b.name}</span>
            <Pill tone={b.blocked ? "ok" : "muted"}>{b.blocked ? "Disallowed" : "Allowed"}</Pill>
          </li>
        ))}
      </ul>
    </Card>
  );
}

const HEADER_UI: Record<HeaderState, { tone: Tone; label: string }> = {
  strong: { tone: "ok", label: "Present" },
  weak: { tone: "warn", label: "Weak" },
  missing: { tone: "bad", label: "Missing" },
};

export function SecurityHeadersCard({ data }: { data: ScanResult["headers"] }) {
  const [activeDict, setActiveDict] = useState<SecurityDictionaryEntry | null>(null);
  const exposures = data.exposures ?? [];
  const isolation = data.isolation ?? [];
  const raw = data.raw ?? [];

  return (
    <Card title="Security Headers" icon={<ShieldHalf className="h-5 w-5" />} accent="cyan">
      <p className="mb-4 text-sm text-slate-400">
        Response headers from the page (HTTP {data.status}). กดไอคอน <Info className="inline h-3.5 w-3.5 text-neon-cyan" /> เพื่อดูคำอธิบายแบบเข้าใจง่าย
      </p>
      <ul className="space-y-2">
        {data.items.map((h) => {
          const ui = HEADER_UI[h.state ?? (h.present ? "strong" : "missing")];
          return (
            <li key={h.key} className="rounded-lg bg-ink-800 px-3 py-2">
              <div className="flex items-center justify-between gap-3">
                <span className="inline-flex items-center gap-1.5 font-mono text-sm">
                  {h.label}
                  <InfoButton lookupKey={h.key} onSelect={setActiveDict} />
                </span>
                <Pill tone={ui.tone}>{ui.label}</Pill>
              </div>
              {h.value && (
                <p className="mt-1 truncate font-mono text-xs text-slate-500" title={h.value}>
                  {h.value}
                </p>
              )}
              {h.note && <p className="mt-1 text-xs text-amber-300/90">{h.note}</p>}
            </li>
          );
        })}
      </ul>
      {activeDict && <DictionaryModal entry={activeDict} onClose={() => setActiveDict(null)} />}

      {exposures.length > 0 && (
        <div className="mt-4 border-t border-white/10 pt-3">
          <p className="mb-2 flex items-center gap-1.5 font-mono text-xs uppercase tracking-wider text-amber-300">
            <EyeOff className="h-3.5 w-3.5" />
            Information Disclosure
          </p>
          <ul className="space-y-2">
            {exposures.map((exp) => (
              <li key={exp.header} className="rounded-lg border border-amber-400/20 bg-amber-400/5 px-3 py-2">
                <div className="flex items-center justify-between gap-3">
                  <span className="font-mono text-xs text-amber-200">
                    {exp.header}: <span className="text-white">{exp.value}</span>
                  </span>
                  <Pill tone="warn">Exposed</Pill>
                </div>
                <p className="mt-1 text-xs text-slate-400">{exp.note}</p>
              </li>
            ))}
          </ul>
        </div>
      )}

      {(isolation.length > 0 || raw.length > 0) && (
        <details className="group mt-4 rounded-lg border border-white/10 bg-ink-950/60 px-3 py-2 text-xs">
          <summary className="flex cursor-pointer list-none items-center justify-between font-mono text-slate-400 hover:text-neon-cyan">
            <span>Upcoming (COOP/COEP/CORP) &amp; Raw Headers ({raw.length})</span>
            <ChevronDown className="h-3.5 w-3.5 transition group-open:rotate-180" />
          </summary>

          {isolation.length > 0 && (
            <div className="mt-3 space-y-1.5 border-t border-white/10 pt-2.5">
              <p className="font-mono text-[11px] uppercase tracking-wider text-slate-500">
                Cross-Origin Isolation (Upcoming)
              </p>
              {isolation.map((iso) => (
                <div key={iso.key} className="flex items-center justify-between gap-2 py-0.5">
                  <span className="truncate font-mono text-slate-300">{iso.label}</span>
                  <Pill tone={iso.present ? (iso.reportOnly ? "warn" : "ok") : "muted"}>
                    {iso.present ? iso.value ?? "Present" : "Not set"}
                  </Pill>
                </div>
              ))}
            </div>
          )}

          {raw.length > 0 && (
            <div className="mt-3 border-t border-white/10 pt-2.5">
              <p className="mb-1.5 font-mono text-[11px] uppercase tracking-wider text-slate-500">Raw Headers</p>
              <dl className="max-h-48 space-y-1 overflow-y-auto pr-1 font-mono text-[11px]">
                {raw.map((entry, idx) => (
                  <div key={`${entry.name}-${idx}`} className="grid grid-cols-[120px_1fr] gap-2 border-b border-white/5 pb-1">
                    <dt className="truncate text-neon-cyan" title={entry.name}>
                      {entry.name}
                    </dt>
                    <dd className="break-all text-slate-400">{entry.value}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}
        </details>
      )}
    </Card>
  );
}

export function CookieSecurityCard({ data }: { data: ScanResult["cookies"] }) {
  return (
    <Card title="Cookie Security" icon={<Cookie className="h-5 w-5" />} accent="cyan">
      <p className="mb-4 text-sm text-slate-400">Cookie values are never collected or displayed.</p>
      {data.length === 0 ? (
        <p className="rounded-lg bg-ink-800 px-3 py-2 text-sm text-slate-400">No Set-Cookie headers observed.</p>
      ) : (
        <ul className="space-y-2">
          {data.map((cookie) => {
            const ui = HEADER_UI[cookie.state];
            return (
              <li key={cookie.name} className="rounded-lg bg-ink-800 px-3 py-2">
                <div className="flex items-center justify-between gap-3">
                  <span className="font-mono text-sm">{cookie.name}</span>
                  <Pill tone={ui.tone}>{cookie.state === "strong" ? "Strong" : "Weak"}</Pill>
                </div>
                <p className="mt-1 text-xs text-slate-500">
                  Secure: {String(cookie.secure)} · HttpOnly: {String(cookie.httpOnly)} · SameSite: {cookie.sameSite ?? "missing"}
                </p>
                {cookie.note && <p className="mt-1 text-xs text-amber-300">{cookie.note}</p>}
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

const HTML_TONE: Record<HtmlFindingSeverity, Tone> = { high: "bad", medium: "warn", low: "muted" };

export function HtmlInspectionCard({ data }: { data: ScanResult["htmlFindings"] }) {
  return (
    <Card title="HTML Inspection" icon={<Code2 className="h-5 w-5" />} accent="purple">
      <p className="mb-4 text-sm text-slate-400">Rule-based source checks; findings require validation.</p>
      {data.length === 0 ? (
        <p className="rounded-lg bg-ink-800 px-3 py-2 text-sm text-slate-400">No high-signal client-side patterns found.</p>
      ) : (
        <ul className="space-y-2">
          {data.map((finding) => (
            <li key={finding.key} className="rounded-lg bg-ink-800 px-3 py-2">
              <div className="flex items-center justify-between gap-3">
                <span className="font-mono text-sm">{finding.title}</span>
                <Pill tone={HTML_TONE[finding.severity]}>{finding.severity}</Pill>
              </div>
              <p className="mt-1 text-xs text-slate-500">{finding.note}</p>
            </li>
          ))}
        </ul>
      )}
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
  const [activeDict, setActiveDict] = useState<SecurityDictionaryEntry | null>(null);

  return (
    <Card title="Dev Leaks" icon={<FileWarning className="h-5 w-5" />} accent="green">
      <p className="mb-4 text-sm text-slate-400">Sensitive paths that should never return a file.</p>
      <ul className="space-y-2">
        {data.map((l) => (
          <li key={l.path} className="rounded-lg bg-ink-800 px-3 py-2">
            <div className="flex items-center justify-between gap-3">
              <span className="inline-flex items-center gap-1.5 font-mono text-sm">
                <span>
                  {l.path} <span className="text-slate-500">{l.status ?? "-"}</span>
                </span>
                <InfoButton lookupKey={l.path} onSelect={setActiveDict} />
              </span>
              <Pill tone={LEAK_UI[l.state].tone}>{LEAK_UI[l.state].label}</Pill>
            </div>
            <p className="mt-1 text-xs text-slate-500">{l.note}</p>
          </li>
        ))}
      </ul>
      {activeDict && <DictionaryModal entry={activeDict} onClose={() => setActiveDict(null)} />}
    </Card>
  );
}
