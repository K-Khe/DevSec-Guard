"use client";

import { useState, type ReactNode } from "react";
import { Check, Copy, Cpu, EyeOff, Lightbulb, Loader2, Lock, RotateCw, Sparkles } from "lucide-react";
import type { AnalysisResult, ScanResult } from "@/lib/types";
import { Card, Pill } from "./ui";

const TOKEN =
  /(\/\/.*|#.*)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)|\b(const|let|export|default|async|await|return|import|from|function|module|location|add_header|always|User-agent|Disallow|Allow|headers|source|key|value|poweredByHeader|server_tokens|fastcgi_hide_header|proxy_hide_header|expose_php|true|false)\b|(\b\d+\b)/g;

const COLORS = ["text-slate-500 italic", "text-neon-green", "text-neon-purple", "text-neon-cyan"];

function highlight(line: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  for (const m of line.matchAll(TOKEN)) {
    const i = m.index ?? 0;
    if (i > last) out.push(line.slice(last, i));
    const group = [1, 2, 3, 4].find((g) => m[g] !== undefined)!;
    out.push(
      <span key={i} className={COLORS[group - 1]}>
        {m[0]}
      </span>
    );
    last = i + m[0].length;
  }
  if (last < line.length) out.push(line.slice(last));
  return out;
}

function CodeBlock({ code, language }: { code: string; language: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <div className="overflow-hidden rounded-lg border border-white/10 bg-ink-950">
      <div className="flex items-center justify-between border-b border-white/10 px-4 py-2">
        <span className="font-mono text-xs text-slate-500">{language}</span>
        <button
          onClick={copy}
          className="inline-flex items-center gap-1.5 rounded px-2 py-1 text-xs text-slate-400 hover:text-neon-cyan focus:outline-none focus-visible:ring-2 focus-visible:ring-neon-cyan"
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto p-4 font-mono text-[13px] leading-relaxed text-slate-300">
        <code>
          {code.split("\n").map((line, i) => (
            <div key={i}>{highlight(line) || "\u00a0"}</div>
          ))}
        </code>
      </pre>
    </div>
  );
}

function gradeColor(grade: string) {
  if (grade.startsWith("A")) return "text-neon-green";
  if (grade.startsWith("B")) return "text-neon-cyan";
  if (grade.startsWith("C")) return "text-neon-purple";
  return "text-red-400";
}

interface Props {
  scan: ScanResult;
  analysis: AnalysisResult | null;
  loading: boolean;
  error: string | null;
  onRetry: () => void;
}

export default function RemediationCard({ scan, analysis, loading, error, onRetry }: Props) {
  const displayGrade = analysis?.grade ?? scan.grade;
  const displayScore = analysis?.score ?? scan.score;
  const stack = scan.detectedStack ?? [];

  return (
    <Card accent="purple" className="md:col-span-3">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3 text-xs text-slate-400">
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 font-mono text-slate-400">
            <Cpu className="h-3.5 w-3.5 text-neon-cyan" />
            Detected Stack:
          </span>
          {stack.length > 0 ? (
            stack.map((item) => (
              <Pill key={item} tone="ok">
                {item}
              </Pill>
            ))
          ) : (
            <Pill tone="muted">Unknown (Generic / nginx)</Pill>
          )}
        </div>
        {analysis && (
          <div className="flex items-center gap-1.5">
            {analysis.mode === "local" ? (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-neon-green/40 bg-neon-green/10 px-2.5 py-0.5 font-mono text-[11px] text-neon-green">
                <Lock className="h-3 w-3" />
                100% Local Engine (Zero External AI)
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-neon-purple/40 bg-neon-purple/10 px-2.5 py-0.5 font-mono text-[11px] text-neon-purple">
                <EyeOff className="h-3 w-3" />
                Target Anonymized (redacted-target.invalid)
              </span>
            )}
          </div>
        )}
      </div>

      {loading && (
        <div className="flex flex-wrap items-center justify-between gap-4">
          <p className="flex items-center gap-2 text-sm text-slate-400" role="status">
            <Loader2 className="h-4 w-4 animate-spin text-neon-purple" />
            The auditor is reviewing the findings and writing a tailored fix...
          </p>
          <div className="flex items-baseline gap-2 font-mono">
            <span className="text-xs text-slate-500">Baseline:</span>
            <span className={`text-2xl font-bold ${gradeColor(displayGrade)}`}>{displayGrade}</span>
            <span className="text-sm text-slate-400">({displayScore}/100)</span>
          </div>
        </div>
      )}

      {error && !loading && (
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3 text-sm text-red-400" role="alert">
            {error}
            <button
              onClick={onRetry}
              className="inline-flex items-center gap-1.5 rounded-md border border-red-400/40 px-3 py-1.5 text-red-300 hover:bg-red-400/10 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-400"
            >
              <RotateCw className="h-3.5 w-3.5" />
              Retry analysis
            </button>
          </div>
          <div className="flex items-baseline gap-2 font-mono">
            <span className="text-xs text-slate-500">Baseline:</span>
            <span className={`text-2xl font-bold ${gradeColor(displayGrade)}`}>{displayGrade}</span>
            <span className="text-sm text-slate-400">({displayScore}/100)</span>
          </div>
        </div>
      )}

      {analysis && !loading && (
        <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
          <div>
            <p className="text-sm text-slate-400">Security grade</p>
            <div className="mt-1 flex items-baseline gap-3">
              <p className={`font-mono text-7xl font-bold leading-none ${gradeColor(displayGrade)}`}>{displayGrade}</p>
              <span className="rounded-md border border-white/10 bg-ink-800 px-2.5 py-1 font-mono text-sm text-slate-300">
                {displayScore}/100
              </span>
            </div>
            <p className="mt-3 text-sm leading-relaxed text-slate-300">{analysis.summary}</p>

            {analysis.laymanSummary && (
              <div className="mt-4 rounded-lg border border-neon-cyan/30 bg-neon-cyan/10 p-3.5">
                <p className="mb-1 flex items-center gap-1.5 font-mono text-xs font-semibold text-neon-cyan">
                  <Lightbulb className="h-3.5 w-3.5 shrink-0" />
                  สรุปเปรียบเทียบสำหรับคนทั่วไป (Layman Summary)
                </p>
                <p className="text-xs leading-relaxed text-slate-200">{analysis.laymanSummary}</p>
              </div>
            )}

            {analysis.findings && analysis.findings.length > 0 && (
              <div className="mt-4 border-t border-white/10 pt-3">
                <p className="mb-2 font-mono text-xs uppercase tracking-wider text-slate-400">Key Findings</p>
                <ul className="space-y-1.5 text-xs leading-relaxed text-slate-300">
                  {analysis.findings.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-neon-purple" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
          <div className="self-start lg:sticky lg:top-24">
            <CodeBlock code={analysis.code} language={analysis.language} />
          </div>
        </div>
      )}
    </Card>
  );
}
