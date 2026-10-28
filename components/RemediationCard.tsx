"use client";

import { useState, type ReactNode } from "react";
import { Check, Copy, Loader2, RotateCw, Sparkles } from "lucide-react";
import type { AnalysisResult } from "@/lib/types";
import { Card } from "./ui";

const TOKEN =
  /(\/\/.*|#.*)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)|\b(const|let|export|default|async|await|return|import|from|function|module|location|add_header|always|User-agent|Disallow|Allow)\b|(\b\d+\b)/g;

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
  analysis: AnalysisResult | null;
  loading: boolean;
  error: string | null;
  onRetry: () => void;
}

export default function RemediationCard({ analysis, loading, error, onRetry }: Props) {
  return (
    <Card title="AI Remediation" icon={<Sparkles className="h-5 w-5" />} accent="purple" className="md:col-span-3">
      {loading && (
        <p className="flex items-center gap-2 text-sm text-slate-400" role="status">
          <Loader2 className="h-4 w-4 animate-spin text-neon-purple" />
          The auditor is reviewing the findings and writing a fix.
        </p>
      )}

      {error && !loading && (
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
      )}

      {analysis && !loading && (
        <div className="grid gap-6 lg:grid-cols-[200px_1fr]">
          <div>
            <p className="text-sm text-slate-400">Security grade</p>
            <p className={`font-mono text-7xl font-bold ${gradeColor(analysis.grade)}`}>{analysis.grade}</p>
            <p className="mt-3 text-sm leading-relaxed text-slate-300">{analysis.summary}</p>
          </div>
          <CodeBlock code={analysis.code} language={analysis.language} />
        </div>
      )}
    </Card>
  );
}
