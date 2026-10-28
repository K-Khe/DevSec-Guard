"use client";

import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import ScanForm from "@/components/ScanForm";
import RemediationCard from "@/components/RemediationCard";
import { DevLeaksCard, ScraperDefenseCard, SecurityHeadersCard } from "@/components/ResultCards";
import type { AnalysisResult, ScanResult } from "@/lib/types";

type Phase = "idle" | "scanning" | "analyzing" | "done";

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(data?.error ?? "Request failed. Try again.");
  return data as T;
}

const msg = (e: unknown) => (e instanceof Error ? e.message : "Something went wrong.");

export default function Home() {
  const [url, setUrl] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);

  async function analyze(findings: ScanResult) {
    setPhase("analyzing");
    setAiError(null);
    setAnalysis(null);
    try {
      setAnalysis(await postJson<AnalysisResult>("/api/analyze", findings));
    } catch (e) {
      setAiError(msg(e));
    } finally {
      setPhase("done");
    }
  }

  async function runScan() {
    setError(null);
    setScan(null);
    setAnalysis(null);
    setAiError(null);
    setPhase("scanning");
    try {
      const findings = await postJson<ScanResult>("/api/scan", { url });
      setScan(findings);
      await analyze(findings);
    } catch (e) {
      setError(msg(e));
      setPhase("idle");
    }
  }

  const busy = phase === "scanning" || phase === "analyzing";

  return (
    <main className="bg-[radial-gradient(ellipse_at_top,rgba(179,102,255,0.16),transparent_55%)]">
      <div className="mx-auto max-w-5xl px-4 pb-24 pt-20 sm:px-6">
        <header className="mb-10 text-center">
          <p className="mb-5 inline-flex items-center gap-2 rounded-full border border-neon-green/30 bg-neon-green/10 px-3 py-1 font-mono text-xs text-neon-green">
            <ShieldCheck className="h-3.5 w-3.5" />
            DevSec Guard
          </p>
          <h1 className="text-4xl font-bold tracking-tight text-white sm:text-6xl">
            See what crawlers and attackers see first
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-base text-slate-400 sm:text-lg">
            Paste a URL. We check whether AI bots can scrape it, which security headers are missing, and whether
            .env or .git files are exposed. Then an AI auditor grades the result and writes the fix.
          </p>
        </header>

        <ScanForm
          url={url}
          onChange={setUrl}
          onSubmit={runScan}
          busy={busy}
          label={phase === "scanning" ? "Scanning..." : phase === "analyzing" ? "Auditing..." : "Scan now"}
        />

        {error && (
          <p
            role="alert"
            className="mx-auto mt-4 max-w-2xl rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300"
          >
            {error}
          </p>
        )}

        {scan && (
          <section className="mt-14" aria-live="polite">
            <p className="mb-5 font-mono text-sm text-slate-500">
              Results for <span className="text-neon-cyan">{scan.url}</span>
            </p>
            <div className="grid gap-5 md:grid-cols-3">
              <ScraperDefenseCard data={scan.robots} />
              <SecurityHeadersCard data={scan.headers} />
              <DevLeaksCard data={scan.leaks} />
              <RemediationCard
                analysis={analysis}
                loading={phase === "analyzing"}
                error={aiError}
                onRetry={() => analyze(scan)}
              />
            </div>
          </section>
        )}

        <footer className="mt-20 text-center text-xs text-slate-600">
          Only scan sites you own or have permission to test.
        </footer>
      </div>
    </main>
  );
}
