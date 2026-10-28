"use client";

import { Download, FileJson, Mail } from "lucide-react";
import type { AnalysisResult, ScanResult } from "@/lib/types";

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]!);
}

function download(name: string, type: string, content: string) {
  const href = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(href);
}

export default function ReportActions({ scan, analysis }: { scan: ScanResult; analysis: AnalysisResult | null }) {
  const report = { scan, analysis, generatedAt: new Date().toISOString() };
  const fileStem = `devsec-guard-${new URL(scan.url).hostname}-${new Date().toISOString().slice(0, 10)}`;

  function exportHtml() {
    const findings = analysis?.findings ?? scan.htmlFindings.map((finding) => `${finding.title}: ${finding.note}`);
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>DevSec Guard report</title><style>body{font-family:Arial,sans-serif;max-width:900px;margin:40px auto;line-height:1.5;color:#172033}code,pre{background:#f2f4f8;padding:12px;display:block;overflow:auto}table{border-collapse:collapse;width:100%}td,th{border:1px solid #d8dee9;padding:8px;text-align:left}</style></head><body><h1>DevSec Guard report</h1><p><strong>Target:</strong> ${escapeHtml(scan.url)}<br><strong>Scanned:</strong> ${escapeHtml(scan.scannedAt)}<br><strong>Score:</strong> ${analysis?.score ?? scan.score}/100 (${escapeHtml(analysis?.grade ?? scan.grade)})</p><h2>Findings</h2><ul>${findings.map((finding) => `<li>${escapeHtml(finding)}</li>`).join("") || "<li>No findings reported.</li>"}</ul><h2>Security headers</h2><table><tr><th>Header</th><th>State</th></tr>${scan.headers.items.map((header) => `<tr><td>${escapeHtml(header.label)}</td><td>${escapeHtml(header.state)}</td></tr>`).join("")}</table>${analysis ? `<h2>Remediation (${escapeHtml(analysis.language)})</h2><pre>${escapeHtml(analysis.code)}</pre>` : ""}<p><small>Automated assessment only. Validate findings before remediation.</small></p></body></html>`;
    download(`${fileStem}.html`, "text/html;charset=utf-8", html);
  }

  function emailSummary() {
    const body = [`DevSec Guard report`, `Target: ${scan.url}`, `Score: ${analysis?.score ?? scan.score}/100 (${analysis?.grade ?? scan.grade})`, "", ...(analysis?.findings ?? scan.htmlFindings.map((finding) => `- ${finding.title}`))].join("\n");
    window.location.href = `mailto:?subject=${encodeURIComponent(`Security report: ${new URL(scan.url).hostname}`)}&body=${encodeURIComponent(body)}`;
  }

  return (
    <div className="mt-5 flex flex-wrap justify-end gap-2">
      <button onClick={() => download(`${fileStem}.json`, "application/json", JSON.stringify(report, null, 2))} className="inline-flex items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-xs text-slate-300 hover:border-neon-cyan/50 hover:text-neon-cyan"><FileJson className="h-3.5 w-3.5" />Export JSON</button>
      <button onClick={exportHtml} className="inline-flex items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-xs text-slate-300 hover:border-neon-cyan/50 hover:text-neon-cyan"><Download className="h-3.5 w-3.5" />Export HTML</button>
      <button onClick={emailSummary} className="inline-flex items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-xs text-slate-300 hover:border-neon-cyan/50 hover:text-neon-cyan"><Mail className="h-3.5 w-3.5" />Email summary</button>
    </div>
  );
}
