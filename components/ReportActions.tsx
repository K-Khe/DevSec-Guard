"use client";

import { Download, FileJson, Mail, Printer } from "lucide-react";
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

  function printReport() {
    const previousTitle = document.title;
    document.title = fileStem;
    window.addEventListener("afterprint", () => {
      document.title = previousTitle;
    }, { once: true });
    window.print();
  }

  const findings = analysis?.findings ?? scan.htmlFindings.map((finding) => finding.title);
  const missingHeaders = scan.headers.items.filter((header) => header.state !== "strong");

  return (
    <>
      <div className="mt-5 flex flex-wrap justify-end gap-2">
        <button onClick={printReport} className="inline-flex items-center gap-2 rounded-md border border-neon-cyan/40 bg-neon-cyan/10 px-3 py-2 text-xs text-neon-cyan hover:bg-neon-cyan/20"><Printer className="h-3.5 w-3.5" />Export PDF</button>
        <button onClick={() => download(`${fileStem}.json`, "application/json", JSON.stringify(report, null, 2))} className="inline-flex items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-xs text-slate-300 hover:border-neon-cyan/50 hover:text-neon-cyan"><FileJson className="h-3.5 w-3.5" />Export JSON</button>
        <button onClick={exportHtml} className="inline-flex items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-xs text-slate-300 hover:border-neon-cyan/50 hover:text-neon-cyan"><Download className="h-3.5 w-3.5" />Export HTML</button>
        <button onClick={emailSummary} className="inline-flex items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-xs text-slate-300 hover:border-neon-cyan/50 hover:text-neon-cyan"><Mail className="h-3.5 w-3.5" />Email summary</button>
      </div>

      <article className="audit-print" aria-hidden="true">
        <header>
          <p>DEVSEC GUARD · EXTERNAL SECURITY REPORT</p>
          <h1>Security assessment</h1>
          <dl className="audit-print-meta">
            <div><dt>Target</dt><dd>{scan.finalUrl ?? scan.url}</dd></div>
            <div><dt>Scanned at</dt><dd>{new Date(scan.scannedAt).toLocaleString()}</dd></div>
            <div><dt>HTTP status</dt><dd>{scan.headers.status ?? "Unavailable"}</dd></div>
          </dl>
        </header>

        <section className="audit-print-score">
          <div><span>DevSec posture</span><strong>{analysis?.grade ?? scan.grade}</strong><small>{analysis?.score ?? scan.score}/100</small></div>
          <p>Deterministic assessment based on the response received at scan time. Validate findings before remediation.</p>
        </section>

        <section>
          <h2>Security headers requiring attention</h2>
          {missingHeaders.length ? <table><thead><tr><th>Header</th><th>Status</th><th>Observed value</th></tr></thead><tbody>{missingHeaders.map((header) => <tr key={header.key}><td>{header.label}</td><td>{header.state}</td><td>{header.value ?? "Not present"}</td></tr>)}</tbody></table> : <p>All measured security headers were strong at scan time.</p>}
        </section>

        <section>
          <h2>Development-file exposure checks</h2>
          <table><thead><tr><th>Path</th><th>Status</th><th>Result</th></tr></thead><tbody>{scan.leaks.map((leak) => <tr key={leak.path}><td>{leak.path}</td><td>{leak.status ?? "—"}</td><td>{leak.state}</td></tr>)}</tbody></table>
        </section>

        <section>
          <h2>Key findings</h2>
          {findings.length ? <ul>{findings.map((finding, index) => <li key={index}>{finding}</li>)}</ul> : <p>No additional high-signal findings were reported.</p>}
        </section>

        {analysis?.code && <section><h2>Recommended remediation</h2><pre>{analysis.code}</pre></section>}
        <footer>Generated by DevSec Guard · This passive report is not a penetration test.</footer>
      </article>
    </>
  );
}
