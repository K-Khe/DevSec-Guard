"use client";

import { useEffect, useState } from "react";
import { BarChart3, CheckCircle2, Clock, Cookie, FileCode2, Globe, History, RotateCw, Server, Trash2, TrendingDown, TrendingUp, XCircle } from "lucide-react";
import type { CspCheckItem, ScanResult } from "@/lib/types";
import { formatCleanUrlOrPath, translateCrawlFinding } from "./ReportActions";
import { Card, Pill } from "./ui";

export interface HistoryEntry {
  url: string;
  host: string;
  scannedAt: string;
  score: number;
  grade: string;
}

const STORAGE_KEY = "devsec_guard_scan_history_v1";

/** Industry benchmark distribution across grades (MDN Observatory reference baseline). */
const BENCHMARK_DIST: { grade: string; pct: number; countLabel: string; tone: string }[] = [
  { grade: "A+", pct: 10, countLabel: "98k", tone: "bg-neon-green" },
  { grade: "A", pct: 4, countLabel: "32k", tone: "bg-neon-green/80" },
  { grade: "A-", pct: 3, countLabel: "24k", tone: "bg-neon-green/70" },
  { grade: "B+", pct: 9, countLabel: "89k", tone: "bg-neon-cyan" },
  { grade: "B", pct: 25, countLabel: "295k", tone: "bg-neon-cyan/80" },
  { grade: "B-", pct: 7, countLabel: "81k", tone: "bg-neon-cyan/70" },
  { grade: "C+", pct: 6, countLabel: "64k", tone: "bg-neon-purple" },
  { grade: "C", pct: 26, countLabel: "310k", tone: "bg-neon-purple/80" },
  { grade: "C-", pct: 13, countLabel: "148k", tone: "bg-neon-purple/70" },
  { grade: "D+", pct: 6, countLabel: "68k", tone: "bg-amber-400" },
  { grade: "D", pct: 38, countLabel: "450k", tone: "bg-amber-500/80" },
  { grade: "D-", pct: 46, countLabel: "545k", tone: "bg-orange-500/80" },
  { grade: "F", pct: 100, countLabel: "1.18M", tone: "bg-red-500/80" },
];

const CSP_CHECK_TH: Record<string, { label: string; passInfo: string; failInfo: string }> = {
  "no-unsafe-inline-script": {
    label: "บล็อก Inline JavaScript ('unsafe-inline' ใน script-src)",
    passInfo: "ไม่อนุญาตสคริปต์แบบ inline หรือมีการใช้ nonce/hash กำกับอย่างปลอดภัย",
    failInfo: "script-src ยังอนุญาต 'unsafe-inline' หรือ * ทำให้เสี่ยงต่อ XSS",
  },
  "no-unsafe-eval": {
    label: "บล็อกการใช้ eval() ใน JavaScript ('unsafe-eval' ใน script-src)",
    passInfo: "ไม่อนุญาตให้รันคำสั่ง eval() ใน script-src",
    failInfo: "script-src ยังอนุญาต 'unsafe-eval'",
  },
  "object-src": {
    label: "จำกัดการโหลดปลั๊กอินภายนอก (object-src)",
    passInfo: "จำกัด object-src เรียบร้อยแล้ว",
    failInfo: "แนะนำให้ตั้ง object-src 'none' เพื่อปิดกั้นปลั๊กอินรุ่นเก่า",
  },
  "style-src": {
    label: "บล็อก Inline CSS ('unsafe-inline' ใน style-src)",
    passInfo: "ไม่อนุญาตสไตล์แบบ inline",
    failInfo: "style-src ยังอนุญาต 'unsafe-inline' (ความเสี่ยงต่ำหากล็อก script-src แล้ว)",
  },
  "frame-ancestors": {
    label: "ป้องกันการถูกฝังใน iframe ลวงตา (frame-ancestors)",
    passInfo: "กำหนดค่า frame-ancestors ป้องกัน Clickjacking เรียบร้อยแล้ว",
    failInfo: "ไม่ได้กำหนด frame-ancestors ใน CSP (อาจใช้ X-Frame-Options แทนได้)",
  },
  "base-uri": {
    label: "จำกัดแท็ก <base> (base-uri 'self' หรือ 'none')",
    passInfo: "จำกัดค่า base-uri เรียบร้อยแล้ว",
    failInfo: "แนะนำให้เพิ่ม base-uri 'self' หรือ 'none'",
  },
  "form-action": {
    label: "จำกัดปลายทางของการส่งฟอร์ม (form-action)",
    passInfo: "จำกัดปลายทาง form-action เรียบร้อยแล้ว",
    failInfo: "แนะนำให้เพิ่ม form-action 'self' เพื่อจำกัดโดเมนรับข้อมูลฟอร์ม",
  },
};

function localizeCspItem(item: CspCheckItem, th: boolean): { label: string; info: string } {
  if (!th) return { label: item.label, info: item.info };
  const mapped = CSP_CHECK_TH[item.id];
  if (!mapped) return { label: item.label, info: item.info };
  return {
    label: mapped.label,
    info: item.passed ? mapped.passInfo : mapped.failInfo,
  };
}

type TabKey = "csp" | "crawl" | "cookies" | "raw" | "history" | "benchmark";

export default function ObservatoryTabs({
  scan,
  onSelectUrl,
  locale = "th",
}: {
  scan: ScanResult;
  onSelectUrl: (url: string) => void;
  locale?: "th" | "en";
}) {
  const th = locale === "th";
  const [tab, setTab] = useState<TabKey>("csp");
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [scoreDelta, setScoreDelta] = useState<number | null>(null);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      const parsed: HistoryEntry[] = raw ? JSON.parse(raw) : [];
      const host = new URL(scan.url).hostname.toLowerCase();

      const prevForHost = parsed.find((h) => h.host === host && h.scannedAt !== scan.scannedAt);
      setScoreDelta(prevForHost ? scan.score - prevForHost.score : null);

      const currentEntry: HistoryEntry = {
        url: scan.url,
        host,
        scannedAt: scan.scannedAt,
        score: scan.score,
        grade: scan.grade,
      };

      const deduplicated = parsed.filter((h) => !(h.host === host && h.scannedAt === scan.scannedAt));
      const updated = [currentEntry, ...deduplicated].slice(0, 30);
      setHistory(updated);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch {
      /* localStorage unavailable */
    }
  }, [scan]);

  function clearHistory() {
    try {
      localStorage.removeItem(STORAGE_KEY);
      setHistory([]);
      setScoreDelta(null);
    } catch {
      /* ignore */
    }
  }

  const cspChecks = scan.headers.cspAnalysis ?? [];
  const rawHeaders = scan.headers.raw ?? [];
  const crawledPages = scan.crawledPages ?? [
    {
      path: "/",
      url: scan.finalUrl ?? scan.url,
      status: scan.headers.status,
      findingsCount: scan.htmlFindings.length,
      cookiesCount: scan.cookies.length,
      findings: scan.htmlFindings.map((f) => f.title),
    },
  ];
  const currentHost = (() => {
    try {
      return new URL(scan.url).hostname.toLowerCase();
    } catch {
      return scan.url;
    }
  })();
  const hostHistory = history.filter((h) => h.host === currentHost);

  return (
    <Card
      title={th ? "เจาะลึกผลตรวจเชิงเทคนิค (Observatory Deep-Dive)" : "Observatory Deep-Dive"}
      icon={<BarChart3 className="h-5 w-5" />}
      accent="cyan"
      className="md:col-span-3"
    >
      {/* Summary bar with Tests Passed & Delta since last scan */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-3 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          {typeof scan.testsPassed === "number" && typeof scan.testsTotal === "number" && (
            <span className="font-mono text-slate-300">
              {th ? "ผ่านเกณฑ์ทดสอบ:" : "Tests Passed:"}{" "}
              <strong className="text-neon-green">
                {scan.testsPassed} / {scan.testsTotal}
              </strong>
            </span>
          )}
          <span className="inline-flex items-center gap-1 font-mono text-slate-400">
            <Clock className="h-3.5 w-3.5 text-neon-cyan" />
            {th ? "เวลาสแกน:" : "Scanned:"} {new Date(scan.scannedAt).toLocaleTimeString()}
          </span>
          {scoreDelta !== null && (
            <span
              className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 font-mono text-xs ${
                scoreDelta > 0
                  ? "bg-neon-green/10 text-neon-green"
                  : scoreDelta < 0
                    ? "bg-red-500/10 text-red-400"
                    : "bg-slate-500/10 text-slate-400"
              }`}
            >
              {scoreDelta > 0 ? (
                <>
                  <TrendingUp className="h-3.5 w-3.5" />+{scoreDelta} {th ? "จากครั้งก่อน" : "since last scan"}
                </>
              ) : scoreDelta < 0 ? (
                <>
                  <TrendingDown className="h-3.5 w-3.5" />
                  {scoreDelta} {th ? "จากครั้งก่อน" : "since last scan"}
                </>
              ) : (
                th ? "คะแนนเท่าเดิมจากครั้งก่อน" : "No change since last scan"
              )}
            </span>
          )}
        </div>

        {/* Navigation tabs */}
        <div className="flex flex-wrap gap-1.5" role="tablist">
          {(
            [
              { key: "csp", label: th ? "วิเคราะห์ CSP" : "CSP analysis", icon: <FileCode2 className="h-3.5 w-3.5" /> },
              { key: "crawl", label: th ? `หน้าเว็บที่ไต่ตรวจ (${crawledPages.length})` : `Crawled pages (${crawledPages.length})`, icon: <Globe className="h-3.5 w-3.5" /> },
              { key: "cookies", label: th ? `คุกกี้ (${scan.cookies.length})` : `Cookies (${scan.cookies.length})`, icon: <Cookie className="h-3.5 w-3.5" /> },
              { key: "raw", label: th ? `Raw Headers (${rawHeaders.length})` : `Raw server headers (${rawHeaders.length})`, icon: <Server className="h-3.5 w-3.5" /> },
              { key: "history", label: th ? `ประวัติการสแกน (${history.length})` : `Scan history (${history.length})`, icon: <History className="h-3.5 w-3.5" /> },
              { key: "benchmark", label: th ? "เทียบเกณฑ์อ้างอิงสากล" : "Benchmark comparison", icon: <BarChart3 className="h-3.5 w-3.5" /> },
            ] as const
          ).map((t) => (
            <button
              key={t.key}
              type="button"
              role="tab"
              aria-selected={tab === t.key}
              onClick={() => setTab(t.key)}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 font-mono text-xs transition ${
                tab === t.key
                  ? "bg-neon-cyan/20 text-neon-cyan ring-1 ring-neon-cyan/50"
                  : "bg-ink-800 text-slate-400 hover:text-white"
              }`}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab 1: CSP Analysis */}
      {tab === "csp" && (
        <div>
          {cspChecks.length === 0 ? (
            <p className="rounded-lg bg-ink-800 px-4 py-3 text-sm text-red-300">
              {th ? (
                <>ไม่พบการตั้งค่า <code className="font-mono">Content-Security-Policy</code> บนหน้าเว็บนี้</>
              ) : (
                <>No <code className="font-mono">Content-Security-Policy</code> header is implemented on this response.</>
              )}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/10 font-mono text-slate-400">
                    <th className="py-2 pr-4">{th ? "หัวข้อตรวจสอบ" : "Test"}</th>
                    <th className="w-24 py-2 pr-4 text-center">{th ? "ผลลัพธ์" : "Result"}</th>
                    <th className="py-2">{th ? "คำอธิบาย" : "Info"}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {cspChecks.map((item) => {
                    const loc = localizeCspItem(item, th);
                    return (
                      <tr key={item.id}>
                        <td className="py-2.5 pr-4 font-mono text-slate-200">{loc.label}</td>
                        <td className="py-2.5 pr-4 text-center">
                          {item.passed ? (
                            <CheckCircle2 className="mx-auto h-4 w-4 text-neon-green" aria-label={th ? "ผ่าน" : "Passed"} />
                          ) : (
                            <XCircle className="mx-auto h-4 w-4 text-red-400" aria-label={th ? "ไม่ผ่าน" : "Failed"} />
                          )}
                        </td>
                        <td className="py-2.5 text-slate-400">{loc.info}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 1.5: Crawled Subpages */}
      {tab === "crawl" && (
        <div>
          <p className="mb-3 text-xs text-slate-400">
            {th
              ? `ระบบไต่ลิงก์ภายในโดเมนเดียวกันอัตโนมัติ (หน้าแรก + หน้าย่อยสำคัญสูงสุด 5 หน้า) เพื่อตรวจหาฟอร์มไม่เข้ารหัส คีย์รั่วไหล และคุกกี้ในหน้าย่อย`
              : `Bounded same-origin crawler (entry page + up to 5 priority subpages) inspecting HTML risks and cookies across subpages.`}
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-white/10 text-slate-400">
                  <th className="py-2 pr-4">{th ? "หน้าเว็บ (Path)" : "Path"}</th>
                  <th className="w-28 py-2 pr-4">{th ? "สถานะ HTTP" : "HTTP Status"}</th>
                  <th className="w-28 py-2 pr-4">{th ? "คุกกี้ที่พบ" : "Cookies"}</th>
                  <th className="py-2">{th ? "จุดสังเกตใน HTML" : "HTML Findings"}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {crawledPages.map((p, idx) => (
                  <tr key={`${p.path}-${idx}`}>
                    <td className="py-2.5 pr-4 text-neon-cyan">{formatCleanUrlOrPath(p.path)}</td>
                    <td className="py-2.5 pr-4 text-slate-300">{p.status ?? (th ? "ไม่ตอบสนอง" : "Timeout")}</td>
                    <td className="py-2.5 pr-4 text-slate-300">{p.cookiesCount}</td>
                    <td className="py-2.5 text-slate-300">
                      {p.findingsCount === 0 ? (
                        <span className="text-neon-green">{th ? "ไม่พบความเสี่ยงใน HTML" : "Clean"}</span>
                      ) : (
                        <span className="text-amber-300">
                          {p.findings.map((f) => translateCrawlFinding(f, th)).join(" · ")}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Detailed Cookies Table */}
      {tab === "cookies" && (
        <div>
          {scan.cookies.length === 0 ? (
            <p className="rounded-lg bg-ink-800 px-4 py-3 text-sm text-slate-400">
              {th ? (
                <>ไม่พบการส่ง <code className="font-mono">Set-Cookie</code> จากการสแกนหน้าแรก</>
              ) : (
                <>No <code className="font-mono">Set-Cookie</code> headers were observed during the scan.</>
              )}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-white/10 text-slate-400">
                    <th className="py-2 pr-4">{th ? "ชื่อคุกกี้" : "Name"}</th>
                    <th className="py-2 pr-4">{th ? "อายุคุกกี้" : "Expires / Max-Age"}</th>
                    <th className="py-2 pr-4">Path</th>
                    <th className="py-2 pr-4 text-center">Secure</th>
                    <th className="py-2 pr-4 text-center">HttpOnly</th>
                    <th className="py-2 pr-4">SameSite</th>
                    <th className="py-2">Prefix</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {scan.cookies.map((c) => (
                    <tr key={c.name}>
                      <td className="py-2.5 pr-4 text-white">{c.name}</td>
                      <td className="py-2.5 pr-4 text-slate-400">{c.expires ?? "Session"}</td>
                      <td className="py-2.5 pr-4 text-slate-300">{c.path ?? "/"}</td>
                      <td className="py-2.5 pr-4 text-center">
                        {c.secure ? (
                          <CheckCircle2 className="mx-auto h-4 w-4 text-neon-green" />
                        ) : (
                          <XCircle className="mx-auto h-4 w-4 text-red-400" />
                        )}
                      </td>
                      <td className="py-2.5 pr-4 text-center">
                        {c.httpOnly ? (
                          <CheckCircle2 className="mx-auto h-4 w-4 text-neon-green" />
                        ) : (
                          <XCircle className="mx-auto h-4 w-4 text-red-400" />
                        )}
                      </td>
                      <td className="py-2.5 pr-4 text-slate-300">{c.sameSite ?? "-"}</td>
                      <td className="py-2.5 text-slate-400">{c.prefix ?? "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Raw Server Headers */}
      {tab === "raw" && (
        <div className="overflow-x-auto">
          {rawHeaders.length === 0 ? (
            <p className="text-sm text-slate-400">{th ? "ไม่พบข้อมูล Raw Headers" : "No raw headers recorded."}</p>
          ) : (
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-white/10 text-slate-400">
                  <th className="w-56 py-2 pr-4">{th ? "ชื่อ Header" : "Header"}</th>
                  <th className="py-2">{th ? "ค่าที่ตรวจพบ (Value)" : "Value"}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {rawHeaders.map((h, i) => (
                  <tr key={`${h.name}-${i}`}>
                    <td className="py-2 pr-4 align-top font-semibold text-neon-cyan">{h.name}</td>
                    <td className="break-all py-2 text-slate-300">{h.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Tab 4: Scan History */}
      {tab === "history" && (
        <div>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs text-slate-400">
              {th ? (
                <>
                  ประวัติการสแกนที่บันทึกไว้ในเบราว์เซอร์เครื่องนี้ (พบ {hostHistory.length} ครั้งสำหรับ{" "}
                  <span className="font-mono text-neon-cyan">{currentHost}</span>)
                </>
              ) : (
                <>
                  Changes in score over time (stored locally in your browser · {hostHistory.length} for{" "}
                  <span className="font-mono text-neon-cyan">{currentHost}</span>).
                </>
              )}
            </p>
            {history.length > 0 && (
              <button
                type="button"
                onClick={clearHistory}
                className="inline-flex items-center gap-1 rounded border border-white/10 px-2.5 py-1 text-xs text-slate-400 hover:border-red-400/40 hover:text-red-300"
              >
                <Trash2 className="h-3 w-3" />
                {th ? "ล้างประวัติ" : "Clear history"}
              </button>
            )}
          </div>
          {history.length === 0 ? (
            <p className="text-sm text-slate-400">{th ? "ยังไม่มีประวัติการสแกนในเบราว์เซอร์นี้" : "No scan history yet."}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-white/10 text-slate-400">
                    <th className="py-2 pr-4">{th ? "วัน-เวลา" : "Date"}</th>
                    <th className="py-2 pr-4">{th ? "เว็บไซต์" : "Target"}</th>
                    <th className="py-2 pr-4">{th ? "คะแนน" : "Score"}</th>
                    <th className="py-2 pr-4">{th ? "เกรด" : "Grade"}</th>
                    <th className="py-2 text-right">{th ? "จัดการ" : "Action"}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {history.map((entry, idx) => (
                    <tr key={`${entry.url}-${entry.scannedAt}-${idx}`}>
                      <td className="py-2 pr-4 text-slate-400">{new Date(entry.scannedAt).toLocaleString()}</td>
                      <td className="py-2 pr-4 text-slate-200">{entry.host}</td>
                      <td className="py-2 pr-4 text-slate-300">{entry.score}/100</td>
                      <td className="py-2 pr-4">
                        <Pill
                          tone={
                            entry.grade.startsWith("A")
                              ? "ok"
                              : entry.grade.startsWith("B") || entry.grade.startsWith("C")
                                ? "warn"
                                : "bad"
                          }
                        >
                          {entry.grade}
                        </Pill>
                      </td>
                      <td className="py-2 text-right">
                        <button
                          type="button"
                          onClick={() => onSelectUrl(entry.url)}
                          className="inline-flex items-center gap-1 text-neon-cyan hover:underline"
                        >
                          <RotateCw className="h-3 w-3" />
                          {th ? "เลือกเว็บนี้" : "Load URL"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 5: Benchmark Comparison */}
      {tab === "benchmark" && (
        <div>
          <p className="mb-4 text-xs text-slate-400">
            {th ? (
              <>
                กราฟเปรียบเทียบเกรดของเว็บคุณ (<strong className="font-mono text-white">{scan.grade}</strong>) เทียบกับค่าสถิติอ้างอิงมาตรฐานสากล (MDN HTTP Observatory Reference Baseline)
              </>
            ) : (
              <>
                Reference grade distribution baseline (MDN Observatory). Your target&apos;s current grade (
                <strong className="font-mono text-white">{scan.grade}</strong>) is highlighted below.
              </>
            )}
          </p>
          <div className="grid grid-cols-13 items-end gap-2 pt-8 sm:gap-3" style={{ gridTemplateColumns: "repeat(13, minmax(0, 1fr))" }}>
            {BENCHMARK_DIST.map((b) => {
              const isCurrent = b.grade === scan.grade;
              return (
                <div key={b.grade} className="flex flex-col items-center">
                  <div className="relative flex h-44 w-full items-end justify-center rounded-t bg-ink-800/50 px-1">
                    {isCurrent && (
                      <span className="absolute -top-7 whitespace-nowrap rounded border border-neon-cyan/50 bg-ink-950 px-1.5 py-0.5 font-mono text-[10px] text-neon-cyan shadow">
                        {th ? "เว็บนี้" : "Current"}
                      </span>
                    )}
                    <div
                      style={{ height: `${Math.max(6, b.pct)}%` }}
                      className={`w-full rounded-t transition-all ${b.tone} ${
                        isCurrent ? "ring-2 ring-white brightness-125" : "opacity-60"
                      }`}
                      title={`${b.grade}: ~${b.countLabel} sites`}
                    />
                  </div>
                  <span
                    className={`mt-2 font-mono text-xs ${
                      isCurrent ? "font-bold text-neon-cyan" : "text-slate-400"
                    }`}
                  >
                    {b.grade}
                  </span>
                  <span className="font-mono text-[10px] text-slate-600">{b.countLabel}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </Card>
  );
}
