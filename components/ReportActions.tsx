"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { Download, FileJson, Mail, Printer } from "lucide-react";
import type { AnalysisResult, HeaderState, LeakState, ScanResult } from "@/lib/types";

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

/** Strips noisy social/ad tracking query parameters (fbclid, gclid, utm_*) for clean report display. */
export function formatCleanUrlOrPath(input: string): string {
  try {
    if (input.startsWith("http://") || input.startsWith("https://")) {
      const u = new URL(input);
      for (const key of [...u.searchParams.keys()]) {
        if (/^(?:fbclid|gclid|msclkid|twclid|mc_eid|utm_[a-z0-9_]+)$/i.test(key)) {
          u.searchParams.delete(key);
        }
      }
      return u.toString();
    }
    const dummy = new URL(input.startsWith("/") ? input : `/${input}`, "https://example.invalid");
    for (const key of [...dummy.searchParams.keys()]) {
      if (/^(?:fbclid|gclid|msclkid|twclid|mc_eid|utm_[a-z0-9_]+)$/i.test(key)) {
        dummy.searchParams.delete(key);
      }
    }
    return `${dummy.pathname}${dummy.search}` || "/";
  } catch {
    return input;
  }
}

export function translateCrawlFinding(text: string, th: boolean): string {
  if (!th) return text;
  return text
    .replace(/Subresource Integrity \(SRI\) missing on (\d+) external script\(s\)/gi, "สคริปต์ภายนอก $1 รายการไม่ได้ตั้งค่า SRI")
    .replace(/New-tab link may lack noopener/gi, 'ลิงก์เปิดแท็บใหม่ไม่ได้ระบุ rel="noopener"')
    .replace(/Possible mixed content/gi, "พบการโหลดทรัพยากรผ่าน HTTP บนหน้า HTTPS (Mixed Content)")
    .replace(/Form submits over HTTP/gi, "พบแบบฟอร์มส่งข้อมูลผ่าน HTTP ที่ไม่เข้ารหัส")
    .replace(/Source-map reference exposed/gi, "พบไฟล์ Source Map (.map) เปิดเผย")
    .replace(/Possible client-side secret pattern/gi, "พบรูปแบบคล้ายคีย์ลับในโค้ด HTML")
    .replace(/WordPress attack surface detected/gi, "ตรวจพบร่องรอยระบบ WordPress")
    .replace(/PHP version exposed/gi, "เปิดเผยเลขเวอร์ชัน PHP");
}

function formatHeaderState(state: HeaderState, th: boolean): string {
  if (!th) return state;
  if (state === "strong") return "แข็งแรง (ผ่านเกณฑ์)";
  if (state === "weak") return "ยังไม่รัดกุม (ควรปรับปรุง)";
  return "ยังไม่ได้ตั้งค่า";
}

function formatLeakState(state: LeakState, th: boolean): string {
  if (!th) return state;
  if (state === "exposed") return "รั่วไหลสู่สาธารณะ (อันตราย)";
  if (state === "safe") return "ปลอดภัย (ปิดกั้นแล้ว)";
  if (state === "soft-200") return "ตอบ 200 แต่ไม่ใช่ไฟล์ความลับ";
  return "ไม่ตอบสนอง";
}

export default function ReportActions({
  scan,
  analysis,
  locale = "th",
}: {
  scan: ScanResult;
  analysis: AnalysisResult | null;
  locale?: "th" | "en";
}) {
  const th = locale === "th";
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const report = { scan, analysis, generatedAt: new Date().toISOString() };
  const fileStem = `devsec-guard-${new URL(scan.url).hostname}-${new Date().toISOString().slice(0, 10)}`;
  const cleanTargetUrl = formatCleanUrlOrPath(scan.finalUrl ?? scan.url);

  function exportHtml() {
    const findings = analysis?.findings ?? scan.htmlFindings.map((finding) => translateCrawlFinding(finding.title, th));
    const titleText = th ? "รายงานการตรวจสอบความปลอดภัยเว็บไซต์ — DevSec Guard" : "DevSec Guard Security Assessment Report";
    const targetLabel = th ? "เว็บไซต์ที่ตรวจสอบ" : "Target";
    const scannedLabel = th ? "วัน-เวลาที่สแกน" : "Scanned at";
    const scoreLabel = th ? "คะแนนและเกรด" : "Score & Grade";
    const summaryLabel = th ? "เปรียบเทียบให้เห็นภาพ" : "Visual Analogy";
    const findingsHeading = th ? "ประเด็นสำคัญที่ตรวจพบ" : "Key Findings";
    const headersHeading = th ? "ตารางตรวจสอบ Security Headers" : "Security Headers";
    const colHeader = th ? "ชื่อ Header" : "Header";
    const colState = th ? "สถานะ" : "State";
    const colVal = th ? "ค่าที่ตรวจพบ" : "Observed Value";
    const notPresentText = th ? "ไม่ได้ตั้งค่า" : "Not present";
    const remHeading = th ? "โค้ดตั้งค่าความปลอดภัยที่แนะนำ" : "Recommended Remediation";
    const footerNote = th
      ? "รายงานนี้เกิดจากการตรวจสอบ HTTP สาธารณะแบบอ่านอย่างเดียว ไม่ใช่การทดสอบเจาะระบบ (Penetration Test) กรุณาตรวจสอบก่อนนำไปใช้งานจริง"
      : "Automated passive assessment only. Validate findings before remediation.";

    const html = `<!doctype html><html lang="${th ? "th" : "en"}"><head><meta charset="utf-8"><title>${escapeHtml(titleText)}</title><style>body{font-family:"Noto Sans Thai","IBM Plex Sans Thai",Arial,sans-serif;max-width:900px;margin:40px auto;line-height:1.55;color:#172033}code,pre{background:#f2f4f8;padding:12px;display:block;overflow:auto;white-space:pre-wrap;border:1px solid #d8dee9;border-radius:6px}table{border-collapse:collapse;width:100%;margin-bottom:16px}td,th{border:1px solid #d8dee9;padding:8px;text-align:left;vertical-align:top}th{background:#edf1f5}</style></head><body><h1>${escapeHtml(titleText)}</h1><p><strong>${targetLabel}:</strong> ${escapeHtml(cleanTargetUrl)}<br><strong>${scannedLabel}:</strong> ${escapeHtml(new Date(scan.scannedAt).toLocaleString())}<br><strong>${scoreLabel}:</strong> ${analysis?.score ?? scan.score}/100 (${escapeHtml(analysis?.grade ?? scan.grade)})</p>${analysis?.laymanSummary ? `<p><strong>${summaryLabel}:</strong> ${escapeHtml(analysis.laymanSummary)}</p>` : ""}<h2>${findingsHeading}</h2><ul>${findings.map((finding) => `<li>${escapeHtml(finding)}</li>`).join("") || `<li>${th ? "ไม่พบความเสี่ยงเพิ่มเติม" : "No findings reported."}</li>`}</ul><h2>${headersHeading}</h2><table><tr><th>${colHeader}</th><th>${colState}</th><th>${colVal}</th></tr>${scan.headers.items.map((header) => `<tr><td>${escapeHtml(header.label)}</td><td>${escapeHtml(formatHeaderState(header.state, th))}</td><td>${escapeHtml(header.value ?? notPresentText)}</td></tr>`).join("")}</table>${analysis ? `<h2>${remHeading} (${escapeHtml(analysis.language)})</h2><pre>${escapeHtml(analysis.code)}</pre>` : ""}<p><small>${escapeHtml(footerNote)}</small></p></body></html>`;
    download(`${fileStem}.html`, "text/html;charset=utf-8", html);
  }

  function emailSummary() {
    const body = [
      th ? `รายงานความปลอดภัยเว็บไซต์จาก DevSec Guard` : `DevSec Guard report`,
      `${th ? "เว็บไซต์" : "Target"}: ${cleanTargetUrl}`,
      `${th ? "คะแนน" : "Score"}: ${analysis?.score ?? scan.score}/100 (${analysis?.grade ?? scan.grade})`,
      "",
      ...(analysis?.findings ?? scan.htmlFindings.map((finding) => `- ${translateCrawlFinding(finding.title, th)}`)),
    ].join("\n");
    const subject = th
      ? `รายงานความปลอดภัยเว็บไซต์: ${new URL(scan.url).hostname}`
      : `Security report: ${new URL(scan.url).hostname}`;
    window.location.href = `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  }

  function printReport() {
    const previousTitle = document.title;
    document.title = fileStem;
    window.addEventListener("afterprint", () => {
      document.title = previousTitle;
    }, { once: true });
    window.print();
  }

  const findings = analysis?.findings ?? scan.htmlFindings.map((finding) => translateCrawlFinding(finding.title, th));
  const strongHeadersCount = scan.headers.items.filter((h) => h.state === "strong").length;
  let secNo = 1;

  const printArticle = (
    <article className="audit-print" aria-hidden="true">
      <header>
        <p>{th ? "DEVSEC GUARD · รายงานการตรวจสอบความปลอดภัยเว็บไซต์จากภายนอก" : "DEVSEC GUARD · EXTERNAL SECURITY REPORT"}</p>
        <h1>{th ? "รายงานผลการตรวจความปลอดภัยเว็บไซต์" : "Security Assessment Report"}</h1>
        <dl className="audit-print-meta">
          <div>
            <dt>{th ? "เว็บไซต์ที่ตรวจสอบ (Target)" : "Target"}</dt>
            <dd>{cleanTargetUrl}</dd>
          </div>
          <div>
            <dt>{th ? "วัน-เวลาที่สแกน" : "Scanned at"}</dt>
            <dd>{new Date(scan.scannedAt).toLocaleString()}</dd>
          </div>
          <div>
            <dt>{th ? "สถานะการตอบกลับ (HTTP)" : "HTTP status"}</dt>
            <dd>{scan.headers.status ?? (th ? "ไม่ทราบ" : "Unavailable")}</dd>
          </div>
        </dl>
      </header>

      <section className="audit-print-score">
        <div>
          <span>{th ? "เกรดความปลอดภัย" : "DevSec posture"}</span>
          <strong>{analysis?.grade ?? scan.grade}</strong>
          <small>{analysis?.score ?? scan.score}/100</small>
        </div>
        <div>
          <p>
            {analysis?.summary ??
              (th
                ? "ประเมินผลจาก HTTP Response ที่ได้รับขณะสแกนแบบอ่านอย่างเดียว กรุณาตรวจสอบก่อนนำไปปรับปรุงระบบ"
                : "Deterministic assessment based on the response received at scan time. Validate findings before remediation.")}
          </p>
          {analysis?.laymanSummary && (
            <p>
              <strong>{th ? "เปรียบเทียบให้เห็นภาพ: " : "Visual analogy: "}</strong>
              {analysis.laymanSummary}
            </p>
          )}
        </div>
      </section>

      <section>
        <h2>
          {th
            ? `${secNo++}. การตั้งค่า HTTP Security Headers (ผ่านเกณฑ์ ${strongHeadersCount}/${scan.headers.items.length} รายการ)`
            : `${secNo++}. Security Headers (${strongHeadersCount}/${scan.headers.items.length} strong)`}
        </h2>
        <table>
          <thead>
            <tr>
              <th>{th ? "ชื่อ Header" : "Header"}</th>
              <th>{th ? "สถานะ" : "Status"}</th>
              <th>{th ? "ค่าที่ตรวจพบ" : "Observed value"}</th>
            </tr>
          </thead>
          <tbody>
            {scan.headers.items.map((header) => (
              <tr key={header.key}>
                <td>{header.label}</td>
                <td>{formatHeaderState(header.state, th)}</td>
                <td>{header.value ?? (th ? "ไม่ได้ตั้งค่า" : "Not present")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section>
        <h2>
          {th
            ? `${secNo++}. การตรวจสอบไฟล์ความลับรั่วไหล (/.env และ /.git/HEAD)`
            : `${secNo++}. Development & Sensitive File Exposure Checks`}
        </h2>
        <table>
          <thead>
            <tr>
              <th>{th ? "พาธที่ตรวจสอบ" : "Path"}</th>
              <th style={{ width: "90px" }}>{th ? "รหัส HTTP" : "HTTP Status"}</th>
              <th>{th ? "ผลการตรวจสอบ" : "Result"}</th>
            </tr>
          </thead>
          <tbody>
            {scan.leaks.map((leak) => (
              <tr key={leak.path}>
                <td>{leak.path}</td>
                <td>{leak.status ?? "—"}</td>
                <td>{formatLeakState(leak.state, th)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {scan.crawledPages && scan.crawledPages.length > 0 && (
        <section>
          <h2>
            {th
              ? `${secNo++}. หน้าเว็บและหน้าย่อยที่ไต่ตรวจ (รวม ${scan.crawledPages.length} หน้า)`
              : `${secNo++}. Crawled Pages (${scan.crawledPages.length} pages inspected)`}
          </h2>
          <table>
            <thead>
              <tr>
                <th style={{ width: "28%" }}>{th ? "หน้าเว็บ (Path)" : "Path"}</th>
                <th style={{ width: "90px" }}>{th ? "รหัส HTTP" : "HTTP Status"}</th>
                <th>{th ? "ผลการตรวจโครงสร้าง HTML" : "HTML Inspection"}</th>
              </tr>
            </thead>
            <tbody>
              {scan.crawledPages.map((p, idx) => (
                <tr key={`${p.path}-${idx}`}>
                  <td>{formatCleanUrlOrPath(p.path)}</td>
                  <td>{p.status ?? "—"}</td>
                  <td>
                    {p.findingsCount === 0
                      ? th
                        ? "ไม่พบความเสี่ยงใน HTML"
                        : "Clean"
                      : p.findings.map((f) => translateCrawlFinding(f, th)).join(" · ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {scan.cookies && scan.cookies.length > 0 && (
        <section>
          <h2>
            {th
              ? `${secNo++}. ความปลอดภัยของคุกกี้ (พบ ${scan.cookies.length} รายการ)`
              : `${secNo++}. Cookie Security (${scan.cookies.length} cookies observed)`}
          </h2>
          <table>
            <thead>
              <tr>
                <th>{th ? "ชื่อคุกกี้" : "Cookie Name"}</th>
                <th>{th ? "สถานะ" : "State"}</th>
                <th>{th ? "แฟล็กความปลอดภัย (Secure / HttpOnly / SameSite)" : "Flags (Secure / HttpOnly / SameSite)"}</th>
              </tr>
            </thead>
            <tbody>
              {scan.cookies.map((c, idx) => (
                <tr key={`${c.name}-${idx}`}>
                  <td>{c.name}</td>
                  <td>{formatHeaderState(c.state, th)}</td>
                  <td>
                    Secure: {c.secure ? (th ? "เปิด" : "Yes") : th ? "ปิด" : "No"} · HttpOnly:{" "}
                    {c.httpOnly ? (th ? "เปิด" : "Yes") : th ? "ปิด" : "No"} · SameSite:{" "}
                    {c.sameSite ?? (th ? "ไม่ได้ระบุ" : "None")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section>
        <h2>{th ? `${secNo++}. สรุปประเด็นสำคัญที่ควรปรับปรุง` : `${secNo++}. Key Findings & Surface Observations`}</h2>
        {findings.length ? (
          <ul>
            {findings.map((finding, index) => (
              <li key={index}>{finding}</li>
            ))}
          </ul>
        ) : (
          <p>{th ? "ไม่พบประเด็นความเสี่ยงเพิ่มเติม" : "No additional high-signal findings were reported."}</p>
        )}
      </section>

      {analysis?.code && (
        <section className="audit-print-remediation">
          <h2>
            {th
              ? `${secNo++}. โค้ดตั้งค่าความปลอดภัยที่แนะนำ (${analysis.language})`
              : `${secNo++}. Recommended Remediation (${analysis.language})`}
          </h2>
          <pre>{analysis.code}</pre>
        </section>
      )}

      <footer>
        {th
          ? "สร้างโดยระบบ DevSec Guard · รายงานนี้เป็นการตรวจจากภายนอกแบบอ่านอย่างเดียว (ไม่ใช่การทดสอบเจาะระบบ)"
          : "Generated by DevSec Guard · Passive read-only posture report (not an active penetration test)."}
      </footer>
    </article>
  );

  return (
    <>
      <div className="mt-5 flex flex-wrap justify-end gap-2">
        <button onClick={printReport} className="inline-flex items-center gap-2 rounded-md border border-neon-cyan/40 bg-neon-cyan/10 px-3 py-2 text-xs text-neon-cyan hover:bg-neon-cyan/20">
          <Printer className="h-3.5 w-3.5" />
          {th ? "พิมพ์รายงาน / บันทึก PDF" : "Export PDF"}
        </button>
        <button onClick={() => download(`${fileStem}.json`, "application/json", JSON.stringify(report, null, 2))} className="inline-flex items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-xs text-slate-300 hover:border-neon-cyan/50 hover:text-neon-cyan">
          <FileJson className="h-3.5 w-3.5" />
          {th ? "ดาวน์โหลด JSON" : "Export JSON"}
        </button>
        <button onClick={exportHtml} className="inline-flex items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-xs text-slate-300 hover:border-neon-cyan/50 hover:text-neon-cyan">
          <Download className="h-3.5 w-3.5" />
          {th ? "ดาวน์โหลด HTML" : "Export HTML"}
        </button>
        <button onClick={emailSummary} className="inline-flex items-center gap-2 rounded-md border border-white/10 px-3 py-2 text-xs text-slate-300 hover:border-neon-cyan/50 hover:text-neon-cyan">
          <Mail className="h-3.5 w-3.5" />
          {th ? "ส่งอีเมลสรุปผล" : "Email summary"}
        </button>
      </div>

      {mounted ? createPortal(printArticle, document.body) : null}
    </>
  );
}
