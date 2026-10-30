"use client";

import { useState } from "react";
import { Bot, ChevronDown, Code2, Cookie, EyeOff, FileWarning, Info, Lightbulb, ShieldAlert, ShieldHalf, Wrench, X } from "lucide-react";
import type { HeaderState, HtmlFindingSeverity, LeakState, ScanResult } from "@/lib/types";
import { getSecurityDictionaryEntry, type FixDifficulty, type SecurityDictionaryEntry } from "@/lib/security-dictionary";
import { Card, Pill, type Tone } from "./ui";

const DIFFICULTY_TONE: Record<FixDifficulty, { tone: Tone; labelTh: string; labelEn: string }> = {
  Easy: { tone: "ok", labelTh: "ง่าย (แก้ได้เร็ว)", labelEn: "Easy" },
  Medium: { tone: "warn", labelTh: "ปานกลาง", labelEn: "Medium" },
  Hard: { tone: "bad", labelTh: "ซับซ้อน", labelEn: "Hard" },
};

function DictionaryModal({
  entry,
  onClose,
  locale = "th",
}: {
  entry: SecurityDictionaryEntry;
  onClose: () => void;
  locale?: "th" | "en";
}) {
  const th = locale === "th";
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
              {th ? "คำอธิบายศัพท์ความปลอดภัย" : "Security Dictionary"}
            </p>
            <h3 id="dict-modal-title" className="mt-1 font-mono text-base font-bold text-white">
              {entry.title}
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={th ? "ปิดหน้าต่างคำอธิบาย" : "Close dictionary modal"}
            className="rounded-lg p-1 text-slate-400 hover:bg-white/10 hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-4 space-y-3.5 text-sm">
          <div className="rounded-lg border border-neon-purple/30 bg-neon-purple/10 p-3.5">
            <p className="mb-1 flex items-center gap-1.5 font-mono text-xs font-semibold text-neon-purple">
              <Lightbulb className="h-3.5 w-3.5" />
              {th ? "เปรียบเทียบให้เห็นภาพ" : "Simple Analogy"}
            </p>
            <p className="leading-relaxed text-slate-200">{entry.simpleAnalogy}</p>
          </div>

          <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3.5">
            <p className="mb-1 flex items-center gap-1.5 font-mono text-xs font-semibold text-red-300">
              <ShieldAlert className="h-3.5 w-3.5" />
              {th ? "ความเสี่ยงหากไม่มีหรือปล่อยรั่วไหล" : "Risk if Missing"}
            </p>
            <p className="leading-relaxed text-slate-200">{entry.riskIfMissing}</p>
          </div>

          <div className="flex items-center justify-between rounded-lg bg-ink-800 px-3.5 py-2.5 text-xs">
            <span className="inline-flex items-center gap-1.5 font-mono text-slate-400">
              <Wrench className="h-3.5 w-3.5 text-neon-cyan" />
              {th ? "ความยากในการแก้ไข:" : "Fix Difficulty:"}
            </span>
            <Pill tone={diff.tone}>{th ? diff.labelTh : diff.labelEn}</Pill>
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

export function ScraperDefenseCard({ data, locale = "th" }: { data: ScanResult["robots"]; locale?: "th" | "en" }) {
  const th = locale === "th";
  return (
    <Card title={th ? "บอตเงา · นโยบาย AI Crawler" : "Phantom Crawlers · AI Crawler Policy"} icon={<Bot className="h-5 w-5" />} accent="purple" className="ward-result-card">
      <p className="mb-4 text-sm text-slate-400">
        {th
          ? data.found
            ? "พบไฟล์ robots.txt (ใช้กำหนดสิทธิ์ให้บอต AI เข้าถึงเนื้อหา ไม่มีผลต่อคะแนนความปลอดภัย)"
            : `ไม่พบไฟล์ robots.txt (HTTP ${data.status ?? "error"}) · บอต AI สามารถเก็บข้อมูลได้ตามค่าเริ่มต้น`
          : data.found
          ? "robots.txt found. Optional content-licensing policy (does not affect security score)."
          : `No robots.txt (HTTP ${data.status ?? "error"}). AI crawlers are allowed by default (informational).`}
      </p>
      <ul className="space-y-2">
        {data.bots.map((b) => (
          <li key={b.name} className="flex items-center justify-between rounded-lg bg-ink-800 px-3 py-2">
            <span className="font-mono text-sm">{b.name}</span>
            <Pill tone={b.blocked ? "ok" : "muted"}>{b.blocked ? (th ? "บล็อกไว้" : "Disallowed") : th ? "อนุญาต" : "Allowed"}</Pill>
          </li>
        ))}
      </ul>
    </Card>
  );
}

const HEADER_UI: Record<HeaderState, { tone: Tone; labelTh: string; labelEn: string }> = {
  strong: { tone: "ok", labelTh: "แข็งแรง", labelEn: "Strong" },
  weak: { tone: "warn", labelTh: "ยังไม่รัดกุม", labelEn: "Weak" },
  missing: { tone: "bad", labelTh: "ยังไม่ได้ตั้งค่า", labelEn: "Missing" },
};

function translateScanNote(note: string | undefined, th: boolean): string | undefined {
  if (!note || !th) return note;
  return note
    .replace(/^Weak:\s*/i, "ยังไม่รัดกุม: ")
    .replace(/^Strong script protection\s*/i, "ป้องกันสคริปต์ได้ดี ")
    .replace(/missing default-src \/ script-src/gi, "ไม่ได้กำหนด default-src หรือ script-src")
    .replace(/script-src allows 'unsafe-inline' or \*/gi, "script-src อนุญาต 'unsafe-inline' หรือ *")
    .replace(/script-src allows 'unsafe-eval'/gi, "script-src อนุญาต 'unsafe-eval'")
    .replace(/style-src includes 'unsafe-inline'/gi, "style-src อนุญาต 'unsafe-inline'")
    .replace(/prefer DENY, SAMEORIGIN, or restrictive frame-ancestors\./gi, "ควรตั้งเป็น DENY, SAMEORIGIN หรือกำหนด frame-ancestors")
    .replace(/Ignored because final URL is not HTTPS\./gi, "ไม่มีผลเพราะหน้าเว็บปลายทางไม่ใช่ HTTPS")
    .replace(/is under 6 months \(15552000\)\./gi, "น้อยกว่า 6 เดือน (ควรตั้งอย่างน้อย 15552000 วินาที)")
    .replace(/value should be 'nosniff'\./gi, "ค่าควรตั้งเป็น 'nosniff'")
    .replace(/leaks full referrer URL across origins\./gi, "อาจส่ง URL เต็มไปยังเว็บภายนอก ควรใช้ strict-origin-when-cross-origin")
    .replace(/allows wildcard \(\*\) feature access\./gi, "อนุญาตสิทธิ์เข้าถึงฟีเจอร์ด้วย * (ควรจำกัดเฉพาะที่จำเป็น)")
    .replace(/Reveals framework\/runtime fingerprint\..*$/gi, "เปิดเผยชื่อเฟรมเวิร์กหรือรันไทม์ ควรซ่อนค่านี้ (เช่น poweredByHeader: false หรือ expose_php = Off)")
    .replace(/Exposes exact server version number\..*$/gi, "เปิดเผยเลขเวอร์ชันของเว็บเซิร์ฟเวอร์ ควรปิดการแสดงเลขเวอร์ชัน (เช่น server_tokens off)")
    .replace(/Discloses runtime or generator details to scanners\./gi, "เปิดเผยรายละเอียดระบบหลังบ้านให้บอตสแกนทราบ")
    .replace(/missing Secure/gi, "ขาดแฟล็ก Secure")
    .replace(/missing HttpOnly/gi, "ขาดแฟล็ก HttpOnly")
    .replace(/missing SameSite/gi, "ขาดแฟล็ก SameSite")
    .replace(/SameSite=None requires Secure/gi, "การใช้ SameSite=None ต้องเปิด Secure ด้วยเสมอ")
    .replace(/__Host- prefix requires Secure and Path=\//gi, "คุกกี้ __Host- ต้องเปิด Secure และกำหนด Path=/");
}

export function SecurityHeadersCard({ data, locale = "th" }: { data: ScanResult["headers"]; locale?: "th" | "en" }) {
  const [activeDict, setActiveDict] = useState<SecurityDictionaryEntry | null>(null);
  const th = locale === "th";
  const exposures = data.exposures ?? [];
  const isolation = data.isolation ?? [];
  const raw = data.raw ?? [];

  return (
    <Card title={th ? "เกราะป้องกัน · Security Headers" : "Protective Wards · Security Headers"} icon={<ShieldHalf className="h-5 w-5" />} accent="cyan" className="ward-result-card">
      <p className="mb-4 text-sm text-slate-400">
        {th
          ? `ตรวจกลอนและกฎความปลอดภัยของหน้าเว็บ (HTTP ${data.status}) — กดไอคอน `
          : `Response headers from the page (HTTP ${data.status}). Click `}
        <Info className="inline h-3.5 w-3.5 text-neon-cyan" />
        {th ? " เพื่อดูคำอธิบายแบบเข้าใจง่าย" : " for a plain-language explanation"}
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
                <Pill tone={ui.tone}>{th ? ui.labelTh : ui.labelEn}</Pill>
              </div>
              {h.value && (
                <p className="mt-1 truncate font-mono text-xs text-slate-500" title={h.value}>
                  {h.value}
                </p>
              )}
              {h.note && <p className="mt-1 text-xs text-amber-300/90">{translateScanNote(h.note, th)}</p>}
            </li>
          );
        })}
      </ul>
      {activeDict && <DictionaryModal entry={activeDict} locale={locale} onClose={() => setActiveDict(null)} />}

      {exposures.length > 0 && (
        <div className="mt-4 border-t border-white/10 pt-3">
          <p className="mb-2 flex items-center gap-1.5 font-mono text-xs uppercase tracking-wider text-amber-300">
            <EyeOff className="h-3.5 w-3.5" />
            {th ? "การเปิดเผยข้อมูลเซิร์ฟเวอร์" : "Information Disclosure"}
          </p>
          <ul className="space-y-2">
            {exposures.map((exp) => (
              <li key={exp.header} className="rounded-lg border border-amber-400/20 bg-amber-400/5 px-3 py-2">
                <div className="flex items-center justify-between gap-3">
                  <span className="font-mono text-xs text-amber-200">
                    {exp.header}: <span className="text-white">{exp.value}</span>
                  </span>
                  <Pill tone="warn">{th ? "เปิดเผย" : "Exposed"}</Pill>
                </div>
                <p className="mt-1 text-xs text-slate-400">{translateScanNote(exp.note, th)}</p>
              </li>
            ))}
          </ul>
        </div>
      )}

      {raw.length > 0 && (
        <details className="group mt-4 rounded-lg border border-white/10 bg-ink-950/60 px-3 py-2 text-xs">
          <summary className="flex cursor-pointer list-none items-center justify-between font-mono text-slate-400 hover:text-neon-cyan">
            <span>{th ? `ดู Raw Response Headers (${raw.length})` : `Raw Response Headers (${raw.length})`}</span>
            <ChevronDown className="h-3.5 w-3.5 transition group-open:rotate-180" />
          </summary>
          <p className="mt-2 border-t border-white/10 pt-2 text-[11px] leading-relaxed text-slate-500">
            {th ? "Header ที่ได้รับจากหน้าเว็บปลายทาง (ซ่อนค่าคุกกี้อัตโนมัติ)" : "Headers received from the final response after redirects. Set-Cookie values are redacted."}
          </p>
          <dl className="mt-2 max-h-52 space-y-1 overflow-y-auto pr-1 font-mono text-[11px]">
            {raw.map((entry, idx) => (
              <div key={`${entry.name}-${idx}`} className="grid grid-cols-[120px_1fr] gap-2 border-b border-white/5 pb-1">
                <dt className="truncate text-neon-cyan" title={entry.name}>
                  {entry.name}
                </dt>
                <dd className="break-all text-slate-400">{entry.value}</dd>
              </div>
            ))}
          </dl>
        </details>
      )}

      {isolation.length > 0 && (
        <details className="group mt-3 rounded-lg border border-white/10 bg-ink-950/60 px-3 py-2 text-xs">
          <summary className="flex cursor-pointer list-none items-center justify-between font-mono text-slate-400 hover:text-neon-cyan">
            <span>Cross-Origin Isolation</span>
            <ChevronDown className="h-3.5 w-3.5 transition group-open:rotate-180" />
          </summary>
          <div className="mt-2 space-y-1.5 border-t border-white/10 pt-2">
            {isolation.map((iso) => (
              <div key={iso.key} className="flex items-center justify-between gap-2 py-0.5">
                <span className="truncate font-mono text-slate-300">{iso.label}</span>
                <Pill tone={iso.present ? (iso.reportOnly ? "warn" : "ok") : "muted"}>
                  {iso.present ? iso.value ?? (th ? "ตั้งค่าแล้ว" : "Present") : th ? "ไม่ได้ตั้งค่า" : "Not set"}
                </Pill>
              </div>
            ))}
          </div>
        </details>
      )}
    </Card>
  );
}

export function CookieSecurityCard({ data, locale = "th" }: { data: ScanResult["cookies"]; locale?: "th" | "en" }) {
  const th = locale === "th";
  return (
    <Card title={th ? "ความปลอดภัยของคุกกี้ (Cookie Security)" : "Cookie Security"} icon={<Cookie className="h-5 w-5" />} accent="cyan">
      <p className="mb-4 text-sm text-slate-400">
        {th ? "ตรวจเฉพาะการตั้งค่าความปลอดภัยของคุกกี้ (ระบบไม่เก็บและไม่แสดงค่าข้อมูลในคุกกี้)" : "Cookie values are never collected or displayed."}
      </p>
      {data.length === 0 ? (
        <p className="rounded-lg bg-ink-800 px-3 py-2 text-sm text-slate-400">
          {th ? "ไม่พบการส่งคุกกี้ (Set-Cookie) จากหน้าแรกของเว็บไซต์นี้" : "No Set-Cookie headers observed."}
        </p>
      ) : (
        <ul className="space-y-2">
          {data.map((cookie) => {
            const ui = HEADER_UI[cookie.state];
            return (
              <li key={cookie.name} className="rounded-lg bg-ink-800 px-3 py-2">
                <div className="flex items-center justify-between gap-3">
                  <span className="font-mono text-sm">{cookie.name}</span>
                  <Pill tone={ui.tone}>{cookie.state === "strong" ? (th ? "ปลอดภัย" : "Strong") : th ? "ควรปรับปรุง" : "Weak"}</Pill>
                </div>
                <p className="mt-1 text-xs text-slate-500">
                  Secure: {cookie.secure ? (th ? "เปิด" : "Yes") : th ? "ปิด" : "No"} · HttpOnly: {cookie.httpOnly ? (th ? "เปิด" : "Yes") : th ? "ปิด" : "No"} · SameSite: {cookie.sameSite ?? (th ? "ไม่ได้ระบุ" : "missing")}
                </p>
                {cookie.note && <p className="mt-1 text-xs text-amber-300">{translateScanNote(cookie.note, th)}</p>}
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

const HTML_TONE: Record<HtmlFindingSeverity, { tone: Tone; labelTh: string; labelEn: string }> = {
  high: { tone: "bad", labelTh: "ความเสี่ยงสูง", labelEn: "High" },
  medium: { tone: "warn", labelTh: "ความเสี่ยงปานกลาง", labelEn: "Medium" },
  low: { tone: "muted", labelTh: "ข้อสังเกต", labelEn: "Low" },
};

const FINDING_TH: Record<string, { title: string; note: string }> = {
  "mixed-content": {
    title: "พบการโหลดทรัพยากรผ่าน HTTP บนหน้า HTTPS (Mixed Content)",
    note: "รูปภาพ สคริปต์ หรือลิงก์ที่ยังใช้ http:// อาจถูกดักฟังหรือปลอมแปลงระหว่างทางได้",
  },
  "insecure-form": {
    title: "พบแบบฟอร์มส่งข้อมูลผ่านช่องทางที่ไม่เข้ารหัส (Insecure Form Action)",
    note: "แท็ก <form> ชี้ไปยัง http:// ซึ่งเสี่ยงต่อการถูกดักข้อมูลที่ผู้ใช้กรอก",
  },
  "source-map": {
    title: "พบไฟล์ Source Map เปิดเผยในหน้าเว็บ",
    note: "ไฟล์ .map อาจทำให้บุคคลภายนอกอ่านซอร์สโค้ดฝั่งหน้าบ้านได้ง่ายขึ้น",
  },
  "possible-secret": {
    title: "พบรูปแบบข้อความคล้าย API Key หรือ Token ใน HTML",
    note: "ควรตรวจสอบว่าไม่ใช่คีย์ลับฝั่งเซิร์ฟเวอร์ที่เผลอฝังไว้ในหน้าเว็บสาธารณะ",
  },
  "unsafe-blank-link": {
    title: "พบลิงก์เปิดแท็บใหม่ (target=\"_blank\") ที่ไม่ระบุ rel=\"noopener\"",
    note: "ควรเพิ่ม rel=\"noopener noreferrer\" เพื่อป้องกันหน้าปลายทางเข้าถึง window.opener",
  },
  "missing-sri": {
    title: "พบสคริปต์หรือสไตล์ชีตภายนอกที่ไม่ได้ตั้งค่า Subresource Integrity (SRI)",
    note: "การเพิ่มแอตทริบิวต์ integrity ช่วยป้องกันกรณี CDN ภายนอกถูกแก้ไขไฟล์",
  },
  "wordpress-surface": {
    title: "ตรวจพบร่องรอยระบบ WordPress (wp-content / wp-json / xmlrpc)",
    note: "ควรอัปเดตปลั๊กอินให้เป็นปัจจุบันและปิดการใช้งาน /xmlrpc.php หากไม่ได้ใช้",
  },
  "php-version-exposure": {
    title: "ตรวจพบการเปิดเผยเลขเวอร์ชัน PHP (X-Powered-By / PHP Surface)",
    note: "แนะนำให้ตั้งค่า expose_php = Off ใน php.ini เพื่อซ่อนเลขเวอร์ชันจากผู้โจมตี",
  },
};

export function HtmlInspectionCard({ data, locale = "th" }: { data: ScanResult["htmlFindings"]; locale?: "th" | "en" }) {
  const th = locale === "th";
  return (
    <Card title={th ? "การตรวจโครงสร้าง HTML (HTML Inspection)" : "HTML Inspection"} icon={<Code2 className="h-5 w-5" />} accent="purple">
      <p className="mb-4 text-sm text-slate-400">
        {th ? "ตรวจหาจุดเสี่ยงในโค้ด HTML หน้าแรก เช่น ฟอร์มไม่เข้ารหัส สคริปต์ภายนอก หรือร่องรอยระบบหลังบ้าน" : "Rule-based source checks; findings require validation."}
      </p>
      {data.length === 0 ? (
        <p className="rounded-lg bg-ink-800 px-3 py-2 text-sm text-slate-400">
          {th ? "ไม่พบรูปแบบความเสี่ยงในโค้ด HTML หน้าแรก" : "No high-signal client-side patterns found."}
        </p>
      ) : (
        <ul className="space-y-2">
          {data.map((finding) => {
            const sev = HTML_TONE[finding.severity];
            const translated = th ? FINDING_TH[finding.key] : undefined;
            return (
              <li key={finding.key} className="rounded-lg bg-ink-800 px-3 py-2">
                <div className="flex items-center justify-between gap-3">
                  <span className="font-mono text-sm">{translated ? translated.title : finding.title}</span>
                  <Pill tone={sev.tone}>{th ? sev.labelTh : sev.labelEn}</Pill>
                </div>
                <p className="mt-1 text-xs text-slate-500">{translated ? translated.note : finding.note}</p>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

const LEAK_UI: Record<LeakState, { tone: Tone; labelTh: string; labelEn: string }> = {
  exposed: { tone: "bad", labelTh: "รั่วไหลสู่สาธารณะ", labelEn: "Exposed" },
  "soft-200": { tone: "warn", labelTh: "ตอบ 200 แต่ไม่ใช่ไฟล์จริง", labelEn: "200, no file" },
  safe: { tone: "ok", labelTh: "ปลอดภัย (ปิดกั้นแล้ว)", labelEn: "Safe" },
  unreachable: { tone: "muted", labelTh: "ไม่ตอบสนอง", labelEn: "No response" },
};

export function DevLeaksCard({ data, locale = "th" }: { data: ScanResult["leaks"]; locale?: "th" | "en" }) {
  const [activeDict, setActiveDict] = useState<SecurityDictionaryEntry | null>(null);
  const th = locale === "th";

  return (
    <Card title={th ? "รอยรั่วซ่อนเร้น · Dev Leaks" : "Crypt Leaks · Dev Leaks"} icon={<FileWarning className="h-5 w-5" />} accent="green" className="ward-result-card">
      <p className="mb-4 text-sm text-slate-400">
        {th ? "ตรวจว่ามีไฟล์ความลับ (.env หรือ .git/HEAD) เปิดให้คนภายนอกดาวน์โหลดได้หรือไม่" : "Sensitive paths that should never return a file."}
      </p>
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
              <Pill tone={LEAK_UI[l.state].tone}>{th ? LEAK_UI[l.state].labelTh : LEAK_UI[l.state].labelEn}</Pill>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              {th
                ? l.state === "exposed"
                  ? "อันตราย: ไฟล์นี้เปิดให้คนทั่วไปเข้าถึงได้ ต้องปิดกั้นทันที"
                  : l.state === "safe"
                  ? "เซิร์ฟเวอร์ปฏิเสธการเข้าถึงไฟล์นี้อย่างถูกต้อง"
                  : l.state === "soft-200"
                  ? "ตอบกลับ HTTP 200 แต่เป็นหน้าเว็บปกติ ไม่ใช่ไฟล์ความลับ"
                  : "ไม่สามารถเชื่อมต่อเพื่อตรวจสอบพาธนี้ได้"
                : l.note}
            </p>
          </li>
        ))}
      </ul>
      {activeDict && <DictionaryModal entry={activeDict} locale={locale} onClose={() => setActiveDict(null)} />}
    </Card>
  );
}
