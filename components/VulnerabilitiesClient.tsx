"use client";

import { useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowLeft,
  Calendar,
  CheckCircle2,
  ExternalLink,
  Flame,
  Globe,
  ShieldAlert,
} from "lucide-react";
import { Pill } from "@/components/ui";

export interface CisaVulnerability {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
}

type Lang = "th" | "en";

const VULN_NAME_MAP: Array<[RegExp, string]> = [
  [/Remote Code Execution Vulnerability/gi, "ช่องโหว่การรันโค้ดจากระยะไกล (Remote Code Execution)"],
  [/Privilege Escalation Vulnerability/gi, "ช่องโหว่การยกระดับสิทธิ์โดยไม่ได้รับอนุญาต (Privilege Escalation)"],
  [/Authentication Bypass Vulnerability/gi, "ช่องโหว่การข้ามขั้นตอนการยืนยันตัวตน (Authentication Bypass)"],
  [/Command Injection Vulnerability/gi, "ช่องโหว่การแทรกคำสั่งระบบ (Command Injection)"],
  [/SQL Injection Vulnerability/gi, "ช่องโหว่การแทรกคำสั่งฐานข้อมูล (SQL Injection)"],
  [/Code Injection Vulnerability/gi, "ช่องโหว่การฝังโค้ดอันตราย (Code Injection)"],
  [/Path Traversal Vulnerability/gi, "ช่องโหว่การเข้าถึงไฟล์นอกโฟลเดอร์ที่กำหนด (Path Traversal)"],
  [/Directory Traversal Vulnerability/gi, "ช่องโหว่การไต่ระดับโฟลเดอร์ (Directory Traversal)"],
  [/Buffer Overflow Vulnerability/gi, "ช่องโหว่หน่วยความจำล้น (Buffer Overflow)"],
  [/Heap-Based Buffer Overflow Vulnerability/gi, "ช่องโหว่หน่วยความจำส่วน Heap ล้น (Heap Buffer Overflow)"],
  [/Stack-Based Buffer Overflow Vulnerability/gi, "ช่องโหว่หน่วยความจำส่วน Stack ล้น (Stack Buffer Overflow)"],
  [/Out-of-Bounds Write Vulnerability/gi, "ช่องโหว่การเขียนข้อมูลเกินขอบเขตหน่วยความจำ (Out-of-Bounds Write)"],
  [/Out-of-Bounds Read Vulnerability/gi, "ช่องโหว่การอ่านข้อมูลเกินขอบเขตหน่วยความจำ (Out-of-Bounds Read)"],
  [/Use-After-Free Vulnerability/gi, "ช่องโหว่การเรียกใช้หน่วยความจำที่คืนค่าแล้ว (Use-After-Free)"],
  [/Deserialization of Untrusted Data Vulnerability/gi, "ช่องโหว่การแปลงข้อมูลที่ไม่น่าเชื่อถือ (Insecure Deserialization)"],
  [/Server-Side Request Forgery \(SSRF\) Vulnerability/gi, "ช่องโหว่การปลอมแปลงคำขอฝั่งเซิร์ฟเวอร์ (SSRF)"],
  [/Cross-Site Scripting \(XSS\) Vulnerability/gi, "ช่องโหว่การฝังสคริปต์ข้ามไซต์ (XSS)"],
  [/Improper Access Control Vulnerability/gi, "ช่องโหว่การควบคุมสิทธิ์การเข้าถึงไม่รัดกุม (Improper Access Control)"],
  [/Improper Input Validation Vulnerability/gi, "ช่องโหว่การตรวจสอบข้อมูลนำเข้าไม่รัดกุม (Improper Input Validation)"],
  [/Missing Authentication for Critical Function Vulnerability/gi, "ช่องโหว่การขาดระบบยืนยันตัวตนในฟังก์ชันสำคัญ"],
  [/Unrestricted Upload of File with Dangerous Type Vulnerability/gi, "ช่องโหว่การอัปโหลดไฟล์อันตรายโดยไม่มีการจำกัด"],
  [/Information Disclosure Vulnerability/gi, "ช่องโหว่การรั่วไหลของข้อมูลสำคัญ (Information Disclosure)"],
  [/Denial-of-Service Vulnerability/gi, "ช่องโหว่ที่ทำให้ระบบหยุดทำงาน (Denial-of-Service)"],
  [/Type Confusion Vulnerability/gi, "ช่องโหว่ความสับสนของชนิดข้อมูลในหน่วยความจำ (Type Confusion)"],
  [/Integer Overflow or Wraparound Vulnerability/gi, "ช่องโหว่ตัวเลขล้นขอบเขต (Integer Overflow)"],
  [/Improper Neutralization of Special Elements/gi, "ช่องโหว่การกรองอักขระพิเศษไม่สมบูรณ์"],
  [/Incorrect Privilege Assignment Vulnerability/gi, "ช่องโหว่การกำหนดสิทธิ์ผู้ใช้งานไม่ถูกต้อง"],
  [/Improper Limitation of a Pathname to a Restricted Directory/gi, "ช่องโหว่การจำกัดพาธของไฟล์ไม่รัดกุม (Path Traversal)"],
  [/Vulnerability/gi, "ช่องโหว่ความปลอดภัย"],
];

export function translateTitleToThai(title: string): string {
  let out = title;
  for (const [pattern, replacement] of VULN_NAME_MAP) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

export function translateDescriptionToThai(desc: string, vendor: string, product: string): string {
  const lower = desc.toLowerCase();
  const traits: string[] = [];

  if (lower.includes("remote code execution") || lower.includes("execute arbitrary code")) {
    traits.push("สั่งรันโค้ดอันตรายจากระยะไกล (Remote Code Execution)");
  }
  if (lower.includes("arbitrary commands") || lower.includes("command injection") || lower.includes("os commands")) {
    traits.push("แทรกคำสั่งควบคุมระบบปฏิบัติการ (Command Injection)");
  }
  if (lower.includes("privilege escalation") || lower.includes("escalate privileges") || lower.includes("root") || lower.includes("system privileges")) {
    traits.push("ยกระดับสิทธิ์เป็นผู้ดูแลระบบ (Privilege Escalation)");
  }
  if (lower.includes("authentication bypass") || lower.includes("bypass authentication") || lower.includes("unauthenticated")) {
    traits.push("เข้าถึงระบบหรือโจมตีได้โดยไม่ต้องล็อกอินยืนยันตัวตน (Unauthenticated / Auth Bypass)");
  }
  if (lower.includes("path traversal") || lower.includes("directory traversal") || lower.includes("arbitrary file")) {
    traits.push("อ่านหรือเขียนไฟล์สำคัญในเซิร์ฟเวอร์โดยไม่ได้รับอนุญาต");
  }
  if (lower.includes("buffer overflow") || lower.includes("out-of-bounds") || lower.includes("use-after-free") || lower.includes("memory corruption")) {
    traits.push("โจมตีผ่านข้อผิดพลาดในการจัดการหน่วยความจำของระบบ");
  }
  if (lower.includes("deserialization")) {
    traits.push("ส่งข้อมูลที่ถูกดัดแปลงเพื่อสั่งรันคำสั่งระหว่างการแปลงข้อมูล (Insecure Deserialization)");
  }
  if (lower.includes("sql injection")) {
    traits.push("แทรกคำสั่งฐานข้อมูล (SQL Injection) เพื่อดึงหรือแก้ไขข้อมูล");
  }
  if (lower.includes("cross-site scripting") || lower.includes("xss")) {
    traits.push("ฝังสคริปต์อันตรายเพื่อขโมยข้อมูลเซสชันของผู้ใช้ (XSS)");
  }
  if (lower.includes("server-side request forgery") || lower.includes("ssrf")) {
    traits.push("หลอกให้เซิร์ฟเวอร์ยิงคำขอไปยังระบบภายในองค์กร (SSRF)");
  }
  if (lower.includes("denial-of-service") || lower.includes("denial of service") || lower.includes("crash")) {
    traits.push("ทำให้ระบบล่มหรือหยุดให้บริการ (Denial-of-Service)");
  }

  if (traits.length > 0) {
    return `${vendor} ${product} มีช่องโหว่ที่ผู้โจมตีสามารถใช้เพื่อ${traits.join(" และ")}ได้ (${desc})`;
  }
  return `พบช่องโหว่ความปลอดภัยใน ${vendor} ${product}: ${desc}`;
}

export function translateActionToThai(action: string): string {
  let out = action;
  out = out.replace(
    /Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable\./gi,
    "ดำเนินการอัปเดตแพตช์หรือตั้งค่าป้องกันตามคำแนะนำของผู้ผลิตทันที (หรือหยุดใช้งานผลิตภัณฑ์ชั่วคราวหากยังไม่มีแพตช์แก้ไข)",
  );
  out = out.replace(
    /Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable\./gi,
    "อัปเดตแพตช์แก้ไขตามคำแนะนำของผู้ผลิตทันที หรือระงับการใช้งานชั่วคราวหากยังไม่มีแพตช์",
  );
  out = out.replace(
    /Apply updates per vendor instructions\./gi,
    "อัปเดตซอฟต์แวร์เป็นเวอร์ชันล่าสุดตามคำแนะนำของผู้ผลิตทันที",
  );
  return out;
}

interface Props {
  items: CisaVulnerability[];
  catalogVersion?: string;
  dateReleased?: string;
  totalCount?: number;
  error?: string;
}

export default function VulnerabilitiesClient({
  items,
  catalogVersion,
  dateReleased,
  totalCount,
  error,
}: Props) {
  const [lang, setLang] = useState<Lang>("th");
  const isTh = lang === "th";

  return (
    <main className="min-h-screen bg-[radial-gradient(ellipse_at_top,rgba(179,102,255,0.16),transparent_55%)]">
      <div className="mx-auto max-w-5xl px-4 pb-24 pt-12 sm:px-6">
        <div className="mb-8 flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-5">
          <div className="flex flex-wrap items-center gap-2.5">
            <Link
              href="/"
              className="inline-flex items-center gap-2 rounded-lg border border-neon-cyan/40 bg-ink-900 px-4 py-2 font-mono text-xs font-semibold text-neon-cyan transition hover:bg-neon-cyan/15 focus:outline-none focus-visible:ring-2 focus-visible:ring-neon-cyan"
            >
              <ArrowLeft className="h-4 w-4" />
              {isTh ? "กลับไปหน้าสแกนหลัก" : "Back to Scanner"}
            </Link>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 font-mono text-xs text-slate-400">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-neon-purple/30 bg-neon-purple/10 px-3 py-1 text-neon-purple">
              <Flame className="h-3.5 w-3.5" />
              CISA KEV
            </span>
            {totalCount !== undefined && (
              <span className="rounded-md border border-white/10 bg-ink-900 px-2.5 py-1 text-slate-400">
                {isTh ? `ทั้งหมด: ${totalCount.toLocaleString()} รายการ` : `Total KEV: ${totalCount.toLocaleString()}`}
              </span>
            )}

            {/* ปุ่มสลับภาษา ไทย / English */}
            <div
              role="group"
              aria-label="Language switcher"
              className="inline-flex items-center rounded-lg border border-neon-cyan/40 bg-ink-900 p-0.5"
            >
              <Globe className="ml-2 mr-1 h-3.5 w-3.5 text-neon-cyan" />
              <button
                type="button"
                onClick={() => setLang("th")}
                aria-pressed={isTh}
                className={`rounded-md px-2.5 py-1 font-mono text-xs font-semibold transition ${
                  isTh
                    ? "bg-neon-cyan text-ink-950 shadow-sm"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                ไทย
              </button>
              <button
                type="button"
                onClick={() => setLang("en")}
                aria-pressed={!isTh}
                className={`rounded-md px-2.5 py-1 font-mono text-xs font-semibold transition ${
                  !isTh
                    ? "bg-neon-cyan text-ink-950 shadow-sm"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                English
              </button>
            </div>
          </div>
        </div>

        <header className="mb-10">
          <h1 className="text-3xl font-bold tracking-tight text-white sm:text-5xl">
            {isTh ? "ฟีดแจ้งเตือนช่องโหว่อันตราย (Threat Intelligence)" : "Threat Intelligence Feed"}
          </h1>
          <p className="mt-3 max-w-3xl text-sm leading-relaxed text-slate-400 sm:text-base">
            {isTh ? (
              <>
                รายการ 10 ช่องโหว่ความปลอดภัยล่าสุดที่ได้รับการยืนยันจาก{" "}
                <strong className="text-slate-200">CISA (Cybersecurity and Infrastructure Security Agency)</strong>{" "}
                ว่ากำลังถูกแฮกเกอร์ใช้โจมตีจริงในโลกไซเบอร์ (Active Exploitation) อัปเดตอัตโนมัติทุกชั่วโมง (ISR 3600s)
              </>
            ) : (
              <>
                The 10 most recent vulnerabilities confirmed by{" "}
                <strong className="text-slate-200">CISA (Cybersecurity and Infrastructure Security Agency)</strong> to
                be actively exploited in the wild. Automatically refreshed every hour (ISR 3600s).
              </>
            )}
          </p>
          {(catalogVersion || dateReleased) && (
            <p className="mt-2 font-mono text-xs text-slate-500">
              {isTh
                ? `เวอร์ชันฐานข้อมูล: ${catalogVersion ?? "-"} · อัปเดตเมื่อ: ${dateReleased ?? "-"}`
                : `Catalog Version: ${catalogVersion ?? "-"} · Released: ${dateReleased ?? "-"}`}
            </p>
          )}
        </header>

        {error && (
          <div
            role="alert"
            className="mb-8 flex items-center gap-3 rounded-xl border border-amber-400/30 bg-amber-400/10 p-4 text-sm text-amber-200"
          >
            <AlertTriangle className="h-5 w-5 shrink-0 text-amber-300" />
            <span>
              {isTh
                ? error
                : "Unable to reach the CISA KEV API right now. Please check your network connection and try again."}
            </span>
          </div>
        )}

        <div className="grid gap-5 md:grid-cols-2">
          {items.map((vuln) => {
            const isRansomware = vuln.knownRansomwareCampaignUse?.toLowerCase() === "known";
            const displayTitle = isTh ? translateTitleToThai(vuln.vulnerabilityName) : vuln.vulnerabilityName;
            const displayDesc = isTh
              ? translateDescriptionToThai(vuln.shortDescription, vuln.vendorProject, vuln.product)
              : vuln.shortDescription;
            const displayAction = isTh ? translateActionToThai(vuln.requiredAction) : vuln.requiredAction;

            return (
              <article
                key={vuln.cveID}
                className="flex flex-col justify-between rounded-xl border border-neon-purple/30 bg-ink-900/85 p-5 shadow-[0_0_30px_-12px] shadow-neon-purple/30 transition hover:border-neon-cyan/50"
              >
                <div>
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3">
                    <div className="flex items-center gap-2">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vuln.cveID)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 font-mono text-base font-bold text-neon-cyan hover:underline"
                      >
                        {vuln.cveID}
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                      <Pill tone="bad">{isTh ? "กำลังถูกโจมตีจริง" : "Actively Exploited"}</Pill>
                    </div>
                    <span className="inline-flex items-center gap-1 font-mono text-xs text-slate-400">
                      <Calendar className="h-3.5 w-3.5 text-slate-500" />
                      {vuln.dateAdded}
                    </span>
                  </div>

                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <span className="rounded-md border border-neon-green/30 bg-neon-green/10 px-2.5 py-0.5 font-mono text-xs font-medium text-neon-green">
                      {vuln.vendorProject} · {vuln.product}
                    </span>
                    {isRansomware && (
                      <span className="inline-flex items-center gap-1 rounded-md border border-red-500/40 bg-red-500/15 px-2 py-0.5 font-mono text-[11px] text-red-300">
                        <ShieldAlert className="h-3 w-3" />
                        {isTh ? "ถูกใช้โจมตีเรียกค่าไถ่ (Ransomware)" : "Ransomware Campaign"}
                      </span>
                    )}
                  </div>

                  <h2 className="mt-2.5 text-base font-semibold text-white">{displayTitle}</h2>

                  <p className="mt-2 text-xs leading-relaxed text-slate-300">{displayDesc}</p>
                </div>

                <div className="mt-4 rounded-lg border border-neon-cyan/25 bg-ink-950/90 p-3.5">
                  <p className="mb-1 flex items-center justify-between font-mono text-[11px] font-semibold uppercase tracking-wider text-neon-cyan">
                    <span className="inline-flex items-center gap-1.5">
                      <CheckCircle2 className="h-3.5 w-3.5 text-neon-green" />
                      {isTh ? "คำแนะนำวิธีแก้ไข (Required Action)" : "Required Action"}
                    </span>
                    {vuln.dueDate && (
                      <span className="text-slate-500">
                        {isTh ? `กำหนดแก้ไข: ${vuln.dueDate}` : `Due: ${vuln.dueDate}`}
                      </span>
                    )}
                  </p>
                  <p className="text-xs leading-relaxed text-slate-300">{displayAction}</p>
                </div>
              </article>
            );
          })}
        </div>
      </div>
    </main>
  );
}

