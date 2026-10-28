import Link from "next/link";
import { AlertTriangle, ArrowLeft, Calendar, CheckCircle2, ExternalLink, Flame, ShieldAlert } from "lucide-react";
import { Pill } from "@/components/ui";

export const revalidate = 3600;

interface CisaVulnerability {
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

interface CisaKevFeed {
  title?: string;
  catalogVersion?: string;
  dateReleased?: string;
  count?: number;
  vulnerabilities: CisaVulnerability[];
}

const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

async function fetchLatestKev(): Promise<{
  items: CisaVulnerability[];
  catalogVersion?: string;
  dateReleased?: string;
  totalCount?: number;
  error?: string;
}> {
  try {
    const res = await fetch(CISA_KEV_URL, {
      next: { revalidate: 3600 },
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      return { items: [], error: `CISA KEV feed returned HTTP ${res.status}.` };
    }
    const data = (await res.json()) as CisaKevFeed;
    const list = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
    const sorted = [...list].sort((a, b) => (b.dateAdded ?? "").localeCompare(a.dateAdded ?? ""));
    return {
      items: sorted.slice(0, 10),
      catalogVersion: data.catalogVersion,
      dateReleased: data.dateReleased,
      totalCount: data.count ?? list.length,
    };
  } catch {
    return {
      items: [],
      error: "ไม่สามารถดึงข้อมูลจาก CISA KEV API ได้ในขณะนี้ กรุณาตรวจสอบการเชื่อมต่ออินเทอร์เน็ตแล้วลองใหม่อีกครั้ง",
    };
  }
}

export default async function VulnerabilitiesPage() {
  const { items, catalogVersion, dateReleased, totalCount, error } = await fetchLatestKev();

  return (
    <main className="min-h-screen bg-[radial-gradient(ellipse_at_top,rgba(179,102,255,0.16),transparent_55%)]">
      <div className="mx-auto max-w-5xl px-4 pb-24 pt-12 sm:px-6">
        <div className="mb-8 flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-5">
          <Link
            href="/"
            className="inline-flex items-center gap-2 rounded-lg border border-neon-cyan/40 bg-ink-900 px-4 py-2 font-mono text-xs font-semibold text-neon-cyan transition hover:bg-neon-cyan/15 focus:outline-none focus-visible:ring-2 focus-visible:ring-neon-cyan"
          >
            <ArrowLeft className="h-4 w-4" />
            กลับไปหน้าสแกนหลัก (Scanner)
          </Link>

          <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-slate-400">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-neon-purple/30 bg-neon-purple/10 px-3 py-1 text-neon-purple">
              <Flame className="h-3.5 w-3.5" />
              CISA Known Exploited Vulnerabilities (KEV)
            </span>
            {totalCount !== undefined && (
              <span className="rounded-md border border-white/10 bg-ink-900 px-2.5 py-1 text-slate-400">
                Total KEV: {totalCount.toLocaleString()}
              </span>
            )}
          </div>
        </div>

        <header className="mb-10">
          <h1 className="text-3xl font-bold tracking-tight text-white sm:text-5xl">
            Threat Intelligence Feed
          </h1>
          <p className="mt-3 max-w-3xl text-sm leading-relaxed text-slate-400 sm:text-base">
            รายการ 10 ช่องโหว่ความปลอดภัยล่าสุดที่ได้รับการยืนยันจาก <strong className="text-slate-200">CISA (Cybersecurity and Infrastructure Security Agency)</strong> ว่ากำลังถูกแฮกเกอร์ใช้โจมตีจริงในโลกไซเบอร์ (Active Exploitation) อัปเดตอัตโนมัติทุกชั่วโมง (ISR 3600s)
          </p>
          {(catalogVersion || dateReleased) && (
            <p className="mt-2 font-mono text-xs text-slate-500">
              Catalog Version: {catalogVersion ?? "-"} · Released: {dateReleased ?? "-"}
            </p>
          )}
        </header>

        {error && (
          <div
            role="alert"
            className="mb-8 flex items-center gap-3 rounded-xl border border-amber-400/30 bg-amber-400/10 p-4 text-sm text-amber-200"
          >
            <AlertTriangle className="h-5 w-5 shrink-0 text-amber-300" />
            <span>{error}</span>
          </div>
        )}

        <div className="grid gap-5 md:grid-cols-2">
          {items.map((vuln) => {
            const isRansomware = vuln.knownRansomwareCampaignUse?.toLowerCase() === "known";
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
                      <Pill tone="bad">Actively Exploited</Pill>
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
                        Ransomware Campaign
                      </span>
                    )}
                  </div>

                  <h2 className="mt-2.5 text-base font-semibold text-white">{vuln.vulnerabilityName}</h2>

                  <p className="mt-2 text-xs leading-relaxed text-slate-300">{vuln.shortDescription}</p>
                </div>

                <div className="mt-4 rounded-lg border border-neon-cyan/25 bg-ink-950/90 p-3.5">
                  <p className="mb-1 flex items-center justify-between font-mono text-[11px] font-semibold uppercase tracking-wider text-neon-cyan">
                    <span className="inline-flex items-center gap-1.5">
                      <CheckCircle2 className="h-3.5 w-3.5 text-neon-green" />
                      คำแนะนำวิธีแก้ไข (Required Action)
                    </span>
                    {vuln.dueDate && <span className="text-slate-500">Due: {vuln.dueDate}</span>}
                  </p>
                  <p className="text-xs leading-relaxed text-slate-300">{vuln.requiredAction}</p>
                </div>
              </article>
            );
          })}
        </div>
      </div>
    </main>
  );
}

