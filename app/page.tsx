"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { ArrowUp, Bot, FileWarning, Flame, MoonStar, ShieldHalf, Sparkles } from "lucide-react";
import ScanForm from "@/components/ScanForm";
import RemediationCard from "@/components/RemediationCard";
import ObservatoryTabs from "@/components/ObservatoryTabs";
import {
  CookieSecurityCard,
  DevLeaksCard,
  HtmlInspectionCard,
  ScraperDefenseCard,
  SecurityHeadersCard,
} from "@/components/ResultCards";
import ReportActions from "@/components/ReportActions";
import CisaSceneSlider from "@/components/CisaSceneSlider";
import type { AnalysisMode, AnalysisResult, ScanResult } from "@/lib/types";

type Phase = "idle" | "scanning" | "analyzing" | "done";
type Locale = "th" | "en";

const headerWeights = {
  csp: { strong: 25, weak: 14 }, hsts: { strong: 20, weak: 10 }, xfo: { strong: 15, weak: 8 },
  xcto: { strong: 12, weak: 6 }, rp: { strong: 10, weak: 5 }, pp: { strong: 8, weak: 4 },
} as const;

function formatRedirectSummary(redirects: NonNullable<ScanResult["redirects"]>, th: boolean): string {
  const redirectCount = Math.max(0, redirects.hops.length - 1);
  if (!th) {
    if (redirects.status === "no_redirect") {
      return `Direct connection (${redirects.secure ? "HTTPS secure" : "HTTP unencrypted"})`;
    }
    return `${redirects.status.replaceAll("_", " ")} · ${redirectCount} redirect${redirectCount === 1 ? "" : "s"} · ${redirects.secure ? "HTTPS secure throughout" : "needs HTTPS review"}`;
  }

  switch (redirects.status) {
    case "no_redirect":
      return redirects.secure
        ? "เชื่อมต่อตรงผ่าน HTTPS อย่างปลอดภัย (ไม่มีการเด้งเปลี่ยนหน้า)"
        : "เชื่อมต่อตรงแต่ยังเป็น HTTP ที่ไม่ได้เข้ารหัส (ควรบังคับใช้ HTTPS)";
    case "http_upgraded":
      return `ปลอดภัย — ระบบบังคับเปลี่ยนจาก HTTP เป็น HTTPS อัตโนมัติ (เปลี่ยนหน้า ${redirectCount || 1} ครั้ง)`;
    case "clean_secure":
      return `ปลอดภัย — เปลี่ยนหน้าภายใต้การเข้ารหัส HTTPS ตลอดเส้นทาง (${redirectCount || 1} ครั้ง)`;
    case "insecure_start":
      return "ควรแก้ไข — หน้าเว็บยังเปิดผ่าน HTTP ปกติโดยไม่บังคับเปลี่ยนเป็น HTTPS";
    case "invalid_first_upgrade":
      return "ควรตรวจสอบ — การเปลี่ยนหน้าจาก HTTP ไปยังโดเมนอื่นก่อนเข้ารหัส HTTPS";
    case "downgrade_detected":
      return "อันตราย — พบการเปลี่ยนหน้าลดระดับจาก HTTPS กลับไปเป็น HTTP ที่ไม่ปลอดภัย";
    case "max_hops_exceeded":
      return "ควรตรวจสอบ — มีการเด้งเปลี่ยนหน้าต่อกันหลายทอดเกินไป (เกิน 5 ครั้ง)";
    default:
      return "ควรตรวจสอบ — รูปแบบการเปลี่ยนหน้าเว็บไม่สมบูรณ์";
  }
}

function getHeaderPosture(scan: ScanResult | null) {
  if (!scan) return null;
  const points = scan.headers.items.reduce((total, item) => total + headerWeights[item.key][item.state === "strong" ? "strong" : "weak"] * (item.state === "missing" ? 0 : 1), 0);
  const strong = scan.headers.items.filter((item) => item.state === "strong").length;
  return { score: Math.round((points / 90) * 100), strong, total: scan.headers.items.length };
}

const h = "https://images.higgs.ai/?default=1&output=webp&url=https%3A%2F%2Fd8j0ntlcm91z4.cloudfront.net%2Fuser_38xzZboKViGWJOttwIXH07lWA1P%2F";
const img = (id: string, w = 2400) => `${h}${id}.png&w=${w}&q=85`;
const assets = {
  hero: img("hf_20261029_023809_d6836117-c958-4680-aa43-1e1973fbc17c"),
  story: img("hf_20261029_023812_40e3f5f5-a613-4a33-9c78-4cab8b04a992"),
  rites: img("hf_20261029_023814_b2c8f33a-3c90-4aa1-bb91-cce7f0deb878"),
  night: img("hf_20261029_023817_3e21faea-ad1c-4723-be92-9b22692094e1"),
  finale: img("hf_20261029_023819_5b21be3d-159e-4d1d-a3b3-80339bc5d5f1"),
  s1: img("hf_20261029_025938_e54c50c3-9748-4d00-af68-886bef6e65e7"),
  s2: img("hf_20261029_030022_7a86d576-94d5-4069-b515-62547af3b50c"),
  s3: img("hf_20261029_025940_a85237c9-d7e3-4c28-b1d9-71ad7d8cbca4"),
  s4: img("hf_20261029_025942_debc2172-5187-4ad4-af0d-307c5e0277b5"),
  sprites: img("hf_20261029_023917_156ac3d3-e103-4a95-947d-07554914ab0b", 1024),
};

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(data?.error ?? "Request failed. Try again.");
  return data as T;
}

function Flow({ lava = false, cn = "" }: { lava?: boolean; cn?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current,
      x = c?.getContext("2d");
    if (!c || !x) return;
    let f = 0;
    const draw = (t: number) => {
      const b = c.getBoundingClientRect(),
        r = Math.min(devicePixelRatio || 1, 1.5);
      if (b.width <= 0 || b.height <= 0 || !Number.isFinite(b.width) || !Number.isFinite(b.height)) {
        f = requestAnimationFrame(draw);
        return;
      }
      if (c.width !== Math.ceil(b.width * r) || c.height !== Math.ceil(b.height * r)) {
        c.width = Math.ceil(b.width * r);
        c.height = Math.ceil(b.height * r);
        x.setTransform(r, 0, 0, r, 0, 0);
      }
      x.clearRect(0, 0, b.width, b.height);
      x.globalCompositeOperation = "lighter";
      for (let i = 0; i < Math.max(9, b.width / (lava ? 7 : 5)); i++) {
        const l = (lava ? 32 : 55) + (i % 6) * (lava ? 13 : 21),
          y = ((t * (lava ? 0.11 : 0.2) + i * 73) % (b.height + l)) - l,
          px = ((i * 23) % b.width) + Math.sin(t / 700 + i) * 2,
          g = x.createLinearGradient(px, y, px, y + l);
        g.addColorStop(0, lava ? "#ff762200" : "#bff5ff00");
        g.addColorStop(0.45, lava ? "#ffe59b" : "#d9fbff");
        g.addColorStop(1, lava ? "#ff421500" : "#6ecbff00");
        x.strokeStyle = g;
        x.lineWidth = 1 + (i % 3);
        x.beginPath();
        x.moveTo(px, y);
        x.lineTo(px + ((i % 3) - 1), y + l);
        x.stroke();
      }
      f = requestAnimationFrame(draw);
    };
    f = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(f);
  }, [lava]);
  return <canvas className={`flow ${lava ? "lava" : ""} ${cn}`} ref={ref} />;
}

function Motes() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current,
      x = c?.getContext("2d");
    if (!c || !x) return;
    let f = 0;
    const p = Array.from({ length: 70 }, (_, i) => [(i * 47) % 100, (i * 29) % 100, 0.5 + (i % 3)]);
    const draw = (t: number) => {
      const b = c.getBoundingClientRect(),
        r = Math.min(devicePixelRatio || 1, 1.5);
      if (b.width <= 0 || b.height <= 0 || !Number.isFinite(b.width) || !Number.isFinite(b.height)) {
        f = requestAnimationFrame(draw);
        return;
      }
      if (c.width !== Math.ceil(b.width * r) || c.height !== Math.ceil(b.height * r)) {
        c.width = Math.ceil(b.width * r);
        c.height = Math.ceil(b.height * r);
        x.setTransform(r, 0, 0, r, 0, 0);
      }
      x.clearRect(0, 0, b.width, b.height);
      p.forEach(([a, d, s]) => {
        x.fillStyle = `rgba(194,240,255,${0.18 + 0.3 * Math.abs(Math.sin(t / 900 + a))})`;
        x.beginPath();
        x.arc((a / 100) * b.width, ((((d - t / 150) % 100) + 100) % 100 / 100) * b.height, s, 0, 7);
        x.fill();
      });
      f = requestAnimationFrame(draw);
    };
    f = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(f);
  }, []);
  return <canvas ref={ref} className="motes" />;
}

function Sprite({ name, x, y, w }: { name: string; x: number; y: number; w: number }) {
  return (
    <i
      className={`sprite ${name}`}
      style={{ left: `${x}%`, top: `${y}%`, width: `${w}%`, backgroundImage: `url('${assets.sprites}')` }}
    />
  );
}

function Copy({ title, children, center = false }: { title: string; children: React.ReactNode; center?: boolean }) {
  return (
    <article className={`copy ${center ? "center" : ""}`}>
      <h2>{title}</h2>
      <i className="rule" />
      {children}
    </article>
  );
}

function Scene({
  id,
  src,
  focus,
  children,
  kind = "",
}: {
  id: string;
  src: string;
  focus: number;
  children: React.ReactNode;
  kind?: string;
}) {
  return (
    <section
      id={id}
      className={`scene ${kind}`}
      style={{ "--img": `url('${src}')`, "--focus": focus } as React.CSSProperties}
    >
      {children}
    </section>
  );
}

function Seam({ src, fall }: { src: string; fall?: string }) {
  return (
    <div className="seam">
      <div className="seam-band">
        {fall && <Flow cn={`seam-fall ${fall}`} />}
        <img src={src} alt="" />
      </div>
    </div>
  );
}

export default function Home() {
  const lamp = useRef<HTMLDivElement>(null);
  const [url, setUrl] = useState("");
  const [locale, setLocale] = useState<Locale>("th");
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [mode, setMode] = useState<AnalysisMode>("ai-anonymized");
  const [phase, setPhase] = useState<Phase>("idle");
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);

  const busy = phase === "scanning" || phase === "analyzing";
  const headerPosture = useMemo(() => getHeaderPosture(scan), [scan]);
  const th = locale === "th";

  useEffect(() => {
    const fn = (e: PointerEvent) => lamp.current?.style.setProperty("--point", `${e.clientX}px ${e.clientY}px`);
    addEventListener("pointermove", fn);
    return () => removeEventListener("pointermove", fn);
  }, []);

  useEffect(() => {
    if (!archiveOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setArchiveOpen(false);
    };
    addEventListener("keydown", closeOnEscape);
    return () => removeEventListener("keydown", closeOnEscape);
  }, [archiveOpen]);

  useEffect(() => {
    const previous = history.scrollRestoration;
    history.scrollRestoration = "manual";
    window.scrollTo(0, 0);
    return () => {
      history.scrollRestoration = previous;
    };
  }, []);

  async function analyze(result: ScanResult, nextMode: AnalysisMode = mode) {
    setPhase("analyzing");
    setAiError(null);
    setAnalysis(null);
    try {
      if (!result.capabilityToken) {
        throw new Error("This scan ticket is unavailable. Run a new scan before requesting analysis.");
      }
      setAnalysis(
        await post<AnalysisResult>("/api/analyze", {
          capabilityToken: result.capabilityToken,
          mode: nextMode,
        }),
      );
    } catch (e) {
      setAiError(e instanceof Error ? e.message : "Analysis failed.");
    } finally {
      setPhase("done");
    }
  }

  async function run() {
    setError(null);
    setScan(null);
    setAnalysis(null);
    setAiError(null);
    setPhase("scanning");
    try {
      const result = await post<ScanResult>("/api/scan", { url });
      setScan(result);
      await analyze(result);
      document.getElementById("wards")?.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed.");
      setPhase("idle");
    }
  }

  function changeMode(next: AnalysisMode) {
    setMode(next);
    if (scan && phase === "done") void analyze(scan, next);
  }

  return (
    <main className="hollowmere">
      <header className="nav">
        <nav aria-label={th ? "ขั้นตอนดูผลตรวจ" : "Scan result steps"}>
          <a href="#wards">
            <span className="nav-step">1</span>
            {th ? "ผลตรวจ 3 ด้าน" : "Summary"}
          </a>
          <a href="#grimoire">
            <span className="nav-step">2</span>
            {th ? "วิธีแก้ไข" : "Fix Guide"}
          </a>
          <button type="button" className="nav-report" onClick={() => setArchiveOpen(true)}>
            <span className="nav-step">3</span>
            {th ? "รายงานละเอียด" : "Full Report"}
            {scan && <i className="nav-ready-dot" aria-hidden="true" />}
          </button>
        </nav>
        <a className="mark" href="#top" aria-label="Hollowmere Top">
          <svg viewBox="0 0 26 24">
            <path d="M13 1 25 23H1Z" />
            <circle cx="13" cy="15.2" r="3.4" />
            <circle cx="14.4" cy="14.4" r="3" />
          </svg>
        </a>
        <nav aria-label={th ? "เครื่องมือและภาษา" : "Tools and language"}>
          <a href="#night" className="nav-feed">
            {th ? "ข่าวช่องโหว่ CISA" : "CISA Alerts"}
          </a>
          <span className="nav-lang" aria-label="Language">
            <button type="button" onClick={() => setLocale("th")} aria-pressed={th}>ไทย</button>
            <button type="button" onClick={() => setLocale("en")} aria-pressed={!th}>EN</button>
          </span>
          <a
            className="tickets"
            href="#top"
            onClick={(e) => {
              e.preventDefault();
              window.scrollTo({ top: 0, behavior: "smooth" });
              window.setTimeout(() => {
                document.querySelector<HTMLInputElement>("#scanner input")?.focus({ preventScroll: true });
              }, 350);
            }}
          >
            {th ? "สแกนเว็บ" : "Scan URL"}
          </a>
        </nav>
      </header>

      <div className="lamp" ref={lamp} />
      <span id="top" />

      <Scene id="hero" src={assets.hero} focus={50} kind="hero">
        <div className="moon" />
        <Flow cn="upper" />
        <Flow cn="lower" />
        <div className="mist hero-mist" />
        <Motes />
        <i className="bat bat-one" style={{ backgroundImage: `url('${assets.sprites}')` }} aria-hidden="true" />
        <i className="bat bat-two" style={{ backgroundImage: `url('${assets.sprites}')` }} aria-hidden="true" />
        <i className="bat bat-three" style={{ backgroundImage: `url('${assets.sprites}')` }} aria-hidden="true" />
        <div className="glow hero-glow" />
        <Sprite name="g1" x={21} y={30} w={4.2} />
        <Sprite name="g2" x={78} y={21} w={3.4} />
        <Sprite name="g4" x={64} y={44} w={2.8} />
        <div className="hero-copy">
          <h1>
              {"DEVSEC GUARD".split("").map((v, i) => (
              <span key={i}>{v}</span>
            ))}
          </h1>
          <div id="scanner" className="hero-scanner">
            <ScanForm
              url={url}
              onChange={setUrl}
              mode={mode}
              onModeChange={changeMode}
              onSubmit={run}
              busy={busy}
              locale={locale}
              label={phase === "scanning" ? (th ? "กำลังสแกน..." : "Scanning...") : phase === "analyzing" ? (th ? "กำลังสรุปผล..." : "Auditing...") : th ? "เริ่มสแกนเลย" : "Scan now"}
            />
            {error && (
              <p role="alert" className="hero-error">
                {error}
              </p>
            )}
            <div className="hero-gate" aria-live="polite">
              <div>
                <strong>
                  {phase === "scanning"
                    ? (th ? "⏳ กำลังตรวจความปลอดภัยหน้าเว็บ..." : "⏳ Scanning website headers & surface...")
                    : phase === "analyzing"
                    ? (th ? "⏳ กำลังสรุปวิธีแก้ไขให้เข้าใจง่าย..." : "⏳ Preparing plain-language fix guide...")
                    : phase === "done" && scan
                    ? (th ? `✅ สแกนเสร็จแล้ว · เกรด ${scan.grade} (${scan.score}/100)` : `✅ Scan complete · Grade ${scan.grade} (${scan.score}/100)`)
                    : (th ? "พิมพ์ชื่อเว็บไซต์แล้วกดเริ่มสแกนได้เลย" : "Enter a website URL and click Scan")}
                </strong>
                <span>
                  {th
                    ? "ตรวจจากภายนอกแบบอ่านอย่างเดียว (ปลอดภัย ไม่กระทบเว็บ) · ซ่อนชื่อโดเมนอัตโนมัติเมื่อสรุปผล"
                    : "Safe read-only external check · Automatically anonymizes domain during analysis"}
                </span>
              </div>
            </div>
            {scan && phase === "done" && (
              <div className="hero-quick-steps">
                <a href="#wards">{th ? "1. ดูผลตรวจ 3 ด้าน ↓" : "1. View 3 Checks ↓"}</a>
                <a href="#grimoire">{th ? "2. ดูโค้ดวิธีแก้ไข ↓" : "2. View Fix Code ↓"}</a>
                <button type="button" onClick={() => setArchiveOpen(true)}>
                  {th ? "3. เปิดรายงานละเอียด (Cookies / CSP / พิมพ์ PDF)" : "3. Full Report & Export"}
                </button>
              </div>
            )}
          </div>
        </div>
      </Scene>

      <Seam src={assets.s1} fall="a" />

      <Scene id="wards" src={assets.story} focus={48} kind="story">
        <Flow cn="story-fall" />
        <Motes />
        <div className="mist story-mist" />
        <div className="glow cold" />
        <Sprite name="g4" x={30} y={22} w={2.6} />
        <div className="ward-deck">
          <header>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-[#ffbe76]">
                {th ? "ขั้นตอนที่ 1 · ผลตรวจหลัก 3 ด้าน" : "STEP 1 · 3 CORE SECURITY CHECKS"}
              </span>
              {scan && (
                <a href="#grimoire" className="rounded-md border border-amber-300/40 bg-amber-400/10 px-2.5 py-1 font-mono text-[11px] text-amber-200 transition hover:bg-amber-400/20">
                  {th ? "ไปขั้นตอนที่ 2: ดูวิธีแก้ไข ↓" : "Next: Step 2 Fix Guide ↓"}
                </a>
              )}
            </div>
            <h2>{th ? "สรุปเกราะป้องกันเว็บไซต์" : "Protective Wards"}</h2>
            <p>{scan ? (th ? `ผลตรวจจากภายนอกสำหรับ ${scan.url}` : `External findings for ${scan.url}`) : th ? "ใส่ชื่อเว็บด้านบนแล้วกดเริ่มสแกน ระบบจะสรุปผลตรวจทั้ง 3 ด้านให้ที่นี่" : "Enter a URL above and click Scan to view your three core checks here."}</p>
            {!scan && (
              <div className="mt-2.5 flex flex-wrap items-center gap-2">
                <span className="inline-flex items-center gap-1.5 rounded-full border border-neon-cyan/40 bg-neon-cyan/10 px-2.5 py-0.5 font-mono text-[11px] text-neon-cyan">
                  <Sparkles className="h-3 w-3" />
                  {th ? "ตรวจลึกรวม 10 มิติ" : "10 In-Depth Dimensions"}
                </span>
                <span className="text-xs text-slate-300/80">
                  {th
                    ? "• พร้อมตรวจคุกกี้, ผ่าลึก CSP 7 จุด, ไต่ลิงก์หน้าย่อยอัตโนมัติ และตรวจโค้ด HTML ในรายงานละเอียด"
                    : "• Includes Cookie audit, 7-Point CSP breakdown, Subpage crawler & HTML inspection in full report"}
                </span>
              </div>
            )}
            {!scan && (
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    window.scrollTo({ top: 0, behavior: "smooth" });
                    const input = document.querySelector<HTMLInputElement>("#scanner input");
                    input?.focus({ preventScroll: true });
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-amber-300/40 bg-amber-400/15 px-3 py-1.5 font-mono text-xs font-semibold text-amber-200 shadow transition hover:bg-amber-400/25 hover:text-white"
                >
                  <ArrowUp className="h-3.5 w-3.5" />
                  {th ? "เลื่อนขึ้นไปเริ่มสแกนเว็บ ↑" : "Scroll up to start scanning ↑"}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setUrl("https://example.com");
                    window.scrollTo({ top: 0, behavior: "smooth" });
                    const input = document.querySelector<HTMLInputElement>("#scanner input");
                    input?.focus({ preventScroll: true });
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-xs text-slate-300 transition hover:border-white/20 hover:bg-white/10 hover:text-white"
                >
                  {th ? "ลองตัวอย่าง: example.com" : "Try sample: example.com"}
                </button>
              </div>
            )}
            {scan && headerPosture && (
              <div className="result-metrics" aria-label="Scan score summary">
                <span><b>{th ? "คะแนน Header" : "Header score"}</b> {headerPosture.score}/100 · {headerPosture.strong}/{headerPosture.total} {th ? "รายการผ่านเกณฑ์" : "strong"}</span>
                <span><b>{th ? "เกรดรวม" : "Overall grade"}</b> {scan.grade} · {scan.score}/100</span>
                {scan.crawledPages && (
                  <span><b>{th ? "ไต่ลิงก์ตรวจ" : "Crawled"}</b> {scan.crawledPages.length} {th ? "หน้า" : `page${scan.crawledPages.length === 1 ? "" : "s"}`}</span>
                )}
              </div>
            )}
            {scan?.redirects && (
              <p className="mt-3 font-mono text-[11px] text-slate-300/80" aria-label="Redirect chain result">
                <b className="text-neon-cyan">{th ? "การเชื่อมต่อลิงก์:" : "Connection:"}</b> · {formatRedirectSummary(scan.redirects, th)}
              </p>
            )}
          </header>
          <div className="ward-grid">
            {scan ? (
              <>
                <ScraperDefenseCard data={scan.robots} locale={locale} />
                <SecurityHeadersCard data={scan.headers} locale={locale} />
                <DevLeaksCard data={scan.leaks} locale={locale} />
              </>
            ) : (
              <>
                <article>
                  <b className="flex items-center gap-1.5 text-[#fff4db]">
                    <Bot className="h-4 w-4 text-neon-purple" />
                    {th ? "บอตเงา" : "Phantom Crawlers"}
                  </b>
                  <small className="text-neon-purple/90 font-medium">
                    {th ? "การป้องกัน AI Scraper" : "AI Scraper Defense"}
                  </small>
                  <div className="mt-3 flex flex-wrap gap-1.5 font-mono text-[11px]">
                    <span className="rounded bg-white/10 px-2 py-0.5 text-slate-200">GPTBot</span>
                    <span className="rounded bg-white/10 px-2 py-0.5 text-slate-200">ClaudeBot</span>
                    <span className="rounded bg-white/10 px-2 py-0.5 text-slate-200">CCBot</span>
                    <span className="rounded bg-white/5 px-2 py-0.5 text-slate-400">Google-Extended</span>
                  </div>
                </article>
                <article>
                  <b className="flex items-center gap-1.5 text-[#fff4db]">
                    <ShieldHalf className="h-4 w-4 text-neon-cyan" />
                    {th ? "เกราะป้องกัน" : "Protective Wards"}
                  </b>
                  <small className="text-neon-cyan/90 font-medium">
                    {th ? "Security Headers (6 รายการ + CSP)" : "Security Headers (6 Rules + CSP)"}
                  </small>
                  <div className="mt-3 flex flex-wrap gap-1.5 font-mono text-[11px]">
                    <span className="rounded bg-white/10 px-2 py-0.5 text-slate-200">CSP (7 จุด)</span>
                    <span className="rounded bg-white/10 px-2 py-0.5 text-slate-200">HSTS</span>
                    <span className="rounded bg-white/10 px-2 py-0.5 text-slate-200">X-Frame-Options</span>
                    <span className="rounded bg-white/10 px-2 py-0.5 text-slate-200">nosniff</span>
                    <span className="rounded bg-white/5 px-2 py-0.5 text-slate-400">Referrer</span>
                    <span className="rounded bg-white/5 px-2 py-0.5 text-slate-400">Permissions</span>
                  </div>
                </article>
                <article>
                  <b className="flex items-center gap-1.5 text-[#fff4db]">
                    <FileWarning className="h-4 w-4 text-emerald-400" />
                    {th ? "รอยรั่วซ่อนเร้น" : "Crypt Leaks"}
                  </b>
                  <small className="text-emerald-400/90 font-medium">
                    {th ? "Dev Leaks (ตรวจจับ Signature)" : "Dev Leaks (Signature Check)"}
                  </small>
                  <div className="mt-3 flex flex-wrap gap-1.5 font-mono text-[11px]">
                    <span className="rounded bg-white/10 px-2 py-0.5 text-slate-200">/.env</span>
                    <span className="rounded bg-white/10 px-2 py-0.5 text-slate-200">/.git/HEAD</span>
                    <span className="rounded border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-emerald-300">
                      {th ? "แยกไฟล์จริง vs 404" : "Real file vs soft-200"}
                    </span>
                  </div>
                </article>
              </>
            )}
          </div>
        </div>
      </Scene>

      <Seam src={assets.s2} fall="b" />

      <Scene id="grimoire" src={assets.rites} focus={40} kind="rites">
        <Flow cn="rites-fall" />
        <Motes />
        <div className="mist rites-mist" />
        <div className="glow rites-glow" />
        <div className="grimoire-panel">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-[#ffbe76]">
              {th ? "ขั้นตอนที่ 2 · สรุปวิธีแก้ไขและโค้ดพร้อมใช้" : "STEP 2 · REMEDIATION & READY-TO-COPY CODE"}
            </span>
            <button
              type="button"
              onClick={() => setArchiveOpen(true)}
              className="rounded-md border border-violet-300/35 bg-violet-400/15 px-3 py-1 font-mono text-[11px] text-violet-100 transition hover:bg-violet-400/25"
            >
              {th ? "3. เปิดรายงานละเอียด (Cookies / CSP / พิมพ์ PDF)" : "3. Open Full Report (Cookies / CSP / PDF)"}
            </button>
          </div>
          <h2>{th ? "คู่มือแก้ไข" : "Fix Guide"} <span>· {th ? "สรุปผลและโค้ดพร้อมใช้งาน" : "Remediation & Code"}</span></h2>
          {scan ? <RemediationCard scan={scan} analysis={analysis} loading={phase === "analyzing"} error={aiError} onRetry={() => analyze(scan)} locale={locale} /> : <p>{th ? "เมื่อสแกนเสร็จ ระบบจะแสดงเกรด สรุปภาพรวม และโค้ดตั้งค่าที่คัดลอกไปวางใช้งานได้ทันที" : "Once scanned, your grade, plain-language diagnosis, and copy-ready repair code will appear here."}</p>}
        </div>
      </Scene>

      <Seam src={assets.s3} fall="c" />

      <Scene id="night" src={assets.night} focus={66} kind="night">
        <Flow cn="night-fall" />
        <Flow lava cn="l1" />
        <Flow lava cn="l2" />
        <Flow lava cn="l3" />
        <Motes />
        <div className="glow night-glow" />
        <CisaSceneSlider locale={locale} />
      </Scene>

      <Seam src={assets.s4} />

      <Scene id="finale" src={assets.finale} focus={45} kind="finale">
        <div className="moon finale-moon" />
        <Motes />
        <div className="glow finale-glow" />
        <Sprite name="g2" x={66} y={26} w={3} />
        <Sprite name="g1" x={27} y={38} w={2.6} />
        <Copy title={th ? "รายงานพร้อมแล้ว" : "See you at midnight."} center>
          <p>{th ? "เปิดรายงานฉบับเต็มเพื่อดูรายละเอียดและวิธีแก้ไข" : "Carry your light down to the lake. The bells will tell you when."}</p>
          <div className="actions">
            <button type="button" className="button" onClick={() => setArchiveOpen(true)}>
              {th ? "เปิดรายงานฉบับเต็ม" : "Open full report"}
            </button>
            <a className="button ghost" href="#top">
              {th ? "กลับไปด้านบน" : "Back to surface"}
            </a>
          </div>
        </Copy>
      </Scene>

      {archiveOpen && (
        <div className="report-overlay" role="dialog" aria-modal="true" aria-labelledby="report-title" onMouseDown={() => setArchiveOpen(false)}>
          <section className="report-dialog halloween-shell" onMouseDown={(event) => event.stopPropagation()}>
            <div className="halloween-orbs" aria-hidden><i /><i /><i /></div>
            <div className="relative z-10 mx-auto max-w-6xl px-4 py-10 sm:px-6">
              <header className="mb-8 text-center">
                <button type="button" className="report-close" onClick={() => setArchiveOpen(false)} aria-label={th ? "ปิดรายงานฉบับเต็ม" : "Close full scan report"}>×</button>
                <div className="mb-4 flex flex-wrap items-center justify-center gap-3">
                  <p className="halloween-chip orange"><MoonStar className="h-3.5 w-3.5" />{th ? "คลังข้อมูลผลการตรวจ" : "Archive of Findings"}</p>
                  <Link href="/vulnerabilities" className="halloween-chip purple"><Flame className="h-3.5 w-3.5" />{th ? "ข่าวเตือนภัยช่องโหว่ (CISA KEV)" : "Threat Intelligence (CISA KEV)"}</Link>
                </div>
                <h2 id="report-title" className="text-3xl font-bold tracking-tight text-white drop-shadow-[0_0_24px_rgba(185,112,255,.5)] sm:text-5xl">
                  {th ? "รายงานผลการตรวจฉบับเต็ม" : "Full scan report"}
                </h2>
                <p className="mx-auto mt-3 max-w-2xl text-sm text-violet-100/75">
                  {th
                    ? "ข้อมูลหลักฐานจากการตรวจสอบภายนอกแบบอ่านอย่างเดียว: เส้นทางการเปลี่ยนหน้า, ความปลอดภัยของคุกกี้, การตรวจโครงสร้าง HTML, รายละเอียด CSP, Raw Headers และการส่งออกรายงาน (ไม่ใช่การเจาะระบบ)"
                    : "Passive external posture evidence: redirects, cookies, HTML inspection, CSP breakdown, raw headers and report export. This is not an intrusion test or a security guarantee."}
                </p>
              </header>

              {error && <p role="alert" className="halloween-alert mx-auto mb-6 max-w-2xl rounded-xl px-4 py-3 text-sm text-orange-100">{error}</p>}
              {scan ? (
                <div aria-live="polite">
                  <p className="mb-5 font-mono text-sm text-violet-100/65">
                    {th ? "ผลการตรวจสำหรับ " : "Results for "}
                    <span className="text-emerald-200">{scan.url}</span>
                    {scan.finalUrl && scan.finalUrl !== scan.url && <span className="ml-2 text-xs">→ {scan.finalUrl}</span>}
                  </p>
                  {scan.redirects && (
                    <div className="mb-5 rounded-lg border border-neon-cyan/20 bg-ink-900/70 px-4 py-3 text-sm text-violet-100/80">
                      <span className="font-mono font-semibold text-neon-cyan">
                        {th ? "การเชื่อมต่อลิงก์ (Redirect):" : "Connection & Redirects:"}
                      </span>
                      <span className="ml-2">{formatRedirectSummary(scan.redirects, th)}</span>
                    </div>
                  )}
                  <div className="scanner-results grid gap-5 md:grid-cols-2">
                    <CookieSecurityCard data={scan.cookies} locale={locale} />
                    <HtmlInspectionCard data={scan.htmlFindings} locale={locale} />
                  </div>
                  <div className="scanner-results mt-5 grid gap-5">
                    <ObservatoryTabs scan={scan} onSelectUrl={setUrl} locale={locale} />
                  </div>
                  <ReportActions scan={scan} analysis={analysis} locale={locale} />
                </div>
              ) : (
                <p className="halloween-glass mx-auto max-w-2xl rounded-xl p-5 text-center text-sm text-violet-100/70">
                  {th
                    ? "กรุณาสแกนเว็บไซต์จากช่องด้านบนของหน้าก่อน รายละเอียดเชิงลึกและปุ่มดาวน์โหลดรายงานจะแสดงที่นี่"
                    : "Run a scan from the top of the page. Detailed results and report export will appear here."}
                </p>
              )}
            </div>
          </section>
        </div>
      )}
    </main>
  );
}
