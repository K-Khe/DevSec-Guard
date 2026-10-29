"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { Flame, MoonStar } from "lucide-react";
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
import type { AnalysisMode, AnalysisResult, ScanResult } from "@/lib/types";

type Phase = "idle" | "scanning" | "analyzing" | "done";

const headerWeights = {
  csp: { strong: 25, weak: 14 }, hsts: { strong: 20, weak: 10 }, xfo: { strong: 15, weak: 8 },
  xcto: { strong: 12, weak: 6 }, rp: { strong: 10, weak: 5 }, pp: { strong: 8, weak: 4 },
} as const;

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
        r = Math.min(devicePixelRatio, 1.5);
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
        r = Math.min(devicePixelRatio, 1.5);
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
  const [mortalMode, setMortalMode] = useState(true);
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [mode, setMode] = useState<AnalysisMode>("ai-anonymized");
  const [phase, setPhase] = useState<Phase>("idle");
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);

  const busy = phase === "scanning" || phase === "analyzing";
  const headerPosture = useMemo(() => getHeaderPosture(scan), [scan]);

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
      setAnalysis(await post<AnalysisResult>("/api/analyze", { ...result, mode: nextMode }));
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
        <nav>
          <a href="#scanner">Scanner</a>
          <a href="#wards">Wards</a>
          <a href="#grimoire">Grimoire</a>
        </nav>
        <a className="mark" href="#top" aria-label="Hollowmere Top">
          <svg viewBox="0 0 26 24">
            <path d="M13 1 25 23H1Z" />
            <circle cx="13" cy="15.2" r="3.4" />
            <circle cx="14.4" cy="14.4" r="3" />
          </svg>
        </a>
        <nav>
          <button type="button" className="nav-report" onClick={() => setArchiveOpen(true)}>Report</button>
          <Link href="/vulnerabilities">CISA Feed</Link>
          <a className="tickets" href="#scanner">
            Scan now
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
              label={phase === "scanning" ? "Scanning..." : phase === "analyzing" ? "Auditing..." : "Scan now"}
            />
            <div className="hero-gate" aria-live="polite">
              <div>
                <strong>{phase === "scanning" ? "Opening the Gate" : phase === "analyzing" ? "Reading the Grimoire" : phase === "done" ? "The Gate Is Open" : "The Scan Gate"}</strong>
                <span>{phase === "scanning" ? "Reading public signals…" : phase === "analyzing" ? "Preparing a plain-language repair…" : phase === "done" ? "Results await below." : "Public, read-only HTTP security check."}</span>
              </div>
              <div className="hero-mode" aria-label="Analysis mode">
                <button type="button" onClick={() => changeMode("ai-anonymized")} aria-pressed={mode === "ai-anonymized"}>AI Auditor</button>
                <button type="button" onClick={() => changeMode("local")} aria-pressed={mode === "local"}>Local Engine</button>
              </div>
            </div>
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
            <span>SCAN RESULTS</span>
            <h2>Protective Wards</h2>
            <p>{scan ? `External findings for ${scan.url}` : "Your three defenses will appear here after the scan."}</p>
            <div className="mb-3 flex flex-wrap items-center gap-2" aria-label="Explanation mode">
              <span className="font-mono text-[11px] uppercase tracking-wider text-slate-400">View as</span>
              <button type="button" onClick={() => setMortalMode(true)} aria-pressed={mortalMode} className={`rounded-md border px-2 py-1 font-mono text-[11px] transition ${mortalMode ? "border-neon-cyan/60 bg-neon-cyan/10 text-neon-cyan" : "border-white/10 text-slate-500 hover:text-slate-300"}`}>Mortals · ภาษาคนทั่วไป</button>
              <button type="button" onClick={() => setMortalMode(false)} aria-pressed={!mortalMode} className={`rounded-md border px-2 py-1 font-mono text-[11px] transition ${!mortalMode ? "border-neon-purple/60 bg-neon-purple/10 text-neon-purple" : "border-white/10 text-slate-500 hover:text-slate-300"}`}>Wizards · Technical</button>
              <span className="text-[11px] text-slate-500">{mortalMode ? "เริ่มจากภาพรวมแบบช่างตรวจบ้าน" : "ดู header และหลักฐานเชิงเทคนิค"}</span>
            </div>
            {scan && headerPosture && <div className="result-metrics" aria-label="Scan score summary"><span><b>Header posture</b> {headerPosture.score}/100 · {headerPosture.strong}/{headerPosture.total} strong</span><span><b>DevSec posture</b> {scan.grade} · {scan.score}/100</span></div>}
          </header>
          <div className="ward-grid">
            {scan ? <><ScraperDefenseCard data={scan.robots} mortal={mortalMode} /><SecurityHeadersCard data={scan.headers} mortal={mortalMode} /><DevLeaksCard data={scan.leaks} mortal={mortalMode} /></> : <><article><b>Phantom Crawlers</b><small>AI Scraper Defense</small><p>GPTBot · ClaudeBot · CCBot</p></article><article><b>Protective Wards</b><small>Security Headers</small><p>Content-Security-Policy · X-Frame-Options · Strict-Transport-Security</p></article><article><b>Crypt Leaks</b><small>Dev Leaks</small><p>/.env · /.git/HEAD</p></article></>}
          </div>
        </div>
      </Scene>

      <Seam src={assets.s2} fall="b" />

      <Scene id="grimoire" src={assets.rites} focus={40} kind="rites">
        <Flow cn="rites-fall" />
        <Motes />
        <div className="mist rites-mist" />
        <div className="glow rites-glow" />
        <div className="grimoire-panel"><h2>Grimoire <span>· AI Remediation</span></h2>{scan ? <RemediationCard scan={scan} analysis={analysis} loading={phase === "analyzing"} error={aiError} onRetry={() => analyze(scan)} /> : <p>At the deepest point of the descent, your grade, plain-language diagnosis, and copy-ready repair code will appear.</p>}</div>
      </Scene>

      <Seam src={assets.s3} fall="c" />

      <Scene id="night" src={assets.night} focus={66} kind="night">
        <Flow cn="night-fall" />
        <Flow lava cn="l1" />
        <Flow lava cn="l2" />
        <Flow lava cn="l3" />
        <Motes />
        <div className="glow night-glow" />
      </Scene>

      <Seam src={assets.s4} />

      <Scene id="finale" src={assets.finale} focus={45} kind="finale">
        <div className="moon finale-moon" />
        <Motes />
        <div className="glow finale-glow" />
        <Sprite name="g2" x={66} y={26} w={3} />
        <Sprite name="g1" x={27} y={38} w={2.6} />
        <Copy title="See you at midnight." center>
          <p>Carry your light down to the lake. The bells will tell you when.</p>
          <div className="actions">
            <button type="button" className="button" onClick={() => setArchiveOpen(true)}>
              Open full report
            </button>
            <a className="button ghost" href="#top">
              Back to surface
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
                <button type="button" className="report-close" onClick={() => setArchiveOpen(false)} aria-label="Close full scan report">×</button>
                <div className="mb-4 flex flex-wrap items-center justify-center gap-3">
                  <p className="halloween-chip orange"><MoonStar className="h-3.5 w-3.5" />Archive of Findings</p>
                  <Link href="/vulnerabilities" className="halloween-chip purple"><Flame className="h-3.5 w-3.5" />Threat Intelligence (CISA KEV)</Link>
                </div>
                <h2 id="report-title" className="text-3xl font-bold tracking-tight text-white drop-shadow-[0_0_24px_rgba(185,112,255,.5)] sm:text-5xl">Full scan report</h2>
                <p className="mx-auto mt-3 max-w-2xl text-sm text-violet-100/75">Cookies, HTML inspection, CSP breakdown, raw headers and report export.</p>
              </header>

              {error && <p role="alert" className="halloween-alert mx-auto mb-6 max-w-2xl rounded-xl px-4 py-3 text-sm text-orange-100">{error}</p>}
              {scan ? (
                <div aria-live="polite">
                  <p className="mb-5 font-mono text-sm text-violet-100/65">Results for <span className="text-emerald-200">{scan.url}</span>{scan.finalUrl && scan.finalUrl !== scan.url && <span className="ml-2 text-xs">→ {scan.finalUrl}</span>}</p>
                  <div className="scanner-results grid gap-5 md:grid-cols-2"><CookieSecurityCard data={scan.cookies} /><HtmlInspectionCard data={scan.htmlFindings} /></div>
                  <div className="scanner-results mt-5 grid gap-5"><ObservatoryTabs scan={scan} onSelectUrl={setUrl} /></div>
                  <ReportActions scan={scan} analysis={analysis} />
                </div>
              ) : <p className="halloween-glass mx-auto max-w-2xl rounded-xl p-5 text-center text-sm text-violet-100/70">Run a scan from the top of the page. Detailed results and report export will appear here.</p>}
            </div>
          </section>
        </div>
      )}
    </main>
  );
}
