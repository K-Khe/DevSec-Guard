"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Flame,
  Pause,
  Play,
  ShieldAlert,
} from "lucide-react";
import {
  type CisaVulnerability,
  translateActionToThai,
  translateDescriptionToThai,
  translateTitleToThai,
} from "@/components/VulnerabilitiesClient";

interface Props {
  locale: "th" | "en";
}

const AUTO_SLIDE_MS = 4500;

export default function CisaSceneSlider({ locale }: Props) {
  const th = locale === "th";
  const [items, setItems] = useState<CisaVulnerability[]>([]);
  const [index, setIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [autoPlay, setAutoPlay] = useState(true);
  const [hoverPaused, setHoverPaused] = useState(false);

  useEffect(() => {
    let active = true;
    fetch("/api/vulnerabilities")
      .then((r) => r.json())
      .then((data) => {
        if (!active) return;
        if (Array.isArray(data?.items) && data.items.length > 0) {
          setItems(data.items);
        }
      })
      .catch(() => {})
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const isRunning = autoPlay && !hoverPaused && items.length > 1;

  useEffect(() => {
    if (!isRunning) return;
    const timer = window.setInterval(() => {
      setIndex((prev) => (prev + 1) % items.length);
    }, AUTO_SLIDE_MS);
    return () => window.clearInterval(timer);
  }, [isRunning, items.length, index]);

  const total = items.length;
  const current = items[index] ?? null;

  function prev() {
    if (total === 0) return;
    setIndex((i) => (i - 1 + total) % total);
  }

  function next() {
    if (total === 0) return;
    setIndex((i) => (i + 1) % total);
  }

  return (
    <aside
      className="cisa-night-panel"
      aria-label={th ? "ข่าวแจ้งเตือนช่องโหว่ CISA KEV" : "CISA KEV Threat Intelligence"}
      onMouseEnter={() => setHoverPaused(true)}
      onMouseLeave={() => setHoverPaused(false)}
    >
      <header className="cisa-night-head">
        <div>
          <span className="cisa-night-eyebrow">
            <Flame className="h-3.5 w-3.5 text-amber-400" />
            {th ? "ข่าวเตือนภัยช่องโหว่ล่าสุด · เลื่อนอัตโนมัติ" : "LIVE THREAT FEED · AUTO-SLIDING"}
          </span>
          <h2>{th ? "ช่องโหว่ที่กำลังถูกโจมตีจริง" : "Known Exploited Vulnerabilities"}</h2>
        </div>

        <div className="cisa-night-controls">
          <button
            type="button"
            onClick={() => setAutoPlay((v) => !v)}
            aria-pressed={autoPlay}
            title={
              autoPlay
                ? th
                  ? "คลิกเพื่อหยุดเลื่อนอัตโนมัติ"
                  : "Pause auto-slide"
                : th
                ? "คลิกเพื่อเลื่อนอัตโนมัติ"
                : "Resume auto-slide"
            }
            className="cisa-nav-btn"
          >
            {isRunning ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
          </button>
          <button
            type="button"
            onClick={prev}
            disabled={total <= 1}
            aria-label={th ? "ข่าวก่อนหน้า" : "Previous alert"}
            className="cisa-nav-btn"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span className="cisa-counter" aria-live="polite">
            {total > 0 ? `${index + 1} / ${total}` : "—"}
          </span>
          <button
            type="button"
            onClick={next}
            disabled={total <= 1}
            aria-label={th ? "ข่าวถัดไป" : "Next alert"}
            className="cisa-nav-btn"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </header>

      {/* Auto-advance progress bar */}
      {total > 1 && (
        <div className="cisa-progress-track" aria-hidden="true">
          <div
            key={`${index}-${isRunning ? "run" : "pause"}`}
            className={`cisa-progress-bar ${isRunning ? "running" : "paused"}`}
            style={{ animationDuration: `${AUTO_SLIDE_MS}ms` }}
          />
        </div>
      )}

      {loading ? (
        <div className="cisa-night-card cisa-night-skeleton">
          <p>{th ? "กำลังดึงข่าวช่องโหว่ล่าสุดจาก CISA..." : "Loading latest CISA KEV alerts..."}</p>
        </div>
      ) : total > 0 ? (
        <div className="cisa-slider-viewport">
          <div
            className="cisa-slider-track"
            style={{ transform: `translate3d(-${index * 100}%, 0, 0)` }}
          >
            {items.map((item, i) => (
              <article
                className="cisa-night-card cisa-slide-item"
                key={item.cveID}
                aria-hidden={i !== index}
              >
                <div className="cisa-card-badges">
                  <span className="cisa-badge cve">{item.cveID}</span>
                  <span className="cisa-badge active">
                    <ShieldAlert className="h-3 w-3" />
                    {th ? "ถูกโจมตีจริง" : "Active Exploit"}
                  </span>
                  {item.knownRansomwareCampaignUse === "Known" && (
                    <span className="cisa-badge ransomware">
                      {th ? "⚠️ แรนซัมแวร์" : "⚠️ Ransomware"}
                    </span>
                  )}
                  <span className="cisa-date">
                    {th ? `อัปเดต: ${item.dateAdded}` : `Added: ${item.dateAdded}`}
                  </span>
                </div>

                <p className="cisa-vendor">
                  {item.vendorProject} · <strong>{item.product}</strong>
                </p>

                <h3 className="cisa-title">
                  {th ? translateTitleToThai(item.vulnerabilityName) : item.vulnerabilityName}
                </h3>

                <p className="cisa-desc">
                  {th
                    ? translateDescriptionToThai(
                        item.shortDescription,
                        item.vendorProject,
                        item.product,
                      )
                    : item.shortDescription}
                </p>

                <div className="cisa-action-box">
                  <strong>{th ? "วิธีป้องกัน / แก้ไข:" : "Required Action:"}</strong>
                  <span>
                    {th ? translateActionToThai(item.requiredAction) : item.requiredAction}
                  </span>
                </div>
              </article>
            ))}
          </div>

          { current && (
            <footer className="cisa-card-foot">
              <div
                className="cisa-dots"
                role="tablist"
                aria-label={th ? "เลือกข่าวช่องโหว่" : "Select vulnerability item"}
              >
                {items.map((item, i) => (
                  <button
                    key={item.cveID}
                    type="button"
                    role="tab"
                    aria-selected={i === index}
                    aria-label={`${item.cveID} (${i + 1}/${total})`}
                    onClick={() => setIndex(i)}
                    className={`cisa-dot ${i === index ? "active" : ""}`}
                  />
                ))}
              </div>

              <div className="cisa-links">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(current.cveID)}`}
                  target="_blank"
                  rel="noreferrer"
                  className="cisa-ext-link"
                >
                  NVD <ExternalLink className="h-3 w-3" />
                </a>
                <Link href="/vulnerabilities" className="cisa-all-link">
                  {th ? "ดูหน้าเต็มทั้งหมด →" : "View all 10 →"}
                </Link>
              </div>
            </footer>
          )}
        </div>
      ) : (
        <div className="cisa-night-card">
          <p>{th ? "ไม่พบรายการแจ้งเตือนในขณะนี้" : "No alerts available right now."}</p>
        </div>
      )}
    </aside>
  );
}
