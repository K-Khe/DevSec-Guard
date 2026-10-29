import { EyeOff, Loader2, Lock, Radar, ShieldAlert } from "lucide-react";
import type { AnalysisMode } from "@/lib/types";

interface Props {
  url: string;
  onChange: (v: string) => void;
  mode: AnalysisMode;
  onModeChange: (m: AnalysisMode) => void;
  onSubmit: () => void;
  busy: boolean;
  label: string;
  /** "full" = URL + submit + options. "options" = only the mode selector and authorization checkbox. */
  variant?: "full" | "options";
}

export default function ScanForm({
  url,
  onChange,
  mode,
  onModeChange,
  onSubmit,
  busy,
  label,
  variant = "full",
}: Props) {
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!busy && url.trim()) onSubmit();
      }}
      className="mx-auto w-full max-w-2xl space-y-3"
    >
      {variant === "full" && (
      <div className="flex flex-col gap-3 sm:flex-row">
        <label className="flex flex-1 items-center gap-3 rounded-lg border border-neon-purple/40 bg-ink-900 px-4 focus-within:border-neon-cyan focus-within:ring-2 focus-within:ring-neon-cyan/30">
          <span className="shrink-0 whitespace-nowrap font-mono text-sm text-neon-green" aria-hidden>
            $ scan
          </span>
          <input
            type="text"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            value={url}
            onChange={(e) => onChange(e.target.value)}
            placeholder="example.com"
            aria-label="Target URL"
            disabled={busy}
            className="w-full bg-transparent py-3.5 font-mono text-sm text-white placeholder:text-slate-600 focus:outline-none disabled:opacity-60"
          />
        </label>
        <button
          type="submit"
          disabled={busy || !url.trim()}
          className="inline-flex min-w-36 items-center justify-center gap-2 rounded-lg bg-neon-purple px-5 py-3.5 text-sm font-semibold text-ink-950 transition hover:bg-neon-cyan focus:outline-none focus-visible:ring-2 focus-visible:ring-neon-cyan disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
          {label}
        </button>
      </div>
      )}

      <div className="grid gap-2.5 sm:grid-cols-2" role="radiogroup" aria-label="Remediation privacy mode">
        <button
          type="button"
          onClick={() => onModeChange("ai-anonymized")}
          disabled={busy}
          aria-pressed={mode === "ai-anonymized"}
          className={`flex items-start gap-2.5 rounded-lg border px-3.5 py-2.5 text-left text-xs transition ${
            mode === "ai-anonymized"
              ? "border-neon-purple/70 bg-neon-purple/10 text-slate-200"
              : "border-white/10 bg-ink-900/60 text-slate-400 hover:border-white/20"
          }`}
        >
          <EyeOff className="mt-0.5 h-4 w-4 shrink-0 text-neon-purple" />
          <span>
            <strong className="block font-mono text-slate-200">AI Auditor (Target Anonymized)</strong>
            <span className="text-[11px] text-slate-400">
              ปกปิดชื่อโดเมน (`redacted-target.invalid`) ก่อนส่งวิเคราะห์ด้วย AI เพื่อป้องกันข้อมูลช่องโหว่ผูกกับเว็บจริง
            </span>
          </span>
        </button>

        <button
          type="button"
          onClick={() => onModeChange("local")}
          disabled={busy}
          aria-pressed={mode === "local"}
          className={`flex items-start gap-2.5 rounded-lg border px-3.5 py-2.5 text-left text-xs transition ${
            mode === "local"
              ? "border-neon-green/70 bg-neon-green/10 text-slate-200"
              : "border-white/10 bg-ink-900/60 text-slate-400 hover:border-white/20"
          }`}
        >
          <Lock className="mt-0.5 h-4 w-4 shrink-0 text-neon-green" />
          <span>
            <strong className="block font-mono text-slate-200">100% Local Engine (Zero External AI)</strong>
            <span className="text-[11px] text-slate-400">
              สร้างสรุปผลและโค้ดแก้ไขภายในเซิร์ฟเวอร์ 100% ไม่ส่งข้อมูลใดๆ ออกไปยัง AI ภายนอก
            </span>
          </span>
        </button>
      </div>

      <p className="flex items-center gap-1.5 px-1 text-[11px] leading-relaxed text-slate-500">
        <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-neon-cyan" />
        Public, read-only HTTP checks only. Private networks and restricted domains are blocked.
      </p>
    </form>
  );
}
