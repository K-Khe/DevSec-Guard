import type { ReactNode } from "react";

export type Accent = "purple" | "cyan" | "green";
export type Tone = "ok" | "bad" | "warn" | "muted";

const ACCENTS: Record<Accent, { border: string; icon: string }> = {
  purple: { border: "border-neon-purple/30 shadow-[0_0_30px_-12px] shadow-neon-purple/40", icon: "text-neon-purple" },
  cyan: { border: "border-neon-cyan/30 shadow-[0_0_30px_-12px] shadow-neon-cyan/40", icon: "text-neon-cyan" },
  green: { border: "border-neon-green/30 shadow-[0_0_30px_-12px] shadow-neon-green/40", icon: "text-neon-green" },
};

const TONES: Record<Tone, string> = {
  ok: "bg-neon-green/10 text-neon-green ring-neon-green/30",
  bad: "bg-red-500/10 text-red-400 ring-red-500/30",
  warn: "bg-amber-400/10 text-amber-300 ring-amber-400/30",
  muted: "bg-slate-500/10 text-slate-400 ring-slate-500/30",
};

export function Card({
  title,
  icon,
  accent,
  className = "",
  children,
}: {
  title?: string;
  icon?: ReactNode;
  accent: Accent;
  className?: string;
  children: ReactNode;
}) {
  const a = ACCENTS[accent];
  return (
    <section className={`rounded-xl border bg-ink-900/80 p-5 ${a.border} ${className}`}>
      {title && (
        <h2 className="mb-4 flex items-center gap-2 text-base font-semibold text-white">
          {icon && <span className={a.icon}>{icon}</span>}
          {title}
        </h2>
      )}
      {children}
    </section>
  );
}

export function Pill({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded-md px-2 py-0.5 font-mono text-xs ring-1 ring-inset ${TONES[tone]}`}
    >
      {children}
    </span>
  );
}
