import { Loader2, Radar } from "lucide-react";

interface Props {
  url: string;
  onChange: (v: string) => void;
  onSubmit: () => void;
  busy: boolean;
  label: string;
}

export default function ScanForm({ url, onChange, onSubmit, busy, label }: Props) {
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!busy) onSubmit();
      }}
      className="mx-auto flex w-full max-w-2xl flex-col gap-3 sm:flex-row"
    >
      <label className="flex flex-1 items-center gap-3 rounded-lg border border-neon-purple/40 bg-ink-900 px-4 focus-within:border-neon-cyan focus-within:ring-2 focus-within:ring-neon-cyan/30">
        <span className="font-mono text-sm text-neon-green" aria-hidden>
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
    </form>
  );
}
