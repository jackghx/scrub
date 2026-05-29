"use client";

interface InputPaneProps {
  value: string;
  onChange: (v: string) => void;
  onScrub: () => void;
  loading: boolean;
  error: string | null;
}

export function InputPane({
  value,
  onChange,
  onScrub,
  loading,
  error,
}: InputPaneProps) {
  return (
    <section className="flex h-full min-h-0 flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]">
      <header className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-2.5">
        <div className="flex items-baseline gap-2">
          <h2 className="text-sm font-semibold tracking-wide text-[var(--color-ink)]">
            Input
          </h2>
          <span className="text-xs text-[var(--color-faint)]">
            paste a log, config, or terminal output
          </span>
        </div>
        <span className="mono text-xs text-[var(--color-muted)]">
          {value.length.toLocaleString()} chars
        </span>
      </header>

      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
        placeholder={"// e.g.\ndefault via 10.10.10.1 dev eth0\nAUTH=Bearer eyJhbGciOi...\npostgres://admin:s3cr3t@db.internal:5432/app"}
        className="mono min-h-0 flex-1 resize-none bg-transparent px-4 py-3 text-[13px] leading-relaxed text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none"
      />

      <footer className="flex items-center gap-3 border-t border-[var(--color-border)] px-4 py-3">
        <button
          onClick={onScrub}
          disabled={loading || value.length === 0}
          className="rounded-md bg-[var(--color-accent)] px-4 py-1.5 text-sm font-semibold text-[#04222a] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? "Scrubbing…" : "Scrub"}
        </button>
        {error ? (
          <p className="text-xs leading-snug text-[var(--color-warn)]">{error}</p>
        ) : (
          <p className="text-xs text-[var(--color-faint)]">
            Detection runs locally · nothing is uploaded
          </p>
        )}
      </footer>
    </section>
  );
}
