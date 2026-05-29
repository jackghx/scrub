"use client";

import { useState } from "react";
import { restore, ApiError } from "@/lib/api";

interface RestorePanelProps {
  /** The last scrub's mapping, held in memory only. Empty until a scrub has run. */
  mapping: Record<string, string>;
  /** The current export string, offered as the default thing to restore. */
  exportText: string;
}

export function RestorePanel({ mapping, exportText }: RestorePanelProps) {
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const hasMapping = Object.keys(mapping).length > 0;

  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const res = await restore(exportText, mapping);
      setResult(res.original);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Restore failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between px-4 py-2.5 text-left"
      >
        <span className="text-sm font-semibold tracking-wide text-[var(--color-ink)]">
          Restore (round-trip check)
        </span>
        <span className="text-xs text-[var(--color-faint)]">{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div className="space-y-3 border-t border-[var(--color-border)] px-4 py-3">
          <p className="text-xs leading-relaxed text-[var(--color-muted)]">
            Reconstructs the original from the scrubbed text + the last scrub&apos;s
            mapping, via the local <code className="mono">/restore</code> endpoint.{" "}
            <span className="text-[var(--color-warn)]">
              The mapping is kept in memory only, never written to disk, localStorage,
              or anywhere else.
            </span>{" "}
            It holds the real secrets; it dies when you reload.
          </p>

          <button
            onClick={run}
            disabled={!hasMapping || busy}
            className="rounded-md border border-[var(--color-border-strong)] px-3 py-1.5 text-xs font-medium text-[var(--color-ink)] transition-colors hover:border-[var(--color-accent)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy ? "Restoring…" : "Restore from current output"}
          </button>

          {!hasMapping && (
            <p className="text-xs text-[var(--color-faint)]">
              Run a scrub first to populate the mapping.
            </p>
          )}
          {error && <p className="text-xs text-[var(--color-warn)]">{error}</p>}
          {result !== null && (
            <pre className="mono max-h-48 overflow-auto whitespace-pre-wrap break-words rounded border border-[var(--color-border)] bg-[var(--color-bg)] p-3 text-[12px] text-[var(--color-ink)]">
              {result}
            </pre>
          )}
        </div>
      )}
    </section>
  );
}
