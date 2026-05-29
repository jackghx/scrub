"use client";

import { useState } from "react";
import { Chip, RestoredMark } from "./Chip";
import type { Token } from "@/lib/types";

interface ReviewPaneProps {
  tokens: Token[];
  exportText: string;
  applied: number;
  dismissed: number;
  total: number;
  hasScrubbed: boolean;
}

export function ReviewPane({
  tokens,
  exportText,
  applied,
  dismissed,
  total,
  hasScrubbed,
}: ReviewPaneProps) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(exportText);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard can be blocked in some contexts; the download path still works.
      setCopied(false);
    }
  }

  function download() {
    const blob = new Blob([exportText], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "scrubbed.txt";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="flex h-full min-h-0 flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]">
      <header className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-2.5">
        <div className="flex items-baseline gap-2">
          <h2 className="text-sm font-semibold tracking-wide text-[var(--color-ink)]">
            Review
          </h2>
          <span className="text-xs text-[var(--color-faint)]">
            chips are scrubbed · amber is exposed
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={copy}
            disabled={!hasScrubbed}
            className="rounded-md border border-[var(--color-border-strong)] px-3 py-1 text-xs font-medium text-[var(--color-ink)] transition-colors hover:border-[var(--color-accent)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            {copied ? "Copied ✓" : "Copy"}
          </button>
          <button
            onClick={download}
            disabled={!hasScrubbed}
            className="rounded-md border border-[var(--color-border-strong)] px-3 py-1 text-xs font-medium text-[var(--color-muted)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-ink)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            .txt
          </button>
        </div>
      </header>

      <div className="mono min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-words px-4 py-3 text-[13px] leading-relaxed">
        {!hasScrubbed ? (
          <p className="mono text-[var(--color-faint)]">
            Scrubbed output appears here. Paste an artefact and hit Scrub.
          </p>
        ) : tokens.length === 0 ? (
          <p className="mono text-[var(--color-faint)]">(empty)</p>
        ) : (
          tokens.map((t, i) => {
            if (t.type === "text") return <span key={i}>{t.text}</span>;
            if (t.type === "chip")
              return <Chip key={i} placeholder={t.placeholder} entity={t.entity} />;
            return <RestoredMark key={i} text={t.text} entity={t.entity} />;
          })
        )}
      </div>

      {hasScrubbed && (
        <footer className="border-t border-[var(--color-border)] px-4 py-2.5">
          <p className="text-xs text-[var(--color-muted)]">
            <span className="font-medium text-[var(--color-ink)]">
              {applied} of {total}
            </span>{" "}
            detections applied
            {dismissed > 0 && (
              <>
                {" · "}
                <span className="font-medium text-[var(--color-warn)]">
                  {dismissed} dismissed
                </span>{" "}
                (original values exposed)
              </>
            )}{" "}
           , review before sharing. Scrub surfaces and applies; you decide what is safe.
          </p>
        </footer>
      )}
    </section>
  );
}
