"use client";

import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { Chip, RestoredMark } from "./Chip";
import { CodeLines } from "./CodeLines";
import { ScrubMinimap } from "./ScrubMinimap";
import { tokenLines } from "@/lib/recompute";
import type { ScrubMark } from "@/lib/recompute";
import type { Token } from "@/lib/types";

/** Derive a download name: "app.log" -> "app.scrubbed.log"; falls back to a
 *  generic name when nothing was uploaded. */
function downloadName(fileName: string | null): string {
  if (!fileName) return "scrubbed.txt";
  const dot = fileName.lastIndexOf(".");
  if (dot <= 0) return `${fileName}.scrubbed`;
  return `${fileName.slice(0, dot)}.scrubbed${fileName.slice(dot)}`;
}

interface ReviewPaneProps {
  tokens: Token[];
  exportText: string;
  marks: ScrubMark[];
  totalLines: number;
  applied: number;
  dismissed: number;
  total: number;
  hasScrubbed: boolean;
  /** Name of the uploaded file, if any, used to name the download. */
  fileName: string | null;
  /** 0-based output line to scroll to and flash; bump focusNonce to re-trigger. */
  focusLine: number | null;
  focusNonce: number;
  /** Diff is controlled by the page (it swaps the left pane for the Original). */
  diff: boolean;
  onToggleDiff: () => void;
}

export function ReviewPane({
  tokens,
  exportText,
  marks,
  totalLines,
  applied,
  dismissed,
  total,
  hasScrubbed,
  fileName,
  focusLine,
  focusNonce,
  diff,
  onToggleDiff,
}: ReviewPaneProps) {
  const [copied, setCopied] = useState(false);
  const [flashLine, setFlashLine] = useState<number | null>(null);
  const scrubbedRef = useRef<HTMLDivElement>(null);
  const flashTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const lines = useMemo(() => tokenLines(tokens), [tokens]);
  const rendered = useMemo(
    () =>
      lines.map((pieces, li) => (
        <Fragment key={li}>
          {pieces.map((p, i) =>
            p.type === "text" ? (
              <span key={i}>{p.text}</span>
            ) : p.type === "chip" ? (
              <Chip key={i} placeholder={p.placeholder} entity={p.entity} />
            ) : (
              <RestoredMark key={i} text={p.text} entity={p.entity} />
            ),
          )}
        </Fragment>
      )),
    [lines],
  );

  // Scroll the requested line into view and flash its line number.
  function locate(line: number) {
    const el = scrubbedRef.current?.querySelector(`[data-line="${line}"]`);
    el?.scrollIntoView({ block: "center", behavior: "smooth" });
    setFlashLine(line);
    if (flashTimer.current) clearTimeout(flashTimer.current);
    flashTimer.current = setTimeout(() => setFlashLine(null), 1600);
  }

  // Re-runs whenever a detection is clicked (focusNonce bumps), even for the same line.
  useEffect(() => {
    if (focusLine !== null) locate(focusLine);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusNonce]);

  useEffect(() => () => {
    if (flashTimer.current) clearTimeout(flashTimer.current);
  }, []);

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
    a.download = downloadName(fileName);
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="flex h-full min-h-0 flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]">
      <header className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-2.5">
        <div className="flex items-baseline gap-2">
          <h2 className="text-sm font-semibold tracking-wide text-[var(--color-ink)]">
            {diff ? "Scrubbed" : "Review"}
          </h2>
          <span className="text-xs text-[var(--color-faint)]">
            chips are scrubbed, amber is exposed
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onToggleDiff}
            disabled={!hasScrubbed}
            className={`rounded-md border px-3 py-1 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
              diff
                ? "border-[var(--color-accent)] text-[var(--color-ink)]"
                : "border-[var(--color-border-strong)] text-[var(--color-muted)] hover:text-[var(--color-ink)]"
            }`}
            title="Show the original alongside the scrubbed output"
          >
            Diff
          </button>
          <button
            onClick={copy}
            disabled={!hasScrubbed}
            className="rounded-md border border-[var(--color-border-strong)] px-3 py-1 text-xs font-medium text-[var(--color-ink)] transition-colors hover:border-[var(--color-accent)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            {copied ? "Copied" : "Copy"}
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

      {!hasScrubbed ? (
        <p className="mono flex-1 overflow-auto px-4 py-3 text-[13px] text-[var(--color-faint)]">
          Scrubbed output appears here. Paste an artefact and hit Scrub.
        </p>
      ) : exportText.length === 0 ? (
        <p className="mono flex-1 overflow-auto px-4 py-3 text-[13px] text-[var(--color-faint)]">
          (empty)
        </p>
      ) : (
        <div className="flex min-h-0 flex-1">
          <CodeLines ref={scrubbedRef} lines={rendered} flashLine={flashLine} />
          <ScrubMinimap marks={marks} totalLines={totalLines} onJump={locate} />
        </div>
      )}

      {hasScrubbed && (
        <footer className="border-t border-[var(--color-border)] px-4 py-2.5">
          <p className="text-xs text-[var(--color-muted)]">
            <span className="font-medium text-[var(--color-ink)]">
              {applied} of {total}
            </span>{" "}
            detections applied
            {dismissed > 0 && (
              <>
                {", "}
                <span className="font-medium text-[var(--color-warn)]">
                  {dismissed} dismissed
                </span>{" "}
                (original values exposed)
              </>
            )}
            .
          </p>
        </footer>
      )}
    </section>
  );
}
