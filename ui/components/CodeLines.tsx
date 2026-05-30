"use client";

import { forwardRef } from "react";

interface CodeLinesProps {
  /** One rendered node per output line (line N is `lines[N]`). */
  lines: React.ReactNode[];
  /** 0-based line whose number should be highlighted (transient locate flash). */
  flashLine?: number | null;
}

/** A scrollable, line-numbered text view. Each line is its own row with a gutter
 *  cell, so a detection's "L42" maps to a real, scroll-to-able element and the
 *  highlight lands on the exact line number. */
export const CodeLines = forwardRef<HTMLDivElement, CodeLinesProps>(
  function CodeLines({ lines, flashLine }, ref) {
    return (
      <div
        ref={ref}
        className="mono min-h-0 flex-1 overflow-auto py-2 text-[13px] leading-relaxed"
      >
        {lines.map((content, i) => {
          const flash = i === flashLine;
          return (
            <div
              key={i}
              data-line={i}
              className={`flex ${flash ? "bg-[var(--color-ink)]/10" : ""}`}
            >
              <span
                className={`w-14 shrink-0 select-none px-3 text-right ${
                  flash
                    ? "bg-[var(--color-ink)] font-semibold text-[var(--color-bg)]"
                    : "text-[var(--color-faint)]"
                }`}
              >
                {i + 1}
              </span>
              <span className="flex-1 whitespace-pre-wrap break-words pr-3">
                {content}
              </span>
            </div>
          );
        })}
      </div>
    );
  },
);
