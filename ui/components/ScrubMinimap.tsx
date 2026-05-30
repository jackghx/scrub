"use client";

import { entityColor } from "@/lib/entities";
import type { ScrubMark } from "@/lib/recompute";

interface ScrubMinimapProps {
  marks: ScrubMark[];
  totalLines: number;
  /** Called with the 0-based line when a tick is clicked, so the pane can jump there. */
  onJump?: (line: number) => void;
}

/** An overview-ruler gutter beside the scrubbed text: one coloured tick per scrubbed
 *  placeholder, positioned by its line so you can see at a glance where in a long
 *  artefact data was scrubbed (and click to jump). */
export function ScrubMinimap({ marks, totalLines, onJump }: ScrubMinimapProps) {
  if (marks.length === 0) return null;
  return (
    <div
      className="relative w-2.5 shrink-0 border-l border-[var(--color-border)] bg-[var(--color-bg)]"
      title={`${marks.length} scrubbed ${marks.length === 1 ? "item" : "items"}`}
    >
      {marks.map((m, i) => {
        const top = ((m.line + 0.5) / totalLines) * 100;
        return (
          <button
            key={`${m.placeholder}-${i}`}
            onClick={() => onJump?.(m.line)}
            className="absolute left-0 right-0 h-[3px] -translate-y-1/2 cursor-pointer opacity-80 transition-opacity hover:opacity-100"
            style={{ top: `${top}%`, backgroundColor: entityColor(m.entity) }}
            title={m.placeholder}
            aria-label={`Go to ${m.placeholder}`}
          />
        );
      })}
    </div>
  );
}
