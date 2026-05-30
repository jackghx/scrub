"use client";

import { useMemo, useState } from "react";
import { entityMeta } from "@/lib/entities";
import { maskValue } from "@/lib/recompute";
import type { Group } from "@/lib/types";

interface DetectionListProps {
  groups: Group[];
  kept: Record<string, boolean>;
  threshold: number;
  revealAll: boolean;
  revealRow: Set<string>;
  /** 0-based output line per placeholder, for the "L42" badge and locate. */
  lineByPlaceholder: Record<string, number>;
  onToggle: (placeholder: string) => void;
  onThreshold: (t: number) => void;
  onKeepAll: () => void;
  onDismissAll: () => void;
  onRevealAll: (v: boolean) => void;
  onRevealRow: (placeholder: string) => void;
  /** Scroll the review pane to (and flash) this 0-based output line. */
  onLocate: (line: number) => void;
}

export function DetectionList(props: DetectionListProps) {
  const {
    groups,
    kept,
    threshold,
    revealAll,
    revealRow,
    lineByPlaceholder,
    onToggle,
    onThreshold,
    onKeepAll,
    onDismissAll,
    onRevealAll,
    onRevealRow,
    onLocate,
  } = props;

  // Display-only filtering: it narrows the visible rows but never changes kept-state
  // or the export. "Keep/Dismiss all" still act on every group, see the buttons.
  const [query, setQuery] = useState("");
  const [entityFilter, setEntityFilter] = useState<string>("");

  const entityTypes = useMemo(
    () => [...new Set(groups.map((g) => g.entity_type))].sort(),
    [groups],
  );

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return groups.filter((g) => {
      if (entityFilter && g.entity_type !== entityFilter) return false;
      if (!q) return true;
      return (
        g.entity_type.toLowerCase().includes(q) ||
        g.placeholder.toLowerCase().includes(q) ||
        g.original.toLowerCase().includes(q)
      );
    });
  }, [groups, query, entityFilter]);

  const filtering = query.trim() !== "" || entityFilter !== "";

  return (
    <section className="flex h-full min-h-0 flex-col rounded-md border border-[var(--color-border)] bg-[var(--color-panel)]">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--color-border)] px-4 py-2">
        <div className="flex items-baseline gap-2">
          <h2 className="text-sm font-semibold tracking-wide text-[var(--color-ink)]">
            Detections
          </h2>
          <span className="mono text-xs text-[var(--color-faint)]">
            {filtering ? `${visible.length} of ${groups.length}` : `${groups.length} unique`}
          </span>
        </div>

        <label className="flex cursor-pointer items-center gap-2 text-xs text-[var(--color-muted)]">
          <input
            type="checkbox"
            checked={revealAll}
            onChange={(e) => onRevealAll(e.target.checked)}
            className="accent-[var(--color-warn)]"
          />
          Reveal originals
        </label>
      </header>

      {/* Threshold + bulk controls */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-[var(--color-border)] px-4 py-2">
        <div className="flex items-center gap-2">
          <span className="text-xs text-[var(--color-muted)]">Min confidence</span>
          <input
            type="range"
            min={0}
            max={1}
            step={0.05}
            value={threshold}
            onChange={(e) => onThreshold(Number(e.target.value))}
            className="w-32"
            aria-label="Confidence threshold"
          />
          <span className="mono w-8 text-xs text-[var(--color-ink)]">
            {threshold.toFixed(2)}
          </span>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={onKeepAll}
            className="rounded border border-[var(--color-border-strong)] px-2.5 py-1 text-xs text-[var(--color-muted)] transition-colors hover:text-[var(--color-ink)]"
          >
            Keep all
          </button>
          <button
            onClick={onDismissAll}
            className="rounded border border-[var(--color-border-strong)] px-2.5 py-1 text-xs text-[var(--color-muted)] transition-colors hover:text-[var(--color-ink)]"
          >
            Dismiss all
          </button>
        </div>
      </div>

      {/* Filter + search */}
      {groups.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-border)] px-4 py-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search value, type or placeholder"
            className="mono min-w-0 flex-1 rounded border border-[var(--color-border-strong)] bg-transparent px-2 py-1 text-xs text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus-visible:border-[var(--color-ink)] focus-visible:outline-none"
          />
          <select
            value={entityFilter}
            onChange={(e) => setEntityFilter(e.target.value)}
            className="rounded border border-[var(--color-border-strong)] bg-[var(--color-panel)] px-2 py-1 text-xs text-[var(--color-ink)] focus-visible:border-[var(--color-ink)] focus-visible:outline-none"
            aria-label="Filter by entity type"
          >
            <option value="">All types</option>
            {entityTypes.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          {filtering && (
            <button
              onClick={() => {
                setQuery("");
                setEntityFilter("");
              }}
              className="rounded border border-[var(--color-border-strong)] px-2 py-1 text-xs text-[var(--color-muted)] transition-colors hover:text-[var(--color-ink)]"
            >
              Clear
            </button>
          )}
        </div>
      )}

      {/* Rows */}
      <div className="min-h-0 flex-1 overflow-auto">
        {groups.length === 0 ? (
          <p className="px-4 py-6 text-sm text-[var(--color-faint)]">
            No detections yet.
          </p>
        ) : visible.length === 0 ? (
          <p className="px-4 py-6 text-sm text-[var(--color-faint)]">
            No detections match the filter.
          </p>
        ) : (
          <ul className="divide-y divide-[var(--color-border)]">
            {visible.map((g) => {
              const meta = entityMeta(g.entity_type);
              const isKept = kept[g.placeholder];
              const revealed = revealAll || revealRow.has(g.placeholder);
              const line = lineByPlaceholder[g.placeholder];
              return (
                <li
                  key={g.placeholder}
                  onClick={() => line !== undefined && onLocate(line)}
                  className="flex cursor-pointer items-center gap-3 px-4 py-2 text-xs transition-colors hover:bg-[var(--color-bg)]"
                  style={{ opacity: isKept ? 1 : 0.55 }}
                  title="Jump to this line in the review"
                >
                  {/* toggle */}
                  <input
                    type="checkbox"
                    checked={isKept}
                    onChange={() => onToggle(g.placeholder)}
                    onClick={(e) => e.stopPropagation()}
                    className="h-4 w-4 shrink-0"
                    style={{ accentColor: meta.color }}
                    aria-label={`${isKept ? "Dismiss" : "Keep"} ${g.placeholder}`}
                  />

                  {/* line number */}
                  {line !== undefined && (
                    <span
                      className="mono w-10 shrink-0 text-right text-[var(--color-faint)]"
                      title={`Output line ${line + 1}`}
                    >
                      L{line + 1}
                    </span>
                  )}

                  {/* entity + placeholder */}
                  <div className="flex w-44 shrink-0 flex-col gap-0.5">
                    <span
                      className="font-semibold uppercase tracking-wide"
                      style={{ color: meta.color }}
                    >
                      {g.entity_type}
                    </span>
                    <span className="mono text-[var(--color-faint)]">
                      {g.placeholder}
                      {g.count > 1 && (
                        <span className="ml-1 text-[var(--color-muted)]">
                          x{g.count}
                        </span>
                      )}
                    </span>
                  </div>

                  {/* original (masked) + reveal */}
                  <div className="flex min-w-0 flex-1 items-center gap-2">
                    <code className="mono truncate text-[var(--color-ink)]">
                      {revealed ? g.original.replace(/\s+/g, " ").trim() : maskValue(g.original)}
                    </code>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onRevealRow(g.placeholder);
                      }}
                      className="shrink-0 px-1 text-[var(--color-faint)] uppercase tracking-wide transition-colors hover:text-[var(--color-muted)]"
                      title={revealed ? "Hide value" : "Reveal value"}
                      aria-label={revealed ? "Hide value" : "Reveal value"}
                    >
                      {revealed ? "Hide" : "Show"}
                    </button>
                  </div>

                  {/* score */}
                  <span
                    className="mono w-10 shrink-0 text-right"
                    style={{
                      color:
                        g.score >= 0.6
                          ? "var(--color-muted)"
                          : "var(--color-faint)",
                    }}
                    title="confidence score"
                  >
                    {g.score.toFixed(2)}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </section>
  );
}
