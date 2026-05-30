// recompute.ts, the client-side heart of the review step.
//
// The /scrub response gives us the original text (we kept it), every detection's
// span/placeholder/original, and the recall-favoured scores. Everything the review
// pane and the export need is derived from those, PURELY, with no further server
// calls, so toggling a detection updates the output instantly.
//
// These functions are deliberately free of React so they can be reasoned about and
// unit-tested in isolation.

import type { Detection, Group, OriginalToken, Token } from "./types";

/** Detections at or above this score are kept (checked) by default. Below it they
 *  surface unchecked, the ambiguous long-tail (HOSTNAME, AWS_ACCOUNT_ID, AWS secret
 *  key) that our pack scores low on purpose, so recall-favoured detection stays
 *  usable instead of training the user to "accept all". */
export const DEFAULT_THRESHOLD = 0.6;

/** Group per-occurrence detections by placeholder → one reviewable row per unique
 *  value. Occurrences of the same value share a placeholder, so they share a toggle.
 *  Sorted by score desc, then document order, for a signal-first list. */
export function groupDetections(detections: Detection[]): Group[] {
  const byPlaceholder = new Map<string, Group>();
  for (const d of detections) {
    const existing = byPlaceholder.get(d.placeholder);
    if (existing) {
      existing.spans.push({ start: d.start, end: d.end });
      existing.count += 1;
      existing.firstStart = Math.min(existing.firstStart, d.start);
    } else {
      byPlaceholder.set(d.placeholder, {
        placeholder: d.placeholder,
        entity_type: d.entity_type,
        original: d.original,
        score: d.score,
        spans: [{ start: d.start, end: d.end }],
        count: 1,
        firstStart: d.start,
      });
    }
  }
  return [...byPlaceholder.values()].sort(
    (a, b) => b.score - a.score || a.firstStart - b.firstStart,
  );
}

/** The default kept-state for a single group at a given threshold. */
export function defaultKept(score: number, threshold: number): boolean {
  return score >= threshold;
}

/** Build the full default kept-map for a set of groups at a threshold. */
export function defaultKeptMap(
  groups: Group[],
  threshold: number,
): Record<string, boolean> {
  const map: Record<string, boolean> = {};
  for (const g of groups) map[g.placeholder] = defaultKept(g.score, threshold);
  return map;
}

/** Apply a new threshold, recomputing kept-state ONLY for groups the user hasn't
 *  manually touched. Manual overrides win, the slider never clobbers a deliberate
 *  choice. */
export function applyThreshold(
  groups: Group[],
  threshold: number,
  prev: Record<string, boolean>,
  touched: Set<string>,
): Record<string, boolean> {
  const next: Record<string, boolean> = { ...prev };
  for (const g of groups) {
    if (!touched.has(g.placeholder)) {
      next[g.placeholder] = defaultKept(g.score, threshold);
    }
  }
  return next;
}

/** Flatten all occurrence spans across groups, sorted by start. Spans are
 *  non-overlapping (overlap was resolved server-side), so this is a clean partition
 *  of the original text. */
function flatSpans(
  groups: Group[],
): { start: number; end: number; placeholder: string; entity: string }[] {
  const spans = groups.flatMap((g) =>
    g.spans.map((s) => ({
      start: s.start,
      end: s.end,
      placeholder: g.placeholder,
      entity: g.entity_type,
    })),
  );
  return spans.sort((a, b) => a.start - b.start);
}

/** Tokenise the original text for rendering: plain text between detections, a chip
 *  where a detection is KEPT, and the restored original (to be warning-highlighted)
 *  where it is DISMISSED. */
export function buildTokens(
  original: string,
  groups: Group[],
  kept: Record<string, boolean>,
): Token[] {
  const tokens: Token[] = [];
  let cursor = 0;
  for (const span of flatSpans(groups)) {
    if (span.start > cursor) {
      tokens.push({ type: "text", text: original.slice(cursor, span.start) });
    }
    if (kept[span.placeholder]) {
      tokens.push({ type: "chip", placeholder: span.placeholder, entity: span.entity });
    } else {
      tokens.push({
        type: "restored",
        text: original.slice(span.start, span.end),
        entity: span.entity,
      });
    }
    cursor = span.end;
  }
  if (cursor < original.length) {
    tokens.push({ type: "text", text: original.slice(cursor) });
  }
  return tokens;
}

/** A piece of a single rendered line in the scrubbed output. */
export type ScrubbedPiece =
  | { type: "text"; text: string }
  | { type: "chip"; placeholder: string; entity: string }
  | { type: "restored"; text: string; entity: string };

/** Split scrubbed tokens into lines (arrays of pieces) so the review can render a
 *  line-number gutter. Newlines only ever live in text/restored tokens; a chip
 *  (placeholder) never contains one. The line index here matches the numbering used
 *  by outputLines() and scrubMarks(). */
export function tokenLines(tokens: Token[]): ScrubbedPiece[][] {
  const lines: ScrubbedPiece[][] = [[]];
  const addText = (text: string, make: (s: string) => ScrubbedPiece) => {
    const parts = text.split("\n");
    parts.forEach((part, i) => {
      if (i > 0) lines.push([]);
      if (part.length > 0) lines[lines.length - 1].push(make(part));
    });
  };
  for (const t of tokens) {
    if (t.type === "text") addText(t.text, (s) => ({ type: "text", text: s }));
    else if (t.type === "chip")
      lines[lines.length - 1].push({
        type: "chip",
        placeholder: t.placeholder,
        entity: t.entity,
      });
    else addText(t.text, (s) => ({ type: "restored", text: s, entity: t.entity }));
  }
  return lines;
}

/** A piece of a single rendered line in the original ("before") panel. */
export type OriginalPiece =
  | { type: "text"; text: string }
  | { type: "highlight"; text: string; entity: string; kept: boolean };

/** Split original-text tokens into lines for the diff "before" panel's gutter. A
 *  highlighted span (e.g. a multi-line PEM block) can itself wrap several lines. */
export function originalTokenLines(tokens: OriginalToken[]): OriginalPiece[][] {
  const lines: OriginalPiece[][] = [[]];
  const addText = (text: string, make: (s: string) => OriginalPiece) => {
    const parts = text.split("\n");
    parts.forEach((part, i) => {
      if (i > 0) lines.push([]);
      if (part.length > 0) lines[lines.length - 1].push(make(part));
    });
  };
  for (const t of tokens) {
    if (t.type === "text") addText(t.text, (s) => ({ type: "text", text: s }));
    else
      addText(t.text, (s) => ({
        type: "highlight",
        text: s,
        entity: t.entity,
        kept: t.kept,
      }));
  }
  return lines;
}

/** Tokenise the ORIGINAL text for the diff "before" panel: plain text with every
 *  detected span highlighted, tagged with whether it will be scrubbed (kept) or left
 *  exposed (dismissed) so the panel can colour them differently. */
export function buildOriginalTokens(
  original: string,
  groups: Group[],
  kept: Record<string, boolean>,
): OriginalToken[] {
  const tokens: OriginalToken[] = [];
  let cursor = 0;
  for (const span of flatSpans(groups)) {
    if (span.start > cursor) {
      tokens.push({ type: "text", text: original.slice(cursor, span.start) });
    }
    tokens.push({
      type: "highlight",
      text: original.slice(span.start, span.end),
      entity: span.entity,
      placeholder: span.placeholder,
      kept: !!kept[span.placeholder],
    });
    cursor = span.end;
  }
  if (cursor < original.length) {
    tokens.push({ type: "text", text: original.slice(cursor) });
  }
  return tokens;
}

/** A scrubbed-position marker for the review minimap. ``line`` is the 0-based line in
 *  the EXPORT output where this placeholder lands, so a vertical gutter can show, at a
 *  glance, where in a long artefact data was scrubbed. */
export interface ScrubMark {
  placeholder: string;
  entity: string;
  line: number;
}

/** Locate every KEPT placeholder by its line in the export output. Dismissed spans
 *  aren't marked (nothing was scrubbed there). Numbering follows the OUTPUT: a
 *  multi-line secret collapsed to a one-line placeholder shifts later lines up,
 *  exactly as the rendered scrubbed text does. */
export function scrubMarks(
  original: string,
  groups: Group[],
  kept: Record<string, boolean>,
): { marks: ScrubMark[]; totalLines: number } {
  const marks: ScrubMark[] = [];
  let cursor = 0;
  let line = 0;
  const countNewlines = (s: string) => {
    for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) === 10) line += 1;
  };
  for (const span of flatSpans(groups)) {
    countNewlines(original.slice(cursor, span.start));
    if (kept[span.placeholder]) {
      marks.push({ placeholder: span.placeholder, entity: span.entity, line });
      // Placeholders are single-line, so they add no newlines to the output.
    } else {
      countNewlines(original.slice(span.start, span.end));
    }
    cursor = span.end;
  }
  countNewlines(original.slice(cursor));
  return { marks, totalLines: line + 1 };
}

/** The 0-based line in the EXPORT output where each group's first occurrence lands,
 *  keyed by placeholder. Matches the line numbering you'd see scrolling the scrubbed
 *  pane, so the detections list and "locate" jump to the same place. Covers both kept
 *  (placeholder) and dismissed (exposed original) groups. */
export function outputLines(
  original: string,
  groups: Group[],
  kept: Record<string, boolean>,
): Record<string, number> {
  const result: Record<string, number> = {};
  let cursor = 0;
  let line = 0;
  const countNewlines = (s: string) => {
    for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) === 10) line += 1;
  };
  for (const span of flatSpans(groups)) {
    countNewlines(original.slice(cursor, span.start));
    if (!(span.placeholder in result)) result[span.placeholder] = line;
    if (!kept[span.placeholder]) {
      // Dismissed: the multi-line original stays in the output, shifting later lines.
      countNewlines(original.slice(span.start, span.end));
    }
    cursor = span.end;
  }
  return result;
}

/** The exact plain-text export for the current toggle state: kept → placeholder,
 *  dismissed → original. This is what Copy and Download emit, byte-for-byte. */
export function buildExport(
  original: string,
  groups: Group[],
  kept: Record<string, boolean>,
): string {
  let out = "";
  let cursor = 0;
  for (const span of flatSpans(groups)) {
    out += original.slice(cursor, span.start);
    out += kept[span.placeholder]
      ? span.placeholder
      : original.slice(span.start, span.end);
    cursor = span.end;
  }
  out += original.slice(cursor);
  return out;
}

/** Honest counts for the status line, by unique value (group), matching the list. */
export function counts(
  groups: Group[],
  kept: Record<string, boolean>,
): { applied: number; dismissed: number; total: number } {
  let applied = 0;
  for (const g of groups) if (kept[g.placeholder]) applied += 1;
  return { applied, dismissed: groups.length - applied, total: groups.length };
}

/** Mask a secret for display: keep a little head and tail, dot the middle. Multi-line
 *  blocks (e.g. PEM private keys) collapse to a one-line masked summary so the list
 *  stays scannable and screenshot-safe. */
export function maskValue(value: string): string {
  const oneLine = value.includes("\n");
  const v = oneLine ? value.replace(/\s+/g, " ").trim() : value;
  if (v.length <= 8) return "•".repeat(Math.max(v.length, 4));
  const head = v.slice(0, 4);
  const tail = v.slice(-4);
  const dots = "•".repeat(Math.min(Math.max(v.length - 8, 4), 12));
  const masked = `${head}${dots}${tail}`;
  return oneLine ? `${masked} (${value.length} chars, multi-line)` : masked;
}
