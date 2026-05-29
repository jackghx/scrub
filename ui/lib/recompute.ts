// recompute.ts, the client-side heart of the review step.
//
// The /scrub response gives us the original text (we kept it), every detection's
// span/placeholder/original, and the recall-favoured scores. Everything the review
// pane and the export need is derived from those, PURELY, with no further server
// calls, so toggling a detection updates the output instantly.
//
// These functions are deliberately free of React so they can be reasoned about and
// unit-tested in isolation.

import type { Detection, Group, Token } from "./types";

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
