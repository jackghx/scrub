// Shared types mirroring the Scrub API contract (see scrub/main.py).

/** One detection occurrence, as returned by POST /scrub. Spans are offsets into the
 *  ORIGINAL text. The same repeated value yields one Detection per occurrence, all
 *  sharing one `placeholder`. */
export interface Detection {
  entity_type: string;
  start: number;
  end: number;
  score: number;
  placeholder: string;
  original: string;
}

export interface ScrubResponse {
  scrubbed: string;
  mapping: Record<string, string>; // placeholder -> original
  detections: Detection[];
}

export interface RestoreResponse {
  original: string;
}

export interface HealthResponse {
  status: string;
  mode: string;
}

/** A user-defined recogniser, mirroring scrub/main.py's CustomRecognizer. The raw
 *  pattern + label live in memory on the local API only; nothing is persisted. */
export interface CustomRecognizer {
  entity: string;
  label: string;
  regex: string;
  score: number;
  context: string[];
}

/** Detections grouped by placeholder (one per unique value) for the review list. */
export interface Group {
  placeholder: string;
  entity_type: string;
  original: string;
  score: number;
  spans: { start: number; end: number }[];
  count: number;
  /** start of the first occurrence, used for stable, document-order sorting. */
  firstStart: number;
}

/** A rendered fragment of the review pane. */
export type Token =
  | { type: "text"; text: string }
  | { type: "chip"; placeholder: string; entity: string }
  | { type: "restored"; text: string; entity: string };

/** A rendered fragment for the diff "before" panel — original text with highlights. */
export type OriginalToken =
  | { type: "text"; text: string }
  | { type: "highlight"; text: string; entity: string; placeholder: string; kept: boolean };
