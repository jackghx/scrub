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
