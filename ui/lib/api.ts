// Thin client for the local Scrub API. The base URL defaults to the local service
// and is overridable via NEXT_PUBLIC_SCRUB_API. The browser talks ONLY to this
// origin, there are no other network calls anywhere in the UI.

import type {
  CustomRecognizer,
  HealthResponse,
  RestoreResponse,
  ScrubResponse,
} from "./types";

export const API_BASE = (
  process.env.NEXT_PUBLIC_SCRUB_API ?? "http://127.0.0.1:8000"
).replace(/\/$/, "");

/** Thrown when the local API can't be reached or returns a non-2xx. The message is
 *  user-facing and points at the most likely cause: the API isn't running. */
export class ApiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApiError";
  }
}

const UNREACHABLE =
  `Couldn't reach the Scrub API at ${API_BASE}. Is it running? ` +
  `Start it with:  cd scrub && uvicorn main:app --host 127.0.0.1 --port 8000`;

/** Pull a human message out of a non-2xx response, preferring FastAPI's JSON
 *  ``{"detail": ...}`` over the raw body. */
async function errorMessage(res: Response): Promise<string> {
  const body = await res.text().catch(() => "");
  try {
    const parsed = JSON.parse(body) as { detail?: unknown };
    if (typeof parsed.detail === "string") return parsed.detail;
  } catch {
    // not JSON; fall through to the raw body
  }
  return body || res.statusText;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, init);
  } catch {
    throw new ApiError(UNREACHABLE);
  }
  if (!res.ok) {
    throw new ApiError(`Scrub API error ${res.status}: ${await errorMessage(res)}`);
  }
  return (await res.json()) as T;
}

function postJson<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

export function scrub(text: string): Promise<ScrubResponse> {
  return postJson<ScrubResponse>("/scrub", { text });
}

export function restore(
  text: string,
  mapping: Record<string, string>,
): Promise<RestoreResponse> {
  return postJson<RestoreResponse>("/restore", { text, mapping });
}

export function health(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

export async function listRecognizers(): Promise<CustomRecognizer[]> {
  const res = await request<{ recognizers: CustomRecognizer[] }>("/recognizers");
  return res.recognizers;
}

export async function addRecognizer(input: {
  label: string;
  regex: string;
  score: number;
  context: string[];
}): Promise<CustomRecognizer[]> {
  const res = await postJson<{ recognizers: CustomRecognizer[] }>(
    "/recognizers",
    input,
  );
  return res.recognizers;
}

export async function deleteRecognizer(entity: string): Promise<CustomRecognizer[]> {
  const res = await request<{ recognizers: CustomRecognizer[] }>(
    `/recognizers/${encodeURIComponent(entity)}`,
    { method: "DELETE" },
  );
  return res.recognizers;
}
