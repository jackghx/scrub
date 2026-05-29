// Thin client for the local Scrub API. The base URL defaults to the local service
// and is overridable via NEXT_PUBLIC_SCRUB_API. The browser talks ONLY to this
// origin, there are no other network calls anywhere in the UI.

import type { HealthResponse, RestoreResponse, ScrubResponse } from "./types";

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

async function postJson<T>(path: string, body: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    throw new ApiError(
      `Couldn't reach the Scrub API at ${API_BASE}. Is it running? ` +
        `Start it with:  cd scrub && uvicorn main:app --host 127.0.0.1 --port 8000`,
    );
  }
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new ApiError(`Scrub API error ${res.status}: ${detail || res.statusText}`);
  }
  return (await res.json()) as T;
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

export async function health(): Promise<HealthResponse> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/health`);
  } catch {
    throw new ApiError(`Couldn't reach the Scrub API at ${API_BASE}.`);
  }
  if (!res.ok) throw new ApiError(`Health check failed: ${res.status}`);
  return (await res.json()) as HealthResponse;
}
