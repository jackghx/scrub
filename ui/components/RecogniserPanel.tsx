"use client";

import { useEffect, useState } from "react";
import {
  ApiError,
  addRecognizer,
  deleteRecognizer,
  listRecognizers,
} from "@/lib/api";
import type { CustomRecognizer } from "@/lib/types";

interface RecognizerPanelProps {
  /** Called after the recogniser set changes, so the page can re-scrub if it wants. */
  onChanged?: () => void;
}

export function RecognizerPanel({ onChanged }: RecognizerPanelProps) {
  const [open, setOpen] = useState(false);
  const [recognizers, setRecognizers] = useState<CustomRecognizer[]>([]);
  const [label, setLabel] = useState("");
  const [regex, setRegex] = useState("");
  const [score, setScore] = useState(0.6);
  const [context, setContext] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load whatever the local API already has registered (in-memory only) on open.
  useEffect(() => {
    if (!open) return;
    listRecognizers()
      .then(setRecognizers)
      .catch(() => {
        // API may be down; the form still explains itself, just no list yet.
      });
  }, [open]);

  async function add() {
    const trimmedLabel = label.trim();
    const trimmedRegex = regex.trim();
    if (!trimmedLabel || !trimmedRegex) {
      setError("Give the recogniser a name and a pattern.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const next = await addRecognizer({
        label: trimmedLabel,
        regex: trimmedRegex,
        score,
        context: context
          .split(",")
          .map((w) => w.trim())
          .filter(Boolean),
      });
      setRecognizers(next);
      setLabel("");
      setRegex("");
      setContext("");
      setScore(0.6);
      onChanged?.();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Couldn't add the recogniser.");
    } finally {
      setBusy(false);
    }
  }

  async function remove(entity: string) {
    setBusy(true);
    setError(null);
    try {
      setRecognizers(await deleteRecognizer(entity));
      onChanged?.();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Couldn't remove the recogniser.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel)]">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between px-4 py-2.5 text-left"
      >
        <span className="text-sm font-semibold tracking-wide text-[var(--color-ink)]">
          Custom recognisers
          {recognizers.length > 0 && (
            <span className="mono ml-2 text-xs text-[var(--color-faint)]">
              {recognizers.length}
            </span>
          )}
        </span>
        <span className="text-xs text-[var(--color-faint)]">{open ? "Hide" : "Show"}</span>
      </button>

      {open && (
        <div className="space-y-3 border-t border-[var(--color-border)] px-4 py-3">
          <p className="text-xs leading-relaxed text-[var(--color-muted)]">
            Add your own regex patterns (employee IDs, internal ticket refs, project
            codenames). They run alongside the built-in pack on the local API.{" "}
            <span className="text-[var(--color-warn)]">
              They live in memory only and are lost when the API restarts.
            </span>
          </p>

          {/* Existing recognisers */}
          {recognizers.length > 0 && (
            <ul className="space-y-1.5">
              {recognizers.map((r) => (
                <li
                  key={r.entity}
                  className="flex items-center gap-3 rounded border border-[var(--color-border)] px-2.5 py-1.5 text-xs"
                >
                  <span className="font-semibold uppercase tracking-wide text-[var(--color-ink)]">
                    {r.entity}
                  </span>
                  <code className="mono min-w-0 flex-1 truncate text-[var(--color-muted)]">
                    {r.regex}
                  </code>
                  <span className="mono text-[var(--color-faint)]">
                    {r.score.toFixed(2)}
                  </span>
                  <button
                    onClick={() => remove(r.entity)}
                    disabled={busy}
                    className="shrink-0 text-[var(--color-faint)] uppercase tracking-wide transition-colors hover:text-[var(--color-warn)] disabled:opacity-40"
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}

          {/* Add form */}
          <div className="grid gap-2 sm:grid-cols-2">
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Name, e.g. Employee ID"
              className="rounded border border-[var(--color-border-strong)] bg-transparent px-2 py-1 text-xs text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus-visible:border-[var(--color-ink)] focus-visible:outline-none"
            />
            <input
              type="text"
              value={context}
              onChange={(e) => setContext(e.target.value)}
              placeholder="Context words (comma-separated, optional)"
              className="rounded border border-[var(--color-border-strong)] bg-transparent px-2 py-1 text-xs text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus-visible:border-[var(--color-ink)] focus-visible:outline-none"
            />
          </div>
          <input
            type="text"
            value={regex}
            onChange={(e) => setRegex(e.target.value)}
            placeholder="Pattern, e.g. EMP-\d{5}"
            spellCheck={false}
            className="mono w-full rounded border border-[var(--color-border-strong)] bg-transparent px-2 py-1 text-xs text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus-visible:border-[var(--color-ink)] focus-visible:outline-none"
          />
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-xs text-[var(--color-muted)]">
              Base confidence
              <input
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={score}
                onChange={(e) => setScore(Number(e.target.value))}
                className="w-28"
              />
              <span className="mono w-8 text-[var(--color-ink)]">{score.toFixed(2)}</span>
            </label>
            <button
              onClick={add}
              disabled={busy}
              className="ml-auto rounded border border-[var(--color-border-strong)] px-3 py-1.5 text-xs font-medium text-[var(--color-ink)] transition-colors hover:border-[var(--color-ink)] disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? "Saving..." : "Add recogniser"}
            </button>
          </div>

          {error && <p className="text-xs text-[var(--color-warn)]">{error}</p>}
        </div>
      )}
    </section>
  );
}
