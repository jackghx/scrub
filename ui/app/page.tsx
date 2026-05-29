"use client";

import { useMemo, useState } from "react";
import { InputPane } from "@/components/InputPane";
import { ReviewPane } from "@/components/ReviewPane";
import { DetectionList } from "@/components/DetectionList";
import { RestorePanel } from "@/components/RestorePanel";
import { scrub, ApiError, API_BASE } from "@/lib/api";
import { entityMeta } from "@/lib/entities";
import {
  DEFAULT_THRESHOLD,
  applyThreshold,
  buildExport,
  buildTokens,
  counts,
  defaultKeptMap,
  groupDetections,
} from "@/lib/recompute";
import type { Detection } from "@/lib/types";

interface ScrubState {
  original: string;
  detections: Detection[];
  mapping: Record<string, string>;
}

export default function Page() {
  const [input, setInput] = useState("");
  const [data, setData] = useState<ScrubState | null>(null);
  const [kept, setKept] = useState<Record<string, boolean>>({});
  const [touched, setTouched] = useState<Set<string>>(new Set());
  const [threshold, setThreshold] = useState(DEFAULT_THRESHOLD);
  const [revealAll, setRevealAll] = useState(false);
  const [revealRow, setRevealRow] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // All review output is derived purely from the original text + detections + toggle
  // state, no server round-trip when toggling.
  const groups = useMemo(
    () => (data ? groupDetections(data.detections) : []),
    [data],
  );
  const tokens = useMemo(
    () => (data ? buildTokens(data.original, groups, kept) : []),
    [data, groups, kept],
  );
  const exportText = useMemo(
    () => (data ? buildExport(data.original, groups, kept) : ""),
    [data, groups, kept],
  );
  const { applied, dismissed, total } = useMemo(
    () => counts(groups, kept),
    [groups, kept],
  );
  const presentEntities = useMemo(
    () => [...new Set(groups.map((g) => g.entity_type))],
    [groups],
  );

  async function onScrub() {
    setLoading(true);
    setError(null);
    try {
      const res = await scrub(input);
      const next: ScrubState = {
        original: input,
        detections: res.detections,
        mapping: res.mapping,
      };
      const g = groupDetections(res.detections);
      setData(next);
      setKept(defaultKeptMap(g, threshold));
      setTouched(new Set());
      setRevealRow(new Set());
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }

  function onToggle(placeholder: string) {
    setKept((prev) => ({ ...prev, [placeholder]: !prev[placeholder] }));
    setTouched((prev) => new Set(prev).add(placeholder));
  }

  function onThreshold(t: number) {
    setThreshold(t);
    setKept((prev) => applyThreshold(groups, t, prev, touched));
  }

  function setAll(value: boolean) {
    const next: Record<string, boolean> = {};
    for (const g of groups) next[g.placeholder] = value;
    setKept(next);
    setTouched(new Set(groups.map((g) => g.placeholder)));
  }

  function onRevealRow(placeholder: string) {
    setRevealRow((prev) => {
      const next = new Set(prev);
      if (next.has(placeholder)) next.delete(placeholder);
      else next.add(placeholder);
      return next;
    });
  }

  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--color-border)] px-5 py-3">
        <div className="flex items-baseline gap-3">
          <h1 className="text-lg font-bold tracking-tight">
            <span className="text-[var(--color-accent)]">Scrub</span>
            <span className="text-[var(--color-faint)]"> / review</span>
          </h1>
          <p className="hidden text-xs text-[var(--color-muted)] sm:block">
            See what was detected · decide what to scrub · then export
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="mono text-xs text-[var(--color-faint)]">{API_BASE}</span>
          <span className="rounded-full border border-[var(--color-border-strong)] px-2.5 py-0.5 text-xs text-[var(--color-muted)]">
            local-first · data never leaves your machine
          </span>
        </div>
      </header>

      <main className="flex flex-1 flex-col gap-4 p-4">
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="h-[42vh] min-h-[260px]">
            <div className="h-full">
              <InputPane
                value={input}
                onChange={setInput}
                onScrub={onScrub}
                loading={loading}
                error={error}
              />
            </div>
          </div>
          <div className="h-[42vh] min-h-[260px]">
            <ReviewPane
              tokens={tokens}
              exportText={exportText}
              applied={applied}
              dismissed={dismissed}
              total={total}
              hasScrubbed={data !== null}
            />
          </div>
        </div>

        {presentEntities.length > 0 && (
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] px-4 py-2.5">
            <span className="text-xs font-medium text-[var(--color-faint)]">
              Legend
            </span>
            {presentEntities.map((e) => {
              const m = entityMeta(e);
              return (
                <span key={e} className="flex items-center gap-1.5 text-xs">
                  <span
                    className="inline-block h-2.5 w-2.5 rounded-sm"
                    style={{ backgroundColor: m.color }}
                  />
                  <span className="text-[var(--color-muted)]">{m.label}</span>
                </span>
              );
            })}
          </div>
        )}

        <div className="min-h-[220px] flex-1">
          <DetectionList
            groups={groups}
            kept={kept}
            threshold={threshold}
            revealAll={revealAll}
            revealRow={revealRow}
            onToggle={onToggle}
            onThreshold={onThreshold}
            onKeepAll={() => setAll(true)}
            onDismissAll={() => setAll(false)}
            onRevealAll={setRevealAll}
            onRevealRow={onRevealRow}
          />
        </div>

        <RestorePanel mapping={data?.mapping ?? {}} exportText={exportText} />
      </main>
    </div>
  );
}
