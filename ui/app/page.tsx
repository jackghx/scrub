"use client";

import { useMemo, useRef, useState } from "react";
import { FileTabs } from "@/components/FileTabs";
import { InputPane } from "@/components/InputPane";
import { OriginalPane } from "@/components/OriginalPane";
import { ReviewPane } from "@/components/ReviewPane";
import { DetectionList } from "@/components/DetectionList";
import { RecognizerPanel } from "@/components/RecogniserPanel";
import { RestorePanel } from "@/components/RestorePanel";
import { scrub, ApiError, API_BASE } from "@/lib/api";
import { entityMeta } from "@/lib/entities";
import {
  DEFAULT_THRESHOLD,
  applyThreshold,
  buildExport,
  buildOriginalTokens,
  buildTokens,
  counts,
  defaultKeptMap,
  groupDetections,
  outputLines,
  scrubMarks,
} from "@/lib/recompute";
import { SAMPLE_LOG } from "@/lib/sample";
import type { Detection } from "@/lib/types";

interface ScrubState {
  original: string;
  detections: Detection[];
  mapping: Record<string, string>;
}

/** One open document. Each tab is an independent scrub session; everything below is
 *  per-document so switching tabs swaps the whole workspace. */
interface Doc {
  id: string;
  name: string;
  input: string;
  fileName: string | null;
  data: ScrubState | null;
  kept: Record<string, boolean>;
  touched: Set<string>;
  threshold: number;
  revealAll: boolean;
  revealRow: Set<string>;
  loading: boolean;
  error: string | null;
}

export default function Page() {
  const idRef = useRef(1);
  const makeDoc = (partial?: Partial<Doc>): Doc => ({
    id: String(idRef.current++),
    name: "Untitled",
    input: "",
    fileName: null,
    data: null,
    kept: {},
    touched: new Set(),
    threshold: DEFAULT_THRESHOLD,
    revealAll: false,
    revealRow: new Set(),
    loading: false,
    error: null,
    ...partial,
  });

  const [docs, setDocs] = useState<Doc[]>(() => [makeDoc()]);
  const [activeId, setActiveId] = useState<string>(() => docs[0].id);
  const [focus, setFocus] = useState<{ line: number | null; nonce: number }>({
    line: null,
    nonce: 0,
  });
  const [diff, setDiff] = useState(false);
  const active = docs.find((d) => d.id === activeId) ?? docs[0];

  // --- derived review state, all from the ACTIVE doc, no server round-trip --------
  const groups = useMemo(
    () => (active.data ? groupDetections(active.data.detections) : []),
    [active.data],
  );
  const tokens = useMemo(
    () => (active.data ? buildTokens(active.data.original, groups, active.kept) : []),
    [active.data, groups, active.kept],
  );
  const originalTokens = useMemo(
    () =>
      active.data ? buildOriginalTokens(active.data.original, groups, active.kept) : [],
    [active.data, groups, active.kept],
  );
  const exportText = useMemo(
    () => (active.data ? buildExport(active.data.original, groups, active.kept) : ""),
    [active.data, groups, active.kept],
  );
  const minimap = useMemo(
    () =>
      active.data
        ? scrubMarks(active.data.original, groups, active.kept)
        : { marks: [], totalLines: 1 },
    [active.data, groups, active.kept],
  );
  const locations = useMemo(
    () =>
      active.data ? outputLines(active.data.original, groups, active.kept) : {},
    [active.data, groups, active.kept],
  );
  const { applied, dismissed, total } = useMemo(
    () => counts(groups, active.kept),
    [groups, active.kept],
  );
  const presentEntities = useMemo(
    () => [...new Set(groups.map((g) => g.entity_type))],
    [groups],
  );

  // --- per-document updates -------------------------------------------------------
  function patchActive(patch: Partial<Doc>) {
    setDocs((prev) => prev.map((d) => (d.id === activeId ? { ...d, ...patch } : d)));
  }

  async function onScrub() {
    const doc = docs.find((d) => d.id === activeId);
    if (!doc || doc.input.length === 0) return;
    patchActive({ loading: true, error: null });
    try {
      const res = await scrub(doc.input);
      const g = groupDetections(res.detections);
      // Target by doc.id, not activeId, so switching tabs mid-scrub still lands here.
      setDocs((prev) =>
        prev.map((d) =>
          d.id === doc.id
            ? {
                ...d,
                data: {
                  original: doc.input,
                  detections: res.detections,
                  mapping: res.mapping,
                },
                kept: defaultKeptMap(g, d.threshold),
                touched: new Set(),
                revealRow: new Set(),
                loading: false,
              }
            : d,
        ),
      );
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Something went wrong.";
      setDocs((prev) =>
        prev.map((d) => (d.id === doc.id ? { ...d, loading: false, error: msg } : d)),
      );
    }
  }

  function onToggle(placeholder: string) {
    setDocs((prev) =>
      prev.map((d) => {
        if (d.id !== activeId) return d;
        const touched = new Set(d.touched).add(placeholder);
        return { ...d, kept: { ...d.kept, [placeholder]: !d.kept[placeholder] }, touched };
      }),
    );
  }

  function onThreshold(t: number) {
    setDocs((prev) =>
      prev.map((d) => {
        if (d.id !== activeId) return d;
        const g = d.data ? groupDetections(d.data.detections) : [];
        return { ...d, threshold: t, kept: applyThreshold(g, t, d.kept, d.touched) };
      }),
    );
  }

  function setAll(value: boolean) {
    setDocs((prev) =>
      prev.map((d) => {
        if (d.id !== activeId) return d;
        const g = d.data ? groupDetections(d.data.detections) : [];
        const next: Record<string, boolean> = {};
        for (const grp of g) next[grp.placeholder] = value;
        return { ...d, kept: next, touched: new Set(g.map((x) => x.placeholder)) };
      }),
    );
  }

  function onRevealRow(placeholder: string) {
    setDocs((prev) =>
      prev.map((d) => {
        if (d.id !== activeId) return d;
        const next = new Set(d.revealRow);
        if (next.has(placeholder)) next.delete(placeholder);
        else next.add(placeholder);
        return { ...d, revealRow: next };
      }),
    );
  }

  // --- tab / file management ------------------------------------------------------
  const isEmptyDoc = (d: Doc) => d.input.trim() === "" && d.data === null;

  function onLoadFiles(files: { name: string; content: string }[]) {
    if (files.length === 0) return;
    const activeDoc = docs.find((d) => d.id === activeId);
    const reuseFirst = activeDoc != null && isEmptyDoc(activeDoc);
    // Build the new docs once, outside the state updater, so the updater stays pure.
    const created = files.map((f, i) =>
      i === 0 && reuseFirst && activeDoc
        ? makeDoc({ id: activeDoc.id, name: f.name, fileName: f.name, input: f.content })
        : makeDoc({ name: f.name, fileName: f.name, input: f.content }),
    );
    const byId = new Map(created.map((d) => [d.id, d]));
    setDocs((prev) => {
      const replaced = prev.map((d) => byId.get(d.id) ?? d);
      const additions = created.filter((d) => !prev.some((p) => p.id === d.id));
      return [...replaced, ...additions];
    });
    setActiveId(created[0].id);
  }

  function loadSample() {
    onLoadFiles([{ name: "sample.log", content: SAMPLE_LOG }]);
  }

  function addDoc() {
    const d = makeDoc();
    setDocs((prev) => [...prev, d]);
    setActiveId(d.id);
  }

  function closeDoc(id: string) {
    if (docs.length <= 1) {
      const fresh = makeDoc();
      setDocs([fresh]);
      setActiveId(fresh.id);
      return;
    }
    const idx = docs.findIndex((d) => d.id === id);
    const next = docs.filter((d) => d.id !== id);
    setDocs(next);
    if (id === activeId) {
      setActiveId(next[Math.min(idx, next.length - 1)].id);
    }
  }

  const tabs = docs.map((d) => ({ id: d.id, name: d.name, scrubbed: d.data !== null }));

  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--color-border)] px-5 py-3">
        <div className="flex items-baseline gap-3">
          <h1 className="text-lg font-bold tracking-tight text-[var(--color-ink)]">
            Scrub
          </h1>
          <p className="hidden text-xs text-[var(--color-muted)] sm:block">
            See what was detected, decide what to scrub, then export.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="mono text-xs text-[var(--color-faint)]">{API_BASE}</span>
        </div>
      </header>

      <FileTabs
        tabs={tabs}
        activeId={activeId}
        onSelect={setActiveId}
        onClose={closeDoc}
        onAdd={addDoc}
      />

      <main className="flex flex-1 flex-col gap-4 p-4">
        <div className="grid items-start gap-4 lg:grid-cols-2">
          <div className="h-[62vh] min-h-[340px] resize-y overflow-hidden">
            {diff && active.data ? (
              <OriginalPane tokens={originalTokens} />
            ) : (
              <InputPane
                value={active.input}
                onChange={(v) => patchActive({ input: v })}
                onScrub={onScrub}
                loading={active.loading}
                error={active.error}
                onLoadFiles={onLoadFiles}
                onLoadSample={loadSample}
              />
            )}
          </div>
          <div className="h-[62vh] min-h-[340px] resize-y overflow-hidden">
            <ReviewPane
              tokens={tokens}
              exportText={exportText}
              marks={minimap.marks}
              totalLines={minimap.totalLines}
              applied={applied}
              dismissed={dismissed}
              total={total}
              hasScrubbed={active.data !== null}
              fileName={active.fileName}
              focusLine={focus.line}
              focusNonce={focus.nonce}
              diff={diff}
              onToggleDiff={() => setDiff((v) => !v)}
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
            kept={active.kept}
            threshold={active.threshold}
            revealAll={active.revealAll}
            revealRow={active.revealRow}
            lineByPlaceholder={locations}
            onToggle={onToggle}
            onThreshold={onThreshold}
            onKeepAll={() => setAll(true)}
            onDismissAll={() => setAll(false)}
            onRevealAll={(v) => patchActive({ revealAll: v })}
            onRevealRow={onRevealRow}
            onLocate={(line) => setFocus((f) => ({ line, nonce: f.nonce + 1 }))}
          />
        </div>

        <RecognizerPanel
          onChanged={() => {
            if (active.data) void onScrub();
          }}
        />

        <RestorePanel mapping={active.data?.mapping ?? {}} exportText={exportText} />
      </main>
    </div>
  );
}
