"use client";

import { Fragment, useMemo } from "react";
import { CodeLines } from "./CodeLines";
import { entityColor } from "@/lib/entities";
import { originalTokenLines } from "@/lib/recompute";
import type { OriginalToken } from "@/lib/types";

/** A detected span in the original: entity-tinted where it'll be scrubbed,
 *  warning-highlighted where it's been dismissed (and will stay exposed). */
function Highlight({
  text,
  entity,
  kept,
}: {
  text: string;
  entity: string;
  kept: boolean;
}) {
  if (!kept) {
    return (
      <span
        className="rounded px-0.5"
        style={{
          color: "var(--color-warn)",
          backgroundColor: "var(--color-warn-bg)",
          border: "1px dashed var(--color-warn)",
        }}
        title={`${entity} (will stay exposed)`}
      >
        {text}
      </span>
    );
  }
  const color = entityColor(entity);
  return (
    <span
      className="rounded px-0.5"
      style={{ backgroundColor: `${color}26`, borderBottom: `1px solid ${color}` }}
      title={`${entity} (will be scrubbed)`}
    >
      {text}
    </span>
  );
}

/** The "before" view shown in the left slot while Diff is on, replacing the input
 *  editor so the comparison gets a full half-width column instead of a cramped split. */
export function OriginalPane({ tokens }: { tokens: OriginalToken[] }) {
  const lines = useMemo(() => originalTokenLines(tokens), [tokens]);
  const rendered = useMemo(
    () =>
      lines.map((pieces, li) => (
        <Fragment key={li}>
          {pieces.map((p, i) =>
            p.type === "text" ? (
              <span key={i}>{p.text}</span>
            ) : (
              <Highlight key={i} text={p.text} entity={p.entity} kept={p.kept} />
            ),
          )}
        </Fragment>
      )),
    [lines],
  );

  return (
    <section className="flex h-full min-h-0 flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]">
      <header className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-2.5">
        <h2 className="text-sm font-semibold tracking-wide text-[var(--color-ink)]">
          Original
        </h2>
        <span className="text-xs text-[var(--color-faint)]">
          before scrubbing; highlights show what changes
        </span>
      </header>
      <CodeLines lines={rendered} />
    </section>
  );
}
