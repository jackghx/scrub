"use client";

import { entityColor } from "@/lib/entities";

/** An inline placeholder chip in the review pane, e.g. ‹INTERNAL_IP_1›, coloured by
 *  entity type. Rendered where a detection is KEPT. */
export function Chip({ placeholder, entity }: { placeholder: string; entity: string }) {
  const color = entityColor(entity);
  // Strip the < > the API uses and show guillemets so chips read as UI, not literals.
  const label = placeholder.replace(/^</, "‹").replace(/>$/, "›");
  return (
    <span
      className="mono inline-flex items-center rounded px-1.5 py-px text-[0.85em] font-medium align-baseline"
      style={{
        color,
        backgroundColor: `${color}1a`, // ~10% alpha
        border: `1px solid ${color}59`, // ~35% alpha
      }}
      title={`${entity} · kept (scrubbed)`}
    >
      {label}
    </span>
  );
}

/** A dismissed (un-scrubbed) original, rendered with a loud warning highlight so an
 *  exposed secret is impossible to miss, never silent. */
export function RestoredMark({ text, entity }: { text: string; entity: string }) {
  return (
    <span
      className="mono rounded px-1 py-px align-baseline"
      style={{
        color: "var(--color-warn)",
        backgroundColor: "var(--color-warn-bg)",
        border: "1px dashed var(--color-warn)",
      }}
      title={`${entity} · DISMISSED, original value will be exposed`}
    >
      {text}
    </span>
  );
}
