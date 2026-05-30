"use client";

import { entityColor } from "@/lib/entities";

/** An inline placeholder in the review pane, e.g. <INTERNAL_IP_1>, rendered with a color that matches the entity type, and a tooltip that shows the original value. */
export function Chip({ placeholder, entity }: { placeholder: string; entity: string }) {
  const color = entityColor(entity);
  return (
    <span
      className="mono font-medium align-baseline"
      style={{ color }}
      title={`${entity} (kept, scrubbed)`}
    >
      {placeholder}
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
      title={`${entity} (DISMISSED, original value will be exposed)`}
    >
      {text}
    </span>
  );
}
