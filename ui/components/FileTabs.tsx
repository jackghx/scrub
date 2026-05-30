"use client";

export interface TabInfo {
  id: string;
  name: string;
  /** True once this document has scrubbed output, shown as a small dot. */
  scrubbed: boolean;
}

interface FileTabsProps {
  tabs: TabInfo[];
  activeId: string;
  onSelect: (id: string) => void;
  onClose: (id: string) => void;
  onAdd: () => void;
}

/** A tab strip across the top of the workspace: one tab per open document, with a
 *  close button each and a "+" to start a fresh blank document. */
export function FileTabs({ tabs, activeId, onSelect, onClose, onAdd }: FileTabsProps) {
  return (
    <div className="flex items-stretch gap-1 overflow-x-auto border-b border-[var(--color-border)] px-2">
      {tabs.map((t) => {
        const active = t.id === activeId;
        return (
          <div
            key={t.id}
            // Middle-click closes the tab (matching browser/editor convention). The
            // mousedown guard suppresses the default middle-click autoscroll cursor.
            onMouseDown={(e) => {
              if (e.button === 1) e.preventDefault();
            }}
            onAuxClick={(e) => {
              if (e.button === 1) {
                e.preventDefault();
                onClose(t.id);
              }
            }}
            className={`group flex shrink-0 items-center gap-2 border-b-2 px-3 py-1.5 text-xs transition-colors ${
              active
                ? "border-[var(--color-accent)] text-[var(--color-ink)]"
                : "border-transparent text-[var(--color-muted)] hover:text-[var(--color-ink)]"
            }`}
          >
            <button
              onClick={() => onSelect(t.id)}
              className="flex max-w-[16rem] items-center gap-1.5"
              title={t.name}
            >
              {t.scrubbed && (
                <span
                  className="inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--color-accent)]"
                  aria-hidden
                />
              )}
              <span className="truncate">{t.name}</span>
            </button>
            <button
              onClick={() => onClose(t.id)}
              className="shrink-0 text-[var(--color-faint)] opacity-60 transition-opacity hover:text-[var(--color-warn)] group-hover:opacity-100"
              aria-label={`Close ${t.name}`}
              title="Close"
            >
              ×
            </button>
          </div>
        );
      })}
      <button
        onClick={onAdd}
        className="shrink-0 px-2.5 py-1.5 text-sm text-[var(--color-faint)] transition-colors hover:text-[var(--color-ink)]"
        aria-label="New document"
        title="New document"
      >
        +
      </button>
    </div>
  );
}
