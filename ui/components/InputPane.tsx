"use client";

import { useRef, useState } from "react";

interface InputPaneProps {
  value: string;
  onChange: (v: string) => void;
  onScrub: () => void;
  loading: boolean;
  error: string | null;
  /** Called when one or more files are loaded from the picker or drag-and-drop.
   *  Each becomes its own document/tab upstream. */
  onLoadFiles: (files: { name: string; content: string }[]) => void;
  /** Load the bundled sample.log demo artefact. */
  onLoadSample: () => void;
}

// Read at most this much, so a stray multi-GB file can't lock up the tab. The whole
// file is read in-browser; only the text ever reaches the localhost API.
const MAX_BYTES = 5 * 1024 * 1024;

/** Heuristic: a control char other than tab (9), newline (10) or CR (13) means this
 *  is almost certainly binary, not a text artefact worth scrubbing. */
function looksBinary(content: string): boolean {
  for (let i = 0; i < content.length; i++) {
    const c = content.charCodeAt(i);
    if (c < 32 && c !== 9 && c !== 10 && c !== 13) return true;
  }
  return false;
}

export function InputPane({
  value,
  onChange,
  onScrub,
  loading,
  error,
  onLoadFiles,
  onLoadSample,
}: InputPaneProps) {
  const fileInput = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);

  async function handleFiles(fileList: FileList | null) {
    const files = fileList ? Array.from(fileList) : [];
    if (files.length === 0) return;
    setFileError(null);
    const loaded: { name: string; content: string }[] = [];
    const skipped: string[] = [];
    for (const file of files) {
      if (file.size > MAX_BYTES) {
        skipped.push(`${file.name} (over 5 MB)`);
        continue;
      }
      const content = await file.text();
      if (looksBinary(content)) {
        skipped.push(`${file.name} (binary)`);
        continue;
      }
      loaded.push({ name: file.name, content });
    }
    if (loaded.length) onLoadFiles(loaded);
    if (skipped.length) setFileError(`Skipped ${skipped.join(", ")}.`);
  }

  function onPick(e: React.ChangeEvent<HTMLInputElement>) {
    void handleFiles(e.target.files);
    // Reset so picking the same file again still fires onChange.
    e.target.value = "";
  }

  function onDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragging(false);
    void handleFiles(e.dataTransfer.files);
  }

  const lines = value.length === 0 ? 0 : value.split("\n").length;

  return (
    <section
      className="relative flex h-full min-h-0 flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]"
      onDragOver={(e) => {
        e.preventDefault();
        if (!dragging) setDragging(true);
      }}
      onDragLeave={(e) => {
        // Only clear when the pointer actually leaves the section, not its children.
        if (e.currentTarget === e.target) setDragging(false);
      }}
      onDrop={onDrop}
    >
      <header className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-2.5">
        <div className="flex items-baseline gap-2">
          <h2 className="text-sm font-semibold tracking-wide text-[var(--color-ink)]">
            Input
          </h2>
          <span className="text-xs text-[var(--color-faint)]">
            paste, or drop files
          </span>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={onLoadSample}
            className="rounded-md border border-[var(--color-border-strong)] px-2.5 py-1 text-xs font-medium text-[var(--color-muted)] transition-colors hover:text-[var(--color-ink)]"
          >
            Load sample
          </button>
          <button
            onClick={() => fileInput.current?.click()}
            className="rounded-md border border-[var(--color-border-strong)] px-2.5 py-1 text-xs font-medium text-[var(--color-muted)] transition-colors hover:text-[var(--color-ink)]"
          >
            Upload files
          </button>
          <span className="mono text-xs text-[var(--color-muted)]">
            {value.length.toLocaleString()} chars, {lines.toLocaleString()} lines
          </span>
        </div>
        <input
          ref={fileInput}
          type="file"
          multiple
          accept=".txt,.log,.conf,.cfg,.ini,.env,.json,.yaml,.yml,.toml,.md,.csv,.pem,.sh,.py,.js,.ts,text/*"
          onChange={onPick}
          className="hidden"
        />
      </header>

      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
        placeholder={"// e.g.\ndefault via 10.10.10.1 dev eth0\nAUTH=Bearer eyJhbGciOi...\npostgres://admin:s3cr3t@db.internal:5432/app\n\n// or drop a log/config file anywhere in this pane"}
        className="mono min-h-0 flex-1 resize-none bg-transparent px-4 py-3 text-[13px] leading-relaxed text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none"
      />

      <footer className="flex items-center gap-3 border-t border-[var(--color-border)] px-4 py-3">
        <button
          onClick={onScrub}
          disabled={loading || value.length === 0}
          className="rounded-md bg-[var(--color-accent)] px-4 py-1.5 text-sm font-semibold text-[#04222a] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? "Scrubbing..." : "Scrub"}
        </button>
        {fileError ? (
          <p className="text-xs leading-snug text-[var(--color-warn)]">{fileError}</p>
        ) : error ? (
          <p className="text-xs leading-snug text-[var(--color-warn)]">{error}</p>
        ) : (
          <p className="text-xs text-[var(--color-faint)]">
            Files are read in your browser; nothing is uploaded.
          </p>
        )}
      </footer>

      {dragging && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center rounded-lg border-2 border-dashed border-[var(--color-accent)] bg-[var(--color-bg)]/70">
          <span className="text-sm font-medium text-[var(--color-accent)]">
            Drop files to load
          </span>
        </div>
      )}
    </section>
  );
}
