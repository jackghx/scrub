# Scrub, review UI

The human-in-the-loop front end for [Scrub](../scrub). Paste a log or config, see what
the detectors found as colour-coded chips, decide what to scrub, then copy out a result
you're confident in.

> **This UI is the review step.** Scrub's detection favours recall (it flags everything
> it suspects, see [why in the project README](../README.md#human-in-the-loop)), which
> only works if you can quickly see and correct what was flagged. The UI is where that
> happens: it applies its detections but leaves the call to you, and it never describes
> the output as "clean" or "safe".

> **Local-first, no persistence.** The browser talks **only** to the local Scrub API,
> no analytics, no CDN fonts, no external calls of any kind. The mapping that can reverse
> a scrub holds the real secrets and is kept **in memory only**: never written to disk,
> `localStorage`, `sessionStorage`, or cookies. Reload the page and it's gone.

## Stack

Next.js (App Router) + TypeScript + Tailwind v4. Single page, no auth, no DB. System
font stacks only (nothing fetched from a font CDN).

## Run

The UI needs the Scrub API running. Install it once from the repo root
(`pip install -e ".[api]"`, the `[api]` extra is what provides uvicorn; full Python setup
is in the [root quickstart](../README.md#get-started-the-review-ui)), then start both:

```bash
# terminal 1, the API
cd scrub
uvicorn main:app --host 127.0.0.1 --port 8000

# terminal 2, the UI
cd ui
npm install        # first time only
npm run dev        # http://localhost:3000
```

The API base defaults to `http://127.0.0.1:8000`; override it with the
`NEXT_PUBLIC_SCRUB_API` env var:

```bash
NEXT_PUBLIC_SCRUB_API=http://127.0.0.1:8000 npm run dev
```

`npm run build` produces a production build; `npm run start` serves it.

## How it works

- **Left pane**, a monospace textarea with a live char count. **Scrub** posts the text
  to `/scrub` once.
- **Right pane**, the scrubbed result. Kept detections render as entity-coloured
  **chips** (`‹INTERNAL_IP_1›`); dismissed ones show the **original value with an amber
  warning highlight** so an exposed secret is impossible to miss.
- **Detections list**, one row per *unique value* (occurrences of the same value are
  grouped and share a toggle, shown as `×3`). Each row has the entity type, the masked
  original (with a reveal eye), the placeholder, and the confidence score.

### The toggle (the heart of it)

Every detection can be **kept** (scrubbed) or **dismissed** (restored to the original in
the output). Toggling recomputes the right pane *and* the export **instantly, in the
browser**, there's no second server call, because the `/scrub` response already gave us
the spans, placeholders, and originals.

- **Default by confidence:** score ≥ 0.6 is **kept**; below 0.6 is **shown but
  unchecked** (the ambiguous long-tail, `HOSTNAME`, `AWS_ACCOUNT_ID`, AWS secret keys,
  that the pack scores low on purpose). Recall-favoured detection stays usable: nothing
  is hidden, but the noise doesn't bury the signal.
- A **confidence slider** bulk-sets the checked state by score, but rows you've manually
  toggled keep your choice (manual overrides always win).
- **Keep all / Dismiss all** are there too, but never as the only path.

### Export

A **Copy** button copies exactly the text as currently rendered for your toggle state;
**.txt** downloads the same. The status line is honest, *"14 of 17 detections applied ·
3 dismissed, review before sharing"*, and never claims safety.

### Restore (round-trip)

The **Restore** panel reconstructs the original from the current output + the last
scrub's in-memory mapping, via the local `/restore` endpoint, a byte-for-byte check.
The mapping is memory-only and stated as such in the UI.

## Anti-patterns this UI deliberately avoids

- No auto-copy, no "looks clean!" banner, the UI never implies safety it can't
  guarantee.
- No silent dismissal, a dismissed detection's original is rendered with a loud warning
  highlight.
- No persistence of originals or mappings to storage of any kind.
- No network calls beyond the local API.

## Layout

```
ui/
  app/        layout.tsx, page.tsx (the two-pane screen), globals.css
  components/ InputPane, ReviewPane, DetectionList, Chip, RestorePanel
  lib/        api.ts, recompute.ts (pure toggle/export logic), entities.ts, types.ts
```
