# Security

Scrub is a security tool, so its own supply chain and threat model are held to the same
standard as the artefacts it sanitises. This document tracks dependency advisories and
how each was handled, states the threat model, and explains how to report a problem.

## Threat model

- **All input is untrusted.** Scrub exists to be fed logs, configs, and terminal output,
  by design, content that may originate from hostile or compromised systems. We therefore
  do **not** treat "it only runs on localhost" as a security boundary. Front-end and
  dependency vulnerabilities are kept patched on their merits, not waved away because the
  UI is local.
- **Local-first guarantee.** There are **no network calls in the scrub/check path**, not
  in the Python core (`scrub/`), the CLI, the `--check` scanner, or the review UI's
  scrubbing flow. No telemetry, no analytics, no "phone home". The browser UI talks only
  to the local API; CORS is restricted to `127.0.0.1:3000` / `localhost:3000`.
- **Custom recognisers stay local and in-memory.** The API's `/recognizers` endpoints
  let the UI register user-supplied regex recognisers at runtime. These are held in
  memory only (never persisted, gone on restart) and the regex is compiled on the
  local, single-user service, a pathological pattern is a self-inflicted local cost,
  not a remote-exploitable surface, since the API is localhost-bound and CORS-locked.
- **Secrets are never emitted unmasked.** The CLI writes the reversible mapping (which
  contains the real secrets) only to the path you pass via `--mapping`, never to stdout.
  The `--check` scanner and the git pre-commit hook mask every value in their reports so
  secrets never land in terminal scrollback. The UI keeps mappings in memory only.
- **The pre-commit hook must stay LF-terminated.** A CRLF on the shebang line breaks the
  hook under many shells, and a broken pre-commit hook fails *open*, it silently stops
  running, the worst failure mode for a leak-prevention control. The repo's
  `.gitattributes` forces LF on `hooks/pre-commit` and `*.sh` so a contributor with
  `core.autocrlf=true` cannot corrupt it.

## Dependency advisories

### Resolved

| ID | Package | Severity | Status |
|----|---------|----------|--------|
| `CVE-2025-66478` | `next` | **Critical** | **Patched.** `next` installed at `15.1.6` during the UI build, which carried this CVE. Upgraded to the patched **`15.5.18`** (latest 15.5.x). |
| `GHSA-qx2v-qp2m-jg93` | `postcss` (`<8.5.10`) | Moderate | **Patched.** XSS via unescaped `</style>` in PostCSS's CSS-stringify output. The vulnerable copy was transitive, nested inside Next's internals (`node_modules/next/node_modules/postcss`). npm's automated `audit fix --force` proposed a **breaking downgrade to `next@9.3.3`**, which we rejected. Instead we added an npm `overrides` entry pinning `postcss` to `^8.5.10`; because it stays within the same major (8.x) it is non-breaking. This hoists a single patched PostCSS (currently `8.5.15`) and removes Next's vulnerable nested copy. Verified with `npm run build` (green) and `npm audit` (**0 vulnerabilities**). |

Current `npm audit` (assessed **2026-05-28**): **0 vulnerabilities.**

### How we decide

For every advisory: if a non-breaking patched version exists, we apply it, regardless of
severity (`npm overrides` counts as a patch when it stays within a compatible major). We
reject "fixes" that trade a smaller issue for a larger regression (e.g. downgrading the
whole framework several major versions, which would itself drop security patches). Any
advisory we cannot patch without such a regression is recorded here as an accepted,
documented, transitive risk with the date assessed and the upstream condition that will
resolve it, never left silent.

## Continuous checks

CI (`.github/workflows/ci.yml`) runs on every push and pull request:

- `pytest` for the Python core,
- `tsc --noEmit` and `next build` for the UI,
- `npm audit --audit-level=high` for the UI, **gated at `high`**: a newly introduced
  **high or critical** advisory fails the build, while known moderates pass. This makes a
  new critical impossible to merge silently without making the gate so noisy that known,
  triaged moderates would block unrelated work.

## Reporting a vulnerability

Please **open an issue** on the project's GitHub repository describing the problem and how
to reproduce it. If the issue is sensitive, note that in the report and avoid posting
working exploit details or real secrets; we will follow up on a private channel.
