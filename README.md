# Scrub, local-first security-artefact sanitiser

**Strip secrets and infrastructure identifiers out of logs, configs, and terminal
output before you share them, with a human review step so you decide what leaves
your machine.**

Scrub runs entirely on your machine. Paste or pipe in an artefact; it detects
internal IPs, hostnames, cloud keys, tokens, private keys, and connection strings,
replaces each with a stable placeholder (e.g. `<INTERNAL_IP_1>`), and gives you a
diff to review before anything is exported. Nothing is ever sent anywhere.

---

## Why

Engineers leak secrets every day by pasting logs into GitHub issues, vendor
tickets, forums, and chat. General PII tools target names and emails; they miss
the things that actually leak in security and infrastructure work: internal IPs,
MAC addresses, cloud keys, JWTs, private-key blocks, DB connection strings.

Scrub fills that gap, and keeps a reversible mapping so the scrubbed artefact
stays useful (you can follow which host talked to which) without exposing the real
identifiers.

---

## What it detects

The detection pack ships **33 entity types**. Two are validated in code rather than
trusted from a regex, IP addresses via the stdlib `ipaddress` module, and credit
cards via the Luhn checksum, and several FP-prone patterns are deliberately scored
low and only cross the threshold when supporting context words are nearby.

- **Network identifiers:** `INTERNAL_IP`, `PUBLIC_IP` (IPv4 + IPv6, validated),
  `MAC_ADDRESS`, `HOSTNAME`
- **Cloud / provider keys:** `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `AWS_ACCOUNT_ID`,
  `GOOGLE_API_KEY`, `STRIPE_KEY`, `OPENAI_KEY`, `OPENROUTER_KEY`,
  `FCM_SERVER_KEY`, `SENDGRID_KEY`, `TWILIO_SID`
- **Source-control / package tokens:** `GITHUB_TOKEN`, `GITLAB_TOKEN`,
  `NPM_TOKEN`, `SHOPIFY_TOKEN`
- **Chat tokens & webhooks:** `SLACK_TOKEN`, `SLACK_WEBHOOK`, `DISCORD_TOKEN`,
  `DISCORD_WEBHOOK`, `TELEGRAM_BOT_TOKEN`
- **Auth tokens / generic secrets:** `JWT`, `BEARER_TOKEN`, `GENERIC_API_KEY`
- **Crypto / connection strings:** `PRIVATE_KEY_BLOCK` (PEM), `SSH_PUBLIC_KEY`,
  `DB_CONNECTION_STRING`, `URL_WITH_CREDENTIALS`
- **PII:** `EMAIL_ADDRESS`, `CREDIT_CARD` (Luhn-validated)
- **Filesystem:** `UNIX_HOME_PATH` (username leak)

The live list is always available from the API (`GET /entities`) or
`Scrubber().entities()`. You can also add your own regex recognisers at runtime
from the review UI (see below), they run alongside the built-in pack.

---

## Install

```bash
pip install -e .
```

This puts a `scrub` command on your PATH. The only runtime dependency for the CLI
is `presidio-analyzer`; the API service and full-Presidio mode are optional extras
(`pip install -e ".[api]"`, and a spaCy model for full mode).

---

## CLI usage

```bash
scrub app.log                      # scrubbed text -> stdout
scrub app.log --mapping m.json     # also save the reversible mapping
cat app.log | scrub                # read stdin, scrub, write stdout
scrub --restore m.json s.txt       # reconstruct the original
scrub --check app.log              # report secrets (stderr); exit 1 if any
```

| Flag | Mode | Meaning |
| --- | --- | --- |
| `FILE…` | all | Input file(s). Omit or use `-` to read stdin. Multiple files are only meaningful with `--check`. |
| `--check` | check | Detection only: print a masked report to stderr, exit 1 if any finding is at/above the threshold, else 0. Built for pre-commit hooks. |
| `--restore MAPPING.json` | restore | Reconstruct the original from scrubbed input + this mapping. |
| `--mapping PATH` | transform | Also write the reversible `{placeholder: original}` mapping as JSON to `PATH`. |
| `-t`, `--threshold N` | transform / check | Only act on detections scoring ≥ N (default `0.6`; use `0` to scrub everything, recall over precision). |
| `--allow ENTITY_TYPE` | check | Suppress an entity type, e.g. `--allow PUBLIC_IP`. Repeatable. |
| `--label NAME` | check | Name to use for stdin in the report (default `<stdin>`). |
| `--no-near-miss` | check | Don't print the non-blocking notice about sub-threshold detections on a passing commit. |
| `--no-color` | all | Disable coloured output (colour is stderr-only and already auto-off when stderr isn't a TTY or `NO_COLOR` is set). |
| `--quiet` | all | Suppress the progress spinner on slow interactive runs. |
| `-V`, `--version` | n/a | Print version and exit. |

Running `scrub` with no input and an interactive terminal prints usage and exits 2
(it won't hang waiting on stdin).

The contract that keeps it pipeable and safe:

- Scrubbed / restored text is the **only** thing on **stdout**.
- Diagnostics, reports, and errors go to **stderr**, including a masked summary of
  low-confidence detections that were *not* applied, so nothing is silently dropped.
- The reversible mapping holds the real secrets, so it is written **only** to the
  `--mapping` path you ask for, never to stdout.
- `--check` and every report **mask** each value, so secrets never hit your
  scrollback or CI logs.

---

## Git pre-commit hook

`--check` is designed to drop into a git pre-commit hook so secrets are caught
before they are committed. A ready-made hook and installers live in
[`hooks/`](hooks/):

```bash
hooks/install.sh        # bash / macOS / Linux
hooks/install.ps1       # Windows PowerShell
```

The hook blocks a commit (exit 1) on any high-confidence finding and prints a
masked report; sub-threshold near-misses are noted without blocking.

---

## The review UI

A local web UI (Next.js) for the paste → review → export flow:

```bash
cd ui
npm install
npm run dev   # http://localhost:3000
```

It talks only to the local API (`http://127.0.0.1:8000`); start that with:

```bash
cd scrub
uvicorn main:app --host 127.0.0.1 --port 8000
```

What the UI gives you:

- **Paste or load files:** drag-and-drop or pick multiple files; each opens in its
  own tab. Files are read in the browser; only the text reaches the localhost API.
- **Review with line numbers:** the scrubbed output is line-numbered; click a
  detection to scroll to and highlight that line. A gutter "minimap" shows where in
  the artefact data was scrubbed.
- **Diff view:** toggle to see the original (with highlights) beside the scrubbed
  output.
- **Per-detection control:** keep/dismiss individual detections, filter/search the
  list, and move a confidence-threshold slider; the export updates instantly.
- **Custom recognisers:** add your own regex patterns at runtime (in memory only).
- **Restore round-trip:** reconstruct the original from the in-memory mapping to
  confirm the scrub is reversible.

API endpoints (all localhost-only): `POST /scrub`, `POST /restore`,
`GET /entities`, `GET /health`, and `GET/POST/DELETE /recognizers` for the custom
recogniser set.

---

## How it works

- **Stable, reversible pseudonymisation.** Every occurrence of the same value gets
  the same placeholder, so the scrubbed artefact still reads as a coherent trace;
  the kept mapping reconstructs the original byte-for-byte.
- **Context-aware scoring.** In the default (custom-pack-only, no-spaCy) mode, a
  lightweight character-window check raises a detection's score when the
  recogniser's context words are nearby, so a real AWS secret next to
  `aws_secret_access_key` clears the threshold while a bare 40-char blob does not.
- **Validated, not just matched.** IPs and credit-card numbers are validated in
  code (stdlib `ipaddress`, Luhn) rather than trusted from a regex.
- **Local-first.** No network calls in the scrub path; no telemetry.

---

## Optional: full Presidio mode

The default mode runs the custom pack only, no spaCy model needed. To also get
Presidio's built-in human-PII recognisers (`PERSON`, etc.) on top:

```bash
python -m spacy download en_core_web_lg
```

```python
Scrubber(use_nlp_engine=True)          # security pack + built-in PII
```

For the API, set `SCRUB_USE_NLP=1` before launching `uvicorn`. If the model isn't
installed, Scrub fails fast with the exact `spacy download` command, it never
silently degrades.

---

## Architecture

- **`security_recognisers.py`:** the detection pack (Presidio recognisers +
  validated IP/credit-card logic).
- **`pseudonymizer.py`:** turns detections into stable placeholders and back.
- **`scrubber.py`:** ties detection + pseudonymisation behind one `Scrubber`
  class, and holds any runtime custom recognisers.
- **`context_enhancer.py`:** spaCy-free context scoring for custom-only mode.
- **`cli.py`:** the command-line interface.
- **`main.py`:** the localhost API used by the review UI.
- **`ui/`:** the Next.js review UI.

---

## Known limitations

- Detection is **pattern + context based**, not semantic. Novel, obfuscated, or
  malformed secrets may not match, by design, the pack favours precision on the
  high-confidence patterns and leans on context for the ambiguous ones.
- At low thresholds, bare values can be mislabelled (the long tail favours recall);
  raise `--threshold`, or use the review step, to tighten this.
- The pack is **not exhaustive:** it targets the identifiers that actually leak in
  security/infra work, not every possible secret format.
- **Review before export is the safety net.** Scrub surfaces what it found (and what
  it nearly found); a human still decides what is safe to share.

---

## Testing

```bash
cd scrub && pytest
```

---

## License

MIT

---

Note to self: *This README reflects scrub v0.3.0. The detected-entity list and CLI flags are the
two things most likely to drift; keep this section honest as recognisers are added.*
