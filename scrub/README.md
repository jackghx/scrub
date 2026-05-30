# Scrub engine (`scrub/`)

The detection + pseudonymisation core behind Scrub: the recogniser pack, the consistent
pseudonymiser, the `scrub` **CLI**, and the localhost **API**. This document is the
engine/CLI/API reference.

> For what Scrub is and why it exists, see the [project README](../README.md). For the
> review front end, see [`ui/README.md`](../ui/README.md). This file does not repeat the
> overview, it covers the engine specifics only.

---

## Install

```bash
pip install -e .
```

This puts a `scrub` command on your PATH. The CLI's only runtime dependencies are
`presidio-analyzer` and `click`. Everything else is an optional extra:

- `pip install -e ".[api]"` adds the API service (FastAPI + uvicorn) the review UI uses.
- `pip install -e ".[dev]"` adds the test runner (pytest).
- The full-Presidio mode additionally needs a spaCy model (see [below](#optional-full-presidio-mode)).

The names in brackets are literal pip "extras" defined in
[`pyproject.toml`](../pyproject.toml), type them as-is; combine them with
`pip install -e ".[api,dev]"`.

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

`--check`'s non-zero exit on a finding is exactly what the git pre-commit hook relies on,
see the [hook section in the project README](../README.md#git-pre-commit-hook).

---

## The local API

The engine ships a localhost FastAPI service (this is what the review UI talks to).
Install the API extra (`pip install -e ".[api]"`), then run it **from `scrub/`**:

```bash
cd scrub
uvicorn main:app --host 127.0.0.1 --port 8000
```

> Run `uvicorn` from inside `scrub/`, the service imports its sibling modules flat, so
> the command won't resolve from the repo root.

Endpoints (all localhost-only, no external calls in the scrub path):

| Method + path | Purpose |
| --- | --- |
| `POST /scrub` | `{text}` → `{scrubbed, mapping, detections}` |
| `POST /restore` | `{text, mapping}` → `{original}` |
| `GET /entities` | the entity types the pack can produce |
| `GET /recognizers` | list the in-memory custom recognisers |
| `POST /recognizers` | register a custom regex recogniser (400 on a bad pattern) |
| `DELETE /recognizers/{entity}` | remove one by entity token (404 if unknown) |
| `GET /health` | `{status, mode}` (`custom-only` or `full`) |

CORS is locked to `http://localhost:3000` / `http://127.0.0.1:3000` only. To launch the
full UI on top of this API, see the
[project quickstart](../README.md#get-started-the-review-ui).

---

## What it detects

The pack ships **33 entity types** across network identifiers, cloud/provider keys,
source-control and chat tokens, auth tokens, crypto and connection strings, and a little
PII; the [full per-type list is in the project README](../README.md#what-it-detects). Two
types are validated in code rather than trusted to a regex: IP addresses (via the stdlib
`ipaddress` module) and credit cards (via the Luhn checksum). Several false-positive-prone
patterns are scored low on purpose and only cross the threshold when supporting context
words are nearby.

At runtime the live list comes from `GET /entities` or `Scrubber().entities()`, and you
can register your own regex recognisers (`add_custom_recognizer`, or the `/recognizers`
endpoints) to run alongside the built-in pack.

---

## How it works

- **Stable, reversible pseudonymisation.** Every occurrence of the same value gets
  the same placeholder, so the scrubbed artefact still reads as a coherent trace;
  the kept mapping reconstructs the original byte-for-byte.
- **Context-aware scoring.** In the default (custom-pack-only, no-spaCy) mode, a
  lightweight character-window check (`context_enhancer.py`) raises a detection's score
  when the recogniser's context words are nearby, so a real AWS secret next to
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
- **`main.py`:** the localhost API.

---

## Testing

Install the test extra (adds pytest), then run the suite from this folder:

```bash
pip install -e ".[dev]"
pytest
```

---

## License

MIT. See [`../LICENSE`](../LICENSE).

---

*The detected-entity list and CLI flags are the two things most likely to drift from the
code; keep them honest as recognisers are added.*
