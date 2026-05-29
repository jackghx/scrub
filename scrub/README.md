# Scrub, the local-first security-artefact sanitiser

Strip infrastructure identifiers and secrets out of logs, configs, and terminal
output **before** you paste them into a public GitHub issue, a vendor ticket, a
forum, or a blog post.

> **The data never leaves your machine.** That is the entire point, a hard
> constraint, not a preference. There are **no network calls in the scrubbing
> path**: no cloud APIs, no telemetry, no phone-home. Scrub runs in-process on
> `127.0.0.1`.

Scrub is deliberately **not** a general PII tool. Presidio, OpenAI's Privacy
Filter, etc. already handle human PII (names, emails, SSNs) well, and they ignore
the things that actually leak in security work: internal IPs, hostnames, MACs,
cloud keys, tokens, private keys, connection strings. Scrub fills that gap and adds
the piece those tools don't: **consistent, reversible pseudonymisation**, so the
scrubbed artefact stays analytically useful.

## What "consistent, reversible" means

Redaction throws information away (`<REDACTED>` everywhere) and breaks the trace.
Scrub instead maps each distinct value to a **stable, human-readable placeholder**:

```
default via 10.10.10.1 dev eth0          ->  default via <INTERNAL_IP_1> dev eth0
upstream 10.10.10.2 timed out            ->  upstream <INTERNAL_IP_2> timed out
retry succeeded via 10.10.10.2:8080      ->  retry succeeded via <INTERNAL_IP_2>:8080
```

* The **same** raw value gets the **same** placeholder everywhere it appears, so
  you can still follow which host talked to which.
* Distinct values of a type get `_1`, `_2`, … in order of first appearance.
* The mapping `{placeholder: original}` is returned so you can **restore the
  original byte-for-byte** later.

> **Keep the mapping secret.** It contains the original secrets. `.gitignore`
> already excludes `*.mapping.json`. Treat it like the credentials it holds.

## Review before export, by design

`scrub` returns the **full list of detections** (entity type, span offsets, score,
placeholder, original), not just the scrubbed text. That's so a UI (or you) can
diff the result and toggle individual detections off before exporting. **No
detector catches everything**, and over-eager detectors flag false positives;
Scrub's defaults favour recall (better to over-scrub than leak), and the
detections list is your chance to correct it. Always eyeball the output.

## Install

Requires Python 3.9+.

```bash
cd scrub
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
```

That's all you need for the default mode, **no spaCy model download required.**

## Quick start (custom-recognisers-only, the default)

```python
from scrubber import Scrubber

s = Scrubber()                      # custom security pack only, no spaCy
result = s.scrub("default via 10.10.10.1 dev eth0; again 10.10.10.1")

print(result.scrubbed_text)         # default via <INTERNAL_IP_1> dev eth0; again <INTERNAL_IP_1>
print(result.mapping)               # {'<INTERNAL_IP_1>': '10.10.10.1'}
print(result.detections)            # [{entity_type, start, end, score, placeholder, original}, ...]

assert s.restore(result.scrubbed_text, result.mapping) == \
    "default via 10.10.10.1 dev eth0; again 10.10.10.1"
```

## Run the API

```bash
cd scrub
uvicorn main:app --host 127.0.0.1 --port 8000
```

Localhost only, by design, don't expose it via router port-forwarding. (If you
ever need remote access, front it with an authenticated tunnel.)

| Method | Path        | Body                              | Returns                            |
|--------|-------------|-----------------------------------|------------------------------------|
| POST   | `/scrub`    | `{ "text": "..." }`               | `{ scrubbed, mapping, detections }`|
| POST   | `/restore`  | `{ "text": "...", "mapping": {} }`| `{ "original": "..." }`            |
| GET    | `/entities` | (none)                            | `{ "entities": [...] }`            |
| GET    | `/health`   | (none)                            | `{ "status": "ok", "mode": ... }`  |

```bash
# scrub
curl -s -X POST 127.0.0.1:8000/scrub \
  -H 'content-type: application/json' \
  -d '{"text": "gateway 10.10.10.1 then 10.10.10.1 again"}'

# restore
curl -s -X POST 127.0.0.1:8000/restore \
  -H 'content-type: application/json' \
  -d '{"text": "gateway <INTERNAL_IP_1> then <INTERNAL_IP_1> again", "mapping": {"<INTERNAL_IP_1>": "10.10.10.1"}}'

curl -s 127.0.0.1:8000/entities
curl -s 127.0.0.1:8000/health
```

Interactive docs at <http://127.0.0.1:8000/docs>.

> **CORS:** the API allows cross-origin requests **only** from
> `http://127.0.0.1:3000` and `http://localhost:3000` (the review UI's dev origin).
> This is deliberately localhost-only and must never be broadened, a permissive CORS
> policy would let any web page you visit talk to your local scrubber.

## Review UI (v0.2)

The API is the engine; the **review UI** in [`../ui`](../ui) is how you actually use it
safely. Detection runs recall-favoured (it surfaces everything), so the point is a
**human-in-the-loop review before export**: you see every detection as a colour-coded
chip, toggle individual ones on/off, and copy out a result you're confident in. The
tool surfaces and applies, *you* decide what's safe. It never claims the output is
"clean".

Run the two together (two terminals):

```bash
# terminal 1, the API
cd scrub
uvicorn main:app --host 127.0.0.1 --port 8000

# terminal 2, the UI
cd ui
npm install      # first time only
npm run dev      # http://localhost:3000
```

Open <http://localhost:3000>, paste an artefact (try `scrub/sample.log`), hit **Scrub**.
Point the UI at a non-default API with `NEXT_PUBLIC_SCRUB_API`
(e.g. `NEXT_PUBLIC_SCRUB_API=http://127.0.0.1:8000 npm run dev`).

**Originals are masked by default** (`AKIA••••••••EXAMPLE`) with a per-row reveal and a
global "reveal originals" toggle that is **off** on load, so the screen is safe to
screen-share or screenshot. **Nothing secret is persisted**, the mapping that can
reverse a scrub (it holds the real secrets) is kept **in memory only**; it is never
written to disk, `localStorage`, or anywhere else, and dies on reload. See
[`../ui/README.md`](../ui/README.md) for the full UI walkthrough.

## Command-line interface (v0.3)

Install the CLI once (puts a `scrub` command on PATH; editable, so code changes take
effect immediately):

```bash
cd ..            # repo root, where pyproject.toml lives
pip install -e .
scrub --help
```

`scrub` reads a file or **stdin** and writes scrubbed text to **stdout**, only the
scrubbed text goes to stdout, so it pipes cleanly; all diagnostics go to stderr.

```bash
scrub app.log                       # scrub a file -> stdout
cat app.log | scrub                 # scrub a pipe -> stdout
scrub app.log --mapping m.json      # ALSO save the reversible mapping to m.json
scrub --restore m.json scrubbed.txt # reconstruct the original (byte-for-byte) -> stdout
```

- **`--mapping PATH`** is the *only* way the mapping is ever written, it holds the real
  secrets, so it never goes to stdout and is never written unless you ask. Keep it safe
  (the repo `.gitignore` excludes `*.mapping.json`).
- **`--threshold/-t FLOAT`** (default **0.6**) only applies detections scoring ≥ the
  threshold. 0.6 is the high-confidence cut. Use **`-t 0`** to scrub everything (recall
  over precision) when you'd rather over-scrub than risk a miss.
- **Context-aware in custom-only mode.** Some recognisers carry a deliberately low base
  score and rely on nearby *context words* to become confident, e.g. `AWS_SECRET_KEY`
  is 0.35 on its own (it matches any 40-char blob) but rises to 0.70 when `aws`/`secret`/
  `key` appear next to it, as in `aws_secret_access_key = …`. Presidio does this with an
  NLP engine; since custom-only mode ships without spaCy, Scrub applies an equivalent
  **spaCy-free** boost (see `context_enhancer.py`), so `aws_secret_access_key = <blob>`
  *is* scrubbed at the default 0.6 while a bare blob in unrelated text stays below it.
- **Surface, never silently drop.** Detections that fall *below* the threshold (and so
  are not scrubbed) are still printed, **masked**, to **stderr**, with the exact
  `--threshold` to include them. A real-but-low-confidence secret is therefore visible,
  never invisible; stdout stays clean for piping.

### Block secrets at commit time, `scrub --check`

`scrub --check` is a detection-only mode for git hooks: it prints a **masked** report to
stderr and **exits 1** if any secret at/above the threshold is found, **0** if clean.

```bash
scrub --check app.log               # report -> stderr, exit 1 if secrets found
scrub --check --allow PUBLIC_IP src/*.conf   # ignore an entity type you commit on purpose
```

The report masks every value (`AKIA••••••••MPLE`), with file and line number, so the
scan itself never leaks a secret into your terminal scrollback. `--check` also defaults
to threshold **0.6** on purpose: a commit hook that cries wolf on low-confidence guesses
gets disabled by its user, which is the worst outcome.

**Non-blocking near-miss notice.** When `--check` *passes* (exit 0) but there were
*sub-threshold* detections it did not block, it prints a single masked notice to stderr
and still exits 0, so a borderline secret on a passing commit is visible rather than a
silent false-confidence:

```
scrub: note: commit allowed; 1 sub-threshold detection NOT blocked:
  HOSTNAME db.i••••rnal (0.25).
  Review if sensitive; re-run with --threshold 0.25 to block on these.
```

This never blocks (exit code is unchanged), never prints on a fully clean file, and is
not appended when the commit is already blocked (one clear message per outcome). Pass
**`--no-near-miss`** to silence it; exit codes are unaffected.

### The git pre-commit hook

Two adoption paths, both in [`../hooks`](../hooks):

```bash
# 1. standalone hook (no extra tooling), run from inside the repo you want to protect
/path/to/scrub/repo/hooks/install.sh      # copies hooks/pre-commit -> .git/hooks, chmod +x
```

```yaml
# 2. pre-commit framework users: the repo ships ../.pre-commit-config.yaml
#    pip install pre-commit && pre-commit install
```

The hook scans the **staged content** of staged text files with `scrub --check`; a
non-zero exit aborts the commit. It is an honest **safety net, not enforcement**, it is
bypassable with `git commit --no-verify`, and it says so when it blocks you. It needs
`scrub` on PATH (`pip install -e .`).

> **The hook must stay LF-terminated.** A CRLF on the shebang line breaks the script
> under many shells, and a broken pre-commit hook fails *open*, it silently stops
> running, the worst failure mode for a security control. The repo's `.gitattributes`
> forces LF on `hooks/pre-commit` and `*.sh` so a contributor with `core.autocrlf=true`
> can't accidentally corrupt it.

## Detected entity types

`MAC_ADDRESS`, `INTERNAL_IP`, `PUBLIC_IP`, `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`,
`AWS_ACCOUNT_ID`, `GITHUB_TOKEN`, `SLACK_TOKEN`, `GOOGLE_API_KEY`, `STRIPE_KEY`,
`JWT`, `PRIVATE_KEY_BLOCK`, `BEARER_TOKEN`, `DB_CONNECTION_STRING`,
`GENERIC_API_KEY`, `UNIX_HOME_PATH`, `HOSTNAME`.

See `security_recognizers.py` for the patterns, scores, and context words. IPs are
validated with the stdlib `ipaddress` module and split into internal vs public.

## Optional: full Presidio mode (built-in PII too)

If you also want Presidio's built-in human-PII recognisers (`PERSON`,
`EMAIL_ADDRESS`, …) on top of the security pack, enable the NLP engine. This needs
a spaCy model:

```bash
python -m spacy download en_core_web_lg
```

```python
from scrubber import Scrubber
s = Scrubber(use_nlp_engine=True)            # security pack + built-in PII
# custom model name: Scrubber(use_nlp_engine=True, model="en_core_web_sm")
```

Or for the API, set the environment variable before launching:

```bash
SCRUB_USE_NLP=1 uvicorn main:app --host 127.0.0.1   # (PowerShell: $env:SCRUB_USE_NLP=1)
```

If the model isn't installed, Scrub fails fast with a clear message telling you the
exact `python -m spacy download ...` command, it never silently degrades.

## Tests

```bash
cd scrub
pytest
```

The suite covers the recogniser pack (the original 19 cases, wired in via
`tests/test_recognizers_pytest.py`), the pseudonymiser (consistency, distinct
indexing, overlap resolution, round-trip, passthrough, custom format), and the
`Scrubber` end-to-end on `sample.log`. All tests run in custom-only mode, so **no
spaCy model is needed to go green.**

The original standalone recogniser harness is preserved verbatim and still runs on
its own (prints the 19/19 table):

```bash
cd scrub
python -m tests.test_recognizers
```

## Layout

```
scrub/
  security_recognizers.py   # the Presidio recogniser pack (foundation)
  pseudonymizer.py          # consistent, reversible placeholder substitution
  scrubber.py               # ties detection + pseudonymisation together
  main.py                   # FastAPI service (4 endpoints)
  sample.log                # realistic multi-entity demo artefact
  tests/
  requirements.txt
```

## Roadmap (not built yet)

Format-preserving pseudonymisation (fake-but-valid IP/MAC), an encrypted vault for
the mapping at rest, screenshot OCR + visual redaction, a CLI (`cat app.log |
scrub`), and a git pre-commit hook. Any future LLM recogniser must be a **local**
model (e.g. Ollama) and clearly opt-in, the local-first promise is non-negotiable.
```
