![CI](https://github.com/jackghx/scrub/actions/workflows/ci.yml/badge.svg)
# Scrub, the local-first security-artefact sanitiser

Strip infrastructure identifiers and secrets out of logs, configs, and terminal output
**before** you paste them into a public GitHub issue, a vendor ticket, a forum, or a
blog post, and then **review what was detected and decide what to scrub** before you copy
it out.

> **The data never leaves your machine.** That's the whole pitch, not a preference.
> There are no network calls in the scrubbing path, no telemetry, no phone-home. The API
> runs on `127.0.0.1`; the UI's browser talks only to that local API.

Scrub is not a general PII tool. It targets what actually leaks in security work,
internal IPs, hostnames, MACs, cloud keys, tokens, private keys, connection strings,
and adds the piece general tools don't: **consistent, reversible pseudonymisation**
(`<INTERNAL_IP_1>`), so the scrubbed artefact stays analytically useful and can be
restored byte-for-byte.

## Human-in-the-loop, by design

Detection is **recall-favoured**, it surfaces everything, because under-scrubbing leaks
a secret. That's only safe if a human can see and correct what was flagged. So Scrub
**surfaces and applies; you decide**. The UI shows every detection, lets you toggle each
one, and **never claims the output is "safe" or "clean"**. Always eyeball the result
before sharing.

## Three ways to use it

| Dir | What | Stack |
|-----|------|-------|
| [`scrub/`](scrub) | The engine: detectors + consistent pseudonymiser + FastAPI service (`/scrub`, `/restore`, `/entities`, `/health`) **and the `scrub` CLI** | Python, Presidio |
| [`ui/`](ui) | The review front end: two-pane paste → review → export, with per-detection toggles | Next.js, TypeScript, Tailwind |
| [`hooks/`](hooks) | A git **pre-commit hook** that blocks commits containing secrets (built on `scrub --check`) | bash |

## Quick start (run both)

```bash
# terminal 1 – the API (no spaCy model needed for the default mode)
cd scrub
python -m venv .venv && . .venv/Scripts/activate   # or: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000

# terminal 2 – the UI
cd ui
npm install
npm run dev        # open http://localhost:3000
```

Paste an artefact (try [`scrub/sample.log`](scrub/sample.log)), hit **Scrub**, review the
colour-coded detections, toggle anything you want to keep in the clear, and copy the
result. See [`scrub/README.md`](scrub/README.md) and [`ui/README.md`](ui/README.md) for
details, the optional full-Presidio mode, and tests.

## Command line + git pre-commit hook

Install the CLI (puts `scrub` on PATH):

```bash
pip install -e .          # from the repo root
```

```bash
scrub app.log                      # scrubbed text -> stdout
cat app.log | scrub                # pipeable
scrub app.log --mapping m.json     # also save the reversible mapping (holds secrets)
scrub --restore m.json scrubbed.txt   # reconstruct the original, byte-for-byte
scrub --check app.log              # masked report -> stderr; exit 1 if secrets found
```

**Block secrets at commit time.** The `scrub --check` mode exits non-zero when it finds
a secret, which lets a git pre-commit hook abort the commit:

```bash
./hooks/install.sh        # copies hooks/pre-commit into this repo's .git/hooks
```

…or, for [pre-commit](https://pre-commit.com) framework users, the repo ships a
[`.pre-commit-config.yaml`](.pre-commit-config.yaml) (`pre-commit install`). Reports are
**masked** so secrets never hit your scrollback, and the hook is an honest safety net which is
bypassable with `git commit --no-verify`. Full CLI + hook docs in
[`scrub/README.md`](scrub/README.md).

## Security & CI

Dependency advisories are triaged and documented in [`SECURITY.md`](SECURITY.md) (a
security tool shouldn't ship untriaged vulns), and [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
runs the Python tests, the UI build/type-check, and a dependency audit gated at `high` on
every push and PR.

## No persistence of secrets

The mapping that reverses a scrub holds the real secrets. It is returned by the API for
the caller to hold and is kept **in memory only** in the UI. It is never written to disk,
`localStorage`, or anywhere else. The repo's `.gitignore` also excludes
`*.mapping.json`. Treat any mapping you do save like the credentials it contains.

## Roadmap (not built yet)

Format-preserving pseudonymisation (fake-but-valid IP/MAC), an encrypted vault for the
mapping at rest, and screenshot OCR + visual redaction. Any future LLM recogniser must be
a **local** model (e.g. Ollama) and opt-in, the local-first promise is non-negotiable.
