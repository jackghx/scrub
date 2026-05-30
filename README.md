![CI](https://github.com/jackghx/scrub/actions/workflows/ci.yml/badge.svg)

# Scrub, the local-first security-artefact sanitiser

Scrub removes secrets and infrastructure identifiers from logs, configs, and terminal
output before you share them in a GitHub issue, a support ticket, a forum, or a blog
post. It shows you what it found so you can review and adjust the result before copying
it out.

<p align="center">
  <img src="https://github.com/user-attachments/assets/3075d7b0-daa0-4606-97ce-50dd41205143" width="900" alt="Scrub review UI: original left, scrubbed output with coloured chips right, detections list visible">
</p>


> **The data never leaves your machine.** There are no network calls in the scrubbing
> path and no telemetry. The API runs on `127.0.0.1`, and the UI's browser only ever
> talks to that local API.

It isn't a general-purpose PII tool. It focuses on what tends to leak in security and
infrastructure work: internal IPs, hostnames, MAC addresses, cloud keys, tokens, private
keys, and connection strings. Each match is replaced with a stable, reversible
placeholder like `<INTERNAL_IP_1>`, so the scrubbed file still reads sensibly and you can
restore the original exactly from the saved mapping.

---

## Human in the loop

Scrub favours recall: it flags everything it suspects, because missing a secret is worse
than flagging one that turns out to be harmless. That trade-off only works if you can see
and correct what it flagged, so the tool applies its detections but leaves the final call
to you. The UI shows every detection and lets you toggle each one, and it never describes
the output as "safe" or "clean". Check the result yourself before you share it.

<p align="center">
  <img src="https://github.com/user-attachments/assets/44cfd40f-30af-4c32-805d-c1c945b11a32" width="900" alt="Detections list">
</p>

A dismissed detection is restored to its original value in the output and marked with an
amber warning highlight, so anything you choose to keep in the clear is impossible to miss.


---

## Three ways to use it

| Use | What you get | Docs |
|-----|------|-------|
| **Review UI** | A two-pane paste → review → export screen with per-detection toggles. The easiest place to start. | [Get started](#get-started-the-review-ui) · [`ui/README.md`](ui/README.md) |
| **CLI** | The `scrub` command for piping, scripting, and CI. | [Command line](#command-line) · [`scrub/README.md`](scrub/README.md) |
| **Pre-commit hook** | A git hook that blocks commits containing secrets. | [Git pre-commit hook](#git-pre-commit-hook) |

All three sit on the same detection engine in [`scrub/`](scrub). The front end lives in
[`ui/`](ui); the hook in [`hooks/`](hooks). This page is the overview and quickstart;
the per-folder READMEs have the full reference.

---

## Get started (the review UI)

**You need:** Python 3.9+ and Node.js 18+ (with npm). That's it, the default mode needs
no NLP model.

**1. Install Scrub with the API server** (from the repo root):

```bash
pip install -e ".[api]"
```

This puts the `scrub` command on your PATH *and* installs the local API (FastAPI +
uvicorn) the UI talks to. To keep Scrub's dependencies isolated from your system Python,
run it inside a virtualenv first (`python -m venv .venv`, then activate it).

**2. Start the API** (terminal 1):

```bash
cd scrub
uvicorn main:app --host 127.0.0.1 --port 8000
```

**3. Start the UI** (terminal 2):

```bash
cd ui
npm install        # first run only
npm run dev
```

**4. Open <http://localhost:3000>.** Paste an artefact (try
[`scrub/sample.log`](scrub/sample.log)), hit **Scrub**, review the colour-coded
detections, toggle anything you want to keep in the clear, and copy the result. Switch to
the diff view to compare the original against the scrubbed output side by side.

<p align="center">
  <img src="https://github.com/user-attachments/assets/98ba30d9-d5a3-4658-84ad-32f5746d2906" width="900" alt="Diff view">
</p>


> The UI talks only to `http://127.0.0.1:8000`; override with `NEXT_PUBLIC_SCRUB_API`.
> Full UI behaviour, the toggle model, diff view, and production build, is documented in
> [`ui/README.md`](ui/README.md).

---

## Command line

If you only want the `scrub` command (no UI), the install is one line from the repo root:

```bash
pip install -e .
```

That's all the CLI needs, no web server, no NLP model. Then:

```bash
scrub app.log                        # print the scrubbed text to your terminal
scrub app.log > clean.txt            # ...or write it straight to a file
cat app.log | scrub                  # also works in a pipe (reads from stdin)
scrub app.log --mapping map.json > clean.txt   # save the result AND the mapping that can undo it
scrub --restore map.json clean.txt   # rebuild the original from a scrubbed file + its mapping
scrub --check app.log                # just report what it found (masked), exit 1 if any secret found
```

Only the scrubbed (or restored) text is printed, so `>` and pipes stay clean; every
report, warning, and error goes to a separate stream instead of mixing into that output.
The mapping holds the real secrets, so it's written only to the `--mapping` file you name,
never printed. The **full flag table** (`--threshold`, `--allow`, `--check`, and the rest)
is in [`scrub/README.md`](scrub/README.md#cli-usage).



---

## Git pre-commit hook

`scrub --check` exits non-zero when it finds a secret, which lets a git pre-commit hook
abort the commit before secrets are ever committed. With the CLI installed
(`pip install -e .`), install the hook into this repo:

```bash
./hooks/install.sh        # copies hooks/pre-commit into .git/hooks
```

…or, for [pre-commit](https://pre-commit.com) framework users, the repo ships a
[`.pre-commit-config.yaml`](.pre-commit-config.yaml) (`pip install pre-commit && pre-commit install`).

**On Windows:** the hook is a bash script; git runs it through the Git Bash that ships
with Git, so run `./hooks/install.sh` from a Git Bash shell (or use the cross-platform
`pre-commit` route above).

The hook blocks a commit on any high-confidence finding and prints a **masked** report,
so secrets never hit your scrollback. It can be bypassed with `git commit --no-verify`,
so treat it as a safety net rather than a guarantee. It scans the *staged* content of
each text file; see [`hooks/pre-commit`](hooks/pre-commit) for the script itself.

---

## What it detects

The detection pack ships **33 entity types**. Two are validated in code rather than
trusted to a regex, IP addresses (via the standard-library `ipaddress` module) and credit
cards (via the Luhn checksum), and several patterns that are prone to false positives are
scored low on purpose, so they only cross the threshold when supporting context words
appear nearby.

- **Network identifiers:** `INTERNAL_IP`, `PUBLIC_IP` (IPv4 + IPv6, validated),
  `MAC_ADDRESS`, `HOSTNAME`
- **Cloud / provider keys:** `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `AWS_ACCOUNT_ID`,
  `GOOGLE_API_KEY`, `STRIPE_KEY`, `OPENAI_KEY`, `OPENROUTER_KEY`, `FCM_SERVER_KEY`,
  `SENDGRID_KEY`, `TWILIO_SID`
- **Source-control / package tokens:** `GITHUB_TOKEN`, `GITLAB_TOKEN`, `NPM_TOKEN`,
  `SHOPIFY_TOKEN`
- **Chat tokens & webhooks:** `SLACK_TOKEN`, `SLACK_WEBHOOK`, `DISCORD_TOKEN`,
  `DISCORD_WEBHOOK`, `TELEGRAM_BOT_TOKEN`
- **Auth tokens / generic secrets:** `JWT`, `BEARER_TOKEN`, `GENERIC_API_KEY`
- **Crypto / connection strings:** `PRIVATE_KEY_BLOCK` (PEM), `SSH_PUBLIC_KEY`,
  `DB_CONNECTION_STRING`, `URL_WITH_CREDENTIALS`
- **PII:** `EMAIL_ADDRESS`, `CREDIT_CARD` (Luhn-validated)
- **Filesystem:** `UNIX_HOME_PATH` (username leak)

The current list is always available from the API (`GET /entities`) or
`Scrubber().entities()`. You can also add your own regex recognisers at runtime from the
review UI; they run alongside the built-in pack.

<img width="1891" height="292" alt="image" src="https://github.com/user-attachments/assets/3d5ec0d1-9d20-49af-8778-2d4e709350ef" />
<img width="1893" height="403" alt="image" src="https://github.com/user-attachments/assets/dbe25fe4-84a5-4cf1-b5e8-827cb302bd8a" />


---

## Security & CI

Dependency advisories are triaged and documented in [`SECURITY.md`](SECURITY.md) (a
security tool shouldn't ship untriaged vulns), and
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the Python tests, the UI
build/type-check, and a dependency audit gated at `high` on every push and PR. To run the
Python tests yourself, install the test extra (`[dev]`, which adds pytest), then run the
suite from `scrub/`:

```bash
pip install -e ".[dev]"
cd scrub && pytest
```

---

## No persistence of secrets

The mapping that reverses a scrub holds the real secrets. It is returned by the API for
the caller to hold and is kept **in memory only** in the UI. It is never written to disk,
`localStorage`, or anywhere else. The repo's `.gitignore` also excludes
`*.mapping.json`. Treat any mapping you do save like the credentials it contains.

---

## Known limitations

Detection is **pattern + context based**, not semantic, so novel or obfuscated secrets
may not match, and at low thresholds bare values can be mislabelled (the long tail favours
recall). The pack is not exhaustive; it targets what actually leaks in security/infra
work. **Review before export is the safety net:** Scrub surfaces what it found (and what
it nearly found); a human still decides what is safe to share. The engine internals, and
the optional full-Presidio mode that adds human-PII recognisers, are in
[`scrub/README.md`](scrub/README.md#optional-full-presidio-mode).

---

## Roadmap (not built yet)

Format-preserving pseudonymisation (fake-but-valid IP/MAC), an encrypted vault for the
mapping at rest, and screenshot OCR + visual redaction. Any future LLM recogniser would
have to run locally (for example via Ollama) and be opt-in, so the local-first behaviour
still holds.

---

## License

MIT, see [`LICENSE`](LICENSE).
