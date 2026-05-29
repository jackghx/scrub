"""
cli.py, Scrub's command-line interface
=======================================

Make Scrub usable from the terminal and from a git pre-commit hook. Three modes,
all built on the existing :class:`Scrubber` (no detection logic is reimplemented):

* **transform** (default) ::

      scrub app.log                 # scrubbed text -> stdout
      cat app.log | scrub           # read stdin, scrub, write stdout
      scrub app.log --mapping m.json    # also save the reversible mapping

* **restore** ::

      scrub --restore m.json s.txt  # reconstruct the original -> stdout
      cat s.txt | scrub --restore m.json

* **check** (detection only, for the hook) ::

      scrub --check app.log         # masked report -> stderr; exit 1 if secrets found

Contract that keeps it pipeable and safe:

* Scrubbed / restored text is the **only** thing written to **stdout**.
* All diagnostics, reports, and errors go to **stderr**.
* The reversible mapping holds the real secrets, so it is written **only** to the
  ``--mapping`` path you ask for, never to stdout, never anywhere else.
* ``--check`` and the report **mask** every value, so secrets never hit scrollback.
* No network calls, no telemetry. Local-first is the whole point.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# --- flat-import bootstrap --------------------------------------------------
# This package's modules import each other flat (``from scrubber import ...``).
# Put this directory on sys.path so those imports resolve no matter how we were
# invoked: the installed ``scrub`` console script, ``python -m scrub.cli``, or
# pytest. Mirrors scrub/conftest.py and means the core modules need no edits.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from scrubber import Scrubber  # noqa: E402  (after sys.path bootstrap)

# Default detection threshold. 0.6 is the high-confidence cut: it catches real
# secrets (keys, tokens, private keys, internal IPs) while leaving the noisy
# low-confidence long-tail (bare hostnames, 12-digit numbers) alone. Used by BOTH
# transform and --check:
#   * transform, consistent with the review UI's applied-default; a careful user
#     can scrub everything with `--threshold 0` (recall over precision) at the cost
#     of over-scrubbing noisy guesses.
#   * --check / hook, a commit hook that cries wolf gets disabled by its user, which
#     is the worst outcome; blocking on high-confidence findings keeps it trusted.
DEFAULT_THRESHOLD = 0.6


def _reconfigure_std() -> None:
    """Make the standard streams byte-exact and UTF-8.

    Two portability fixes, mostly for Windows:

    * ``newline=""`` on stdin/stdout disables the text-mode ``\\n`` <-> ``\\r\\n``
      translation, so a scrub -> restore round-trip is **byte-for-byte** regardless of
      platform (without this, stdout would rewrite line endings).
    * ``encoding="utf-8"`` so the masked report's bullet characters (and any UTF-8 in
      the artefact) are emitted correctly rather than mangled by a legacy code page.

    Guarded: under pytest's capture (or if a stream is already detached) ``reconfigure``
    may be absent or raise, in which case we leave the stream as-is.
    """
    for stream, kwargs in (
        (sys.stdin, {"encoding": "utf-8", "newline": ""}),
        (sys.stdout, {"encoding": "utf-8", "newline": ""}),
        (sys.stderr, {"encoding": "utf-8"}),
    ):
        try:
            stream.reconfigure(**kwargs)  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass


def _err(*args: object) -> None:
    """Print a diagnostic to stderr (never stdout, keeps pipes clean)."""
    print("scrub:", *args, file=sys.stderr)


def mask(value: str, head: int = 4, tail: int = 4) -> str:
    """Mask a secret for display so a report never leaks it.

    Keeps a few head/tail characters and dots the middle (``AKIA••••••••MPLE``).
    Multi-line blocks (e.g. PEM private keys) collapse to a one-line summary.
    """
    if "\n" in value:
        flat = " ".join(value.split())
        lead = flat[:head] if len(flat) >= head else flat
        return f"{lead}… ({len(value)} chars, multi-line)"
    if len(value) <= head + tail:
        return "•" * max(len(value), 4)
    dots = "•" * min(max(len(value) - head - tail, 4), 12)
    return f"{value[:head]}{dots}{value[-tail:]}"


def _read_text(path: str | None) -> str:
    """Read one source. ``None`` or ``"-"`` means stdin. ``newline=""`` preserves
    bytes so the round-trip stays exact."""
    if path is None or path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scrub",
        description=(
            "Local-first security-artefact sanitiser. Scrub secrets and infra "
            "identifiers out of logs/configs before you share them."
        ),
        epilog=(
            "Examples:\n"
            "  scrub app.log                      scrub a file to stdout\n"
            "  cat app.log | scrub                scrub a pipe to stdout\n"
            "  scrub app.log --mapping m.json     also save the reversible mapping\n"
            "  scrub --restore m.json s.txt       reconstruct the original\n"
            "  scrub --check app.log              report secrets (stderr); exit 1 if any\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "files",
        nargs="*",
        help="Input file(s). Omit (or use '-') to read stdin. "
        "Multiple files are only meaningful with --check.",
    )
    p.add_argument(
        "--check",
        action="store_true",
        help="Detection mode: report findings (masked) to stderr and exit 1 if any "
        "detection at/above the threshold is found, 0 if clean. For pre-commit hooks.",
    )
    p.add_argument(
        "--restore",
        metavar="MAPPING.json",
        help="Restore mode: reconstruct the original from scrubbed input + this mapping.",
    )
    p.add_argument(
        "--mapping",
        metavar="PATH",
        help="(transform only) Also write the reversible {placeholder: original} mapping "
        "as JSON to PATH. The mapping holds the real secrets, keep it safe; it is never "
        "written anywhere unless you pass this.",
    )
    p.add_argument(
        "-t",
        "--threshold",
        type=float,
        default=None,
        help=f"Only act on detections with score >= THRESHOLD (default {DEFAULT_THRESHOLD}). "
        "Use 0 to scrub everything (recall over precision).",
    )
    p.add_argument(
        "--allow",
        action="append",
        metavar="ENTITY_TYPE",
        help="(--check only) Suppress an entity type, e.g. --allow PUBLIC_IP. Repeatable.",
    )
    p.add_argument(
        "--label",
        metavar="NAME",
        default="<stdin>",
        help="(--check only) Name to use for stdin in the report (default '<stdin>').",
    )
    p.add_argument(
        "--no-near-miss",
        action="store_true",
        help="(--check only) Don't print the non-blocking notice about sub-threshold "
        "detections on a passing commit. Exit codes are unaffected.",
    )
    p.add_argument("-V", "--version", action="store_true", help="Print version and exit.")
    return p


def _print_near_miss(subthreshold: list, threshold: float) -> None:
    """Non-blocking notice (stderr, exit code unchanged) listing MASKED sub-threshold
    detections that were NOT blocked on a passing commit, so a borderline secret is
    visible rather than a silent false-confidence."""
    # One entry per unique (entity, value); show the lowest-scoring first.
    seen: dict = {}
    for entity, original, score in subthreshold:
        key = (entity, original)
        if key not in seen:
            seen[key] = (entity, mask(original), score)
    rows = sorted(seen.values(), key=lambda r: r[2])
    lowest = min(r[2] for r in rows)
    items = ", ".join(f"{e} {m} ({s:.2f})" for e, m, s in rows)
    plural = "s" if len(rows) != 1 else ""
    print(
        f"scrub: note: commit allowed; {len(rows)} sub-threshold detection{plural} "
        f"NOT blocked:",
        file=sys.stderr,
    )
    print(f"  {items}.", file=sys.stderr)
    print(
        f"  Review if sensitive; re-run with --threshold {lowest:.2f} to block on these.",
        file=sys.stderr,
    )


def _run_check(
    files: list[str],
    threshold: float,
    allow: set[str],
    label: str,
    near_miss: bool = True,
) -> int:
    """Scan files (or stdin) and report masked findings to stderr.

    Exit 1 (block) if any detection is at/above the threshold, printing the blocking
    report. Exit 0 (pass) otherwise, and, unless ``near_miss`` is off, print a single
    non-blocking note about any sub-threshold detections that were *not* blocked.
    """
    # Detect everything (threshold 0) so we can partition into blocking vs sub-threshold.
    scrubber = Scrubber(score_threshold=0.0)
    sources = files or ["-"]
    blocking: list[tuple[str, int, str, str]] = []  # (label, line, entity, masked)
    subthreshold: list[tuple[str, str, float]] = []  # (entity, original, score)

    for path in sources:
        try:
            text = _read_text(path)
        except OSError as exc:
            _err(f"cannot read {path!r}: {exc.strerror or exc}")
            return 2
        name = label if path in (None, "-") else path
        result = scrubber.scrub(text)
        for det in result.detections:
            if det["entity_type"] in allow:
                continue
            if det["score"] >= threshold:
                line = text[: det["start"]].count("\n") + 1
                blocking.append((name, line, det["entity_type"], mask(det["original"])))
            else:
                subthreshold.append(
                    (det["entity_type"], det["original"], det["score"])
                )

    if blocking:
        # Blocked: one clear message for this outcome, the blocking report only.
        plural = "s" if len(blocking) != 1 else ""
        _err(
            f"--check: {len(blocking)} possible secret{plural} found "
            f"(threshold {threshold}):"
        )
        width = max(len(e) for _, _, e, _ in blocking)
        for name, line, entity, masked in blocking:
            print(f"  {name}:{line}  {entity:<{width}}  {masked}", file=sys.stderr)
        return 1

    # Passed: optionally note (without blocking) any sub-threshold near-misses.
    if near_miss and subthreshold:
        _print_near_miss(subthreshold, threshold)
    return 0


def _run_restore(mapping_path: str, source: str | None) -> int:
    try:
        with open(mapping_path, "r", encoding="utf-8") as fh:
            mapping = json.load(fh)
    except OSError as exc:
        _err(f"cannot read mapping {mapping_path!r}: {exc.strerror or exc}")
        return 2
    except json.JSONDecodeError as exc:
        _err(f"invalid mapping JSON in {mapping_path!r}: {exc}")
        return 2
    try:
        text = _read_text(source)
    except OSError as exc:
        _err(f"cannot read input: {exc.strerror or exc}")
        return 2
    sys.stdout.write(Scrubber().restore(text, mapping))
    return 0


def _warn_subthreshold(text: str, all_detections: list, threshold: float) -> None:
    """Surface, don't silently drop. Print a MASKED stderr summary of detections that
    fell below the threshold and were therefore NOT scrubbed, so a real-but-low-
    confidence secret is visible rather than invisible (mirrors the UI's surface-
    everything principle in the non-interactive path). stderr only, stdout stays clean.
    """
    sub = [d for d in all_detections if d["score"] < threshold]
    if not sub:
        return
    # One row per unique (entity, value); keep the earliest occurrence's line number.
    seen: dict = {}
    for d in sub:
        key = (d["entity_type"], d["original"])
        if key not in seen:
            line = text[: d["start"]].count("\n") + 1
            seen[key] = (line, d["entity_type"], mask(d["original"]), d["score"])
    rows = sorted(seen.values(), key=lambda r: r[0])
    lowest = min(r[3] for r in rows)
    plural = "s" if len(rows) != 1 else ""
    _err(f"{len(rows)} low-confidence detection{plural} NOT applied (score < {threshold}):")
    width = max(len(r[1]) for r in rows)
    for line, entity, masked, score in rows:
        print(
            f"  line {line}  {entity:<{width}}  {masked}  (score {round(score, 2)})",
            file=sys.stderr,
        )
    _err(f"re-run with --threshold {lowest:.2f} to include them.")


def _run_transform(source: str | None, threshold: float, mapping_path: str | None) -> int:
    try:
        text = _read_text(source)
    except OSError as exc:
        _err(f"cannot read input: {exc.strerror or exc}")
        return 2
    # Detect everything once (threshold 0) so we can both produce the thresholded output
    # AND report what sits below the line. Detection is cheap (regex); correctness of
    # "never silently drop a secret" is worth the second pass.
    all_detections = Scrubber(score_threshold=0.0).scrub(text).detections
    result = Scrubber(score_threshold=threshold).scrub(text)
    if mapping_path:
        try:
            with open(mapping_path, "w", encoding="utf-8") as fh:
                json.dump(result.mapping, fh, indent=2, sort_keys=True)
        except OSError as exc:
            _err(f"cannot write mapping {mapping_path!r}: {exc.strerror or exc}")
            return 2
    sys.stdout.write(result.scrubbed_text)
    _warn_subthreshold(text, all_detections, threshold)
    return 0


def main(argv: list[str] | None = None) -> int:
    _reconfigure_std()
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        try:
            from scrub import __version__
        except Exception:  # running flat without the installed package
            __version__ = "0.3.0"
        print(f"scrub {__version__}")
        return 0

    threshold = DEFAULT_THRESHOLD if args.threshold is None else args.threshold

    # --- mode validation (return 2 on misuse; keep main() return-code testable) ---
    if args.check and args.restore:
        _err("--check and --restore are mutually exclusive.")
        return 2
    if args.mapping and (args.check or args.restore):
        _err("--mapping only applies to the default (transform) mode.")
        return 2
    if args.allow and not args.check:
        _err("--allow only applies to --check.")
        return 2

    if args.check:
        return _run_check(
            args.files,
            threshold,
            set(args.allow or []),
            args.label,
            near_miss=not args.no_near_miss,
        )

    # transform and restore take a single source (file or stdin).
    if len(args.files) > 1:
        _err("expected at most one input file (use --check to scan multiple files).")
        return 2
    source = args.files[0] if args.files else None

    if args.restore:
        return _run_restore(args.restore, source)
    return _run_transform(source, threshold, args.mapping)


if __name__ == "__main__":
    raise SystemExit(main())
