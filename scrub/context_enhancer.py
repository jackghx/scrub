"""
context_enhancer.py
===================

A **spaCy-free** context-aware score boost for custom-pack-only mode.

Why this exists
---------------
Custom-only mode runs the recognisers directly, with no NLP engine, so Presidio's
``LemmaContextAwareEnhancer``, which needs spaCy tokens/lemmas, never runs and every
detection stays at its base pattern score. That silently caps the recognisers that were
*deliberately* given a low base score on the assumption that context would lift them:
``AWS_SECRET_KEY`` (0.35), ``HOSTNAME`` (0.25), ``AWS_ACCOUNT_ID`` (0.2). In the mode we
ship by default, a real AWS secret key sitting next to ``aws``/``secret``/``key`` never
crossed the 0.6 threshold, the CLI and the commit hook passed it through.

What this does
--------------
For each detection, scan a character window around the span for the recogniser's own
context words and, if any is present, raise the score. This is a cruder match than
Presidio's lemma-based one, so the constants below are **chosen by the outcome we need
and pinned by tests**, not copied as gospel:

* a context-dependent secret **with** its trigger words nearby clears 0.6
  (``AWS_SECRET_KEY`` 0.35 -> 0.70), and
* a bare high-entropy blob **with no** trigger words nearby stays at base (0.35) and is
  still dropped at 0.6, this is the false-positive guard.

Matching
--------
A context word matches when it appears in the window bounded by non-letters on both
sides. That is deliberately *not* whole-word-only and *not* naive substring:

* it fires when the trigger is fused into an identifier, ``aws_secret_access_key`` is a
  single token whose ``_``-delimited components include ``aws``, ``secret`` and ``key``;
* but it does **not** fire when the trigger is embedded mid-word, ``key`` inside
  ``monkey`` or ``keyboard`` must not count, or any prose near a blob would lift it.

No spaCy, no network, consistent with custom-only mode's zero-dependency promise.
"""

from __future__ import annotations

import re
from typing import List, Optional, Sequence

# Tuned for the character-window match (NOT Presidio's lemma match) and verified in
# tests/test_context_enhancer.py. The boost is what lifts AWS_SECRET_KEY (0.35) over
# 0.6; the window is wide enough to reach the trigger fused into the variable name on
# the same assignment, but narrow enough that an unrelated trigger elsewhere on a long
# line does not bleed in.
CONTEXT_WINDOW = 40
CONTEXT_BOOST = 0.35
CONTEXT_SCORE_FLOOR = 0.40
MAX_SCORE = 1.0


def _supportive_word(window_text: str, context_words: Sequence[str]) -> Optional[str]:
    """Return the first context word present in ``window_text`` at a token boundary
    (bounded by non-letters), or ``None``. Case-insensitive."""
    lowered = window_text.lower()
    for word in context_words:
        wl = word.lower().strip()
        if not wl:
            continue
        if re.search(rf"(?<![a-z]){re.escape(wl)}(?![a-z])", lowered):
            return word
    return None


def enhance_with_context(
    text: str,
    results: List,
    context_words: Optional[Sequence[str]],
    *,
    window: int = CONTEXT_WINDOW,
    boost: float = CONTEXT_BOOST,
    floor: float = CONTEXT_SCORE_FLOOR,
) -> List:
    """Raise the score of any detection in ``results`` whose recogniser ``context_words``
    appear within ``window`` characters of the span. Mutates and returns ``results``.

    The match span itself is excluded from the scanned window so a context word that
    happens to appear inside the secret cannot self-support the detection.
    """
    if not context_words:
        return results
    for r in results:
        left = max(0, r.start - window)
        right = min(len(text), r.end + window)
        # Prefix + suffix around the match, joined by a newline so a word can't be
        # accidentally formed across the excised span.
        around = text[left : r.start] + "\n" + text[r.end : right]
        if _supportive_word(around, context_words):
            r.score = min(max(r.score + boost, floor), MAX_SCORE)
    return results


__all__ = [
    "enhance_with_context",
    "CONTEXT_WINDOW",
    "CONTEXT_BOOST",
    "CONTEXT_SCORE_FLOOR",
]
