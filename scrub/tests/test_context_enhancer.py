"""Tests for the spaCy-free context enhancer (custom-pack-only mode).

The whole point is a two-way property, so both directions are asserted explicitly:
  * context PRESENT  -> a context-dependent secret clears 0.6, and
  * context ABSENT   -> a bare high-entropy blob stays at base (the false-positive
    guard, the easy one to forget).
Plus the underscored-fused-token case from the real line, and the mid-word non-match
that keeps substring matching from firing on 'monkey'/'keyboard'.
"""

from types import SimpleNamespace

import pytest

from context_enhancer import enhance_with_context, CONTEXT_BOOST
from scrubber import Scrubber

BLOB = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40 chars, AWS_SECRET_KEY shape
AWS_CTX = ["aws", "secret", "access", "key", "credential"]


def _det(text, sub, score, entity="AWS_SECRET_KEY"):
    start = text.index(sub)
    return SimpleNamespace(entity_type=entity, start=start, end=start + len(sub), score=score)


# --- unit level: the enhancer function in isolation -------------------------

def test_fused_token_lifts_score():
    text = f"aws_secret_access_key = {BLOB}"
    d = _det(text, BLOB, 0.35)
    enhance_with_context(text, [d], AWS_CTX)
    assert d.score == pytest.approx(0.35 + CONTEXT_BOOST)
    assert d.score >= 0.6


def test_separate_words_lift_score():
    text = f"aws secret key: {BLOB}"
    d = _det(text, BLOB, 0.35)
    enhance_with_context(text, [d], AWS_CTX)
    assert d.score >= 0.6


def test_no_context_does_not_lift():
    text = f"the quick brown fox jumps {BLOB} over the lazy dog"
    d = _det(text, BLOB, 0.35)
    enhance_with_context(text, [d], AWS_CTX)
    assert d.score == 0.35  # unchanged, the FP guard


def test_midword_substring_does_not_lift():
    # 'key' is a substring of 'monkey' but must not count as context.
    text = f"the monkey ate {BLOB} for lunch on the keyboard"
    d = _det(text, BLOB, 0.35)
    enhance_with_context(text, [d], AWS_CTX)
    assert d.score == 0.35


def test_context_outside_window_does_not_lift():
    # trigger word far away (beyond the 40-char window) must not bleed in.
    text = "secret" + " " * 80 + BLOB
    d = _det(text, BLOB, 0.35)
    enhance_with_context(text, [d], AWS_CTX)
    assert d.score == 0.35


def test_match_span_itself_is_not_self_supporting():
    # a value that literally contains a trigger word must not support itself.
    val = "aws_supersecret_key_value_aaaaaaaaaaaaaa"
    text = f"x = {val}"
    d = _det(text, val, 0.35)
    enhance_with_context(text, [d], AWS_CTX)
    assert d.score == 0.35


# --- integration: through the real Scrubber in custom-only mode -------------

def test_scrubber_custom_only_lifts_aws_secret_with_context():
    line = f"aws_secret_access_key = {BLOB}"
    dets = Scrubber(score_threshold=0.0).scrub(line).detections
    aws = [d for d in dets if d["entity_type"] == "AWS_SECRET_KEY"]
    assert aws and aws[0]["score"] >= 0.6


def test_scrubber_custom_only_keeps_bare_blob_low():
    line = f"value: {BLOB}"  # 'value' is not an AWS_SECRET_KEY context word
    dets = Scrubber(score_threshold=0.6).scrub(line).detections
    assert not any(d["entity_type"] == "AWS_SECRET_KEY" for d in dets)
