"""End-to-end tests for the Scrubber in its default (custom-pack-only) mode.

These run the real security recogniser pack, but need **no spaCy model** because
custom-only mode has no NLP engine. They exercise the full path: detect ->
consistently pseudonymise -> restore, on a realistic multi-entity log.
"""

import os

import pytest

from scrubber import Scrubber

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_PATH = os.path.join(ROOT, "sample.log")


@pytest.fixture(scope="module")
def scrubber():
    return Scrubber()  # custom-only, no model needed


@pytest.fixture(scope="module")
def sample_text():
    # newline="" keeps the bytes exactly as written so the round-trip assertion
    # is a true byte-for-byte check.
    with open(SAMPLE_PATH, encoding="utf-8", newline="") as fh:
        return fh.read()


def test_finds_detections(scrubber, sample_text):
    result = scrubber.scrub(sample_text)
    assert result.detections, "expected the pack to flag something in the sample log"
    types = {d["entity_type"] for d in result.detections}
    # the obvious infra leaks should be caught
    assert "INTERNAL_IP" in types
    assert "MAC_ADDRESS" in types


def test_round_trip_byte_for_byte(scrubber, sample_text):
    result = scrubber.scrub(sample_text)
    assert scrubber.restore(result.scrubbed_text, result.mapping) == sample_text


def test_repeated_identifier_shares_placeholder(scrubber, sample_text):
    """10.10.10.2 appears 3x in the sample; it must map to a single placeholder
    that is reused 3x."""
    result = scrubber.scrub(sample_text)
    placeholders_for_ip = [
        ph for ph, original in result.mapping.items() if original == "10.10.10.2"
    ]
    assert len(placeholders_for_ip) == 1
    placeholder = placeholders_for_ip[0]
    assert sample_text.count("10.10.10.2") == 3
    assert result.scrubbed_text.count(placeholder) == 3
    assert "10.10.10.2" not in result.scrubbed_text


def test_no_raw_secret_value_survives_for_kept_detections(scrubber, sample_text):
    """Every applied detection's original value is gone from the scrubbed text."""
    result = scrubber.scrub(sample_text)
    for det in result.detections:
        assert det["original"] not in result.scrubbed_text


def test_clean_text_passthrough(scrubber):
    clean = "the quick brown fox jumps over the lazy dog\n"
    result = scrubber.scrub(clean)
    assert result.scrubbed_text == clean
    assert result.mapping == {}
    assert result.detections == []


def test_entities_listed(scrubber):
    ents = scrubber.entities()
    assert "INTERNAL_IP" in ents and "PUBLIC_IP" in ents
    assert "PRIVATE_KEY_BLOCK" in ents
    # the pack advertises 32 entity types (derived from the recogniser list)
    assert len(ents) == 32
