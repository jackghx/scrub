"""Unit tests for the consistent pseudonymiser.

These don't need Presidio or a spaCy model: ``pseudonymize`` only duck-types its
detections (anything with ``entity_type``/``start``/``end``/``score``), so we feed
it tiny hand-built spans and assert the placeholder behaviour directly.
"""

from types import SimpleNamespace

from pseudonymizer import pseudonymize, restore


def det(entity_type, start, end, score=0.9):
    """A minimal stand-in for a Presidio RecognizerResult."""
    return SimpleNamespace(entity_type=entity_type, start=start, end=end, score=score)


def spans(text, value):
    """All [start, end) spans where ``value`` occurs in ``text``."""
    out = []
    i = text.find(value)
    while i != -1:
        out.append((i, i + len(value)))
        i = text.find(value, i + 1)
    return out


def test_consistency_one_value_three_times():
    """A value repeated 3x yields one placeholder used 3x."""
    text = "host 10.10.10.2 talked to 10.10.10.2 then 10.10.10.2 again"
    results = [det("INTERNAL_IP", s, e) for s, e in spans(text, "10.10.10.2")]
    assert len(results) == 3

    out = pseudonymize(text, results)

    assert len(out.mapping) == 1
    placeholder = next(iter(out.mapping))
    assert out.mapping[placeholder] == "10.10.10.2"
    assert out.scrubbed_text.count(placeholder) == 3
    assert "10.10.10.2" not in out.scrubbed_text


def test_distinct_values_get_incrementing_indices():
    """Two different IPs of the same type become _1 and _2, in document order."""
    text = "from 10.10.10.2 to 10.10.10.5"
    results = [
        det("INTERNAL_IP", *spans(text, "10.10.10.2")[0]),
        det("INTERNAL_IP", *spans(text, "10.10.10.5")[0]),
    ]

    out = pseudonymize(text, results)

    assert out.mapping == {
        "<INTERNAL_IP_1>": "10.10.10.2",
        "<INTERNAL_IP_2>": "10.10.10.5",
    }
    assert out.scrubbed_text == "from <INTERNAL_IP_1> to <INTERNAL_IP_2>"


def test_per_entity_type_counters_are_independent():
    """Counters increment per entity type, not globally."""
    text = "ip 10.0.0.1 mac D8:85:AC:A4:42:B9 ip 10.0.0.2"
    results = [
        det("INTERNAL_IP", *spans(text, "10.0.0.1")[0]),
        det("MAC_ADDRESS", *spans(text, "D8:85:AC:A4:42:B9")[0]),
        det("INTERNAL_IP", *spans(text, "10.0.0.2")[0]),
    ]

    out = pseudonymize(text, results)

    assert out.mapping == {
        "<INTERNAL_IP_1>": "10.0.0.1",
        "<MAC_ADDRESS_1>": "D8:85:AC:A4:42:B9",
        "<INTERNAL_IP_2>": "10.0.0.2",
    }


def test_round_trip_multi_entity():
    """restore(scrub(x)) == x for a realistic multi-entity sample."""
    text = (
        "default via 10.10.10.1 dev eth0\n"
        "wlan0 HWaddr D8:85:AC:A4:42:B9\n"
        "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"
        "again 10.10.10.1 seen"
    )
    results = []
    for s, e in spans(text, "10.10.10.1"):
        results.append(det("INTERNAL_IP", s, e))
    results.append(det("MAC_ADDRESS", *spans(text, "D8:85:AC:A4:42:B9")[0]))
    results.append(det("AWS_ACCESS_KEY", *spans(text, "AKIAIOSFODNN7EXAMPLE")[0]))

    out = pseudonymize(text, results)

    assert restore(out.scrubbed_text, out.mapping) == text
    # repeated IP shares its placeholder
    assert out.scrubbed_text.count("<INTERNAL_IP_1>") == 2


def test_overlap_inner_span_dropped():
    """A span fully inside another is not double-substituted; the stronger/longer
    span wins."""
    text = "secret AKIAIOSFODNN7EXAMPLE here"
    outer = det("AWS_ACCESS_KEY", *spans(text, "AKIAIOSFODNN7EXAMPLE")[0], score=0.9)
    # an inner, weaker span sitting wholly within the outer one
    inner_start = text.find("IOSFODNN")
    inner = det("GENERIC_API_KEY", inner_start, inner_start + len("IOSFODNN"), score=0.6)

    out = pseudonymize(text, [outer, inner])

    assert len(out.detections) == 1
    assert out.detections[0]["entity_type"] == "AWS_ACCESS_KEY"
    assert out.scrubbed_text == "secret <AWS_ACCESS_KEY_1> here"


def test_overlap_higher_score_wins_when_same_span():
    text = "value ABCDEF here"
    s, e = spans(text, "ABCDEF")[0]
    low = det("GENERIC_API_KEY", s, e, score=0.3)
    high = det("AWS_SECRET_KEY", s, e, score=0.8)

    out = pseudonymize(text, [low, high])

    assert len(out.detections) == 1
    assert out.detections[0]["entity_type"] == "AWS_SECRET_KEY"


def test_no_detections_passthrough():
    text = "nothing sensitive here, just prose."
    out = pseudonymize(text, [])
    assert out.scrubbed_text == text
    assert out.mapping == {}
    assert out.detections == []


def test_custom_format_honoured():
    text = "ip 10.0.0.1 again 10.0.0.1"
    results = [det("INTERNAL_IP", s, e) for s, e in spans(text, "10.0.0.1")]

    out = pseudonymize(text, results, fmt="[[{entity}#{n}]]")

    assert out.mapping == {"[[INTERNAL_IP#1]]": "10.0.0.1"}
    assert out.scrubbed_text == "ip [[INTERNAL_IP#1]] again [[INTERNAL_IP#1]]"
    assert restore(out.scrubbed_text, out.mapping) == text


def test_detections_in_document_order_with_offsets():
    text = "from 10.0.0.2 to 10.0.0.5"
    results = [
        det("INTERNAL_IP", *spans(text, "10.0.0.5")[0]),  # deliberately out of order
        det("INTERNAL_IP", *spans(text, "10.0.0.2")[0]),
    ]

    out = pseudonymize(text, results)

    starts = [d["start"] for d in out.detections]
    assert starts == sorted(starts)
    # offsets index into the ORIGINAL text
    first = out.detections[0]
    assert text[first["start"] : first["end"]] == first["original"]
