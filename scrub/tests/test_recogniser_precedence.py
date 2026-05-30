"""Precedence + negative tests for the expanded recogniser pack.

The standalone ``find_entities`` harness in ``test_recognisers.py`` runs each
recogniser in isolation, so it can prove a regex fires but NOT how competing
detections resolve. These cases run the full ``Scrubber`` pipeline (detect ->
context-enhance -> threshold -> overlap-resolve) to assert the behaviour the
stress test cared about: a specific high-score recogniser must *win* the span
against the deliberately-low-score generic matchers (AWS_SECRET_KEY blob,
HOSTNAME), and the precision guards on those low-score recognisers must hold.
"""

import pytest

from scrubber import Scrubber

# Realistic-format fakes (none are live secrets).
OPENAI_PROJ = "sk-proj-" + "A" * 48 + "T3BlbkFJ" + "B" * 20
OPENAI_LEGACY = "sk-" + "A" * 48
SENDGRID = "SG." + "A" * 22 + "." + "B" * 43
# Discord token whose trailing segment is all letters, exactly the shape that the
# stress test mis-tagged as HOSTNAME (".tokenexample…").
DISCORD = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA.GhIjKl.tokenexampleabcdefghijklmnopqrstuvwxyz"
BLOB = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40-char AWS_SECRET_KEY shape


def _types_over_span(text, sub, threshold=0.0):
    """Entity types of the surviving detections overlapping ``sub`` in ``text``."""
    result = Scrubber(score_threshold=threshold).scrub(text)
    start = text.index(sub)
    end = start + len(sub)
    return sorted(
        {d["entity_type"] for d in result.detections if d["start"] < end and start < d["end"]}
    )


# --- specific recogniser wins over the generic AWS_SECRET_KEY blob --------------

def test_openai_project_key_not_aws_or_stripe():
    types = _types_over_span(f"openai api key {OPENAI_PROJ}", OPENAI_PROJ)
    assert types == ["OPENAI_KEY"]
    assert "AWS_SECRET_KEY" not in types
    assert "STRIPE_KEY" not in types


def test_openai_legacy_key_not_aws_or_stripe():
    types = _types_over_span(OPENAI_LEGACY, OPENAI_LEGACY)
    assert "OPENAI_KEY" in types
    assert "AWS_SECRET_KEY" not in types
    assert "STRIPE_KEY" not in types


def test_sendgrid_key_not_aws_secret():
    types = _types_over_span(f"sendgrid api key {SENDGRID}", SENDGRID)
    assert types == ["SENDGRID_KEY"]
    assert "AWS_SECRET_KEY" not in types


# --- email + discord win over HOSTNAME ------------------------------------------

def test_email_tagged_email_not_hostname():
    types = _types_over_span("please contact jack@example.com today", "jack@example.com")
    assert types == ["EMAIL_ADDRESS"]
    assert "HOSTNAME" not in types


def test_discord_trailing_segment_not_hostname():
    types = _types_over_span(f"discord bot token: {DISCORD}", DISCORD)
    assert "DISCORD_TOKEN" in types
    assert "HOSTNAME" not in types


# --- precision guards: low-score recognisers stay quiet without justification ---

def test_bare_blob_without_context_stays_below_default_threshold():
    # A 40-char blob with no trigger words nearby must not cross 0.6 (AWS_SECRET_KEY
    # precision preserved): nothing is applied at the default threshold.
    dets = Scrubber(score_threshold=0.6).scrub(f"the quick brown fox {BLOB} lazy dog").detections
    assert not any(d["entity_type"] == "AWS_SECRET_KEY" for d in dets)


def test_word_secret_in_prose_does_not_flood():
    line = "the secret to happiness is a good cup of coffee in the morning"
    dets = Scrubber(score_threshold=0.6).scrub(line).detections
    assert dets == []


def test_secret_token_key_name_is_caught():
    # The compound key name SECRET_TOKEN= used to slip through the generic
    # assigned-secret recogniser; it must now be flagged GENERIC_API_KEY.
    dets = Scrubber(score_threshold=0.6).scrub("SECRET_TOKEN=fake_secret_token_example").detections
    assert any(d["entity_type"] == "GENERIC_API_KEY" for d in dets)


def test_secret_token_fix_does_not_flood_prose():
    # The same fix must not make ordinary prose containing 'secret'/'token' match.
    line = "keeping this a secret means the token of trust is never broken"
    assert Scrubber(score_threshold=0.6).scrub(line).detections == []


def test_db_uri_not_double_flagged_as_url_with_credentials():
    # postgres://user:pass@host is owned by the more specific DB_CONNECTION_STRING;
    # the http/ftp/ssh-scoped URL_WITH_CREDENTIALS recogniser must not also claim it.
    text = "DATABASE_URL=postgres://admin:s3cret@db.internal:5432/app"
    types = _types_over_span(text, "postgres://admin:s3cret@db.internal:5432/app")
    assert "DB_CONNECTION_STRING" in types
    assert "URL_WITH_CREDENTIALS" not in types


def test_http_url_with_credentials_is_flagged():
    # An http(s) URL embedding credentials is a leak the DB recogniser does NOT own.
    text = "git clone https://admin:s3cret@git.example.com/repo.git"
    types = _types_over_span(text, "https://admin:s3cret@git.example.com")
    assert "URL_WITH_CREDENTIALS" in types


def test_credit_card_luhn_valid_caught_invalid_ignored():
    valid = Scrubber(score_threshold=0.6).scrub("card 4111 1111 1111 1111 on file").detections
    assert any(d["entity_type"] == "CREDIT_CARD" for d in valid)
    invalid = Scrubber(score_threshold=0.6).scrub("order 1234 5678 9012 3456 shipped").detections
    assert not any(d["entity_type"] == "CREDIT_CARD" for d in invalid)


def test_ipv6_internal_vs_public_classification():
    pub = Scrubber(score_threshold=0.6).scrub("resolver 2606:4700:4700::1111 reached").detections
    assert any(d["entity_type"] == "PUBLIC_IP" for d in pub)
    loop = Scrubber(score_threshold=0.6).scrub("bound to ::1 on startup").detections
    assert any(d["entity_type"] == "INTERNAL_IP" for d in loop)
    # malformed candidate is rejected by ipaddress validation, no detection at all.
    bad = Scrubber(score_threshold=0.0).scrub("garbage ::::: not an address").detections
    assert not any(d["entity_type"] in ("INTERNAL_IP", "PUBLIC_IP") for d in bad)


def test_twilio_sid_needs_context_to_block():
    # FP-prone two-letter prefix: a bare AC… SID stays at base 0.4 (below 0.6)...
    sid = "AC" + "0123456789abcdef" * 2
    assert not any(
        d["entity_type"] == "TWILIO_SID"
        for d in Scrubber(score_threshold=0.6).scrub(f"value {sid}").detections
    )
    # ...but with the 'twilio' context word nearby it is lifted over the threshold.
    assert any(
        d["entity_type"] == "TWILIO_SID"
        for d in Scrubber(score_threshold=0.6).scrub(f"twilio account sid {sid}").detections
    )
