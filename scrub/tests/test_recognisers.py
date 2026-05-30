"""
test_recognisers.py, exercises every recogniser in the pack.

PatternRecognizer.analyze() and our custom IpAddressRecognizer.analyze() both run
without an NLP engine, so we can validate detection logic without downloading a
spaCy model. Each case asserts that a given entity is found in (or absent from) a
sample string.
"""

from security_recognisers import get_security_recognizers

# (description, text, expected_entity, should_be_found)
CASES = [
    ("MAC address",        "wlan0 HWaddr D8:85:AC:A4:42:B9 up",        "MAC_ADDRESS",          True),
    ("AWS access key",     "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",   "AWS_ACCESS_KEY",       True),
    ("AWS secret key",     "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AWS_SECRET_KEY", True),
    ("GitHub PAT",         "token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",  "GITHUB_TOKEN",  True),
    ("GitHub fine-grained","github_pat_" + "A" * 82,                   "GITHUB_TOKEN",         True),
    ("Slack bot token",    "xoxb-2401234567-2412345678901-AbCdEfGhIjKlMnOpQr", "SLACK_TOKEN",  True),
    ("Google API key",     "key=AIza" + "B" * 35,                       "GOOGLE_API_KEY",   True),
    ("Stripe live key",    "sk_live_4eC39HqLyjWDarjtT1zdp7dc",         "STRIPE_KEY",           True),
    ("JWT",                "Authorization: Bearer eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM", "JWT",     True),
    ("Private key block",  "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAA\n-----END RSA PRIVATE KEY-----", "PRIVATE_KEY_BLOCK", True),
    ("Bearer token",       "Authorization: Bearer abc123def456ghi789",  "BEARER_TOKEN",        True),
    ("DB connection str",  "DATABASE_URL=postgres://admin:s3cret@db.internal:5432/app", "DB_CONNECTION_STRING", True),
    ("Generic api_key",    'api_key = "sk-proj-abc123def456ghi"',       "GENERIC_API_KEY",      True),
    ("Generic SECRET_TOKEN","SECRET_TOKEN=fake_secret_token_example",    "GENERIC_API_KEY",      True),
    ("Unix home path",     "error opening /home/jack/.ssh/config",      "UNIX_HOME_PATH",       True),
    ("Internal IP",        "default via 10.10.10.1 dev eth0",           "INTERNAL_IP",          True),
    ("Public IP",          "connect to 8.8.8.8 port 53",               "PUBLIC_IP",            True),
    ("Invalid IP rejected","build version 999.1.2.3 released",         "PUBLIC_IP",            False),
    ("Internal not public","gateway 192.168.1.254",                    "PUBLIC_IP",            False),
    ("Hostname",           "server proxmox.lan responded",             "HOSTNAME",             True),
    # --- expanded coverage (Part 2): new secret types ---------------------------------
    ("Google key (valid)", "key=AIzaSyB" + "C" * 32,                    "GOOGLE_API_KEY",       True),
    ("OpenAI project key", "sk-proj-" + "A" * 48 + "T3BlbkFJ" + "B" * 20, "OPENAI_KEY",         True),
    ("OpenAI legacy key",  "sk-" + "A" * 48,                            "OPENAI_KEY",           True),
    ("OpenRouter key",     "sk-or-v1-" + "a1b2c3d4" * 8,                "OPENROUTER_KEY",       True),
    ("Discord bot token",  "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA.GhIjKl." + "a" * 38, "DISCORD_TOKEN",   True),
    ("FCM server key",     "AAAAbcdefgh:APA91b" + "X" * 130,            "FCM_SERVER_KEY",       True),
    ("Twilio account SID", "AC" + "0123456789abcdef" * 2,               "TWILIO_SID",           True),
    ("Twilio API key SID", "SK" + "0123456789abcdef" * 2,               "TWILIO_SID",           True),
    ("SendGrid key",       "SG." + "A" * 22 + "." + "B" * 43,           "SENDGRID_KEY",         True),
    ("SSH rsa public key", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDabcXYZ+/123def456", "SSH_PUBLIC_KEY", True),
    ("SSH ed25519 pubkey", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdef",  "SSH_PUBLIC_KEY",    True),
    ("Email address",      "from jack@example.com today",               "EMAIL_ADDRESS",        True),
    # --- expanded coverage (final batch): more high-value, low-FP secret types ----------
    ("GitLab PAT",         "CI_JOB_TOKEN glpat-" + "A" * 20,            "GITLAB_TOKEN",         True),
    ("npm token",          "//registry.npmjs.org/:_authToken=npm_" + "a" * 36, "NPM_TOKEN",     True),
    ("Shopify token",      "shpat_" + "0123456789abcdef" * 2,           "SHOPIFY_TOKEN",        True),
    ("Telegram bot token", "bot 123456789:" + "A" * 35,                 "TELEGRAM_BOT_TOKEN",   True),
    ("Slack webhook",      "https://hooks.slack.com/services/T00000000/B11111111/" + "a" * 24, "SLACK_WEBHOOK", True),
    ("Discord webhook",    "https://discord.com/api/webhooks/123456789012345678/" + "A" * 68, "DISCORD_WEBHOOK", True),
    ("URL with creds",     "clone https://admin:s3cret@git.example.com/x", "URL_WITH_CREDENTIALS", True),
    ("Plain URL no creds", "see https://example.com/docs for details",  "URL_WITH_CREDENTIALS", False),
    ("Credit card (Luhn)", "card 4111 1111 1111 1111 on file",          "CREDIT_CARD",          True),
    ("Non-Luhn rejected",  "order 1234 5678 9012 3456 shipped",         "CREDIT_CARD",          False),
    ("IPv6 public",        "resolver 2606:4700:4700::1111 reached",     "PUBLIC_IP",            True),
    ("IPv6 loopback",      "bound to ::1 on startup",                   "INTERNAL_IP",          True),
    ("IPv6 link-local",    "neighbour fe80::1 discovered",              "INTERNAL_IP",          True),
    ("IPv6 malformed",     "garbage ::::: not an address",              "PUBLIC_IP",            False),
]


def find_entities(text, target_entity):
    """Run every recogniser whose supported set includes target_entity."""
    found = []
    for rec in get_security_recognizers():
        if target_entity in rec.supported_entities:
            results = rec.analyze(text, entities=rec.supported_entities, nlp_artifacts=None)
            found.extend(r.entity_type for r in results)
    return found


def main():
    passed = failed = 0
    width = max(len(d) for d, *_ in CASES)
    for desc, text, entity, should_find in CASES:
        found = find_entities(text, entity)
        ok = (entity in found) == should_find
        status = "PASS" if ok else "FAIL"
        verb = "found" if should_find else "absent"
        print(f"[{status}] {desc:<{width}}  expect {entity} {verb:<6} -> got {sorted(set(found)) or '[]'}")
        passed += ok
        failed += (not ok)
    print(f"\n{passed}/{passed + failed} passed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if main() else 0)
