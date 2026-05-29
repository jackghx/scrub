"""
test_recognizers.py, exercises every recogniser in the pack.

PatternRecognizer.analyze() and our custom IpAddressRecognizer.analyze() both run
without an NLP engine, so we can validate detection logic without downloading a
spaCy model. Each case asserts that a given entity is found in (or absent from) a
sample string.
"""

from security_recognizers import get_security_recognizers

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
    ("Unix home path",     "error opening /home/jack/.ssh/config",      "UNIX_HOME_PATH",       True),
    ("Internal IP",        "default via 10.10.10.1 dev eth0",           "INTERNAL_IP",          True),
    ("Public IP",          "connect to 8.8.8.8 port 53",               "PUBLIC_IP",            True),
    ("Invalid IP rejected","build version 999.1.2.3 released",         "PUBLIC_IP",            False),
    ("Internal not public","gateway 192.168.1.254",                    "PUBLIC_IP",            False),
    ("Hostname",           "server proxmox.lan responded",             "HOSTNAME",             True),
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
