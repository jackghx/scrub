"""
security_recognizers.py
=======================

A Presidio recogniser pack tuned for *security and infrastructure artefacts*,
the identifiers and secrets that leak when an engineer pastes a log, config, or
terminal output into a public GitHub issue, a vendor ticket, a forum, or a blog.

General-purpose PII tools (Presidio's defaults, OpenAI Privacy Filter, etc.) are
tuned for *human* PII: names, emails, SSNs. They largely ignore the things that
actually leak in security work, internal IPs, hostnames, MAC addresses, cloud
keys, tokens, private-key blocks and connection strings. This pack fills that gap
and is designed to sit *on top of* Presidio rather than replace it.

Design notes
------------
* Every recogniser carries ``context`` words. Presidio's ContextAwareEnhancer
  raises a detection's score when those words appear nearby, which sharply cuts
  false positives on the ambiguous patterns (generic keys, hostnames).
* IPs are validated with the stdlib ``ipaddress`` module rather than trusted from
  regex alone, and are split into INTERNAL_IP vs PUBLIC_IP, internal addresses
  are the higher-risk leak and get the higher score.
* High-entropy secrets that are FP-prone on their own (AWS secret keys, generic
  assigned keys) are given a deliberately low base score and rely on context to
  cross the decision threshold, rather than firing on any 40-char blob.
* Scores are starting points, not gospel. Tune them against your own corpus.

Usage
-----
    from presidio_analyzer import AnalyzerEngine
    from security_recognizers import register_security_recognizers

    analyzer = AnalyzerEngine()
    register_security_recognizers(analyzer)
    results = analyzer.analyze(text=my_log, language="en")
"""

from __future__ import annotations

import ipaddress
import re
from typing import List, Optional

from presidio_analyzer import EntityRecognizer, Pattern, PatternRecognizer, RecognizerResult

# ---------------------------------------------------------------------------
# Pattern-based recognisers
# ---------------------------------------------------------------------------
# Each is a small subclass so the entity name, patterns and context live together
# and the pack reads as a catalogue. Scores: 0.9+ = structurally unambiguous
# (private key headers, AWS key IDs), ~0.6 = needs context to be sure.


class MacAddressRecognizer(PatternRecognizer):
    """Colon- or hyphen-separated 48-bit MAC addresses (e.g. D8:85:AC:A4:42:B9)."""

    PATTERNS = [
        Pattern(
            name="mac_address",
            regex=r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            score=0.85,
        ),
    ]
    CONTEXT = ["mac", "hwaddr", "ether", "bssid", "physical address", "lladdr"]

    def __init__(self):
        super().__init__(
            supported_entity="MAC_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class AwsAccessKeyRecognizer(PatternRecognizer):
    """AWS access key IDs, AKIA/ASIA/AGPA/AIDA/AROA + 16 base32 chars."""

    PATTERNS = [
        Pattern(
            name="aws_access_key_id",
            regex=r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b",
            score=0.9,
        ),
    ]
    CONTEXT = ["aws", "access", "key", "credential", "secret"]

    def __init__(self):
        super().__init__(
            supported_entity="AWS_ACCESS_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class AwsSecretKeyRecognizer(PatternRecognizer):
    """AWS secret access keys: 40 chars of base64 alphabet.

    Deliberately low base score, this pattern is FP-prone (any 40-char blob),
    so it relies on the surrounding context words to cross the threshold.
    """

    PATTERNS = [
        Pattern(
            name="aws_secret_access_key",
            regex=r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
            score=0.35,
        ),
    ]
    CONTEXT = ["aws", "secret", "access", "key", "credential"]

    def __init__(self):
        super().__init__(
            supported_entity="AWS_SECRET_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class AwsAccountIdRecognizer(PatternRecognizer):
    """12-digit AWS account IDs. Low base score; needs context (very FP-prone)."""

    PATTERNS = [
        Pattern(name="aws_account_id", regex=r"\b\d{12}\b", score=0.2),
    ]
    CONTEXT = ["aws", "account", "arn", "iam"]

    def __init__(self):
        super().__init__(
            supported_entity="AWS_ACCOUNT_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class GitHubTokenRecognizer(PatternRecognizer):
    """GitHub PATs / OAuth / app tokens: ghp_, gho_, ghu_, ghs_, ghr_, github_pat_."""

    PATTERNS = [
        Pattern(
            name="github_token",
            regex=r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
            score=0.95,
        ),
    ]
    CONTEXT = ["github", "token", "pat", "gh"]

    def __init__(self):
        super().__init__(
            supported_entity="GITHUB_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class SlackTokenRecognizer(PatternRecognizer):
    """Slack tokens: xoxb-, xoxp-, xoxa-, xoxr-, xoxs-."""

    PATTERNS = [
        Pattern(
            name="slack_token",
            regex=r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
            score=0.9,
        ),
    ]
    CONTEXT = ["slack", "token", "bot"]

    def __init__(self):
        super().__init__(
            supported_entity="SLACK_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class GoogleApiKeyRecognizer(PatternRecognizer):
    """Google API keys: AIza + 35 chars."""

    PATTERNS = [
        Pattern(
            name="google_api_key",
            regex=r"\bAIza[0-9A-Za-z_-]{35}\b",
            score=0.9,
        ),
    ]
    CONTEXT = ["google", "api", "key", "gcp", "maps", "firebase"]

    def __init__(self):
        super().__init__(
            supported_entity="GOOGLE_API_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class StripeKeyRecognizer(PatternRecognizer):
    """Stripe secret/publishable/restricted keys: sk_/pk_/rk_ live or test."""

    PATTERNS = [
        Pattern(
            name="stripe_key",
            regex=r"\b[rsp]k_(?:live|test)_[0-9A-Za-z]{16,}\b",
            score=0.95,
        ),
    ]
    CONTEXT = ["stripe", "key", "secret", "payment"]

    def __init__(self):
        super().__init__(
            supported_entity="STRIPE_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class JwtRecognizer(PatternRecognizer):
    """JSON Web Tokens: three base64url segments separated by dots, starting eyJ."""

    PATTERNS = [
        Pattern(
            name="jwt",
            regex=r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            score=0.9,
        ),
    ]
    CONTEXT = ["jwt", "token", "bearer", "authorization"]

    def __init__(self):
        super().__init__(
            supported_entity="JWT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class PrivateKeyBlockRecognizer(PatternRecognizer):
    """PEM private-key blocks (RSA/EC/OPENSSH/DSA/PGP). Matches the whole block."""

    PATTERNS = [
        Pattern(
            name="private_key_block",
            regex=(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
                r"[\s\S]*?"
                r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            ),
            score=0.99,
        ),
    ]
    CONTEXT = ["private", "key", "ssh", "rsa", "pem"]

    def __init__(self):
        super().__init__(
            supported_entity="PRIVATE_KEY_BLOCK",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class BearerTokenRecognizer(PatternRecognizer):
    """Bearer/Basic tokens inside an Authorization header value."""

    PATTERNS = [
        Pattern(
            name="bearer_token",
            regex=r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{10,}",
            score=0.7,
        ),
    ]
    CONTEXT = ["authorization", "auth", "header", "bearer", "basic"]

    def __init__(self):
        super().__init__(
            supported_entity="BEARER_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class DbConnectionStringRecognizer(PatternRecognizer):
    """Database / broker connection URIs that embed credentials.

    e.g. postgres://user:pass@host:5432/db, mongodb+srv://..., redis://...
    """

    PATTERNS = [
        Pattern(
            name="db_connection_string",
            regex=(
                r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|"
                r"jdbc:[a-z]+)://"
                r"[^\s:@/]+(?::[^\s@/]+)?@[^\s/]+"
            ),
            score=0.85,
        ),
    ]
    CONTEXT = ["database", "connection", "dsn", "uri", "url", "conn"]

    def __init__(self):
        super().__init__(
            supported_entity="DB_CONNECTION_STRING",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class GenericApiKeyRecognizer(PatternRecognizer):
    """Assignment-style secrets: api_key = "...", token: '...', SECRET="...".

    Captures the *value* of common key/token/password assignments. Low-ish score
    because the key name is the real signal; context reinforces it.
    """

    PATTERNS = [
        Pattern(
            name="assigned_secret",
            regex=(
                # Compound key names first so they win the ordered alternation:
                # a bare ``secret``/``token`` alternative would match the prefix of
                # ``SECRET_TOKEN`` and then fail before the ``=`` (and ``token`` can't
                # match mid-name because ``_`` leaves no word boundary), so the
                # compound names must be listed explicitly.
                r"(?i)\b(?:secret[_-]?token|auth[_-]?token|private[_-]?token|"
                r"client[_-]?secret|access[_-]?key|api[_-]?key|"
                r"secret|token|passwd|password)"
                r"['\"]?\s*[:=]\s*['\"]?"
                r"([A-Za-z0-9_\-\.+/=]{8,})"
            ),
            score=0.6,
        ),
    ]
    CONTEXT = ["key", "secret", "token", "password", "credential", "env"]

    def __init__(self):
        super().__init__(
            supported_entity="GENERIC_API_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class UnixHomePathRecognizer(PatternRecognizer):
    """Home-directory paths that quietly dox the author's username.

    /home/jack/... or /Users/jack/..., the username segment is the leak.
    """

    PATTERNS = [
        Pattern(
            name="unix_home_path",
            regex=r"(?<!\w)/(?:home|Users)/[A-Za-z0-9._-]+(?:/[^\s'\"]*)?",
            score=0.6,
        ),
    ]
    CONTEXT = ["home", "path", "directory", "user", "cwd"]

    def __init__(self):
        super().__init__(
            supported_entity="UNIX_HOME_PATH",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class HostnameRecognizer(PatternRecognizer):
    """FQDNs / internal hostnames. Low base score (very FP-prone in prose);
    context words like 'host', 'server', 'fqdn' lift it. Public registrable
    domains are better left to allow-listing downstream.
    """

    PATTERNS = [
        Pattern(
            name="hostname",
            regex=(
                r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
                r"(?:local|internal|lan|home|corp|intranet|"
                r"[a-zA-Z]{2,24})\b"
            ),
            score=0.25,
        ),
    ]
    CONTEXT = ["host", "hostname", "server", "fqdn", "node", "domain", "endpoint"]

    def __init__(self):
        super().__init__(
            supported_entity="HOSTNAME",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class OpenAiKeyRecognizer(PatternRecognizer):
    """OpenAI API keys.

    Two distinctive shapes, both unambiguous enough to score high:
    * project / service-account / admin keys: ``sk-proj-``, ``sk-svcacct-``,
      ``sk-admin-`` followed by a long body, and
    * legacy secret keys: ``sk-`` + 40+ chars.

    Note the separator: OpenAI uses ``sk-`` (hyphen); Stripe uses ``sk_``
    (underscore), so the two never collide. The legacy ``sk-`` form requires 40+
    trailing chars, so it won't grab a short ``sk-proj-abc…`` value either.
    """

    PATTERNS = [
        Pattern(
            name="openai_key",
            regex=(
                r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b"
                r"|\bsk-[A-Za-z0-9]{40,}\b"
            ),
            score=0.9,
        ),
    ]
    CONTEXT = ["openai", "gpt", "api", "key"]

    def __init__(self):
        super().__init__(
            supported_entity="OPENAI_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class OpenRouterKeyRecognizer(PatternRecognizer):
    """OpenRouter API keys: ``sk-or-v1-`` + a long alphanumeric body.

    The ``-or-v1-`` infix (with hyphens) means the generic OpenAI ``sk-`` patterns
    never match these, the hyphen breaks ``sk-[A-Za-z0-9]{40,}``, so they need their
    own recogniser. The long, near-unique ``sk-or-v1-`` prefix is what provides the
    precision (false positives are effectively nil), so the body is matched as bounded
    alphanumerics rather than fixed-length hex: real keys are hex and are still caught,
    and the recogniser is robust to length/charset variants without losing precision.
    The bound (40-100) keeps a pathological long line from being swallowed whole.
    """

    PATTERNS = [
        Pattern(
            name="openrouter_key",
            regex=r"\bsk-or-v1-[A-Za-z0-9]{40,100}\b",
            score=0.95,
        ),
    ]
    CONTEXT = ["openrouter", "api", "key"]

    def __init__(self):
        super().__init__(
            supported_entity="OPENROUTER_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class DiscordTokenRecognizer(PatternRecognizer):
    """Discord bot tokens: ``<base64 id>.<base64 ts>.<base64 hmac>``.

    FP-prone, it's just three dot-separated base64-ish segments, which a lot of
    other dotted tokens resemble, so the base score is deliberately modest and it
    leans on the context words. A modest score is still well above HOSTNAME (0.25),
    so overlap resolution keeps the whole-token DISCORD_TOKEN span and drops the
    spurious HOSTNAME match on the trailing ``.segment`` (the stress-test bug).
    """

    PATTERNS = [
        Pattern(
            name="discord_token",
            regex=r"\b[A-Za-z0-9_-]{24,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,40}\b",
            score=0.4,
        ),
    ]
    CONTEXT = ["discord", "bot", "token"]

    def __init__(self):
        super().__init__(
            supported_entity="DISCORD_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class FcmServerKeyRecognizer(PatternRecognizer):
    """Legacy Firebase/Google Cloud Messaging server keys.

    ``AAAA`` + short id + ``:APA91b`` + a long base64url body. The ``:APA91b``
    infix is distinctive enough that this won't collide with generic base64, so
    it scores high.
    """

    PATTERNS = [
        Pattern(
            name="fcm_server_key",
            regex=r"\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}\b",
            score=0.9,
        ),
    ]
    CONTEXT = ["firebase", "fcm", "gcm", "google", "messaging"]

    def __init__(self):
        super().__init__(
            supported_entity="FCM_SERVER_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class TwilioSidRecognizer(PatternRecognizer):
    """Twilio account / API key SIDs: ``AC`` or ``SK`` + 32 hex chars.

    Two-letter prefixes are FP-prone (any 34-char hex string starting AC/SK), so
    the base score is low and it relies on the ``twilio`` context to become
    confident, the same approach as AWS_SECRET_KEY / AWS_ACCOUNT_ID.
    """

    PATTERNS = [
        Pattern(
            name="twilio_sid",
            regex=r"\b(?:AC|SK)[0-9a-fA-F]{32}\b",
            score=0.4,
        ),
    ]
    CONTEXT = ["twilio", "sid", "account", "auth"]

    def __init__(self):
        super().__init__(
            supported_entity="TWILIO_SID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class SendGridKeyRecognizer(PatternRecognizer):
    """SendGrid API keys: ``SG.`` + two base64url segments. Distinctive prefix,
    scores high (and so wins overlap against the generic AWS_SECRET_KEY blob)."""

    PATTERNS = [
        Pattern(
            name="sendgrid_key",
            regex=r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b",
            score=0.9,
        ),
    ]
    CONTEXT = ["sendgrid", "api", "key", "mail"]

    def __init__(self):
        super().__init__(
            supported_entity="SENDGRID_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class SshPublicKeyRecognizer(PatternRecognizer):
    """SSH public keys: ``ssh-rsa AAAA…``, ``ssh-ed25519 AAAA…``, ``ecdsa-sha2-…``.

    A public key isn't a secret, but it identifies a host/user, so it's scrubbed
    as a lower-severity *identifier* with its own entity and a modest score. The
    body match stops at the first non-base64 char, so a trailing ``user@host``
    comment is left for the EMAIL_ADDRESS recogniser rather than swallowed here.
    """

    PATTERNS = [
        Pattern(
            name="ssh_public_key",
            regex=(
                r"\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521))"
                r"\s+AAAA[0-9A-Za-z+/]+=*"
            ),
            score=0.7,
        ),
    ]
    CONTEXT = ["ssh", "key", "authorized_keys", "public", "pubkey"]

    def __init__(self):
        super().__init__(
            supported_entity="SSH_PUBLIC_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class EmailAddressRecognizer(PatternRecognizer):
    """Email addresses. Scored high-ish so that, in overlap resolution, the full
    address beats a bare HOSTNAME match on its domain part, this is what fixes the
    stress-test mis-classification of an email domain as HOSTNAME."""

    PATTERNS = [
        Pattern(
            name="email_address",
            regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            score=0.8,
        ),
    ]
    CONTEXT = ["email", "mail", "from", "to", "contact", "sender", "recipient"]

    def __init__(self):
        super().__init__(
            supported_entity="EMAIL_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class GitLabTokenRecognizer(PatternRecognizer):
    """GitLab personal access tokens: ``glpat-`` + 20 chars. Distinctive prefix."""

    PATTERNS = [
        Pattern(
            name="gitlab_token",
            regex=r"\bglpat-[A-Za-z0-9_-]{20}\b",
            score=0.9,
        ),
    ]
    CONTEXT = ["gitlab", "token", "pat", "ci"]

    def __init__(self):
        super().__init__(
            supported_entity="GITLAB_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class NpmTokenRecognizer(PatternRecognizer):
    """npm access tokens: ``npm_`` + 36 chars. Often seen as
    ``//registry.npmjs.org/:_authToken=npm_…``, we match the ``npm_…`` token itself."""

    PATTERNS = [
        Pattern(
            name="npm_token",
            regex=r"\bnpm_[A-Za-z0-9]{36}\b",
            score=0.9,
        ),
    ]
    CONTEXT = ["npm", "token", "registry", "authtoken"]

    def __init__(self):
        super().__init__(
            supported_entity="NPM_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class ShopifyTokenRecognizer(PatternRecognizer):
    """Shopify access tokens: ``shpat_``/``shpca_``/``shppa_``/``shpss_`` + 32 hex."""

    PATTERNS = [
        Pattern(
            name="shopify_token",
            regex=r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b",
            score=0.9,
        ),
    ]
    CONTEXT = ["shopify", "token", "access", "api"]

    def __init__(self):
        super().__init__(
            supported_entity="SHOPIFY_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class TelegramBotTokenRecognizer(PatternRecognizer):
    """Telegram bot tokens: ``<8-10 digit bot id>:<35-char secret>``.

    The bare digits-colon-base64 shape can resemble other ``id:secret`` pairs, so
    while the score is high the context words ('telegram', 'bot') reinforce it.
    """

    PATTERNS = [
        Pattern(
            name="telegram_bot_token",
            regex=r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
            score=0.85,
        ),
    ]
    CONTEXT = ["telegram", "bot", "token"]

    def __init__(self):
        super().__init__(
            supported_entity="TELEGRAM_BOT_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class SlackWebhookRecognizer(PatternRecognizer):
    """Slack incoming-webhook URLs: ``https://hooks.slack.com/services/T…/B…/…``.

    Fixed host and path make this unambiguous, so it scores high.
    """

    PATTERNS = [
        Pattern(
            name="slack_webhook",
            regex=(
                r"\bhttps://hooks\.slack\.com/services/"
                r"T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"
            ),
            score=0.9,
        ),
    ]
    CONTEXT = ["slack", "webhook", "hook", "incoming"]

    def __init__(self):
        super().__init__(
            supported_entity="SLACK_WEBHOOK",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class DiscordWebhookRecognizer(PatternRecognizer):
    """Discord webhook URLs: ``https://discord(app).com/api/webhooks/<id>/<token>``.

    Fixed host and path make this unambiguous, so it scores high.
    """

    PATTERNS = [
        Pattern(
            name="discord_webhook",
            regex=(
                r"\bhttps://(?:ptb\.|canary\.)?discord(?:app)?\.com"
                r"/api/webhooks/\d+/[A-Za-z0-9_-]+"
            ),
            score=0.9,
        ),
    ]
    CONTEXT = ["discord", "webhook", "hook"]

    def __init__(self):
        super().__init__(
            supported_entity="DISCORD_WEBHOOK",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class UrlWithCredentialsRecognizer(PatternRecognizer):
    """URLs that embed ``user:password@`` credentials, a high-value leak.

    Scoped to ``http(s)``/``ftp(s)``/``ssh`` schemes so it *complements* rather
    than duplicates ``DB_CONNECTION_STRING`` (which owns ``postgres://``,
    ``mysql://`` etc.); those keep their own, more specific entity via overlap
    resolution. The mandatory ``:password@`` means a plain credential-less URL
    such as ``https://example.com`` does not match.
    """

    PATTERNS = [
        Pattern(
            name="url_with_credentials",
            regex=r"\b(?:https?|ftps?|ssh)://[^\s:@/]+:[^\s@/]+@[^\s/]+",
            score=0.85,
        ),
    ]
    CONTEXT = ["url", "credentials", "password", "login", "auth"]

    def __init__(self):
        super().__init__(
            supported_entity="URL_WITH_CREDENTIALS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


# ---------------------------------------------------------------------------
# Validated recognisers (not just regex), IP addresses and credit cards
# ---------------------------------------------------------------------------

# Candidate IPv4 / IPv6 strings; validity + scope decided by `ipaddress`.
# The IPv6 candidate is deliberately permissive (it allows ``::`` compression by
# letting each hextet group be empty) because ``ipaddress.ip_address`` is the real
# gate, malformed candidates like ``:::::`` or a MAC address are rejected there.
_IPV4_CANDIDATE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f:.])"
    r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?"
    r"(?![0-9A-Fa-f:.])"
)


class IpAddressRecognizer(EntityRecognizer):
    """Finds IPv4/IPv6 and *validates* with the stdlib, classifying each as
    INTERNAL_IP (RFC1918 / loopback / link-local) or PUBLIC_IP.

    Internal addresses are the higher-risk leak (they map your topology) and so
    get the higher score. This avoids the classic regex FP where '999.1.2.3' or a
    version string like '1.2.3.4.5' is flagged as an address.
    """

    ENTITIES = ["INTERNAL_IP", "PUBLIC_IP"]
    CONTEXT = ["ip", "addr", "address", "gateway", "subnet", "host", "src", "dst"]

    def __init__(self):
        super().__init__(
            supported_entities=self.ENTITIES,
            name="IpAddressRecognizer",
            supported_language="en",
        )

    def load(self) -> None:  # required by EntityRecognizer
        pass

    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts=None,
    ) -> List[RecognizerResult]:
        results: List[RecognizerResult] = []
        for pattern in (_IPV4_CANDIDATE, _IPV6_CANDIDATE):
            for match in pattern.finditer(text):
                raw = match.group()
                host_part = raw.split("/")[0]
                try:
                    ip = ipaddress.ip_address(host_part)
                except ValueError:
                    continue  # not a real address, skip the FP
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    entity, score = "INTERNAL_IP", 0.85
                elif ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                    continue
                else:
                    entity, score = "PUBLIC_IP", 0.6
                if entity in entities:
                    results.append(
                        RecognizerResult(
                            entity_type=entity,
                            start=match.start(),
                            end=match.end(),
                            score=score,
                            analysis_explanation=None,
                        )
                    )
        return results


# Candidate card-number strings: 13-19 digits in the usual 4-digit groupings,
# separated by an optional single space or hyphen. Validity is decided by the
# Luhn checksum in code, not the regex, the same "validate, don't trust the
# pattern" approach used for IP addresses (a bare digit run is far too FP-prone).
_CC_CANDIDATE = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")


def _luhn_valid(digits: str) -> bool:
    """Return True if ``digits`` (a bare digit string) passes the Luhn checksum."""
    nums = [int(c) for c in digits]
    checksum = sum(nums[-1::-2])
    checksum += sum(sum(divmod(d * 2, 10)) for d in nums[-2::-2])
    return checksum % 10 == 0


class CreditCardRecognizer(EntityRecognizer):
    """Payment-card numbers, validated with the Luhn checksum.

    A long digit run is extremely FP-prone (order ids, phone numbers, account
    numbers all look the same), so a regex match alone is not enough: a candidate
    is only emitted when it is 13-19 digits *and* passes Luhn. This mirrors the
    IP recogniser's "validate in code" technique rather than trusting the pattern.
    """

    ENTITIES = ["CREDIT_CARD"]
    CONTEXT = ["card", "credit", "visa", "mastercard", "amex", "payment", "cc"]

    def __init__(self):
        super().__init__(
            supported_entities=self.ENTITIES,
            name="CreditCardRecognizer",
            supported_language="en",
        )

    def load(self) -> None:  # required by EntityRecognizer
        pass

    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts=None,
    ) -> List[RecognizerResult]:
        if "CREDIT_CARD" not in entities:
            return []
        results: List[RecognizerResult] = []
        for match in _CC_CANDIDATE.finditer(text):
            digits = re.sub(r"[ -]", "", match.group())
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                results.append(
                    RecognizerResult(
                        entity_type="CREDIT_CARD",
                        start=match.start(),
                        end=match.end(),
                        score=0.8,
                        analysis_explanation=None,
                    )
                )
        return results


# ---------------------------------------------------------------------------
# Registry / factory
# ---------------------------------------------------------------------------

_PATTERN_RECOGNIZERS = [
    MacAddressRecognizer,
    AwsAccessKeyRecognizer,
    AwsSecretKeyRecognizer,
    AwsAccountIdRecognizer,
    GitHubTokenRecognizer,
    SlackTokenRecognizer,
    GoogleApiKeyRecognizer,
    StripeKeyRecognizer,
    JwtRecognizer,
    PrivateKeyBlockRecognizer,
    BearerTokenRecognizer,
    DbConnectionStringRecognizer,
    GenericApiKeyRecognizer,
    UnixHomePathRecognizer,
    HostnameRecognizer,
    OpenAiKeyRecognizer,
    OpenRouterKeyRecognizer,
    DiscordTokenRecognizer,
    FcmServerKeyRecognizer,
    TwilioSidRecognizer,
    SendGridKeyRecognizer,
    SshPublicKeyRecognizer,
    EmailAddressRecognizer,
    GitLabTokenRecognizer,
    NpmTokenRecognizer,
    ShopifyTokenRecognizer,
    TelegramBotTokenRecognizer,
    SlackWebhookRecognizer,
    DiscordWebhookRecognizer,
    UrlWithCredentialsRecognizer,
]


def get_security_recognizers() -> List[EntityRecognizer]:
    """Return one instance of every recogniser in the pack."""
    recognizers: List[EntityRecognizer] = [cls() for cls in _PATTERN_RECOGNIZERS]
    recognizers.append(IpAddressRecognizer())
    recognizers.append(CreditCardRecognizer())
    return recognizers


def supported_entities() -> List[str]:
    """All entity types this pack can produce."""
    entities: List[str] = []
    for r in get_security_recognizers():
        entities.extend(r.supported_entities)
    return sorted(set(entities))


def register_security_recognizers(analyzer) -> None:
    """Add every recogniser in the pack to a Presidio AnalyzerEngine.

        analyzer = AnalyzerEngine()
        register_security_recognizers(analyzer)
    """
    for recognizer in get_security_recognizers():
        analyzer.registry.add_recognizer(recognizer)


__all__ = [
    "get_security_recognizers",
    "register_security_recognizers",
    "supported_entities",
]
