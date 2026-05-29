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
                r"(?i)\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?key|"
                r"client[_-]?secret|private[_-]?token|auth[_-]?token)"
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


# ---------------------------------------------------------------------------
# Validated recogniser (not just regex), IP addresses
# ---------------------------------------------------------------------------

# Candidate IPv4 / IPv6 strings; validity + scope decided by `ipaddress`.
_IPV4_CANDIDATE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_IPV6_CANDIDATE = re.compile(
    r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?\b"
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
]


def get_security_recognizers() -> List[EntityRecognizer]:
    """Return one instance of every recogniser in the pack."""
    recognizers: List[EntityRecognizer] = [cls() for cls in _PATTERN_RECOGNIZERS]
    recognizers.append(IpAddressRecognizer())
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
