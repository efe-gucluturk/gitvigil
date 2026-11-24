"""Shared engine helpers: entropy, redaction, fingerprints, placeholder heuristics."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter

# Well-known, non-secret, public prefixes that are safe (and useful) to keep when redacting.
_PUBLIC_PREFIXES = ("AKIA", "ASIA", "ABIA", "ACCA", "AIza", "eyJ", "SG.", "ya29.")
_SEP_PREFIX = re.compile(r"[A-Za-z0-9]{2,12}[_-]")

_PLACEHOLDER_SUBSTRINGS = (
    "example", "sample", "dummy", "fake", "placeholder", "changeme", "change_me", "change-me",
    "your_", "your-", "yourkey", "yoursecret", "<your", "redacted", "replace_me", "replaceme",
    "insert_", "xxxxx", "todo", "notasecret", "not_a_secret", "foobar", "${", "{{", "%(",
    "test_secret", "testsecret", "test_password", "testpassword", "test_token", "testtoken",
    "test-token", "test_key", "testkey",
)  # fmt: skip
_PLACEHOLDER_EXACT = frozenset(
    {
        "password", "passwd", "pass", "secret", "token", "admin", "root", "user", "username",
        "postgres", "test", "null", "none", "true", "false", "changeit", "default",
    }
)  # fmt: skip
_REFERENCE_PREFIXES = ("$", "<", "{", "%", "@", "*")

SECRET_NAME = re.compile(
    r"(?i)(?:passwor[dt]|passwd|secret|api[_-]?key|private[_-]?key|credential|auth[_-]?token"
    r"|access[_-]?key|access[_-]?token|token)"
)
_NON_SECRET_SUFFIX = re.compile(
    r"(?i)(?:_file|_path|_name|_arn|_id|_length|_version|_ref|_url|_uri|_dir|_endpoint)$"
)
_LITERAL_NON_SECRETS = frozenset(
    {"true", "false", "yes", "no", "none", "null", "0", "1", "on", "off"}
)


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character (0.0 for empty input)."""
    if not value:
        return 0.0
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in Counter(value).values())


def char_classes(value: str) -> int:
    return sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )


def redact(secret: str, mode: str = "partial") -> str:
    """Mask a secret for display, e.g. ``ghp_****9x2a``. Never returns more than 4 tail chars."""
    if mode == "full" or len(secret) < 12:
        return "****"
    prefix = ""
    for pub in _PUBLIC_PREFIXES:
        if secret.startswith(pub):
            prefix = pub
            break
    else:
        m = _SEP_PREFIX.match(secret)
        if m:
            prefix = m.group(0)
    tail = secret[-4:] if len(secret) >= 16 else ""
    return f"{prefix}****{tail}"


def fingerprint(rule_id: str, path: str, evidence: str) -> str:
    """Stable SHA-256 over rule, path and evidence; safe to commit to an allowlist."""
    h = hashlib.sha256()
    for part in (rule_id, path, evidence):
        h.update(part.encode("utf-8", "replace"))
        h.update(b"\0")
    return h.hexdigest()


def is_placeholder(value: str) -> bool:
    """True if ``value`` looks like documentation/test filler rather than a real credential."""
    low = value.strip().lower()
    if not low:
        return True
    if low in _PLACEHOLDER_EXACT or low.startswith(_REFERENCE_PREFIXES):
        return True
    if any(tok in low for tok in _PLACEHOLDER_SUBSTRINGS):
        return True
    return len(set(low)) <= 2 and len(low) >= 6  # "aaaaaaaa", "0101010101"


def looks_like_secret_assignment(name: str, value: str) -> bool:
    """Heuristic for ENV/ARG/attribute pairs: secret-ish name + literal, non-placeholder value."""
    if len(name) > 256 or not SECRET_NAME.search(name) or _NON_SECRET_SUFFIX.search(name):
        return False
    if value.strip().lower() in _LITERAL_NON_SECRETS:
        return False
    return not is_placeholder(value)
