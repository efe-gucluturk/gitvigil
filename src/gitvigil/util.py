"""Small helpers for sanitising attacker-controlled strings."""

from __future__ import annotations

import re

# C0/C1 controls (incl. ESC), DEL, and Unicode bidi overrides/isolates used to spoof terminal
# output. Written with escapes (not literal characters) so the source itself stays inert.
_UNSAFE = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u202a-\\u202e\\u2066-\\u2069]")


def sanitize(text: str, limit: int = 500) -> str:
    """Neutralise control characters so repo-controlled strings cannot spoof a terminal."""
    return _UNSAFE.sub("?", text)[:limit]
