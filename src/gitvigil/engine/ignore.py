""".gitvigilignore: gitignore-style path exclusions plus SHA-256 fingerprint allowlisting.

Globbing is implemented with a segment-wise DP (O(pattern * path)) on top of ``fnmatch``,
never by translating whole patterns to backtracking regexes, so hostile ignore files and
hostile paths cannot trigger ReDoS.

Syntax (one entry per line)::

    # comment
    vendor/               directory (any depth when it has no inner slash)
    /docs/**/*.md         anchored to the repository root
    *.min.js              any depth
    sha256:<64 hex>       allowlist one finding fingerprint
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from gitvigil.constants import (
    IGNORE_FILENAME,
    MAX_IGNORE_FILE_BYTES,
    MAX_IGNORE_PATTERN_CHARS,
    MAX_IGNORE_PATTERNS,
)
from gitvigil.models import ScanWarning

_FP_LINE = re.compile(r"(?:sha256|fingerprint):([0-9a-fA-F]{64})")


@dataclass(frozen=True, slots=True)
class _Pattern:
    segments: tuple[str, ...]
    dir_only: bool


@lru_cache(maxsize=4096)
def _seg_match(pattern: str, name: str) -> bool:
    return fnmatch.fnmatchcase(name, pattern)


def _match_prefix(pat: tuple[str, ...], segs: tuple[str, ...], dir_only: bool) -> bool:
    """Does ``pat`` match some leading run of ``segs`` (a path or one of its parent dirs)?"""
    n, m = len(segs), len(pat)
    # reach[i][j]: first i path segments consumed by first j pattern segments.
    reach = [[False] * (m + 1) for _ in range(n + 1)]
    reach[0][0] = True
    for i in range(n + 1):
        for j in range(m + 1):
            if not reach[i][j]:
                continue
            if j < m and pat[j] == "**":
                reach[i][j + 1] = True  # ** matches zero segments
                if i < n:
                    reach[i + 1][j] = True  # ** swallows one more segment
            elif j < m and i < n and _seg_match(pat[j], segs[i]):
                reach[i + 1][j + 1] = True
    last = n - 1 if dir_only else n  # dir-only patterns must match a *parent* directory
    return any(reach[i][m] for i in range(1, last + 1))


@dataclass(slots=True)
class IgnoreRules:
    patterns: list[_Pattern] = field(default_factory=list)
    fingerprints: set[str] = field(default_factory=set)

    def is_path_ignored(self, path: str) -> bool:
        segs = tuple(path.split("/"))
        return any(_match_prefix(p.segments, segs, p.dir_only) for p in self.patterns)

    def is_fingerprint_allowed(self, fp: str) -> bool:
        return fp in self.fingerprints

    @classmethod
    def parse(cls, text: str) -> tuple[IgnoreRules, list[ScanWarning]]:
        rules = cls()
        warnings: list[ScanWarning] = []
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if (m := _FP_LINE.fullmatch(line)) is not None:
                rules.fingerprints.add(m.group(1).lower())
                continue
            if len(rules.patterns) >= MAX_IGNORE_PATTERNS:
                warnings.append(_warn(f"too many patterns (limit {MAX_IGNORE_PATTERNS})"))
                break
            if line.startswith("!") or len(line) > MAX_IGNORE_PATTERN_CHARS or "\0" in line:
                warnings.append(_warn(f"line {lineno}: unsupported or oversized pattern ignored"))
                continue
            dir_only = line.endswith("/")
            body = line.strip("/")
            anchored = line.startswith("/") or "/" in body
            segs = tuple(s for s in body.split("/") if s)
            if not segs or any(s in (".", "..") for s in segs):
                warnings.append(_warn(f"line {lineno}: invalid pattern ignored"))
                continue
            if not anchored:
                segs = ("**", *segs)
            rules.patterns.append(_Pattern(segs, dir_only))
        return rules, warnings


def _warn(message: str) -> ScanWarning:
    return ScanWarning(code="ignore-file", message=f"{IGNORE_FILENAME}: {message}")


def load_ignore_file(path: Path) -> tuple[IgnoreRules, list[ScanWarning]]:
    """Load an ignore file, refusing symlinks and oversized files."""
    try:
        if path.is_symlink() or not path.is_file():
            return IgnoreRules(), []
        if path.stat().st_size > MAX_IGNORE_FILE_BYTES:
            return IgnoreRules(), [_warn("file too large; ignored")]
        text = path.read_bytes().decode("utf-8", "replace")
    except OSError:
        return IgnoreRules(), []
    return IgnoreRules.parse(text)
