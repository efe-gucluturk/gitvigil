"""Static linter that rejects regexes capable of catastrophic backtracking.

Python's ``re`` is a backtracking engine. We cannot swap engines, so instead rule patterns must
be *provably cheap*: all quantifiers bounded, no nested quantifiers, no backreferences.
Together with line-windowing, worst-case cost is polynomial with a small fixed degree.
"""

from __future__ import annotations

import re
from re import _constants as sre_constants  # type: ignore[attr-defined]
from re import _parser as sre_parse  # type: ignore[attr-defined]

MAX_PATTERN_CHARS = 1000
MAX_REPEAT_BOUND = 4096
MAX_REPEATS_PER_PATTERN = 16

_REPEAT_OPS = {sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT, sre_constants.POSSESSIVE_REPEAT}
_BACKREF_OPS = {sre_constants.GROUPREF, sre_constants.GROUPREF_EXISTS}


class UnsafeRegexError(ValueError):
    """Raised when a rule pattern fails the ReDoS lint."""


def compile_safe(pattern: str) -> re.Pattern[str]:
    """Lint then compile ``pattern``; raises :class:`UnsafeRegexError` on any violation."""
    if not isinstance(pattern, str) or not pattern:
        raise UnsafeRegexError("pattern must be a non-empty string")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise UnsafeRegexError(f"pattern longer than {MAX_PATTERN_CHARS} characters")
    try:
        tree = sre_parse.parse(pattern)
    except (re.error, RecursionError, OverflowError) as exc:
        raise UnsafeRegexError(f"invalid regex: {exc}") from exc
    counter = [0]
    _walk(list(tree), in_repeat=False, counter=counter)
    try:
        return re.compile(pattern)
    except re.error as exc:  # pragma: no cover - parse() already succeeded
        raise UnsafeRegexError(f"invalid regex: {exc}") from exc


def _walk(items: list, *, in_repeat: bool, counter: list[int]) -> None:
    for op, av in items:
        if op in _BACKREF_OPS:
            raise UnsafeRegexError("backreferences are not allowed")
        if op in _REPEAT_OPS:
            _lo, hi, sub = av
            if hi == sre_constants.MAXREPEAT or hi > MAX_REPEAT_BOUND:
                raise UnsafeRegexError(
                    f"unbounded or oversized quantifier (max {MAX_REPEAT_BOUND}); use {{m,n}}"
                )
            counter[0] += 1
            if counter[0] > MAX_REPEATS_PER_PATTERN:
                raise UnsafeRegexError("too many quantifiers")
            if in_repeat and hi > 1:
                raise UnsafeRegexError("nested quantifiers are not allowed")
            # A repeat of exactly {0,1} is harmless wrapper; anything wider is "in a repeat".
            _walk(list(sub), in_repeat=in_repeat or hi > 1, counter=counter)
        elif op is sre_constants.SUBPATTERN:
            _walk(list(av[3]), in_repeat=in_repeat, counter=counter)
        elif op is sre_constants.BRANCH:
            for branch in av[1]:
                _walk(list(branch), in_repeat=in_repeat, counter=counter)
        elif op in (sre_constants.ASSERT, sre_constants.ASSERT_NOT):
            _walk(list(av[1]), in_repeat=in_repeat, counter=counter)
        elif op is sre_constants.ATOMIC_GROUP:
            _walk(list(av), in_repeat=in_repeat, counter=counter)
