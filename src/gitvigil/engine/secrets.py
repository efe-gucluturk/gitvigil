"""Secret detection: declarative regex rules + Shannon entropy + false-positive suppression."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, ValidationError, field_validator

from gitvigil.constants import (
    INLINE_IGNORE_MARKER,
    LINE_WINDOW_CHARS,
    LINE_WINDOW_OVERLAP,
    MAX_FINDINGS_PER_BLOB,
    MAX_RULE_FILE_BYTES,
)
from gitvigil.engine.common import (
    char_classes,
    fingerprint,
    is_placeholder,
    redact,
    shannon_entropy,
)
from gitvigil.engine.regex_safety import UnsafeRegexError, compile_safe
from gitvigil.models import (
    Category,
    Finding,
    Severity,
    Source,
    StrictModel,
    coerce_severity,
)

DEFAULT_REMEDIATION = (
    "Revoke and rotate the credential immediately, then purge it from Git history "
    "(git filter-repo / BFG) and move it to a secrets manager."
)


class RuleLoadError(ValueError):
    """A rule file is malformed, unsafe, or inconsistent."""


class SecretRule(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]{2,63}$")
    description: str = Field(min_length=1, max_length=300)
    severity: Severity
    cwe: str = Field(default="CWE-798", pattern=r"^CWE-\d{1,4}$")
    regex: str = Field(min_length=1, max_length=1000)
    keywords: tuple[str, ...] = Field(min_length=1, max_length=32)
    secret_group: int = Field(default=0, ge=0, le=9)
    entropy_min: float | None = Field(default=None, ge=0.0, le=8.0)
    min_char_classes: int = Field(default=1, ge=1, le=4)
    redaction: Literal["partial", "full"] = "partial"
    remediation: str = Field(default=DEFAULT_REMEDIATION, max_length=500)

    _sev = field_validator("severity", mode="before")(coerce_severity)

    @field_validator("keywords", mode="before")
    @classmethod
    def _keywords_lower(cls, v: Any) -> Any:
        if isinstance(v, list):
            if not all(isinstance(k, str) and k for k in v):
                raise ValueError("keywords must be non-empty strings")
            return tuple(k.lower() for k in v)
        return v


@dataclass(frozen=True, slots=True)
class _Compiled:
    rule: SecretRule
    pattern: re.Pattern[str]


class _RuleFile(StrictModel):
    version: Literal[1]
    rules: list[SecretRule] = Field(min_length=1)


def load_secret_rules(path: Path | None = None) -> list[SecretRule]:
    """Load and validate rules. Raises :class:`RuleLoadError` on *any* problem (fail closed)."""
    raw = _read_rule_bytes(path)
    try:
        data = yaml.safe_load(raw)  # safe_load only: rule files may be user-supplied
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"invalid YAML in secret rules: {exc}") from exc
    if not isinstance(data, dict):
        raise RuleLoadError("secret rules file must be a mapping")
    try:
        parsed = _RuleFile.model_validate(data)
    except ValidationError as exc:
        raise RuleLoadError(f"invalid secret rules: {exc}") from exc
    seen: set[str] = set()
    for rule in parsed.rules:
        if rule.id in seen:
            raise RuleLoadError(f"duplicate rule id: {rule.id}")
        seen.add(rule.id)
        try:
            pattern = compile_safe(rule.regex)
        except UnsafeRegexError as exc:
            raise RuleLoadError(f"rule {rule.id}: {exc}") from exc
        if rule.secret_group > pattern.groups:
            raise RuleLoadError(f"rule {rule.id}: secret_group exceeds capture groups")
    return parsed.rules


def _read_rule_bytes(path: Path | None) -> bytes:
    try:
        if path is None:
            data = resources.files("gitvigil.rules").joinpath("secrets.yaml").read_bytes()
        else:
            if path.stat().st_size > MAX_RULE_FILE_BYTES:
                raise RuleLoadError("rule file too large")
            data = path.read_bytes()
    except OSError as exc:
        raise RuleLoadError(f"cannot read rule file: {exc}") from exc
    if len(data) > MAX_RULE_FILE_BYTES:
        raise RuleLoadError("rule file too large")
    return data


class SecretEngine:
    def __init__(self, rules: list[SecretRule] | None = None, *, keep_secret: bool = False) -> None:
        self.rules = rules if rules is not None else load_secret_rules()
        self.keep_secret = keep_secret
        self._compiled = [_Compiled(r, compile_safe(r.regex)) for r in self.rules]

    def scan_text(
        self,
        text: str,
        *,
        path: str,
        blob_sha: str,
        commit: str | None,
        source: Source,
    ) -> list[Finding]:
        findings: dict[tuple[str, int, int], Finding] = {}
        for lineno, line in enumerate(text.split("\n"), 1):
            if len(line) < 8 or INLINE_IGNORE_MARKER in line:
                continue
            for offset, window in _windows(line):
                low = window.lower()
                for comp in self._compiled:
                    rule = comp.rule
                    if not any(k in low for k in rule.keywords):
                        continue
                    for m in comp.pattern.finditer(window):
                        key = (rule.id, lineno, offset + m.start())
                        if key in findings:
                            continue
                        finding = self._evaluate(comp, m, path, blob_sha, commit, source, lineno)
                        if finding is not None:
                            findings[key] = finding
                        if len(findings) >= MAX_FINDINGS_PER_BLOB:
                            return list(findings.values())
        return list(findings.values())

    def _evaluate(
        self,
        comp: _Compiled,
        m: re.Match[str],
        path: str,
        blob_sha: str,
        commit: str | None,
        source: Source,
        lineno: int,
    ) -> Finding | None:
        rule = comp.rule
        secret = m.group(rule.secret_group)
        if not secret or is_placeholder(secret):
            return None
        entropy = shannon_entropy(secret)
        if rule.entropy_min is not None and entropy < rule.entropy_min:
            return None
        if char_classes(secret) < rule.min_char_classes:
            return None
        return Finding(
            rule_id=rule.id,
            title=rule.description,
            category=Category.SECRET,
            severity=rule.severity,
            cwe=rule.cwe,
            path=path,
            line=lineno,
            commit=commit,
            blob_sha=blob_sha,
            source=source,
            redacted_match=redact(secret, rule.redaction),
            fingerprint=fingerprint(rule.id, path, secret),
            remediation=rule.remediation,
            entropy=round(entropy, 2),
            secret=secret if self.keep_secret else None,
        )


def _windows(line: str):
    """Yield ``(offset, window)``; long lines become bounded, overlapping windows."""
    if len(line) <= LINE_WINDOW_CHARS:
        yield 0, line
        return
    step = LINE_WINDOW_CHARS - LINE_WINDOW_OVERLAP
    for start in range(0, len(line), step):
        yield start, line[start : start + LINE_WINDOW_CHARS]
        if start + LINE_WINDOW_CHARS >= len(line):
            break
