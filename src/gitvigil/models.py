"""Strict pydantic v2 models shared by scanner, engines and CLI."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]


class Category(StrEnum):
    # Enum label, not a credential (hence the S105/B105 suppressions below).
    SECRET = "secret"  # noqa: S105  # nosec B105
    IAC = "iac"


class Source(StrEnum):
    HISTORY = "history"
    DANGLING = "dangling"
    STAGED = "staged"


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


def coerce_severity(value: Any) -> Any:
    """Rule files are YAML strings; strict mode needs real enum members."""
    if isinstance(value, str):
        try:
            return Severity(value)
        except ValueError:
            return value
    return value


class Finding(StrictModel):
    rule_id: str
    title: str
    category: Category
    severity: Severity
    cwe: str
    path: str
    line: int = Field(ge=1)
    commit: str | None
    blob_sha: str
    source: Source
    redacted_match: str
    fingerprint: str
    remediation: str
    entropy: float | None = None
    # Populated ONLY when the caller explicitly opts in (--reveal-secrets).
    # Untrusted commit metadata (attacker-controlled): always escape before rendering.
    author: str | None = None
    message: str | None = None
    secret: str | None = Field(default=None, repr=False)

    _sev = field_validator("severity", mode="before")(coerce_severity)


class ScanWarning(StrictModel):
    code: str
    message: str
    path: str | None = None
    blob_sha: str | None = None


class ScanStats(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    commits: int = 0
    blobs_scanned: int = 0
    blobs_dangling: int = 0
    skipped_binary: int = 0
    skipped_oversize: int = 0
    skipped_ignored: int = 0
    suppressed_findings: int = 0


class ScanResult(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    repository: str
    findings: list[Finding] = Field(default_factory=list)
    warnings: list[ScanWarning] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)
