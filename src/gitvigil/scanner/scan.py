"""Scan orchestration: walker -> engines -> suppression -> deduplicated findings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from gitvigil.constants import IGNORE_FILENAME
from gitvigil.engine.iac import IacEngine
from gitvigil.engine.ignore import load_ignore_file
from gitvigil.engine.secrets import SecretEngine
from gitvigil.models import Finding, ScanResult, ScanWarning
from gitvigil.scanner.git_walker import GitWalker, validate_repo_path
from gitvigil.util import sanitize


@dataclass(slots=True)
class ScanOptions:
    rev: str | None = None
    include_dangling: bool = True
    reveal_secrets: bool = False
    ignore_file: Path | None = None
    scan_secrets: bool = True
    scan_iac: bool = True


def scan_repository(repo: str | os.PathLike[str], options: ScanOptions | None = None) -> ScanResult:
    opts = options or ScanOptions()
    root = validate_repo_path(repo)

    # The ignore file comes from the scanner operator (flag) or the checked-out root. It is read
    # as a plain file - never from the (untrusted) history being scanned.
    ignore, ignore_warnings = load_ignore_file(opts.ignore_file or root / IGNORE_FILENAME)

    secret_engine = SecretEngine(keep_secret=opts.reveal_secrets) if opts.scan_secrets else None
    iac_engine = IacEngine() if opts.scan_iac else None

    walker = GitWalker(
        root,
        rev=opts.rev,
        include_dangling=opts.include_dangling,
        path_filter=ignore.is_path_ignored,
    )
    # Keyed by fingerprint; rev-list is newest-first so later hits are older commits and replace
    # earlier ones, leaving the commit that *introduced* each finding.
    found: dict[str, Finding] = {}
    warnings: list[ScanWarning] = list(ignore_warnings)

    for blob in walker.blobs():
        text = blob.content.decode("utf-8", errors="replace")
        batch: list[Finding] = []
        if secret_engine:
            batch += secret_engine.scan_text(
                text, path=blob.path, blob_sha=blob.sha, commit=blob.commit, source=blob.source
            )
        if iac_engine:
            iac_findings, iac_warnings = iac_engine.scan_text(
                text, path=blob.path, blob_sha=blob.sha, commit=blob.commit, source=blob.source
            )
            batch += iac_findings
            warnings += iac_warnings
        for f in batch:
            if ignore.is_fingerprint_allowed(f.fingerprint):
                walker.stats.suppressed_findings += 1
                continue
            found[f.fingerprint] = f

    warnings = walker.warnings + warnings
    findings = sorted(found.values(), key=lambda f: (-f.severity.rank, f.path, f.line, f.rule_id))
    return ScanResult(
        repository=sanitize(str(root), 300),
        findings=findings,
        warnings=warnings,
        stats=walker.stats,
    )
