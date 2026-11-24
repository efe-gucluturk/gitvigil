"""GitVigil command line interface."""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from gitvigil import __version__
from gitvigil.engine.iac import load_iac_rules
from gitvigil.engine.secrets import RuleLoadError, load_secret_rules
from gitvigil.models import ScanResult, Severity
from gitvigil.scanner.git_walker import GitError, GitSecurityError
from gitvigil.scanner.scan import ScanOptions, scan_repository
from gitvigil.util import sanitize

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Scan full Git history for leaked secrets and IaC misconfigurations.",
)

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


class OutputFormat(StrEnum):
    table = "table"
    json = "json"


def _fail(message: str, code: int = 2) -> typer.Exit:
    Console(stderr=True, markup=False, highlight=False).print(f"error: {sanitize(message)}")
    return typer.Exit(code)


@app.command()
def scan(
    path: Annotated[
        str, typer.Argument(help="Repository root. Use `--` before paths starting with '-'.")
    ],
    rev: Annotated[
        str | None, typer.Option("--rev", help="Scan only this ref (default: all refs).")
    ] = None,
    no_dangling: Annotated[
        bool, typer.Option("--no-dangling", help="Skip unreachable blobs.")
    ] = False,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.table,
    fail_on: Annotated[
        Severity,
        typer.Option("--fail-on", help="Exit 1 if any finding has at least this severity."),
    ] = Severity.LOW,
    ignore_file: Annotated[
        Path | None, typer.Option("--ignore-file", help="Custom ignore file.")
    ] = None,
    reveal_secrets: Annotated[
        bool,
        typer.Option("--reveal-secrets", help="DANGEROUS: include raw secret values in output."),
    ] = False,
    no_secrets: Annotated[bool, typer.Option("--no-secrets", help="Disable secret rules.")] = False,
    no_iac: Annotated[bool, typer.Option("--no-iac", help="Disable IaC rules.")] = False,
) -> None:
    """Scan a Git repository's entire history."""
    if reveal_secrets:
        Console(stderr=True, markup=False).print(
            "warning: --reveal-secrets prints raw credentials; do not use in CI logs."
        )
    try:
        result = scan_repository(
            path,
            ScanOptions(
                rev=rev,
                include_dangling=not no_dangling,
                reveal_secrets=reveal_secrets,
                ignore_file=ignore_file,
                scan_secrets=not no_secrets,
                scan_iac=not no_iac,
            ),
        )
    except (GitSecurityError, GitError, RuleLoadError) as exc:
        raise _fail(str(exc)) from exc

    if output_format is OutputFormat.json:
        exclude = None if reveal_secrets else {"findings": {"__all__": {"secret"}}}
        sys.stdout.write(result.model_dump_json(indent=2, exclude=exclude) + "\n")
    else:
        _render_table(result, reveal_secrets)

    if any(f.severity.rank >= fail_on.rank for f in result.findings):
        raise typer.Exit(1)


def _render_table(result: ScanResult, reveal: bool) -> None:
    console = Console(markup=False, highlight=False)
    stats = result.stats
    console.print(
        Text(
            f"GitVigil {__version__} - {result.repository}\n"
            f"commits={stats.commits} blobs={stats.blobs_scanned} dangling={stats.blobs_dangling} "
            f"binary-skipped={stats.skipped_binary} oversize-skipped={stats.skipped_oversize} "
            f"ignored={stats.skipped_ignored} suppressed={stats.suppressed_findings}"
        )
    )
    if result.findings:
        table = Table(show_lines=False)
        for col in ("Severity", "Rule", "Location", "Commit", "Source", "Match", "CWE"):
            table.add_column(col, overflow="fold")
        for f in result.findings:
            match = f.secret if (reveal and f.secret) else f.redacted_match
            table.add_row(
                Text(f.severity.value, style=_SEV_STYLE[f.severity]),
                Text(f.rule_id),
                Text(f"{sanitize(f.path)}:{f.line}"),
                Text(f.commit[:10] if f.commit else "-"),
                Text(f.source.value),
                Text(sanitize(match)),
                Text(f.cwe),
            )
        console.print(table)
    else:
        console.print(Text("No findings.", style="green"))
    for w in result.warnings:
        console.print(Text(f"warning[{w.code}]: {w.message}" + (f" ({w.path})" if w.path else "")))


@app.command()
def rules() -> None:
    """List all loaded detection rules."""
    try:
        secret_rules, iac_rules = load_secret_rules(), load_iac_rules()
    except RuleLoadError as exc:
        raise _fail(str(exc)) from exc
    console = Console(markup=False, highlight=False)
    table = Table()
    for col in ("Rule", "Type", "Severity", "CWE"):
        table.add_column(col)
    for s in secret_rules:
        table.add_row(s.id, "secret", s.severity.value, s.cwe)
    for r in iac_rules:
        table.add_row(r.id, "iac", r.severity.value, r.cwe)
    console.print(table)
    console.print(f"{len(secret_rules)} secret rules, {len(iac_rules)} IaC rules")


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)
