# GitVigil — Engineering & Security Standards

GitVigil scans Git history for leaked secrets and IaC misconfigurations. It processes
**untrusted repositories**, so every rule below is mandatory. Violations are bugs.

## Stack
Python 3.12+, `src/gitvigil/` layout, `typer` + `rich` CLI, `pyyaml` (`safe_load` only),
`pydantic` v2 **strict** models (`ConfigDict(strict=True, extra="forbid", frozen=True)`).

## Subprocess / Git safety
1. `subprocess.run`/`Popen` with `shell=False` and a **list** of args. Never build command strings.
2. All Git calls go through `scanner/git_walker.py` helpers. No other module spawns processes.
3. Any user-supplied path or ref is validated first and **rejected if it starts with `-`**
   (prevents flag injection such as `--upload-pack=...` or `-c core.sshCommand=...`).
4. Place `--` (or `--end-of-options`) before user-supplied refs/paths so they cannot be parsed
   as options. Object IDs are validated against `^[0-9a-f]{40,64}$` before use.
5. Run git with a scrubbed environment (no inherited `GIT_*`), `GIT_TERMINAL_PROMPT=0`,
   `core.fsmonitor=false`, and a timeout on every non-streaming call.
6. Read repository content only via Git objects (`cat-file`), never by following working-tree
   paths or symlinks. Reject tree paths containing `..`, NUL, or absolute roots.

## Resource limits
- Skip binary blobs (NUL byte in first 8000 bytes).
- **Max blob size 2 MB** (`constants.MAX_BLOB_BYTES`). Size is checked via `cat-file --batch-check`
  *before* content is read; oversize blobs emit a structured `ScanWarning`.
- Long lines are scanned in bounded overlapping windows; findings per blob are capped.

## Regex rules (ReDoS safety)
- Python `re` is backtracking, so rules must be provably cheap: every quantifier **bounded**
  (no `*`, `+`, `{n,}`), no nested quantifiers, no backreferences. `engine/regex_safety.py`
  enforces this at rule-load time; rules failing lint are rejected, never run.
- Rules are loaded with `yaml.safe_load` and validated by strict pydantic models.

## Secret handling
- Secret values are **redacted by default** (`ghp_****9x2a`) in every output (table, JSON, logs,
  exceptions). The raw value is stored on a finding only when `--reveal-secrets` is passed.
- Never log or print line contents of a match. Fingerprints are SHA-256 over rule/path/secret.
- Sanitize control characters in any attacker-controlled string (paths) before printing.

## Quality gates (must all pass with zero errors)
```
ruff check .
bandit -r src/ -c pyproject.toml
pytest -v
```
`# nosec` / `# noqa` require a justification comment and are allowed only on the audited
subprocess call sites in `git_walker.py`, the `SafeLoader`-subclass YAML load in `engine/iac.py`,
and the `Category.SECRET` enum label.
