# GitVigil

Security-hardened scanner for leaked secrets and IaC misconfigurations across full Git history,
including commits where the secret was later deleted and unreachable (dangling) blobs.

```
gitvigil scan PATH [--rev REF] [--no-dangling] [--format table|json] [--fail-on LEVEL]
                   [--ignore-file FILE] [--reveal-secrets]
gitvigil rules
```

Secrets are redacted by default. See `CLAUDE.md` for the security model.
Suppress with a `.gitvigilignore` (gitignore-style path globs, plus `sha256:<fingerprint>` lines).
