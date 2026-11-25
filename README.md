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

## Authorized & Educational Use Only

GitVigil is provided for authorized security auditing of repositories you own or have explicit
permission to test, and for educational purposes. It is a passive, read-only scanner of Git
history and IaC files; do not use it against systems or data you are not authorized to assess.
The author accepts no liability for misuse. Provided under the MIT License (see `LICENSE`).
