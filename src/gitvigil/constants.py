"""Hard limits shared across GitVigil. Changing these weakens the security posture."""

from __future__ import annotations

MAX_BLOB_BYTES = 2 * 1024 * 1024  # 2 MB: larger blobs are skipped with a warning (OOM guard)
BINARY_SNIFF_BYTES = 8000  # NUL byte within this prefix => binary (same heuristic as git)
LINE_WINDOW_CHARS = 8192  # long lines are scanned in overlapping windows of this size
LINE_WINDOW_OVERLAP = 2048
MAX_FINDINGS_PER_BLOB = 500
MAX_RULE_FILE_BYTES = 1024 * 1024
MAX_IGNORE_FILE_BYTES = 1024 * 1024
MAX_IGNORE_PATTERNS = 10_000
MAX_IGNORE_PATTERN_CHARS = 512
MAX_YAML_DOCUMENTS = 64
GIT_TIMEOUT_SECONDS = 600
IGNORE_FILENAME = ".gitvigilignore"
INLINE_IGNORE_MARKER = "gitvigil:ignore"
