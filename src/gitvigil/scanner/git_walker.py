"""Hardened Git history + dangling-object walker.

Security model: the repository is *untrusted input*. We never execute anything from it, never
read the working tree, validate every user-supplied path/ref, and bound all memory use.
All process spawning in GitVigil lives in this module.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from gitvigil.constants import (
    BINARY_SNIFF_BYTES,
    GIT_TIMEOUT_SECONDS,
    MAX_BLOB_BYTES,
)
from gitvigil.models import ScanStats, ScanWarning, Source
from gitvigil.util import sanitize


class GitSecurityError(ValueError):
    """User input (path/ref) was rejected as unsafe."""


class GitError(RuntimeError):
    """A git invocation failed."""


_SHA_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
# No ':' (blocks "REV:path" tree access), no whitespace, no '=' (blocks "--opt=value" shapes).
_REF_RE = re.compile(r"[A-Za-z0-9_@./^~{}+\-]{1,256}")
_SKIP_MODES = {"120000", "160000"}  # symlink targets and submodule commits are not file content

_GIT = shutil.which("git")

# Hardening applied to every invocation. Hooks never run for these plumbing commands, but a
# hostile .git/config could still set e.g. core.fsmonitor / core.pager.
_GLOBAL_OPTS = (
    "--no-pager",
    "--no-optional-locks",
    "-c", "core.fsmonitor=false",
    "-c", "core.pager=cat",
    "-c", "core.quotepath=false",
    "-c", "protocol.ext.allow=never",
)  # fmt: skip


def _git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",  # never hit the network for partial-clone promisor blobs
            "GIT_ASKPASS": "",
            "LC_ALL": "C",
        }
    )
    return env


def _require_git() -> str:
    if _GIT is None:
        raise GitError("git executable not found on PATH")
    return _GIT


def _check_args(args: Sequence[str]) -> None:
    for arg in args:
        if not isinstance(arg, str) or "\0" in arg:
            raise GitSecurityError("invalid git argument")


# ---------------------------------------------------------------- input validation


def validate_ref(ref: str) -> str:
    """Return ``ref`` if it is safe to hand to git, else raise :class:`GitSecurityError`."""
    if not isinstance(ref, str) or not ref:
        raise GitSecurityError("ref must be a non-empty string")
    if ref.startswith("-"):
        raise GitSecurityError("ref must not start with '-' (git flag injection)")
    if not _REF_RE.fullmatch(ref):
        raise GitSecurityError("ref contains disallowed characters")
    return ref


def validate_sha(sha: str) -> str:
    if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
        raise GitSecurityError("invalid object id")
    return sha


def validate_repo_path(path: str | os.PathLike[str]) -> Path:
    """Resolve ``path`` and require that it is exactly the root of a Git repository.

    Rejects leading ``-`` (flag injection), NUL bytes, missing paths, non-directories and
    sub-directories of a repository (which would silently widen/narrow the scan scope).
    """
    raw = os.fspath(path)
    if not raw or "\0" in raw:
        raise GitSecurityError("invalid repository path")
    if raw.startswith("-"):
        raise GitSecurityError("repository path must not start with '-' (git flag injection)")
    try:
        resolved = Path(raw).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise GitSecurityError(f"repository path not accessible: {sanitize(raw, 200)}") from exc
    if not resolved.is_dir():
        raise GitSecurityError("repository path is not a directory")

    bare = _run_git(resolved, ["rev-parse", "--is-bare-repository"], check=False)
    if bare.returncode != 0:
        raise GitSecurityError("path is not a git repository (or git refused: dubious ownership)")
    if bare.stdout.strip() == b"true":
        gitdir = _run_git(resolved, ["rev-parse", "--absolute-git-dir"]).stdout.decode().strip()
        top = Path(gitdir)
    else:
        top = Path(_run_git(resolved, ["rev-parse", "--show-toplevel"]).stdout.decode().strip())
    try:
        same = os.path.samefile(top, resolved)
    except OSError:
        same = False
    if not same:
        raise GitSecurityError("path must be the root of the repository")
    return resolved


def sanitize_tree_path(path: str) -> str | None:
    """Return a safe repo-relative path, or ``None`` if the tree entry looks malicious."""
    if not path or "\0" in path or path.startswith("/") or path.startswith("\\"):
        return None
    if len(path) > 1 and path[1] == ":":  # drive-letter absolute path
        return None
    parts = path.split("/")
    if any(p in ("", ".", "..") or p.lower() == ".git" for p in parts):
        return None
    return path


# ---------------------------------------------------------------- git plumbing


def _run_git(
    repo: Path,
    args: Sequence[str],
    *,
    timeout: float = GIT_TIMEOUT_SECONDS,
    check: bool = True,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    _check_args(args)
    cmd = [_require_git(), *_GLOBAL_OPTS, "-C", str(repo), *args]
    try:
        proc = subprocess.run(  # noqa: S603  # nosec B603
            cmd,
            capture_output=True,
            shell=False,
            check=False,
            timeout=timeout,
            env={**_git_env(), **(extra_env or {})},
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {args[0]} timed out after {timeout}s") from exc
    if check and proc.returncode != 0:
        msg = sanitize(proc.stderr.decode("utf-8", "replace").strip(), 300)
        raise GitError(f"git {args[0]} failed: {msg}")
    return proc


class _ObjectReader:
    """Two long-lived ``cat-file`` processes: size probe first, content only if allowed."""

    def __init__(self, repo: Path) -> None:
        self._repo = repo
        self._check: subprocess.Popen[bytes] | None = None
        self._batch: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> _ObjectReader:
        self._check = self._spawn("--batch-check")
        self._batch = self._spawn("--batch")
        return self

    def __exit__(self, *exc: object) -> None:
        for proc in (self._check, self._batch):
            if proc is None:
                continue
            try:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                proc.kill()
                proc.wait()
            finally:
                if proc.stdout:
                    proc.stdout.close()

    def _spawn(self, mode: str) -> subprocess.Popen[bytes]:
        cmd = [_require_git(), *_GLOBAL_OPTS, "-C", str(self._repo), "cat-file", mode]
        return subprocess.Popen(  # noqa: S603  # nosec B603
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # avoid pipe deadlock; errors surface as "missing"
            shell=False,
            env=_git_env(),
        )

    @staticmethod
    def _send(proc: subprocess.Popen[bytes], sha: str) -> IO[bytes]:
        if proc.stdin is None or proc.stdout is None:
            raise GitError("cat-file pipe unavailable")
        proc.stdin.write(validate_sha(sha).encode("ascii") + b"\n")
        proc.stdin.flush()
        return proc.stdout

    def size(self, sha: str) -> tuple[str, int] | None:
        """Return ``(type, size)`` or ``None`` if the object is missing."""
        if self._check is None:
            raise GitError("reader not started")
        out = self._send(self._check, sha)
        parts = out.readline().split()
        if len(parts) != 3 or parts[1] == b"missing":
            return None
        return parts[1].decode("ascii", "replace"), int(parts[2])

    def read(self, sha: str, expected_size: int) -> bytes:
        """Read a blob whose size was already checked against the cap."""
        if self._batch is None:
            raise GitError("reader not started")
        out = self._send(self._batch, sha)
        parts = out.readline().split()
        if len(parts) != 3 or int(parts[2]) != expected_size:
            raise GitError("unexpected cat-file header")
        data = out.read(expected_size)
        out.read(1)  # trailing LF
        if len(data) != expected_size:
            raise GitError("short read from cat-file")
        return data


# ---------------------------------------------------------------- walker


@dataclass(frozen=True, slots=True)
class BlobRecord:
    sha: str
    path: str
    commit: str | None
    source: Source
    content: bytes = field(repr=False)


class GitWalker:
    """Yield every text blob ever committed, plus unreachable (dangling) blobs."""

    def __init__(
        self,
        repo: str | os.PathLike[str],
        *,
        rev: str | None = None,
        include_dangling: bool = True,
        max_blob_bytes: int = MAX_BLOB_BYTES,
        path_filter: Callable[[str], bool] | None = None,
    ) -> None:
        self.repo = validate_repo_path(repo)
        self.rev = validate_ref(rev) if rev is not None else None
        self.include_dangling = include_dangling
        self.max_blob_bytes = max_blob_bytes
        self.path_filter = path_filter  # returns True => skip this path
        self.warnings: list[ScanWarning] = []
        self.stats = ScanStats()

    def blobs(self) -> Iterator[BlobRecord]:
        with _ObjectReader(self.repo) as reader:
            seen: set[tuple[str, str]] = set()
            for commit in self._commits():
                self.stats.commits += 1
                for sha, path in self._changed_blobs(commit):
                    if (sha, path) in seen:
                        continue
                    seen.add((sha, path))
                    if self.path_filter and self.path_filter(path):
                        self.stats.skipped_ignored += 1
                        continue
                    rec = self._load(reader, sha, path, commit, Source.HISTORY)
                    if rec:
                        yield rec
            if self.include_dangling:
                for sha in self._dangling_blobs():
                    path = f"<dangling:{sha[:12]}>"
                    rec = self._load(reader, sha, path, None, Source.DANGLING)
                    if rec:
                        self.stats.blobs_dangling += 1
                        yield rec

    # -- internals ------------------------------------------------------

    def _warn(
        self, code: str, message: str, path: str | None = None, sha: str | None = None
    ) -> None:
        self.warnings.append(
            ScanWarning(
                code=code,
                message=sanitize(message, 300),
                path=sanitize(path, 300) if path else None,
                blob_sha=sha,
            )
        )

    def _commits(self) -> list[str]:
        if self.rev is None:
            args = ["rev-list", "--all", "--"]
        else:
            args = ["rev-list", "--end-of-options", self.rev, "--"]
        proc = _run_git(self.repo, args, check=False)
        if proc.returncode != 0:
            raise GitError(f"cannot list commits: {sanitize(self.rev or '--all', 100)}")
        return [validate_sha(ln) for ln in proc.stdout.decode("ascii", "replace").split()]

    def _changed_blobs(self, commit: str) -> Iterator[tuple[str, str]]:
        proc = _run_git(
            self.repo,
            [
                "diff-tree", "-r", "-z", "--root", "-m", "--no-renames", "--no-abbrev",
                "--no-commit-id", "--diff-filter=AMT", commit, "--",
            ],
            check=False,
        )  # fmt: skip
        if proc.returncode != 0:
            self._warn("diff-failed", f"diff-tree failed for commit {commit[:12]}")
            return
        yield from self._parse_raw_diff(proc.stdout)

    def _parse_raw_diff(self, data: bytes) -> Iterator[tuple[str, str]]:
        fields = data.split(b"\0")
        i = 0
        while i + 1 < len(fields):
            meta = fields[i].decode("ascii", "replace")
            raw_path = fields[i + 1].decode("utf-8", "replace")
            i += 2
            parts = meta.lstrip(":").split()
            if len(parts) < 5:
                continue
            new_mode, new_sha = parts[1], parts[3]
            if new_mode in _SKIP_MODES or not _SHA_RE.fullmatch(new_sha):
                continue
            safe = sanitize_tree_path(raw_path)
            if safe is None:
                self._warn("unsafe-path", "skipped tree entry with unsafe path", raw_path, new_sha)
                continue
            yield new_sha, safe

    def staged_blobs(self) -> Iterator[BlobRecord]:
        """Yield blobs staged in the index (for the pre-commit hook), read from the object db."""
        head = _run_git(self.repo, ["rev-parse", "--verify", "--quiet", "HEAD"], check=False)
        if head.returncode == 0:
            base = validate_sha(head.stdout.decode("ascii", "replace").strip())
        else:  # initial commit: diff against the empty tree
            empty = _run_git(self.repo, ["hash-object", "-t", "tree", "--stdin"])
            base = validate_sha(empty.stdout.decode().strip())
        extra = None
        if "GIT_INDEX_FILE" in os.environ:  # hook runs with a temp index for `commit -a`/`--only`
            extra = {"GIT_INDEX_FILE": os.environ["GIT_INDEX_FILE"]}
        proc = _run_git(
            self.repo,
            ["diff-index", "--cached", "-r", "-z", "--no-renames", "--no-abbrev",
             "--diff-filter=AMT", base, "--"],
            extra_env=extra,
            check=False,
        )  # fmt: skip
        if proc.returncode != 0:
            raise GitError("cannot read the staged changes")
        with _ObjectReader(self.repo) as reader:
            for sha, path in self._parse_raw_diff(proc.stdout):
                if self.path_filter and self.path_filter(path):
                    self.stats.skipped_ignored += 1
                    continue
                rec = self._load(reader, sha, path, None, Source.STAGED)
                if rec:
                    yield rec

    def _dangling_blobs(self) -> list[str]:
        proc = _run_git(
            self.repo,
            ["fsck", "--full", "--no-reflogs", "--unreachable", "--no-progress"],
            check=False,
        )
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            self._warn("fsck-errors", f"git fsck reported problems: {err[0] if err else 'unknown'}")
        found: dict[str, None] = {}
        for line in proc.stdout.decode("ascii", "replace").splitlines():
            parts = line.split()
            is_blob = len(parts) == 3 and parts[0] in ("dangling", "unreachable")
            if is_blob and parts[1] == "blob" and _SHA_RE.fullmatch(parts[2]):
                found[parts[2]] = None
        return list(found)

    def _load(
        self,
        reader: _ObjectReader,
        sha: str,
        path: str,
        commit: str | None,
        source: Source,
    ) -> BlobRecord | None:
        info = reader.size(sha)
        if info is None:
            self._warn("blob-missing", "blob not present in object database", path, sha)
            return None
        otype, size = info
        if otype != "blob":
            return None
        if size > self.max_blob_bytes:
            self.stats.skipped_oversize += 1
            self._warn(
                "blob-too-large",
                f"skipped blob of {size} bytes (limit {self.max_blob_bytes})",
                path,
                sha,
            )
            return None
        data = reader.read(sha, size)
        if b"\0" in data[:BINARY_SNIFF_BYTES]:
            self.stats.skipped_binary += 1
            return None
        self.stats.blobs_scanned += 1
        return BlobRecord(sha=sha, path=path, commit=commit, source=source, content=data)


# ---------------------------------------------------------------- repository metadata helpers


def git_dir(repo: Path) -> Path:
    """Absolute path of the repository's git directory."""
    out = _run_git(repo, ["rev-parse", "--absolute-git-dir"]).stdout.decode().strip()
    return Path(out)


def git_config_get(repo: Path, key: str) -> str | None:
    """Read one config value (``key`` must be a fixed, internal name, never user input)."""
    proc = _run_git(repo, ["config", "--get", "--", key], check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "replace").strip() or None


def read_commit_metadata(repo: Path, shas: Sequence[str]) -> dict[str, tuple[str, str]]:
    """Map commit sha -> (author name, subject). Values are untrusted: escape before display."""
    out: dict[str, tuple[str, str]] = {}
    unique = [validate_sha(s) for s in dict.fromkeys(shas)]
    fmt = "--format=%H%x1f%an%x1f%s%x1e"
    for i in range(0, len(unique), 200):
        chunk = unique[i : i + 200]
        proc = _run_git(
            repo, ["log", "--no-walk=unsorted", fmt, "--end-of-options", *chunk, "--"], check=False
        )
        if proc.returncode != 0:
            continue
        for record in proc.stdout.decode("utf-8", "replace").split("\x1e"):
            parts = record.strip("\n").split("\x1f", 2)
            if len(parts) == 3 and _SHA_RE.fullmatch(parts[0]):
                out[parts[0]] = (parts[1][:200], parts[2][:500])
    return out
